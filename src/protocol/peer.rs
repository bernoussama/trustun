use std::net::SocketAddr;
use std::time::{Duration, Instant};

use snow::params::NoiseParams;

use crate::protocol::errors::ProtocolError;
use crate::protocol::events::{Input, Output};
use crate::protocol::wire::{HandshakeInit, HandshakeResp, TransportData, WirePacket};

const OVERHEAD: usize = 64;
const KEEPALIVE_SECS: u64 = 15;
const REPLAY_WINDOW: u64 = 128;

pub struct PeerConfig {
    pub static_private: [u8; 32],
    pub remote_public: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub sender_index: u32,
    pub receiver_index: u32,
}

enum PeerState {
    Handshaking {
        noise: snow::HandshakeState,
        sender_index: u32,
        receiver_index: u32,
    },
    Established {
        transport: snow::TransportState,
        sender_index: u32,
        receiver_index: u32,
        replay: ReplayWindow,
    },
    Dead,
}

pub struct Peer {
    state: PeerState,
    endpoint: SocketAddr,
    last_activity: Instant,
    pending: Vec<Output>,
}

impl Peer {
    pub fn new(config: PeerConfig, endpoint: SocketAddr) -> Result<Self, ProtocolError> {
        let noise = build_noise(&config, true)?;
        let mut peer = Peer {
            state: PeerState::Handshaking {
                noise,
                sender_index: config.sender_index,
                receiver_index: config.receiver_index,
            },
            endpoint,
            last_activity: Instant::now(),
            pending: Vec::new(),
        };
        peer.queue_handshake_init()?;
        Ok(peer)
    }

    pub fn new_responder(config: PeerConfig, endpoint: SocketAddr) -> Result<Self, ProtocolError> {
        let noise = build_noise(&config, false)?;
        Ok(Peer {
            state: PeerState::Handshaking {
                noise,
                sender_index: config.sender_index,
                receiver_index: config.receiver_index,
            },
            endpoint,
            last_activity: Instant::now(),
            pending: Vec::new(),
        })
    }

    pub fn tick(&mut self, input: Input) -> Result<Vec<Output>, ProtocolError> {
        let mut outputs = self.pending.drain(..).collect::<Vec<_>>();
        match input {
            Input::UdpPacket(data, addr) => match self.state {
                PeerState::Handshaking { .. } => {
                    self.handle_handshake_packet(data, addr, &mut outputs)?
                }
                PeerState::Established { .. } => {
                    self.handle_transport_packet(data, addr, &mut outputs)?
                }
                PeerState::Dead => outputs.push(Output::Log("peer is inactive".into())),
            },
            Input::TunPacket(packet) => {
                self.handle_tun_packet(packet, &mut outputs)?;
            }
            Input::Tick(now) => {
                self.handle_tick(now, &mut outputs)?;
            }
        }
        Ok(outputs)
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, PeerState::Established { .. })
    }

    fn handle_tick(
        &mut self,
        now: Instant,
        outputs: &mut Vec<Output>,
    ) -> Result<(), ProtocolError> {
        if let PeerState::Established {
            transport,
            receiver_index,
            ..
        } = &mut self.state
        {
            if now.duration_since(self.last_activity) >= Duration::from_secs(KEEPALIVE_SECS) {
                let counter = transport.sending_nonce();
                let mut buf = vec![0u8; OVERHEAD];
                let len = transport.write_message(&[], &mut buf)?;
                buf.truncate(len);
                let packet = WirePacket::TransportData(TransportData {
                    receiver_index: *receiver_index,
                    counter,
                    payload: buf,
                });
                outputs.push(Output::SendUdp(packet.serialize()?, self.endpoint));
                self.last_activity = now;
            }
        }
        Ok(())
    }

    fn handle_handshake_packet(
        &mut self,
        data: Vec<u8>,
        addr: SocketAddr,
        outputs: &mut Vec<Output>,
    ) -> Result<(), ProtocolError> {
        let packet = WirePacket::deserialize(&data)?;
        match packet {
            WirePacket::HandshakeInit(init) => {
                let mut finished = false;
                if let PeerState::Handshaking {
                    noise,
                    sender_index,
                    ..
                } = &mut self.state
                {
                    let mut buf = vec![0u8; 256];
                    let _ = noise.read_message(&init.payload, &mut buf)?;
                    let len = noise.write_message(&[], &mut buf)?;
                    buf.truncate(len);
                    let ephemeral = Self::take_ephemeral(&buf);
                    let resp = WirePacket::HandshakeResp(HandshakeResp {
                        sender_index: *sender_index,
                        ephemeral,
                        payload: buf.clone(),
                    });
                    outputs.push(Output::SendUdp(resp.serialize()?, addr));
                    self.last_activity = Instant::now();
                    finished = noise.is_handshake_finished();
                }
                if finished {
                    self.finish_handshake()?;
                }
            }
            WirePacket::HandshakeResp(resp) => {
                let mut finished = false;
                if let PeerState::Handshaking { noise, .. } = &mut self.state {
                    let mut buf = vec![0u8; 256];
                    let _ = noise.read_message(&resp.payload, &mut buf)?;
                    self.last_activity = Instant::now();
                    finished = noise.is_handshake_finished();
                }
                if finished {
                    self.finish_handshake()?;
                }
            }
            WirePacket::TransportData(_) => outputs.push(Output::Log(
                "ignoring transport data during handshake".into(),
            )),
        }
        Ok(())
    }

    fn handle_transport_packet(
        &mut self,
        data: Vec<u8>,
        addr: SocketAddr,
        outputs: &mut Vec<Output>,
    ) -> Result<(), ProtocolError> {
        let packet = WirePacket::deserialize(&data)?;
        if let WirePacket::TransportData(data) = packet {
            if let PeerState::Established {
                transport,
                replay,
                sender_index,
                ..
            } = &mut self.state
            {
                if !replay.accept(data.counter) {
                    return Err(ProtocolError::InvalidNonce);
                }
                transport.set_receiving_nonce(data.counter);
                let mut buf = vec![0u8; data.payload.len() + OVERHEAD];
                let len = transport.read_message(&data.payload, &mut buf)?;
                buf.truncate(len);
                outputs.push(Output::WriteTun(buf));
                if addr != self.endpoint {
                    self.endpoint = addr;
                    outputs.push(Output::Log(format!(
                        "updated endpoint for sender {}",
                        sender_index
                    )));
                }
                self.last_activity = Instant::now();
            }
        }
        Ok(())
    }

    fn handle_tun_packet(
        &mut self,
        packet: Vec<u8>,
        outputs: &mut Vec<Output>,
    ) -> Result<(), ProtocolError> {
        if packet.len() > 1500 - OVERHEAD {
            return Err(ProtocolError::PacketTooLarge);
        }
        if let PeerState::Established {
            transport,
            receiver_index,
            ..
        } = &mut self.state
        {
            let counter = transport.sending_nonce();
            let mut buf = vec![0u8; packet.len() + OVERHEAD];
            let len = transport.write_message(&packet, &mut buf)?;
            buf.truncate(len);
            let wire = WirePacket::TransportData(TransportData {
                receiver_index: *receiver_index,
                counter,
                payload: buf,
            });
            outputs.push(Output::SendUdp(wire.serialize()?, self.endpoint));
            self.last_activity = Instant::now();
        } else {
            outputs.push(Output::Log(
                "received tun packet before establishment".into(),
            ));
        }
        Ok(())
    }

    fn queue_handshake_init(&mut self) -> Result<(), ProtocolError> {
        if let PeerState::Handshaking {
            noise,
            sender_index,
            ..
        } = &mut self.state
        {
            let mut buf = vec![0u8; 256];
            let len = noise.write_message(&[], &mut buf)?;
            buf.truncate(len);
            let ephemeral = Self::take_ephemeral(&buf);
            let packet = WirePacket::HandshakeInit(HandshakeInit {
                sender_index: *sender_index,
                ephemeral,
                payload: buf,
            });
            self.pending
                .push(Output::SendUdp(packet.serialize()?, self.endpoint));
        }
        Ok(())
    }

    /// Capture the leading bytes of a handshake message for the wire header.
    fn take_ephemeral(buf: &[u8]) -> [u8; 32] {
        let mut ephemeral = [0u8; 32];
        let copy_len = buf.len().min(32);
        ephemeral[..copy_len].copy_from_slice(&buf[..copy_len]);
        ephemeral
    }

    fn finish_handshake(&mut self) -> Result<(), ProtocolError> {
        let state = std::mem::replace(&mut self.state, PeerState::Dead);
        if let PeerState::Handshaking {
            noise,
            sender_index,
            receiver_index,
        } = state
        {
            let transport = noise.into_transport_mode()?;
            self.state = PeerState::Established {
                transport,
                sender_index,
                receiver_index,
                replay: ReplayWindow::new(),
            };
        } else {
            self.state = state;
        }
        Ok(())
    }
}

fn build_noise(
    config: &PeerConfig,
    initiator: bool,
) -> Result<snow::HandshakeState, ProtocolError> {
    let params: NoiseParams = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("valid noise pattern");
    let mut builder = snow::Builder::new(params)
        .local_private_key(&config.static_private)
        .remote_public_key(&config.remote_public);
    if let Some(psk) = config.psk.as_ref() {
        builder = builder.psk(2, psk);
    }
    let noise = if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    };
    Ok(noise)
}

#[derive(Debug, Clone)]
struct ReplayWindow {
    bitmap: [u64; 2],
    max_nonce: u64,
    initialized: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            bitmap: [0; 2],
            max_nonce: 0,
            initialized: false,
        }
    }

    fn accept(&mut self, nonce: u64) -> bool {
        if !self.initialized {
            self.set_bit(0);
            self.max_nonce = nonce;
            self.initialized = true;
            return true;
        }

        if nonce > self.max_nonce {
            let shift = nonce - self.max_nonce;
            if shift >= REPLAY_WINDOW {
                self.bitmap = [0; 2];
            } else {
                self.shift_left(shift);
            }
            self.max_nonce = nonce;
            self.set_bit(0);
            return true;
        }

        let offset = self.max_nonce - nonce;
        if offset >= REPLAY_WINDOW {
            return false;
        }
        if self.get_bit(offset) {
            return false;
        }
        self.set_bit(offset);
        true
    }

    fn shift_left(&mut self, shift: u64) {
        if shift == 0 {
            return;
        }
        let combined = ((self.bitmap[1] as u128) << 64) | self.bitmap[0] as u128;
        let shifted = combined << shift;
        self.bitmap[0] = shifted as u64;
        self.bitmap[1] = (shifted >> 64) as u64;
    }

    fn set_bit(&mut self, offset: u64) {
        if offset >= REPLAY_WINDOW {
            return;
        }
        let combined = ((self.bitmap[1] as u128) << 64) | self.bitmap[0] as u128;
        let updated = combined | (1u128 << offset);
        self.bitmap[0] = updated as u64;
        self.bitmap[1] = (updated >> 64) as u64;
    }

    fn get_bit(&self, offset: u64) -> bool {
        if offset >= REPLAY_WINDOW {
            return false;
        }
        let combined = ((self.bitmap[1] as u128) << 64) | self.bitmap[0] as u128;
        ((combined >> offset) & 1) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn gen_keypair() -> (StaticSecret, PublicKey) {
        let sk = StaticSecret::random();
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    #[test]
    fn tick_accepts_tun_packet() {
        let (local_sk, _local_pk) = gen_keypair();
        let (_remote_sk, remote_pk) = gen_keypair();
        let config = PeerConfig {
            static_private: local_sk.to_bytes(),
            remote_public: remote_pk.to_bytes(),
            psk: None,
            sender_index: 1,
            receiver_index: 2,
        };
        let mut peer = Peer::new(config, "127.0.0.1:10000".parse().unwrap()).unwrap();
        let result = peer.tick(Input::TunPacket(vec![1, 2, 3, 4]));
        assert!(result.is_ok());
    }
}
