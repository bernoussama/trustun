use super::events::{Input, Output};
use super::errors::ProtocolError;
use super::wire::{WirePacket, HandshakeInit, HandshakeResp, TransportData};
use snow::{Builder, TransportState, HandshakeState};
use rand::Rng;
use std::net::SocketAddr;
use std::time::{Instant, Duration};
use bincode::Options;

const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const OVERHEAD: usize = 128; // Conservative overhead for Noise + Headers
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

struct ReplayFilter {
    highest: u64,
    bitmap: u64,
}

impl ReplayFilter {
    fn new() -> Self { Self { highest: 0, bitmap: 0 } }
    
    fn check(&mut self, counter: u64) -> bool {
         if counter > self.highest {
             let diff = counter - self.highest;
             if diff >= 64 {
                 self.bitmap = 0;
             } else {
                 self.bitmap <<= diff;
             }
             self.highest = counter;
             self.bitmap |= 1;
             return true;
         }
         
         let diff = self.highest - counter;
         if diff >= 64 { return false; }
         
         if (self.bitmap & (1 << diff)) != 0 {
             return false;
         }
         
         self.bitmap |= 1 << diff;
         true
    }
}

pub struct PeerConfig {
    pub static_private: [u8; 32],
    pub remote_public: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub remote_endpoint: SocketAddr,
    pub initiator: bool,
}

pub enum PeerState {
    Handshaking(Box<HandshakeState>),
    Established(Box<TransportState>),
    Poisoned,
}

pub struct Peer {
    state: PeerState,
    local_index: u32,
    remote_index: u32,
    started: bool,
    remote_endpoint: SocketAddr,
    replay_filter: ReplayFilter,
    last_sent: Option<Instant>,
    last_recv: Option<Instant>,
}

impl Peer {
    pub fn new(config: PeerConfig) -> Result<Self, ProtocolError> {
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let builder = builder
            .local_private_key(&config.static_private)
            .remote_public_key(&config.remote_public);
            
        let handshake = if config.initiator {
            builder.build_initiator()?
        } else {
            builder.build_responder()?
        };

        let mut rng = rand::rng();
        let local_index = rng.random();

        Ok(Self {
            state: PeerState::Handshaking(Box::new(handshake)),
            local_index,
            remote_index: 0,
            started: false, // Will be set to true on first tick
            remote_endpoint: config.remote_endpoint,
            replay_filter: ReplayFilter::new(),
            last_sent: None,
            last_recv: None,
        })
    }

    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    pub fn tick(&mut self, input: Input) -> Result<Vec<Output>, ProtocolError> {
        let mut outputs = Vec::new();

        // 1. Check if we need to start handshake
        if !self.started {
            self.started = true;
            if let PeerState::Handshaking(ref mut noise) = self.state {
                if noise.is_initiator() {
                    let mut buf = [0u8; 65535];
                    let len = noise.write_message(&[], &mut buf)?;
                    
                    if len < 32 {
                         return Err(ProtocolError::Snow(snow::Error::Input));
                    }
                    let mut ephemeral = [0u8; 32];
                    ephemeral.copy_from_slice(&buf[0..32]);
                    let payload = buf[32..len].to_vec();

                    let packet = WirePacket::HandshakeInit(HandshakeInit {
                        sender_index: self.local_index,
                        ephemeral,
                        payload,
                    });
                    
                    let bytes = bincode::serialize(&packet)?;
                    outputs.push(Output::SendUdp(bytes, self.remote_endpoint));
                    self.last_sent = Some(Instant::now());
                }
            }
        }

        // 2. Handle Input
        match input {
            Input::UdpPacket(data, addr) => {
                let packet: WirePacket = bincode::options()
                    .with_limit(crate::MTU as u64)
                    .with_little_endian()
                    .with_fixint_encoding()
                    .deserialize(&data)?;

                match packet {
                    WirePacket::HandshakeInit(init) => {
                        let current_state = std::mem::replace(&mut self.state, PeerState::Poisoned);
                        if let PeerState::Handshaking(mut noise) = current_state {
                             if !noise.is_initiator() {
                                 let mut message = Vec::with_capacity(32 + init.payload.len());
                                 message.extend_from_slice(&init.ephemeral);
                                 message.extend_from_slice(&init.payload);
                                 
                                 let mut buf = [0u8; 65535];
                                 match noise.read_message(&message, &mut buf) {
                                     Ok(_) => {
                                         let len = noise.write_message(&[], &mut buf)?;
                                         
                                         if len < 32 { 
                                             self.state = PeerState::Handshaking(noise);
                                             return Err(ProtocolError::Snow(snow::Error::Input)); 
                                         }
                                         
                                         let mut ephemeral = [0u8; 32];
                                         ephemeral.copy_from_slice(&buf[0..32]);
                                         let payload = buf[32..len].to_vec();
                                         
                                         let resp_packet = WirePacket::HandshakeResp(HandshakeResp {
                                             sender_index: self.local_index,
                                             receiver_index: init.sender_index,
                                             ephemeral,
                                             payload,
                                         });
                                         
                                         let bytes = bincode::serialize(&resp_packet)?;
                                         outputs.push(Output::SendUdp(bytes, addr));
                                         
                                         let transport = noise.into_transport_mode()?;
                                         self.state = PeerState::Established(Box::new(transport));
                                         self.remote_index = init.sender_index;
                                         self.remote_endpoint = addr;
                                         self.last_recv = Some(Instant::now());
                                         self.last_sent = Some(Instant::now());
                                     }
                                     Err(e) => {
                                         self.state = PeerState::Handshaking(noise);
                                         return Err(ProtocolError::Snow(e));
                                     }
                                 }
                             } else {
                                 self.state = PeerState::Handshaking(noise);
                             }
                        } else {
                            self.state = current_state;
                        }
                    }
                    WirePacket::HandshakeResp(resp) => {
                         let current_state = std::mem::replace(&mut self.state, PeerState::Poisoned);
                         if let PeerState::Handshaking(mut noise) = current_state {
                             let mut message = Vec::with_capacity(32 + resp.payload.len());
                             message.extend_from_slice(&resp.ephemeral);
                             message.extend_from_slice(&resp.payload);

                             let mut buf = [0u8; 65535];
                             match noise.read_message(&message, &mut buf) {
                                 Ok(_) => {
                                     let transport = noise.into_transport_mode()?;
                                     self.state = PeerState::Established(Box::new(transport));
                                     self.remote_index = resp.sender_index;
                                     self.remote_endpoint = addr; 
                                     self.last_recv = Some(Instant::now());
                                 }
                                 Err(e) => {
                                     self.state = PeerState::Handshaking(noise);
                                     return Err(ProtocolError::Snow(e));
                                 }
                             }
                         } else {
                             self.state = current_state; 
                         }
                    }
                    WirePacket::TransportData(data) => {
                        if let PeerState::Established(ref mut transport) = self.state {
                             if !self.replay_filter.check(data.counter) {
                                 // Replay detected
                                 return Ok(outputs);
                             }

                             transport.set_receiving_nonce(data.counter);
                             let mut buf = [0u8; 65535];
                             let len = transport.read_message(&data.payload, &mut buf)?;
                             if len > 0 {
                                 outputs.push(Output::WriteTun(buf[0..len].to_vec()));
                             }
                             self.remote_endpoint = addr;
                             self.last_recv = Some(Instant::now());
                        }
                    }
                }
            }
            Input::TunPacket(data) => {
                 if let PeerState::Established(ref mut transport) = self.state {
                     if data.len() > 1500 - OVERHEAD {
                         return Err(ProtocolError::PacketTooLarge);
                     }
                     let mut buf = [0u8; 65535];
                     let nonce = transport.sending_nonce();
                     let len = transport.write_message(&data, &mut buf)?;
                     
                     let packet = WirePacket::TransportData(TransportData {
                         receiver_index: self.remote_index,
                         counter: nonce,
                         payload: buf[0..len].to_vec(),
                     });
                     
                     let bytes = bincode::serialize(&packet)?;
                     outputs.push(Output::SendUdp(bytes, self.remote_endpoint));
                     self.last_sent = Some(Instant::now());
                 }
            }
            Input::Tick(now) => {
                if let PeerState::Established(ref mut transport) = self.state {
                     // Check Keepalive
                     if let Some(last) = self.last_sent {
                         if now.duration_since(last) > KEEPALIVE_INTERVAL {
                             // Send Keepalive (Empty TransportData)
                             let mut buf = [0u8; 65535];
                             let nonce = transport.sending_nonce();
                             let len = transport.write_message(&[], &mut buf)?; // Empty payload
                             
                             let packet = WirePacket::TransportData(TransportData {
                                 receiver_index: self.remote_index,
                                 counter: nonce,
                                 payload: buf[0..len].to_vec(),
                             });
                             
                             let bytes = bincode::serialize(&packet)?;
                             outputs.push(Output::SendUdp(bytes, self.remote_endpoint));
                             self.last_sent = Some(now);
                         }
                     } else {
                         self.last_sent = Some(now);
                     }
                }
            }
        }
        
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_tick_skeleton() {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
        let builder = Builder::new(params);
        let keypair = builder.generate_keypair().unwrap();
        
        let mut static_private = [0u8; 32];
        static_private.copy_from_slice(&keypair.private);

        let config = PeerConfig {
            static_private,
            remote_public: [0u8; 32], 
            psk: None,
            remote_endpoint: "127.0.0.1:0".parse().unwrap(),
            initiator: true,
        };

        if let Ok(mut peer) = Peer::new(config) {
             // First tick triggers handshake
             let input = Input::Tick(Instant::now());
             let result = peer.tick(input);
             assert!(result.is_ok());
             
             let outputs = result.unwrap();
             assert_eq!(outputs.len(), 1);
        }
    }
}
