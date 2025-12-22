use crate::protocol::events::{Input, Output};
use crate::protocol::errors::ProtocolError;
use crate::protocol::wire::WirePacket;
use snow::{Builder, HandshakeState, TransportState};
use snow::params::NoiseParams;
use std::net::SocketAddr;
use std::time::{Instant, Duration};

#[derive(Clone)]
pub struct PeerConfig {
    pub static_private: [u8; 32],
    pub remote_public: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub index: u32,
    pub initiator: bool,
    pub endpoint: Option<SocketAddr>,
}

pub enum PeerState {
    Handshaking(Box<HandshakeState>),
    Established {
        transport: TransportState,
    },
    Poisoned,
}

pub struct Peer {
    pub state: PeerState,
    config: PeerConfig,
    endpoint: Option<SocketAddr>,
    remote_index: Option<u32>,
    replay_bitmap: u128,
    replay_highest: u64,
    last_sent: Instant,
}

impl Peer {
    pub fn new(config: PeerConfig) -> Result<(Self, Vec<Output>), ProtocolError> {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let builder = Builder::new(params)
            .local_private_key(&config.static_private)
            .remote_public_key(&config.remote_public);

        let mut noise = if config.initiator {
            builder.build_initiator()?
        } else {
            builder.build_responder()?
        };

        let mut outputs = Vec::new();
        let endpoint = config.endpoint;

        if config.initiator {
            let mut buf = [0u8; 1024];
            let len = noise.write_message(&[], &mut buf)?;

            if len < 32 {
                 return Err(ProtocolError::Serialization("Handshake generated too short".into()));
            }
            let mut ephemeral = [0u8; 32];
            ephemeral.copy_from_slice(&buf[..32]);
            let payload = buf[32..len].to_vec();

            let packet = WirePacket::HandshakeInit {
                sender_index: config.index,
                ephemeral,
                payload,
            };

            if let Some(addr) = endpoint {
                outputs.push(Output::SendUdp(packet.serialize(), addr));
            }
        }

        Ok((Self {
            state: PeerState::Handshaking(Box::new(noise)),
            config,
            endpoint,
            remote_index: None,
            replay_bitmap: 0,
            replay_highest: 0,
            last_sent: Instant::now(),
        }, outputs))
    }

    fn validate_replay(&self, counter: u64) -> bool {
        if counter >= self.replay_highest {
            return true;
        }
        if self.replay_highest - counter > 127 {
            return false;
        }
        let diff = self.replay_highest - counter;
        if (self.replay_bitmap >> diff) & 1 == 1 {
            return false;
        }
        true
    }

    fn update_replay(&mut self, counter: u64) {
        if counter >= self.replay_highest {
            let diff = counter - self.replay_highest;
            if diff < 128 {
                self.replay_bitmap <<= diff;
            } else {
                self.replay_bitmap = 0;
            }
            self.replay_bitmap |= 1;
            self.replay_highest = counter;
        } else {
            let diff = self.replay_highest - counter;
            self.replay_bitmap |= 1 << diff;
        }
    }

    pub fn tick(&mut self, input: Input) -> Result<Vec<Output>, ProtocolError> {
        match input {
            Input::Tick(now) => {
                let state = std::mem::replace(&mut self.state, PeerState::Poisoned);
                match state {
                     PeerState::Established { mut transport } => {
                         if now.duration_since(self.last_sent) > Duration::from_secs(15) {
                             let counter = transport.sending_nonce();
                             let mut buf = [0u8; 128];
                             if let Ok(len) = transport.write_message(&[], &mut buf) {
                                 let payload = buf[..len].to_vec();
                                 if let Some(remote_idx) = self.remote_index {
                                      let packet = WirePacket::TransportData {
                                          receiver_index: remote_idx,
                                          counter,
                                          payload,
                                      };
                                      if let Some(addr) = self.endpoint {
                                           self.last_sent = now;
                                           self.state = PeerState::Established { transport };
                                           return Ok(vec![Output::SendUdp(packet.serialize(), addr)]);
                                      }
                                 }
                             }
                         }
                         self.state = PeerState::Established { transport };
                         Ok(vec![])
                     }
                     _ => {
                         self.state = state;
                         Ok(vec![])
                     }
                }
            }
            Input::UdpPacket(data, src_addr) => {
                let packet = match WirePacket::deserialize(&data) {
                    Ok(p) => p,
                    Err(_) => return Ok(vec![]),
                };

                let state = std::mem::replace(&mut self.state, PeerState::Poisoned);

                match state {
                    PeerState::Handshaking(mut noise) => {
                        match packet {
                            WirePacket::HandshakeInit { sender_index, ephemeral, payload } => {
                                if self.config.initiator {
                                    self.state = PeerState::Handshaking(noise);
                                    return Ok(vec![]);
                                }

                                let mut message = Vec::with_capacity(32 + payload.len());
                                message.extend_from_slice(&ephemeral);
                                message.extend_from_slice(&payload);

                                let mut buf = [0u8; 1024];
                                if let Err(e) = noise.read_message(&message, &mut buf) {
                                    self.state = PeerState::Handshaking(noise);
                                    return Err(ProtocolError::Snow(e));
                                }

                                let len = noise.write_message(&[], &mut buf)?;
                                let mut resp_ephemeral = [0u8; 32];
                                resp_ephemeral.copy_from_slice(&buf[..32]);
                                let resp_payload = buf[32..len].to_vec();

                                let resp = WirePacket::HandshakeResp {
                                    sender_index: self.config.index,
                                    ephemeral: resp_ephemeral,
                                    payload: resp_payload,
                                };

                                self.endpoint = Some(src_addr);
                                self.remote_index = Some(sender_index);
                                let transport = noise.into_transport_mode()?;
                                self.state = PeerState::Established { transport };

                                Ok(vec![Output::SendUdp(resp.serialize(), src_addr)])
                            }
                            WirePacket::HandshakeResp { sender_index, ephemeral, payload } => {
                                if !self.config.initiator {
                                    self.state = PeerState::Handshaking(noise);
                                    return Ok(vec![]);
                                }

                                let mut message = Vec::with_capacity(32 + payload.len());
                                message.extend_from_slice(&ephemeral);
                                message.extend_from_slice(&payload);

                                let mut buf = [0u8; 1024];
                                if let Err(e) = noise.read_message(&message, &mut buf) {
                                    self.state = PeerState::Handshaking(noise);
                                    return Err(ProtocolError::Snow(e));
                                }

                                self.endpoint = Some(src_addr);
                                self.remote_index = Some(sender_index);
                                let transport = noise.into_transport_mode()?;
                                self.state = PeerState::Established { transport };
                                Ok(vec![])
                            }
                            _ => {
                                self.state = PeerState::Handshaking(noise);
                                Ok(vec![])
                            }
                        }
                    }
                    PeerState::Established { mut transport } => {
                        match packet {
                            WirePacket::TransportData { receiver_index, counter, payload } => {
                                if receiver_index != self.config.index {
                                     self.state = PeerState::Established { transport };
                                     return Ok(vec![]);
                                }

                                if !self.validate_replay(counter) {
                                     self.state = PeerState::Established { transport };
                                     return Ok(vec![Output::Log("Replay detected".into())]);
                                }

                                transport.set_receiving_nonce(counter);
                                let mut buf = [0u8; 65535];
                                match transport.read_message(&payload, &mut buf) {
                                    Ok(len) => {
                                        self.update_replay(counter);

                                        self.state = PeerState::Established { transport };
                                        if len > 0 {
                                            Ok(vec![Output::WriteTun(buf[..len].to_vec())])
                                        } else {
                                            Ok(vec![])
                                        }
                                    }
                                    Err(e) => {
                                        self.state = PeerState::Established { transport };
                                        Ok(vec![Output::Log(format!("Decryption failed: {}", e))])
                                    }
                                }
                            }
                            _ => {
                                self.state = PeerState::Established { transport };
                                Ok(vec![])
                            }
                        }
                    }
                    PeerState::Poisoned => Err(ProtocolError::UnknownPacket),
                }
            }
            Input::TunPacket(data) => {
                if data.len() > 1450 {
                    return Err(ProtocolError::PacketTooLarge);
                }

                let state = std::mem::replace(&mut self.state, PeerState::Poisoned);
                match state {
                    PeerState::Established { mut transport } => {
                         let counter = transport.sending_nonce();
                         let mut buf = [0u8; 2048];
                         match transport.write_message(&data, &mut buf) {
                             Ok(len) => {
                                 let payload = buf[..len].to_vec();
                                 if let Some(remote_idx) = self.remote_index {
                                     let packet = WirePacket::TransportData {
                                         receiver_index: remote_idx,
                                         counter,
                                         payload,
                                     };
                                     if let Some(addr) = self.endpoint {
                                          self.last_sent = Instant::now();
                                          self.state = PeerState::Established { transport };
                                          Ok(vec![Output::SendUdp(packet.serialize(), addr)])
                                     } else {
                                          self.state = PeerState::Established { transport };
                                          Ok(vec![])
                                     }
                                 } else {
                                     self.state = PeerState::Established { transport };
                                     Ok(vec![])
                                 }
                             }
                             Err(e) => {
                                 self.state = PeerState::Established { transport };
                                 Err(ProtocolError::Snow(e))
                             }
                         }
                    }
                    _ => {
                        self.state = state;
                         Ok(vec![])
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_handshake_init() {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let builder = Builder::new(params);
        let keypair = builder.generate_keypair().unwrap();

        let mut static_private = [0u8; 32];
        static_private.copy_from_slice(&keypair.private);
        let mut remote_public = [0u8; 32];
        remote_public.copy_from_slice(&keypair.public);

        let config = PeerConfig {
            static_private,
            remote_public,
            psk: None,
            index: 100,
            initiator: true,
            endpoint: Some("127.0.0.1:1234".parse().unwrap()),
        };

        let (mut _peer, outputs) = Peer::new(config).unwrap();
        assert_eq!(outputs.len(), 1);
        if let Output::SendUdp(data, _) = &outputs[0] {
            assert_eq!(data[0], 1);
        } else {
            panic!("Expected SendUdp");
        }
    }

    #[test]
    fn test_handshake_and_transport() {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let builder = Builder::new(params);
        let keypair1 = builder.generate_keypair().unwrap();
        let keypair2 = builder.generate_keypair().unwrap();

        let mut static_private1 = [0u8; 32]; static_private1.copy_from_slice(&keypair1.private);
        let mut public1 = [0u8; 32]; public1.copy_from_slice(&keypair1.public);

        let mut static_private2 = [0u8; 32]; static_private2.copy_from_slice(&keypair2.private);
        let mut public2 = [0u8; 32]; public2.copy_from_slice(&keypair2.public);

        // Setup P1 (Initiator)
        let config1 = PeerConfig {
            static_private: static_private1,
            remote_public: public2,
            psk: None,
            index: 101,
            initiator: true,
            endpoint: Some("127.0.0.1:2000".parse().unwrap()),
        };
        let (mut p1, outputs1) = Peer::new(config1).unwrap();

        // Setup P2 (Responder)
        let config2 = PeerConfig {
            static_private: static_private2,
            remote_public: public1,
            psk: None,
            index: 102,
            initiator: false,
            endpoint: None,
        };
        let (mut p2, outputs2) = Peer::new(config2).unwrap();
        assert!(outputs2.is_empty());

        // P1 emits Init
        assert_eq!(outputs1.len(), 1);
        let init_pkt = match &outputs1[0] {
             Output::SendUdp(data, _) => data.clone(),
             _ => panic!("Expected SendUdp"),
        };

        // P2 receives Init
        let out_p2 = p2.tick(Input::UdpPacket(init_pkt, "127.0.0.1:1000".parse().unwrap())).unwrap();
        assert_eq!(out_p2.len(), 1);
        let resp_pkt = match &out_p2[0] {
             Output::SendUdp(data, _) => data.clone(),
             _ => panic!("Expected SendUdp"),
        };

        // P1 receives Resp
        let out_p1 = p1.tick(Input::UdpPacket(resp_pkt, "127.0.0.1:2000".parse().unwrap())).unwrap();
        assert!(out_p1.is_empty());

        // P1 sends Data
        let payload = b"Hello World".to_vec();
        let out_data = p1.tick(Input::TunPacket(payload.clone())).unwrap();
        assert_eq!(out_data.len(), 1);
        let data_pkt = match &out_data[0] {
             Output::SendUdp(data, _) => data.clone(),
             _ => panic!("Expected SendUdp"),
        };

        // P2 receives Data
        let out_final = p2.tick(Input::UdpPacket(data_pkt, "127.0.0.1:1000".parse().unwrap())).unwrap();
        assert_eq!(out_final.len(), 1);
        match &out_final[0] {
            Output::WriteTun(data) => assert_eq!(data, &payload),
            _ => panic!("Expected WriteTun"),
        }
    }
}
