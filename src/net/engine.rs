use std::sync::Arc;
use crate::config::{Config, RuntimeConfig};
use crate::proto::{TunInput, TunOutput, UdpInput, UdpOutput};
use chacha20poly1305::Nonce;
use chacha20poly1305::aead::Aead;
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr};

pub struct TunProcessor {
    config: Arc<Config>,
    runtime_config: Arc<RuntimeConfig>,
}

impl TunProcessor {
    pub fn new(config: Arc<Config>, runtime_config: Arc<RuntimeConfig>) -> Self {
        Self { config, runtime_config }
    }

    pub fn process(&self, input: TunInput) -> TunOutput {
        match input {
            TunInput::Packet(buf) => {
                if let Some(dst_ip) = extract_dst_ip(buf) {
                    if let Some(peer) = self.config.peers.get(&dst_ip) {
                        if let Some(cipher) = self.runtime_config.ciphers.get(&dst_ip) {
                            let mut nonce_bytes = [0u8; 12];
                            rand::rng().fill_bytes(&mut nonce_bytes);
                            let nonce = Nonce::from_slice(&nonce_bytes);
                            match cipher.encrypt(nonce, buf) {
                                Ok(encrypted) => {
                                    let mut packet = Vec::with_capacity(12 + encrypted.len());
                                    packet.extend_from_slice(&nonce_bytes);
                                    packet.extend_from_slice(&encrypted);
                                    TunOutput::Encrypted {
                                        data: packet,
                                        target: peer.sock_addr,
                                    }
                                }
                                Err(e) => TunOutput::Drop(format!("Encryption failed: {}", e)),
                            }
                        } else {
                            TunOutput::Drop(format!("No cipher for peer {}", dst_ip))
                        }
                    } else {
                        TunOutput::Drop(format!("Unknown destination IP {}", dst_ip))
                    }
                } else {
                    TunOutput::Drop("Invalid IP packet or not IPv4".to_string())
                }
            }
        }
    }
}

pub struct UdpProcessor {
    runtime_config: Arc<RuntimeConfig>,
}

impl UdpProcessor {
    pub fn new(runtime_config: Arc<RuntimeConfig>) -> Self {
        Self { runtime_config }
    }

    pub fn process(&self, input: UdpInput) -> UdpOutput {
        match input {
            UdpInput::Packet(buf, peer_addr) => {
                if buf.len() < 12 {
                    return UdpOutput::Drop("Packet too short".to_string());
                }
                let nonce = Nonce::from_slice(&buf[..12]);
                let encrypted_data = &buf[12..];

                if let Some(ip) = self.runtime_config.ips.get(&peer_addr) {
                    if let Some(cipher) = self.runtime_config.ciphers.get(ip) {
                         match cipher.decrypt(nonce, encrypted_data) {
                            Ok(decrypted) => {
                                if decrypted.len() >= 20 {
                                    UdpOutput::Decrypted(decrypted)
                                } else {
                                    UdpOutput::Drop(format!("Decrypted packet too short: {}", decrypted.len()))
                                }
                            }
                            Err(e) => UdpOutput::Drop(format!("Decryption failed: {}", e)),
                         }
                    } else {
                        UdpOutput::Drop(format!("No cipher for peer {}", ip))
                    }
                } else {
                    UdpOutput::Drop(format!("Unknown peer address {}", peer_addr))
                }
            }
        }
    }
}

fn extract_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version == 4 {
        Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use crate::Peer;
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};

    fn create_test_configs() -> (Arc<Config>, Arc<RuntimeConfig>) {
         let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
         let peer_socket = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 51820));

         let mut peers = HashMap::new();
         peers.insert(peer_ip, Peer {
             sock_addr: peer_socket,
             pub_key: "dummy".to_string(),
         });

         let config = Arc::new(Config {
             name: "tun0".into(),
             address: "10.0.0.1".into(),
             port: 51820,
             secret: "secret".into(),
             pubkey: "pubkey".into(),
             peers,
         });

         let key_bytes = [1u8; 32];
         let cipher = ChaCha20Poly1305::new(&key_bytes.into());
         let mut ciphers = HashMap::new();
         ciphers.insert(peer_ip, cipher);

         let mut ips = HashMap::new();
         ips.insert(peer_socket, peer_ip);

         let runtime_config = Arc::new(RuntimeConfig {
             shared_secrets: HashMap::new(),
             ciphers,
             ips,
         });

         (config, runtime_config)
    }

    #[test]
    fn test_tun_processor_encrypts() {
        let (config, runtime_config) = create_test_configs();
        let processor = TunProcessor::new(config, runtime_config);

        // IPv4 packet to 10.0.0.2
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 2;

        let input = TunInput::Packet(&packet);
        match processor.process(input) {
            TunOutput::Encrypted { data, target } => {
                assert_eq!(target.port(), 51820);
                assert!(data.len() > 20); // nonce + ciphertext
                // 12 bytes nonce + 20 bytes payload + 16 bytes tag = 48 bytes
                assert_eq!(data.len(), 12 + 20 + 16);
            }
            TunOutput::Drop(reason) => panic!("Should not drop: {}", reason),
        }
    }

    #[test]
    fn test_udp_processor_decrypts() {
        let (_config, runtime_config) = create_test_configs();
        let processor = UdpProcessor::new(runtime_config);

        // Create a valid encrypted packet
        let key_bytes = [1u8; 32];
        let cipher = ChaCha20Poly1305::new(&key_bytes.into());
        let nonce_bytes = [2u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = vec![0u8; 20]; // Mock payload
        let encrypted = cipher.encrypt(nonce, payload.as_ref()).unwrap();

        let mut packet = Vec::new();
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&encrypted);

        let peer_socket = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 51820));
        let input = UdpInput::Packet(&packet, peer_socket);

        match processor.process(input) {
            UdpOutput::Decrypted(data) => {
                assert_eq!(data, payload);
            }
            UdpOutput::Drop(reason) => panic!("Should not drop: {}", reason),
        }
    }
}
