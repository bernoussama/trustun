//! Pure protocol logic for the VPN tunnel
//!
//! This module contains all protocol-handling logic independent of I/O,
//! networking, or async runtime concerns. The functions here work purely
//! with in-memory buffers and can be unit tested without network I/O.

use chacha20poly1305::Nonce;
use chacha20poly1305::aead::Aead;
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::config::RuntimeConfig;

/// Packet processing result
#[derive(Debug, Clone)]
pub enum ProcessResult {
    /// Successful processing with optional response data
    Success(Option<Vec<u8>>),
    /// Processing completed but no action needed
    NoAction,
    /// Processing failed with error
    Error(String),
}

/// Protocol handler for VPN packets
pub struct PacketProcessor {
    pub config: RuntimeConfig,
}

impl PacketProcessor {
    /// Create a new packet processor with the given runtime configuration
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }

    /// Process an incoming encrypted UDP packet
    /// Returns decrypted packet data ready for TUN interface
    pub fn process_udp_packet(
        &self,
        encrypted_data: &[u8],
        peer_addr: SocketAddr,
    ) -> ProcessResult {
        if encrypted_data.len() < 28 {
            return ProcessResult::Error("Packet too short for encryption".to_string());
        }

        // Extract nonce (first 12 bytes) and encrypted payload
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let payload = &encrypted_data[12..];

        // Look up the destination IP for this peer address
        if let Some(dest_ip) = self.config.ips.get(&peer_addr) {
            if let Some(cipher) = self.config.ciphers.get(dest_ip) {
                match cipher.decrypt(nonce, payload) {
                    Ok(decrypted) => {
                        if decrypted.len() >= 20 {
                            ProcessResult::Success(Some(decrypted))
                        } else {
                            ProcessResult::Error("Decrypted packet too short".to_string())
                        }
                    }
                    Err(e) => ProcessResult::Error(format!("Decryption failed: {e}")),
                }
            } else {
                ProcessResult::Error("No cipher found for peer".to_string())
            }
        } else {
            ProcessResult::Error("Unknown peer address".to_string())
        }
    }

    /// Process an outgoing TUN packet
    /// Returns encrypted data and destination peer address
    pub fn process_tun_packet(&self, packet: &[u8]) -> ProcessResult {
        let dest_ip = match extract_dest_ip(packet) {
            Some(ip) => ip,
            None => return ProcessResult::Error("Failed to extract destination IP".to_string()),
        };

        // Look up peer configuration for destination IP
        if let Some(peer) = self.config.peers.get(&dest_ip) {
            if let Some(cipher) = self.config.ciphers.get(&dest_ip) {
                match encrypt_packet(packet, cipher) {
                    Ok(encrypted_data) => {
                        let result = EncryptedPacket::new(encrypted_data, peer.sock_addr);
                        ProcessResult::Success(Some(result.data))
                    }
                    Err(e) => ProcessResult::Error(format!("Encryption failed: {e}")),
                }
            } else {
                ProcessResult::Error("No cipher configured for destination".to_string())
            }
        } else {
            ProcessResult::Error("No peer configured for destination".to_string())
        }
    }
}

/// Encrypted packet representation
#[derive(Debug, Clone)]
pub struct EncryptedPacket {
    pub data: Vec<u8>,
    pub destination: SocketAddr,
}

impl EncryptedPacket {
    /// Create a new encrypted packet
    pub fn new(data: Vec<u8>, destination: SocketAddr) -> Self {
        Self { data, destination }
    }
}

/// Pure encryption function
pub fn encrypt_packet(
    data: &[u8],
    cipher: &chacha20poly1305::ChaCha20Poly1305,
) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("Encryption error: {e}"))
        .map(|mut encrypted| {
            // Prepend nonce to encrypted data
            let mut result = nonce_bytes.to_vec();
            result.append(&mut encrypted);
            result
        })
}

/// Extract destination IPv4 address from packet header
pub fn extract_dest_ip(packet: &[u8]) -> Option<IpAddr> {
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

/// Extract source IPv4 address from packet header
pub fn extract_src_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        return None;
    }

    if packet[0] >> 4 == 4 {
        Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )))
    } else {
        None
    }
}

/// Validate IPv4 packet structure
pub fn validate_ipv4_packet(packet: &[u8]) -> Result<(), String> {
    if packet.len() < 20 {
        return Err("Packet too short for IPv4 header".to_string());
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return Err("Not an IPv4 packet".to_string());
    }

    let header_length = (packet[0] & 0x0F) * 4;
    if header_length < 20 || usize::from(header_length) > packet.len() {
        return Err("Invalid IPv4 header length".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_extract_dest_ip() {
        // IPv4 packet with destination 192.168.1.1
        let mut packet = vec![0x45, 0x00, 0x00, 0x3C];
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]); // TTL, Protocol, Checksum
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]); // Source: 10.11.12.13
        packet.extend_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // Dest: 192.168.1.1

        let dest = extract_dest_ip(&packet);
        assert_eq!(dest, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_extract_src_ip() {
        let mut packet = vec![0x45, 0x00, 0x00, 0x3C];
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]); // Source: 10.11.12.13
        packet.extend_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // Dest: 192.168.1.1

        let src = extract_src_ip(&packet);
        assert_eq!(src, Some(IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13))));
    }

    #[test]
    fn test_validate_ipv4_packet_valid() {
        let mut packet = vec![0x45, 0x00, 0x00, 0x3C];
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);
        packet.extend_from_slice(&[0xC0, 0xA8, 0x01, 0x01]);

        assert!(validate_ipv4_packet(&packet).is_ok());
    }

    #[test]
    fn test_validate_ipv4_packet_too_short() {
        let packet = vec![0x45, 0x00, 0x00];
        assert!(validate_ipv4_packet(&packet).is_err());
    }

    #[test]
    fn test_validate_ipv4_packet_wrong_version() {
        let mut packet = vec![0x60, 0x00, 0x00, 0x00]; // IPv6 packet
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);
        packet.extend_from_slice(&[0xC0, 0xA8, 0x01, 0x01]);

        assert!(validate_ipv4_packet(&packet).is_err());
    }
}
