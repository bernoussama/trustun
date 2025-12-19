use chacha20poly1305::Nonce;
use chacha20poly1305::aead::Aead;
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;

use crate::EncryptedPacket;
use crate::config::{Config, RuntimeConfig};

pub async fn handle_udp_packet(
    udp_buf: [u8; crate::MTU + 512],
    len: usize,
    peer_addr: SocketAddr,
    runtime_conf: Arc<RuntimeConfig>,
    dtx: mpsc::Sender<crate::DecryptedPacket>,
) {
    // Extract nonce and encrypted data
    let nonce = Nonce::from_slice(&udp_buf[..12]);
    let encrypted_data = &udp_buf[12..len];

    if let Some(ip) = runtime_conf.ips.get(&peer_addr) {
        if let Some(cipher) = runtime_conf.ciphers.get(ip) {
            match cipher.decrypt(nonce, encrypted_data) {
                Ok(decrypted) => {
                    if decrypted.len() >= 20 {
                        if let Err(e) = dtx.send(decrypted).await {
                            eprintln!("Error sending decrypted packet through channel: {e}");
                        }
                    } else {
                        eprintln!("Decrypted packet too short: {} bytes", decrypted.len());
                    }
                }
                Err(e) => {
                    eprintln!("Decryption failed for peer {ip}: {e}");
                }
            }
        } else {
            eprintln!("No cipher found for peer: {ip}");
        }
    } else {
        eprintln!("No IP found for peer address: {peer_addr}");
    }
}

pub async fn handle_tun_packet(
    buf: [u8; crate::MTU],
    len: usize,
    conf_clone: Arc<Config>,
    runtime_conf: Arc<RuntimeConfig>,
    etx: mpsc::Sender<crate::EncryptedPacket>,
) {
    let mut packet = Vec::with_capacity(crate::MTU + crate::ENCRYPTION_OVERHEAD);
    if let Some(dst_ip) = extract_dst_ip(&buf) {
        if let Some(peer) = conf_clone.peers.get(&dst_ip) {
            if let Some(cipher) = runtime_conf.ciphers.get(&dst_ip) {
                let mut nonce_bytes = [0u8; 12];
                rand::rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let data = &buf[..len];
                match cipher.encrypt(nonce, data) {
                    Ok(encrypted) => {
                        packet.clear();
                        packet.extend_from_slice(&nonce_bytes); // Include nonce
                        packet.extend_from_slice(&encrypted);
                        #[cfg(debug_assertions)]
                        println!(
                            "Sending encrypted packet to {}: {} bytes",
                            peer.sock_addr,
                            packet.len()
                        );
                        if let Err(e) = etx
                            .send(EncryptedPacket::new(packet.clone(), peer.sock_addr))
                            .await
                        {
                            #[cfg(debug_assertions)]
                            eprintln!("Error sending encrypted packet through channel: {e}");
                        }
                    }
                    Err(_e) => {
                        #[cfg(debug_assertions)]
                        eprintln!("Error encrypting packet for destination IP: {dst_ip}");
                    }
                }
            } else {
                #[cfg(debug_assertions)]
                eprintln!("No cipher found for source IP: {dst_ip}")
            }
        }
    } else {
        #[cfg(debug_assertions)]
        eprintln!("Failed to extract destination IP from packet");
    }
}

fn _extract_src_ip(packet: &[u8]) -> Option<IpAddr> {
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

fn extract_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        #[cfg(debug_assertions)]
        eprintln!("Packet too short: {} bytes", packet.len());
        return None;
    }

    let version = packet[0] >> 4;
    #[cfg(debug_assertions)]
    eprintln!(
        "IP version: {}, first bytes: {:02x} {:02x} {:02x} {:02x}",
        version, packet[0], packet[1], packet[2], packet[3]
    );

    if version == 4 {
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        #[cfg(debug_assertions)]
        eprintln!("Extracted destination IP: {dst_ip}");
        Some(dst_ip)
    } else {
        #[cfg(debug_assertions)]
        eprintln!("Non-IPv4 packet, version: {version}");
        None
    }
}
