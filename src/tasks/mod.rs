use std::sync::Arc;

use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, Sender},
};
use tun::AsyncDevice;

use crate::EncryptedPacket;
use crate::config::{Config, RuntimeConfig};

// Spawned listeners
pub async fn tun_listener(
    dev: Arc<AsyncDevice>,
    conf_clone: Arc<Config>,
    runtime_conf: Arc<RuntimeConfig>,
    etx: Sender<EncryptedPacket>,
) -> crate::Result<()> {
    let mut tun_buf = [0u8; crate::MTU];

    loop {
        // Listen for TUN packets
        let len = dev.recv(&mut tun_buf).await?;
        // Spawn handler task for each packet
        if len >= 20 {
            tokio::spawn(crate::net::handle_tun_packet(
                tun_buf,
                len,
                Arc::clone(&conf_clone),
                Arc::clone(&runtime_conf),
                etx.clone(),
            ));
        }
        // Send raw packet + result channel to handler
    }
}

pub async fn udp_listener(
    sock: Arc<UdpSocket>,
    runtime_conf: Arc<RuntimeConfig>,
    dtx: Sender<crate::DecryptedPacket>,
) -> crate::Result<()> {
    let mut udp_buf = [0u8; crate::MTU + 512];
    loop {
        // Listen for UDP packets
        let (len, peer_addr) = sock.recv_from(&mut udp_buf).await?;
        // Spawn handler task for each packet
        if len >= 28 {
            // 12 bytes nonce + 16 bytes auth tag
            tokio::spawn(crate::net::handle_udp_packet(
                udp_buf,
                len,
                peer_addr,
                Arc::clone(&runtime_conf),
                dtx.clone(),
            ));
        };
        // Send raw packet + result channel to handler
    }
}

pub async fn result_coordinator(
    dev: Arc<AsyncDevice>,
    sock: Arc<UdpSocket>,
    mut erx: Receiver<crate::EncryptedPacket>,
    mut drx: Receiver<crate::DecryptedPacket>,
) -> crate::Result<()> {
    // This task coordinates sending decrypted packets to TUN and encrypted packets to UDP
    // It runs indefinitely, processing packets as they arrive

    #[cfg(debug_assertions)]
    println!("Starting result coordinator...");

    loop {
        tokio::select! {
                   // Receive decrypted packets from channel and send to TUN
                   Some(decrypted_packet) = drx.recv() => {
                       match dev.send(&decrypted_packet).await {
                        Ok(sent) => {
                            #[cfg(debug_assertions)]
                            println!("Sent {sent} bytes to TUN dev");
                        },
                        Err(e) => {
                        eprintln!("Error sending packet to TUN device: {e}");
                        },
                       }
                   }

                   // Receive enccrypted packets from channel and send to UDP
                                       Some(encrypted_packet) = erx.recv() => {
                                            #[cfg(debug_assertions)]
                                           println!("Sending encrypted packet to peer: {}", encrypted_packet.destination);
                                          match sock.send_to(&encrypted_packet.data, encrypted_packet.destination).await {
                                              Ok(sent) => {
                                               #[cfg(debug_assertions)]
                                               println!("Sent {sent} bytes to {}", encrypted_packet.destination);
                                           },
                                              Err(e) => {
                                                  eprintln!("Error sending encrypted packet to peer {}: {}", encrypted_packet.destination, e);
                                           },
                                          }
                   }
        }
    }
}
