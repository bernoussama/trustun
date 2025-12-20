use std::sync::Arc;
use tokio::net::UdpSocket;
use tun::AsyncDevice;

use crate::config::{Config, RuntimeConfig};
use crate::net::engine::{TunProcessor, UdpProcessor};
use crate::proto::{TunInput, TunOutput, UdpInput, UdpOutput};

pub async fn tun_worker(
    dev: Arc<AsyncDevice>,
    sock: Arc<UdpSocket>,
    conf: Arc<Config>,
    runtime_conf: Arc<RuntimeConfig>,
) -> crate::Result<()> {
    let mut buf = [0u8; crate::MTU];
    let processor = TunProcessor::new(conf, runtime_conf);

    loop {
        match dev.recv(&mut buf).await {
            Ok(len) => {
                let input = TunInput::Packet(&buf[..len]);
                match processor.process(input) {
                    TunOutput::Encrypted { data, target } => {
                        #[cfg(debug_assertions)]
                        println!("Sending encrypted packet to {}: {} bytes", target, data.len());
                        if let Err(e) = sock.send_to(&data, target).await {
                             eprintln!("Error sending encrypted packet to peer {target}: {e}");
                        }
                    }
                    TunOutput::Drop(reason) => {
                         #[cfg(debug_assertions)]
                         eprintln!("Dropping TUN packet: {}", reason);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from TUN: {}", e);
            }
        }
    }
}

pub async fn udp_worker(
    sock: Arc<UdpSocket>,
    dev: Arc<AsyncDevice>,
    runtime_conf: Arc<RuntimeConfig>,
) -> crate::Result<()> {
    let mut buf = [0u8; crate::MTU + 512];
    let processor = UdpProcessor::new(runtime_conf);

    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, peer_addr)) => {
                let input = UdpInput::Packet(&buf[..len], peer_addr);
                match processor.process(input) {
                    UdpOutput::Decrypted(data) => {
                         match dev.send(&data).await {
                             Ok(sent) => {
                                 #[cfg(debug_assertions)]
                                 println!("Sent {sent} bytes to TUN dev");
                             }
                             Err(e) => {
                                 eprintln!("Error sending packet to TUN device: {e}");
                             }
                         }
                    }
                    UdpOutput::Drop(reason) => {
                         #[cfg(debug_assertions)]
                         eprintln!("Dropping UDP packet: {}", reason);
                    }
                }
            }
            Err(e) => {
                 eprintln!("Error reading from UDP: {}", e);
            }
        }
    }
}
