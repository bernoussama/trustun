use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tun::AsyncDevice;

use crate::net::router::Router;
use crate::protocol::errors::ProtocolError;
use crate::protocol::events::{Input, Output};

const TUN_MTU: usize = 1280;
const IPV4_MIN_HEADER: usize = 20;

pub async fn run(
    dev: Arc<AsyncDevice>,
    router: Arc<Router>,
    socket: Arc<UdpSocket>,
) -> Result<(), ProtocolError> {
    let mut buf = [0u8; TUN_MTU];
    loop {
        let len = match dev.recv(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                #[cfg(debug_assertions)]
                eprintln!("tun receive error: {e}");
                continue;
            }
        };
        if len < IPV4_MIN_HEADER {
            continue;
        }
        if let Some(dst) = extract_dst_ip(&buf[..len]) {
            let index = u32::from(dst);
            if let Some(peer) = router.lookup(index) {
                let packet = buf[..len].to_vec();
                let mut guard = match peer.lock() {
                    Ok(g) => g,
                    Err(poisoned) => {
                        #[cfg(debug_assertions)]
                        eprintln!("peer lock poisoned for index {index}");
                        poisoned.into_inner()
                    }
                };
                let outputs = guard.tick(Input::TunPacket(packet))?;
                for output in outputs {
                    match output {
                        Output::SendUdp(data, target) => {
                            if let Err(e) = socket.send_to(&data, target).await {
                                #[cfg(debug_assertions)]
                                eprintln!("udp send error: {e}");
                            }
                        }
                        Output::WriteTun(data) => {
                            if let Err(e) = dev.send(&data).await {
                                #[cfg(debug_assertions)]
                                eprintln!("tun send error: {e}");
                            }
                        }
                        Output::Log(msg) => {
                            #[cfg(debug_assertions)]
                            println!("{msg}");
                        }
                    }
                }
            }
        }
    }
}

fn extract_dst_ip(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version == 4 {
        let ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        return Some(ip);
    }
    None
}
