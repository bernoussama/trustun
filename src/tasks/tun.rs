use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tun::AsyncDevice;

use crate::TunMessage;
use crate::net::router::Router;
use crate::protocol::events::{Input, Output};

pub async fn run(
    dev: Arc<AsyncDevice>,
    router: Arc<Mutex<Router>>,
    socket: Arc<UdpSocket>,
    mut tun_rx: mpsc::Receiver<TunMessage>,
) {
    let mut buf = [0u8; 1500];

    loop {
        tokio::select! {
            res = dev.recv(&mut buf) => {
                match res {
                    Ok(len) => {
                        let data = &buf[..len];
                        if let Some(dst_ip) = extract_dst_ip(data) {
                             let peer_opt = {
                                 router.lock().unwrap().route_by_ip(&dst_ip)
                             };

                             if let Some(peer) = peer_opt {
                                 let outputs = {
                                     let mut peer_lock = peer.lock().unwrap();
                                     match peer_lock.tick(Input::TunPacket(data.to_vec())) {
                                         Ok(outputs) => outputs,
                                         Err(e) => {
                                             eprintln!("Peer error: {}", e);
                                             Vec::new()
                                         }
                                     }
                                 };

                                 for output in outputs {
                                     match output {
                                         Output::SendUdp(out_data, dest) => {
                                             let _ = socket.send_to(&out_data, dest).await;
                                         }
                                         Output::WriteTun(_) => {
                                         }
                                         Output::Log(s) => println!("Peer log: {}", s),
                                     }
                                 }
                             }
                        }
                    }
                    Err(e) => {
                        eprintln!("Tun recv error: {}", e);
                    }
                }
            }

            Some(msg) = tun_rx.recv() => {
                match msg {
                    TunMessage::Packet(data) => {
                        let _ = dev.send(&data).await;
                    }
                    TunMessage::Shutdown => {
                        break;
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
        Some(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))
    } else {
        None
    }
}
