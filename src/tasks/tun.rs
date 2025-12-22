use std::sync::{Arc, Mutex};
use crate::net::router::Router;
use crate::protocol::events::{Input, Output};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::convert::TryInto;

pub async fn run_tun(
    mut tun: tun::AsyncDevice,
    router: Arc<Mutex<Router>>,
    udp_socket: Arc<tokio::net::UdpSocket>,
    mut tun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 65535];
    
    loop {
        tokio::select! {
            res = tun.read(&mut buf) => {
                match res {
                    Ok(len) => {
                        let packet_data = &buf[0..len];
                        
                        if packet_data.len() >= 20 && (packet_data[0] >> 4) == 4 {
                            let dst_ip_bytes: [u8; 4] = packet_data[16..20].try_into().unwrap();
                            let dst_ip = std::net::Ipv4Addr::from(dst_ip_bytes);
                            
                            let peer_opt = {
                                router.lock().unwrap().get_by_ip(dst_ip)
                            };
                            
                            if let Some(peer) = peer_opt {
                                 let input = Input::TunPacket(packet_data.to_vec());
                                 let outputs = {
                                     let mut p = peer.lock().unwrap();
                                     match p.tick(input) {
                                         Ok(o) => o,
                                         Err(e) => {
                                             eprintln!("Peer tick error (TUN): {}", e);
                                             vec![]
                                         }
                                     }
                                 };
                                 
                                 for output in outputs {
                                     match output {
                                         Output::SendUdp(data, dst) => {
                                             let _ = udp_socket.send_to(&data, dst).await;
                                         }
                                         Output::WriteTun(_) => {
                                             // Should not happen, but if so, ignore or log
                                         }
                                         Output::Log(msg) => println!("Log: {}", msg),
                                     }
                                 }
                            }
                        }
                    },
                    Err(e) => return Err(e),
                }
            }
            
            Some(data) = tun_rx.recv() => {
                if let Err(e) = tun.write_all(&data).await {
                    eprintln!("Failed to write to TUN: {}", e);
                }
            }
        }
    }
}
