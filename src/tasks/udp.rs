use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use crate::net::router::Router;
use crate::protocol::events::{Input, Output};
use std::convert::TryInto;

pub async fn run_udp(
    socket: Arc<UdpSocket>,
    router: Arc<Mutex<Router>>,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 65535];
    
    loop {
        let (len, addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("UDP Recv Error: {}", e);
                continue;
            }
        };

        let packet_data = &buf[0..len];
        
        if packet_data.len() < 4 { continue; }
        
        let variant = u32::from_le_bytes(packet_data[0..4].try_into().unwrap());

        let receiver_index = match variant {
            1 => { // HandshakeResp: variant(4) + sender(4) + receiver(4)
                if packet_data.len() < 12 { continue; }
                u32::from_le_bytes(packet_data[8..12].try_into().unwrap())
            },
            2 => { // TransportData: variant(4) + receiver(4)
                if packet_data.len() < 8 { continue; }
                u32::from_le_bytes(packet_data[4..8].try_into().unwrap())
            },
            _ => {
                // HandshakeInit(0) or Unknown.
                continue; 
            }
        };

        // Scope the lock
        let peer_opt = {
            let r = router.lock().unwrap();
            r.get_by_index(receiver_index)
        };

        if let Some(peer) = peer_opt {
             // We have to clone packet_data to pass it to Input::UdpPacket (Vec<u8>)
             // Optimization: In Phase 4, we could avoid allocation by using Cow or slice references if Peer supported it.
             let input = Input::UdpPacket(packet_data.to_vec(), addr);
             
             let outputs = {
                 let mut p = peer.lock().unwrap();
                 match p.tick(input) {
                     Ok(o) => o,
                     Err(e) => {
                         eprintln!("Peer tick error: {}", e);
                         continue;
                     }
                 }
             };

             for output in outputs {
                 match output {
                     Output::SendUdp(data, dst) => {
                         let _ = socket.send_to(&data, dst).await;
                     }
                     Output::WriteTun(data) => {
                         let _ = tun_tx.send(data).await;
                     }
                     Output::Log(msg) => println!("Log: {}", msg),
                 }
             }
        }
    }
}
