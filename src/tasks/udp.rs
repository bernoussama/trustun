use crate::TunMessage;
use crate::net::router::Router;
use crate::protocol::events::{Input, Output};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub async fn run(
    socket: Arc<UdpSocket>,
    router: Arc<Mutex<Router>>,
    tun_tx: mpsc::Sender<TunMessage>,
) {
    let mut buf = [0u8; 65535];
    loop {
        let (len, src_addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("UDP recv error: {}", e);
                continue;
            }
        };

        let data = &buf[..len];

        if len < 1 {
            continue;
        }
        let type_byte = data[0];

        let peer_opt = {
            let router_lock = router.lock().unwrap();
            if type_byte == 3 {
                if len >= 5 {
                    let mut idx_bytes = [0u8; 4];
                    idx_bytes.copy_from_slice(&data[1..5]);
                    let idx = u32::from_be_bytes(idx_bytes);
                    router_lock.route_by_index(idx)
                } else {
                    None
                }
            } else {
                router_lock.route_by_addr(&src_addr)
            }
        };

        if let Some(peer) = peer_opt {
            let outputs = {
                let mut peer_lock = peer.lock().unwrap();
                match peer_lock.tick(Input::UdpPacket(data.to_vec(), src_addr)) {
                    Ok(outputs) => outputs,
                    Err(e) => {
                        eprintln!("Peer[{}] error: {}", src_addr, e);
                        Vec::new()
                    }
                }
            };

            for output in outputs {
                match output {
                    Output::SendUdp(out_data, dest) => {
                        let _ = socket.send_to(&out_data, dest).await;
                    }
                    Output::WriteTun(out_data) => {
                        let _ = tun_tx.send(TunMessage::Packet(out_data)).await;
                    }
                    Output::Log(s) => println!("Peer[{}] log: {}", src_addr, s),
                }
            }
        }
    }
}
