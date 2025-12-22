use std::sync::Arc;

use tokio::net::UdpSocket;
use tun::AsyncDevice;

use crate::net::router::Router;
use crate::protocol::errors::ProtocolError;
use crate::protocol::events::{Input, Output};

const MIN_WIRE_PACKET: usize = 5;

pub async fn run(
    socket: Arc<UdpSocket>,
    router: Arc<Router>,
    tun: Arc<AsyncDevice>,
) -> Result<(), ProtocolError> {
    let mut buf = [0u8; 65535];

    loop {
        let (len, addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                #[cfg(debug_assertions)]
                eprintln!("udp receive error: {e}");
                continue;
            }
        };
        if len < MIN_WIRE_PACKET {
            continue;
        }
        let receiver_index = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if let Some(peer) = router.lookup(receiver_index) {
            let packet = buf[..len].to_vec();
            let mut guard = match peer.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    #[cfg(debug_assertions)]
                    eprintln!("peer lock poisoned for index {receiver_index}");
                    poisoned.into_inner()
                }
            };
            let outputs = guard.tick(Input::UdpPacket(packet, addr))?;
            for output in outputs {
                match output {
                    Output::SendUdp(data, target) => {
                        if let Err(e) = socket.send_to(&data, target).await {
                            #[cfg(debug_assertions)]
                            eprintln!("udp send error: {e}");
                        }
                    }
                    Output::WriteTun(data) => {
                        if let Err(e) = tun.send(&data).await {
                            #[cfg(debug_assertions)]
                            eprintln!("tun write error: {e}");
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
