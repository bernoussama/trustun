use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};

use crate::net::router::Router;

use super::{Dispatcher, timer};

pub async fn run_reader(
    socket: Arc<UdpSocket>,
    router: Arc<Mutex<Router>>,
    dispatcher: Dispatcher,
) -> crate::Result<()> {
    let mut buffer = vec![0u8; 65_535];

    loop {
        let (len, addr) = socket.recv_from(&mut buffer).await?;
        let bytes = buffer[..len].to_vec();
        let actions = router
            .lock()
            .await
            .handle_udp_datagram(addr, bytes, timer::now_ms())?;
        dispatcher.dispatch(actions)?;
    }
}

pub async fn run_writer(
    socket: Arc<UdpSocket>,
    mut rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
) -> crate::Result<()> {
    while let Some((bytes, addr)) = rx.recv().await {
        socket.send_to(&bytes, addr).await?;
    }

    Err(crate::IpouError::ChannelClosed("udp writer"))
}
