use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};
use tun::AsyncDevice;

use crate::net::router::Router;

use super::Dispatcher;

pub async fn run_reader(
    dev: Arc<AsyncDevice>,
    router: Arc<Mutex<Router>>,
    dispatcher: Dispatcher,
) -> crate::Result<()> {
    let mut buffer = vec![0u8; crate::MTU.max(2048)];

    loop {
        let len = dev.recv(&mut buffer).await?;
        let packet = buffer[..len].to_vec();
        let actions = router.lock().await.handle_tun_packet(packet)?;
        dispatcher.dispatch(actions)?;
    }
}

pub async fn run_writer(
    dev: Arc<AsyncDevice>,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) -> crate::Result<()> {
    while let Some(packet) = rx.recv().await {
        dev.send(&packet).await?;
    }

    Err(crate::IpouError::ChannelClosed("tun writer"))
}
