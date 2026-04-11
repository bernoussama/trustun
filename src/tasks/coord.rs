use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

use crate::control::coord::CoordMessage;
use crate::net::router::Router;

use super::Dispatcher;

pub async fn run_client(
    url: String,
    local_pubkey: [u8; 32],
    auth_token: Option<String>,
    outgoing_rx: mpsc::UnboundedReceiver<CoordMessage>,
    router: Arc<Mutex<Router>>,
    dispatcher: Dispatcher,
) -> crate::Result<()> {
    let (incoming_tx, mut incoming_rx) = mpsc::unbounded_channel();
    let client = tokio::spawn(async move {
        crate::control::coord::run_coord_client(
            &url,
            local_pubkey,
            auth_token,
            outgoing_rx,
            incoming_tx,
        )
        .await
    });

    while let Some(message) = incoming_rx.recv().await {
        let actions = router.lock().await.handle_coord_message(message)?;
        dispatcher.dispatch(actions)?;
    }

    client.await??;
    Ok(())
}
