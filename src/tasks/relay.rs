use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;

use crate::net::router::Router;
use crate::relay::RelayFrame;

use super::{Dispatcher, timer};

#[derive(Default)]
struct RelayServerState {
    clients: HashMap<[u8; 32], mpsc::UnboundedSender<Message>>,
}

pub async fn run_server(listen_addr: &str) -> crate::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let state = Arc::new(Mutex::new(RelayServerState::default()));

    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(err) = handle_server_connection(stream, state).await {
                eprintln!("relay connection failed: {err}");
            }
        });
    }
}

pub async fn run_client(
    url: String,
    local_pubkey: [u8; 32],
    mut outgoing_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    router: Arc<Mutex<Router>>,
    dispatcher: Dispatcher,
) -> crate::Result<()> {
    let (stream, _) = tokio_tungstenite::connect_async(&url).await?;
    let (mut write, mut read) = stream.split();
    let announce = RelayFrame::PeerPresent { pubkey: local_pubkey }.serialize()?;
    write.send(Message::Binary(announce.into())).await?;

    loop {
        tokio::select! {
            Some(frame) = outgoing_rx.recv() => {
                write.send(Message::Binary(frame.into())).await?;
            }
            Some(message) = read.next() => {
                let message = message?;
                match message {
                    Message::Binary(bytes) => {
                        let frame = RelayFrame::deserialize(&bytes)?;
                        let actions = router.lock().await.handle_relay_frame(frame, timer::now_ms())?;
                        dispatcher.dispatch(actions)?;
                    }
                    Message::Ping(payload) => {
                        write.send(Message::Pong(payload)).await?;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            else => break,
        }
    }

    Ok(())
}

async fn handle_server_connection(
    stream: TcpStream,
    state: Arc<Mutex<RelayServerState>>,
) -> crate::Result<()> {
    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    let (mut write, mut read) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if write.send(message).await.is_err() {
                break;
            }
        }
    });

    let mut registered = None;
    while let Some(message) = read.next().await {
        let message = message?;
        match message {
            Message::Binary(bytes) => match RelayFrame::deserialize(&bytes)? {
                RelayFrame::PeerPresent { pubkey } => {
                    state.lock().await.clients.insert(pubkey, tx.clone());
                    registered = Some(pubkey);
                }
                RelayFrame::SendPacket { dst_pubkey, packet } => {
                    if let Some(src_pubkey) = registered {
                        if let Some(target) = state.lock().await.clients.get(&dst_pubkey) {
                            let forward = RelayFrame::RecvPacket { src_pubkey, packet }.serialize()?;
                            let _ = target.send(Message::Binary(forward.into()));
                        }
                    }
                }
                RelayFrame::Ping { nonce } => {
                    let pong = RelayFrame::Pong { nonce }.serialize()?;
                    let _ = tx.send(Message::Binary(pong.into()));
                }
                RelayFrame::RecvPacket { .. } | RelayFrame::Pong { .. } => {}
            },
            Message::Ping(payload) => {
                let _ = tx.send(Message::Pong(payload));
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    if let Some(pubkey) = registered {
        state.lock().await.clients.remove(&pubkey);
    }
    writer.abort();
    Ok(())
}
