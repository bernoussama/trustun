use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;

use crate::protocol::Candidate;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CandidateRecord {
    Lan { addr: String },
    Reflexive { addr: String },
    Relay,
}

impl TryFrom<CandidateRecord> for Candidate {
    type Error = crate::IpouError;

    fn try_from(value: CandidateRecord) -> Result<Self, Self::Error> {
        match value {
            CandidateRecord::Lan { addr } => Ok(Candidate::Lan(addr.parse()?)),
            CandidateRecord::Reflexive { addr } => Ok(Candidate::Reflexive(addr.parse()?)),
            CandidateRecord::Relay => Ok(Candidate::Relay),
        }
    }
}

impl From<&Candidate> for CandidateRecord {
    fn from(value: &Candidate) -> Self {
        match value {
            Candidate::Lan(addr) => Self::Lan {
                addr: addr.to_string(),
            },
            Candidate::Reflexive(addr) => Self::Reflexive {
                addr: addr.to_string(),
            },
            Candidate::Relay => Self::Relay,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordMessage {
    Register {
        pubkey: String,
        auth_token: Option<String>,
    },
    PublishCandidates {
        pubkey: String,
        peer_pubkey: String,
        candidates: Vec<CandidateRecord>,
    },
    PeerCandidates {
        peer_pubkey: String,
        candidates: Vec<CandidateRecord>,
    },
    Ping,
    Pong,
}

#[derive(Default)]
struct CoordServerState {
    clients: HashMap<String, mpsc::UnboundedSender<Message>>,
    cached: HashMap<String, Vec<CoordMessage>>,
}

pub async fn run_coord_server(
    listen_addr: &str,
    auth_token: Option<String>,
) -> crate::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let state = Arc::new(Mutex::new(CoordServerState::default()));

    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        let auth_token = auth_token.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_coord_connection(stream, state, auth_token).await {
                eprintln!("coord connection failed: {err}");
            }
        });
    }
}

pub async fn run_coord_client(
    url: &str,
    local_pubkey: [u8; 32],
    auth_token: Option<String>,
    mut outgoing_rx: mpsc::UnboundedReceiver<CoordMessage>,
    incoming_tx: mpsc::UnboundedSender<CoordMessage>,
) -> crate::Result<()> {
    let (stream, _) = tokio_tungstenite::connect_async(url).await?;
    let (mut write, mut read) = stream.split();
    let register = CoordMessage::Register {
        pubkey: base64::encode(local_pubkey),
        auth_token,
    };
    write
        .send(Message::Text(serde_json::to_string(&register)?.into()))
        .await?;

    loop {
        tokio::select! {
            Some(message) = outgoing_rx.recv() => {
                let payload = serde_json::to_string(&message)?;
                write.send(Message::Text(payload.into())).await?;
            }
            Some(message) = read.next() => {
                let message = message?;
                match message {
                    Message::Text(text) => {
                        let decoded: CoordMessage = serde_json::from_str(&text)?;
                        let _ = incoming_tx.send(decoded);
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

async fn handle_coord_connection(
    stream: TcpStream,
    state: Arc<Mutex<CoordServerState>>,
    auth_token: Option<String>,
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

    let mut registered_pubkey = None;

    while let Some(message) = read.next().await {
        let message = message?;
        match message {
            Message::Text(text) => {
                let decoded: CoordMessage = serde_json::from_str(&text)?;
                match decoded {
                    CoordMessage::Register { pubkey, auth_token: supplied } => {
                        if auth_token.is_some() && supplied != auth_token {
                            return Err(crate::IpouError::Config("coord auth token mismatch".to_string()));
                        }

                        registered_pubkey = Some(pubkey.clone());
                        let mut state = state.lock().await;
                        state.clients.insert(pubkey.clone(), tx.clone());
                        if let Some(backlog) = state.cached.remove(&pubkey) {
                            for message in backlog {
                                let payload = serde_json::to_string(&message)?;
                                let _ = tx.send(Message::Text(payload.into()));
                            }
                        }
                    }
                    CoordMessage::PublishCandidates {
                        pubkey,
                        peer_pubkey,
                        candidates,
                    } => {
                        let forward = CoordMessage::PeerCandidates {
                            peer_pubkey: pubkey,
                            candidates,
                        };
                        let payload = serde_json::to_string(&forward)?;
                        let mut state = state.lock().await;
                        if let Some(target) = state.clients.get(&peer_pubkey) {
                            let _ = target.send(Message::Text(payload.clone().into()));
                        } else {
                            state.cached.entry(peer_pubkey).or_default().push(forward);
                        }
                    }
                    CoordMessage::Ping => {
                        let _ = tx.send(Message::Text(serde_json::to_string(&CoordMessage::Pong)?.into()));
                    }
                    CoordMessage::PeerCandidates { .. } | CoordMessage::Pong => {}
                }
            }
            Message::Ping(payload) => {
                let _ = tx.send(Message::Pong(payload));
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    if let Some(pubkey) = registered_pubkey {
        state.lock().await.clients.remove(&pubkey);
    }

    writer.abort();
    Ok(())
}

pub async fn resolve_socket_addr(value: &str) -> crate::Result<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let mut addrs = tokio::net::lookup_host(value).await?;
    addrs
        .next()
        .ok_or_else(|| crate::IpouError::Config(format!("unable to resolve address {value}")))
}
