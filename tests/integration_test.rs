use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use opentun::control::coord::{CandidateRecord, CoordMessage};
use opentun::relay::RelayFrame;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

fn free_local_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr.to_string()
}

fn ws_url(addr: &str) -> String {
    format!("ws://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_relay_server_forwards_packet_between_registered_peers() {
    let listen_addr = free_local_addr();
    let server = tokio::spawn({
        let listen_addr = listen_addr.clone();
        async move { opentun::tasks::run_relay_server(&listen_addr).await }
    });
    sleep(Duration::from_millis(50)).await;

    let (peer_a, _) = connect_async(ws_url(&listen_addr)).await.unwrap();
    let (peer_b, _) = connect_async(ws_url(&listen_addr)).await.unwrap();
    let (mut write_a, _read_a) = peer_a.split();
    let (mut write_b, mut read_b) = peer_b.split();

    write_a
        .send(Message::Binary(
            RelayFrame::PeerPresent { pubkey: [1; 32] }
                .serialize()
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    write_b
        .send(Message::Binary(
            RelayFrame::PeerPresent { pubkey: [2; 32] }
                .serialize()
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();

    write_a
        .send(Message::Binary(
            RelayFrame::SendPacket {
                dst_pubkey: [2; 32],
                packet: vec![9, 8, 7, 6],
            }
            .serialize()
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    let received = timeout(Duration::from_secs(2), read_b.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let Message::Binary(bytes) = received else {
        panic!("expected binary relay frame");
    };
    let frame = RelayFrame::deserialize(&bytes).unwrap();
    assert_eq!(
        frame,
        RelayFrame::RecvPacket {
            src_pubkey: [1; 32],
            packet: vec![9, 8, 7, 6],
        }
    );

    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_coord_server_forwards_candidate_updates_between_registered_peers() {
    let listen_addr = free_local_addr();
    let server = tokio::spawn({
        let listen_addr = listen_addr.clone();
        async move { opentun::tasks::run_coord_server(&listen_addr, None).await }
    });
    sleep(Duration::from_millis(50)).await;

    let (tx_a, rx_a) = mpsc::unbounded_channel();
    let (tx_b, rx_b) = mpsc::unbounded_channel();
    let (incoming_a_tx, _incoming_a_rx) = mpsc::unbounded_channel();
    let (incoming_b_tx, mut incoming_b_rx) = mpsc::unbounded_channel();
    let url = ws_url(&listen_addr);

    let client_a = tokio::spawn({
        let url = url.clone();
        async move { opentun::control::coord::run_coord_client(&url, [3; 32], None, rx_a, incoming_a_tx).await }
    });
    let client_b = tokio::spawn({
        let url = url.clone();
        async move { opentun::control::coord::run_coord_client(&url, [4; 32], None, rx_b, incoming_b_tx).await }
    });
    sleep(Duration::from_millis(100)).await;

    tx_a
        .send(CoordMessage::PublishCandidates {
            pubkey: base64::encode([3; 32]),
            peer_pubkey: base64::encode([4; 32]),
            candidates: vec![
                CandidateRecord::Lan {
                    addr: "192.0.2.10:5000".to_string(),
                },
                CandidateRecord::Relay,
            ],
        })
        .unwrap();

    let forwarded = timeout(Duration::from_secs(2), incoming_b_rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        forwarded,
        CoordMessage::PeerCandidates {
            peer_pubkey: base64::encode([3; 32]),
            candidates: vec![
                CandidateRecord::Lan {
                    addr: "192.0.2.10:5000".to_string(),
                },
                CandidateRecord::Relay,
            ],
        }
    );

    drop(tx_a);
    drop(tx_b);
    client_a.abort();
    client_b.abort();
    server.abort();
}
