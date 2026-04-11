use std::net::SocketAddr;

use opentun::protocol::{
    path_id_for_candidate, Candidate, Input, Output, Peer, PeerConfig, PeerRole, PeerState,
    ProtocolError, WirePacket,
};
use opentun::relay::{RelayError, RelayFrame};
use x25519_dalek::{PublicKey, StaticSecret};

fn peer_config(
    role: PeerRole,
    local_secret: [u8; 32],
    remote_public: [u8; 32],
    mtu: usize,
) -> PeerConfig {
    PeerConfig {
        role,
        static_private: local_secret,
        remote_public,
        psk: None,
        mtu,
        home_relay_path: 7,
    }
}

fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = [seed; 32];
    let public = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
    (secret, public)
}

fn unwrap_packet(output: &Output) -> Vec<u8> {
    match output {
        Output::NetworkTx { bytes, .. } => bytes.clone(),
        Output::RelayTx { frame, .. } => match RelayFrame::deserialize(frame).unwrap() {
            RelayFrame::SendPacket { packet, .. } => packet,
            other => panic!("unexpected relay frame: {other:?}"),
        },
        other => panic!("unexpected output: {other:?}"),
    }
}

fn first_packet(outputs: &[Output]) -> Vec<u8> {
    outputs
        .iter()
        .find(|output| matches!(output, Output::NetworkTx { .. } | Output::RelayTx { .. }))
        .map(unwrap_packet)
        .unwrap()
}

fn has_publish_local_candidates(outputs: &[Output]) -> bool {
    outputs
        .iter()
        .any(|output| matches!(output, Output::PublishLocalCandidates))
}

#[test]
fn wire_packet_round_trip_encoding_decoding() {
    let packets = [
        WirePacket::HandshakeInit {
            sender_index: 11,
            receiver_index: None,
            noise_msg: vec![1, 2, 3],
        },
        WirePacket::HandshakeResp {
            sender_index: 12,
            receiver_index: 11,
            noise_msg: vec![4, 5, 6],
        },
        WirePacket::TransportData {
            receiver_index: 77,
            counter: 9,
            payload: vec![7, 8, 9],
        },
        WirePacket::KeepAlive {
            receiver_index: 88,
            counter: 10,
        },
    ];

    for packet in packets {
        let encoded = packet.serialize().unwrap();
        let decoded = WirePacket::deserialize(&encoded).unwrap();
        assert_eq!(decoded, packet);
    }
}

#[test]
fn relay_frame_round_trip_encoding_decoding() {
    let frame = RelayFrame::SendPacket {
        dst_pubkey: [9; 32],
        packet: vec![1, 2, 3, 4],
    };

    let encoded = frame.serialize().unwrap();
    let decoded = RelayFrame::deserialize(&encoded).unwrap();

    assert_eq!(decoded, frame);
}

#[test]
fn tick_tun_rx_while_handshaking_does_not_panic() {
    let (initiator_secret, responder_public) = {
        let (a_secret, _) = keypair(1);
        let (_, b_public) = keypair(2);
        (a_secret, b_public)
    };

    let mut peer = Peer::new(peer_config(
        PeerRole::Responder,
        initiator_secret,
        responder_public,
        1280,
    ))
    .unwrap();

    let result = peer.tick(Input::TunRx(vec![0u8; 20]));

    assert!(result.is_ok());
}

#[test]
fn initiator_and_responder_complete_handshake() {
    let (initiator_secret, initiator_public) = keypair(11);
    let (responder_secret, responder_public) = keypair(22);

    let mut initiator = Peer::new(peer_config(
        PeerRole::Initiator,
        initiator_secret,
        responder_public,
        1280,
    ))
    .unwrap();
    let mut responder = Peer::new(peer_config(
        PeerRole::Responder,
        responder_secret,
        initiator_public,
        1280,
    ))
    .unwrap();

    let bootstrap = initiator.bootstrap(0).unwrap();
    assert!(has_publish_local_candidates(&bootstrap));

    let responder_outputs = responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&bootstrap),
            now_ms: 0,
        })
        .unwrap();

    assert_eq!(responder_outputs.len(), 1);

    let initiator_outputs = initiator
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&responder_outputs),
            now_ms: 0,
        })
        .unwrap();

    assert!(initiator_outputs.is_empty());
    assert!(matches!(initiator.state, PeerState::Established { .. }));
    assert!(matches!(responder.state, PeerState::Established { .. }));
}

#[test]
fn transport_encrypts_and_decrypts_payload_after_handshake() {
    let (initiator_secret, initiator_public) = keypair(31);
    let (responder_secret, responder_public) = keypair(32);

    let mut initiator = Peer::new(peer_config(
        PeerRole::Initiator,
        initiator_secret,
        responder_public,
        1280,
    ))
    .unwrap();
    let mut responder = Peer::new(peer_config(
        PeerRole::Responder,
        responder_secret,
        initiator_public,
        1280,
    ))
    .unwrap();

    let bootstrap = initiator.bootstrap(0).unwrap();
    let responder_outputs = responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&bootstrap),
            now_ms: 0,
        })
        .unwrap();
    initiator
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&responder_outputs),
            now_ms: 0,
        })
        .unwrap();

    let vpn_payload = vec![
        0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    let outbound = initiator.tick(Input::TunRx(vpn_payload.clone())).unwrap();

    let inbound = responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: unwrap_packet(&outbound[0]),
            now_ms: 1,
        })
        .unwrap();

    assert_eq!(inbound, vec![Output::TunTx(vpn_payload)]);
}

#[test]
fn transport_encrypts_and_decrypts_payloads_in_both_directions() {
    let (initiator_secret, initiator_public) = keypair(33);
    let (responder_secret, responder_public) = keypair(34);

    let mut initiator = Peer::new(peer_config(
        PeerRole::Initiator,
        initiator_secret,
        responder_public,
        1280,
    ))
    .unwrap();
    let mut responder = Peer::new(peer_config(
        PeerRole::Responder,
        responder_secret,
        initiator_public,
        1280,
    ))
    .unwrap();

    let bootstrap = initiator.bootstrap(0).unwrap();
    let responder_outputs = responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&bootstrap),
            now_ms: 0,
        })
        .unwrap();
    initiator
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&responder_outputs),
            now_ms: 0,
        })
        .unwrap();

    let to_responder = vec![
        0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    let outbound = initiator.tick(Input::TunRx(to_responder.clone())).unwrap();
    let inbound = responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: unwrap_packet(&outbound[0]),
            now_ms: 1,
        })
        .unwrap();
    assert_eq!(inbound, vec![Output::TunTx(to_responder)]);

    let to_initiator = vec![
        0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
    ];
    let outbound = responder.tick(Input::TunRx(to_initiator.clone())).unwrap();
    let inbound = initiator
        .tick(Input::NetworkRx {
            path: 7,
            bytes: unwrap_packet(&outbound[0]),
            now_ms: 2,
        })
        .unwrap();
    assert_eq!(inbound, vec![Output::TunTx(to_initiator)]);
}

#[test]
fn duplicate_transport_counter_is_rejected() {
    let (initiator_secret, initiator_public) = keypair(41);
    let (responder_secret, responder_public) = keypair(42);

    let mut initiator = Peer::new(peer_config(
        PeerRole::Initiator,
        initiator_secret,
        responder_public,
        1280,
    ))
    .unwrap();
    let mut responder = Peer::new(peer_config(
        PeerRole::Responder,
        responder_secret,
        initiator_public,
        1280,
    ))
    .unwrap();

    let bootstrap = initiator.bootstrap(0).unwrap();
    let responder_outputs = responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&bootstrap),
            now_ms: 0,
        })
        .unwrap();
    initiator
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&responder_outputs),
            now_ms: 0,
        })
        .unwrap();

    let outbound = initiator.tick(Input::TunRx(vec![1; 20])).unwrap();
    let packet = unwrap_packet(&outbound[0]);

    responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: packet.clone(),
            now_ms: 1,
        })
        .unwrap();

    let duplicate = responder.tick(Input::NetworkRx {
        path: 7,
        bytes: packet,
        now_ms: 2,
    });

    assert!(matches!(duplicate, Err(ProtocolError::ReplayRejected)));
}

#[test]
fn oversized_tun_packet_is_rejected() {
    let (initiator_secret, initiator_public) = keypair(51);
    let (responder_secret, responder_public) = keypair(52);

    let mut initiator = Peer::new(peer_config(
        PeerRole::Initiator,
        initiator_secret,
        responder_public,
        64,
    ))
    .unwrap();
    let mut responder = Peer::new(peer_config(
        PeerRole::Responder,
        responder_secret,
        initiator_public,
        64,
    ))
    .unwrap();

    let bootstrap = initiator.bootstrap(0).unwrap();
    let responder_outputs = responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&bootstrap),
            now_ms: 0,
        })
        .unwrap();
    initiator
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&responder_outputs),
            now_ms: 0,
        })
        .unwrap();

    let result = initiator.tick(Input::TunRx(vec![0u8; 128]));

    assert!(matches!(result, Err(ProtocolError::PacketTooLarge)));
}

#[test]
fn truncated_relay_frame_is_rejected() {
    let result = RelayFrame::deserialize(&[1, 0, 0, 0]);

    assert_eq!(result, Err(RelayError::Truncated));
}

#[test]
fn candidates_update_emits_direct_probe_without_switching_immediately() {
    let (initiator_secret, initiator_public) = keypair(61);
    let (responder_secret, responder_public) = keypair(62);

    let mut initiator = Peer::new(peer_config(
        PeerRole::Initiator,
        initiator_secret,
        responder_public,
        1280,
    ))
    .unwrap();
    let mut responder = Peer::new(peer_config(
        PeerRole::Responder,
        responder_secret,
        initiator_public,
        1280,
    ))
    .unwrap();

    let bootstrap = initiator.bootstrap(0).unwrap();
    let responder_outputs = responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&bootstrap),
            now_ms: 0,
        })
        .unwrap();
    initiator
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&responder_outputs),
            now_ms: 1,
        })
        .unwrap();

    let candidate = Candidate::Lan("192.0.2.10:4242".parse::<SocketAddr>().unwrap());
    let path = path_id_for_candidate(&candidate).unwrap();
    let outputs = initiator
        .tick(Input::CandidatesUpdated {
            peer: 1,
            candidates: vec![candidate],
        })
        .unwrap();

    assert!(outputs.iter().any(|output| matches!(output, Output::NetworkTx { path: output_path, .. } if *output_path == path)));
    assert_eq!(initiator.path_manager.active_path(), 7);
}

#[test]
fn direct_path_switches_after_authenticated_packet_and_falls_back_on_timeout() {
    let (initiator_secret, initiator_public) = keypair(71);
    let (responder_secret, responder_public) = keypair(72);

    let mut initiator = Peer::new(peer_config(
        PeerRole::Initiator,
        initiator_secret,
        responder_public,
        1280,
    ))
    .unwrap();
    let mut responder = Peer::new(peer_config(
        PeerRole::Responder,
        responder_secret,
        initiator_public,
        1280,
    ))
    .unwrap();

    let bootstrap = initiator.bootstrap(0).unwrap();
    let responder_outputs = responder
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&bootstrap),
            now_ms: 0,
        })
        .unwrap();
    initiator
        .tick(Input::NetworkRx {
            path: 7,
            bytes: first_packet(&responder_outputs),
            now_ms: 1,
        })
        .unwrap();

    let candidate = Candidate::Lan("192.0.2.20:5252".parse::<SocketAddr>().unwrap());
    let path = path_id_for_candidate(&candidate).unwrap();
    let initiator_probe = initiator
        .tick(Input::CandidatesUpdated {
            peer: 1,
            candidates: vec![candidate.clone()],
        })
        .unwrap();
    responder
        .tick(Input::NetworkRx {
            path,
            bytes: first_packet(&initiator_probe),
            now_ms: 2,
        })
        .unwrap();

    let responder_probe = responder
        .tick(Input::CandidatesUpdated {
            peer: 1,
            candidates: vec![candidate],
        })
        .unwrap();
    initiator
        .tick(Input::NetworkRx {
            path,
            bytes: first_packet(&responder_probe),
            now_ms: 3,
        })
        .unwrap();

    assert_eq!(initiator.path_manager.active_path(), path);

    let tick_outputs = initiator.tick(Input::Tick { now_ms: 40_000 }).unwrap();

    assert_eq!(initiator.path_manager.active_path(), 7);
    assert!(tick_outputs.iter().any(
        |output| matches!(output, Output::Log(message) if message.contains("falling back to relay"))
    ));
}
