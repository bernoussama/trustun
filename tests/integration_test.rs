use std::net::Ipv4Addr;
use std::time::Instant;

use opentun::protocol::events::{Input, Output};
use opentun::protocol::peer::{Peer, PeerConfig};
use x25519_dalek::{PublicKey, StaticSecret};

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let sk = StaticSecret::random();
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

#[tokio::test]
async fn handshake_and_transport_flow() {
    let (init_sk, init_pk) = gen_keypair();
    let (resp_sk, resp_pk) = gen_keypair();

    let initiator_index = u32::from(Ipv4Addr::new(10, 0, 0, 1));
    let responder_index = u32::from(Ipv4Addr::new(10, 0, 0, 2));

    let init_conf = PeerConfig {
        static_private: init_sk.to_bytes(),
        remote_public: resp_pk.to_bytes(),
        psk: Some([1u8; 32]),
        sender_index: initiator_index,
        receiver_index: responder_index,
    };
    let resp_conf = PeerConfig {
        static_private: resp_sk.to_bytes(),
        remote_public: init_pk.to_bytes(),
        psk: Some([1u8; 32]),
        sender_index: responder_index,
        receiver_index: initiator_index,
    };

    let mut initiator =
        Peer::new(init_conf, "127.0.0.1:10000".parse().unwrap()).expect("init peer");
    let mut responder =
        Peer::new_responder(resp_conf, "127.0.0.1:20000".parse().unwrap()).expect("resp peer");

    let initial = initiator
        .tick(Input::Tick(Instant::now()))
        .expect("initial handshake");
    assert!(!initial.is_empty());

    let mut responder_outputs = Vec::new();
    for out in initial {
        if let Output::SendUdp(data, addr) = out {
            responder_outputs = responder
                .tick(Input::UdpPacket(data, addr))
                .expect("responder process");
        }
    }

    let mut _initiator_outputs = Vec::new();
    for out in responder_outputs {
        if let Output::SendUdp(data, addr) = out {
            _initiator_outputs = initiator
                .tick(Input::UdpPacket(data, addr))
                .expect("initiator process");
        }
    }

    assert!(initiator.is_established());
    assert!(responder.is_established());

    let payload = b"hello tun".to_vec();
    let outbound = initiator
        .tick(Input::TunPacket(payload.clone()))
        .expect("encrypt tun");

    let mut inbound = Vec::new();
    for out in outbound {
        if let Output::SendUdp(data, addr) = out {
            inbound = responder
                .tick(Input::UdpPacket(data, addr))
                .expect("decrypt transport");
        }
    }

    let mut recovered = None;
    for out in inbound {
        if let Output::WriteTun(data) = out {
            recovered = Some(data);
        }
    }

    assert_eq!(recovered.expect("tun output"), payload);
}
