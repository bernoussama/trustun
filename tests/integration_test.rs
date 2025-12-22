use opentun::protocol::peer::{Peer, PeerConfig};
use opentun::protocol::events::{Input, Output};
use snow::Builder;
use std::net::SocketAddr;
use std::time::Instant;

const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[test]
fn test_handshake_and_transport() {
    // 1. Generate Keys
    let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
    let alice_keys = builder.generate_keypair().unwrap();
    let bob_keys = builder.generate_keypair().unwrap();

    let mut alice_static = [0u8; 32]; alice_static.copy_from_slice(&alice_keys.private);
    let mut bob_static = [0u8; 32]; bob_static.copy_from_slice(&bob_keys.private);
    let mut alice_pub = [0u8; 32]; alice_pub.copy_from_slice(&alice_keys.public);
    let mut bob_pub = [0u8; 32]; bob_pub.copy_from_slice(&bob_keys.public);

    let alice_addr: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let bob_addr: SocketAddr = "127.0.0.1:10002".parse().unwrap();

    // 2. Setup Alice (Initiator)
    let mut alice = Peer::new(PeerConfig {
        static_private: alice_static,
        remote_public: bob_pub,
        psk: None,
        remote_endpoint: bob_addr,
        initiator: true,
    }).unwrap();

    // 3. Setup Bob (Responder)
    let mut bob = Peer::new(PeerConfig {
        static_private: bob_static,
        remote_public: alice_pub,
        psk: None,
        remote_endpoint: alice_addr,
        initiator: false,
    }).unwrap();

    // 4. Alice starts handshake
    let outputs = alice.tick(Input::Tick(Instant::now())).unwrap();
    assert_eq!(outputs.len(), 1);
    let packet1 = match &outputs[0] {
        Output::SendUdp(data, dst) => {
            assert_eq!(*dst, bob_addr);
            data.clone()
        },
        _ => panic!("Expected SendUdp"),
    };

    // 5. Bob receives Packet 1 (HandshakeInit)
    let outputs = bob.tick(Input::UdpPacket(packet1, alice_addr)).unwrap();
    assert_eq!(outputs.len(), 1);
    let packet2 = match &outputs[0] {
        Output::SendUdp(data, dst) => {
            assert_eq!(*dst, alice_addr);
            data.clone()
        },
        _ => panic!("Expected SendUdp"),
    };

    // 6. Alice receives Packet 2 (HandshakeResp)
    let outputs = alice.tick(Input::UdpPacket(packet2, bob_addr)).unwrap();
    assert_eq!(outputs.len(), 0); // Handshake complete, no output unless we send data

    // 7. Data Transfer: Alice -> Bob
    let tun_data = vec![0x01, 0x02, 0x03, 0x04];
    let outputs = alice.tick(Input::TunPacket(tun_data.clone())).unwrap();
    assert_eq!(outputs.len(), 1);
    let packet3 = match &outputs[0] {
        Output::SendUdp(data, dst) => {
            assert_eq!(*dst, bob_addr);
            data.clone()
        },
        _ => panic!("Expected SendUdp"),
    };

    // 8. Bob receives Data
    let outputs = bob.tick(Input::UdpPacket(packet3, alice_addr)).unwrap();
    assert_eq!(outputs.len(), 1);
    match &outputs[0] {
        Output::WriteTun(data) => {
            assert_eq!(*data, tun_data);
        },
        _ => panic!("Expected WriteTun"),
    };
    
    // 9. Data Transfer: Bob -> Alice
    let tun_data2 = vec![0xAA, 0xBB];
    let outputs = bob.tick(Input::TunPacket(tun_data2.clone())).unwrap();
    assert_eq!(outputs.len(), 1);
    let packet4 = match &outputs[0] {
        Output::SendUdp(data, dst) => {
            assert_eq!(*dst, alice_addr);
            data.clone()
        },
        _ => panic!("Expected SendUdp"),
    };

    // 10. Alice receives Data
    let outputs = alice.tick(Input::UdpPacket(packet4, bob_addr)).unwrap();
    assert_eq!(outputs.len(), 1);
    match &outputs[0] {
        Output::WriteTun(data) => {
            assert_eq!(*data, tun_data2);
        },
        _ => panic!("Expected WriteTun"),
    };
}