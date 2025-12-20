use opentun::config::{Config, RuntimeConfig};
use opentun::Peer;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use x25519_dalek::{PublicKey, StaticSecret};

// Helper to generate keypair
fn generate_keypair() -> (StaticSecret, PublicKey) {
    let private = StaticSecret::random();
    let public = PublicKey::from(&private);
    (private, public)
}

// Helper to create a dummy IPv4 packet
fn create_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    // Version 4, IHL 5
    packet.push(0x45);
    // DSCP/ECN
    packet.push(0x00);
    // Total Length (20 header + payload)
    let total_len = (20 + payload.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    // ID
    packet.extend_from_slice(&[0x00, 0x00]);
    // Flags/Frag Offset
    packet.extend_from_slice(&[0x00, 0x00]);
    // TTL
    packet.push(0x40);
    // Protocol (UDP = 17)
    packet.push(17);
    // Checksum (0 for now)
    packet.extend_from_slice(&[0x00, 0x00]);
    // Src IP
    packet.extend_from_slice(&src.octets());
    // Dst IP
    packet.extend_from_slice(&dst.octets());
    // Payload
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn test_config_loading() {
    let config_content = r#"
name: utun100
address: 10.0.0.5
port: 5000
secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
pubkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
peers:
    10.0.0.6:
        sock_addr: "192.168.1.6:5000"
        pub_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
"#;

    let path = format!("test_config_temp_{}.yaml", std::process::id());
    std::fs::write(path, config_content).expect("Failed to write temp config");

    let result = std::panic::catch_unwind(|| {
        opentun::config::load_config(&path)
    });

    let _ = std::fs::remove_file(&path);

    let config = result.expect("load_config failed/panicked");

    assert_eq!(config.name, "utun100");
    assert_eq!(config.address, "10.0.0.5");
    assert_eq!(config.port, 5000);
    assert_eq!(config.peers.len(), 1);

    let peer_ip: IpAddr = "10.0.0.6".parse().unwrap();
    assert!(config.peers.contains_key(&peer_ip));

    let peer = config.peers.get(&peer_ip).unwrap();
    assert_eq!(peer.sock_addr.to_string(), "192.168.1.6:5000");
}

#[tokio::test]
async fn test_packet_flow() {
    // 1. Setup Keys
    let (host_secret, host_public) = generate_keypair();
    let (peer_secret, peer_public) = generate_keypair();

    // 2. Setup Configs
    let host_ip: IpAddr = "10.0.0.1".parse().unwrap();
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let peer_socket: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    let mut peers = HashMap::new();
    peers.insert(peer_ip, Peer {
        sock_addr: peer_socket,
        pub_key: base64::encode(peer_public.as_bytes()),
    });

    let config = Arc::new(Config {
        name: "utun_test".to_string(),
        address: host_ip.to_string(),
        port: 9000,
        secret: base64::encode(host_secret.to_bytes()),
        pubkey: base64::encode(host_public.as_bytes()),
        peers: peers,
    });

    // 3. Setup RuntimeConfig
    let shared_secret = host_secret.diffie_hellman(&peer_public);
    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());

    let mut shared_secrets = HashMap::new();
    shared_secrets.insert(peer_ip, *shared_secret.as_bytes());

    let mut ciphers = HashMap::new();
    ciphers.insert(peer_ip, cipher);

    let mut ips = HashMap::new();
    ips.insert(peer_socket, peer_ip);

    let runtime_config = Arc::new(RuntimeConfig {
        shared_secrets,
        ciphers,
        ips,
    });

    // 4. Setup Channels
    let (dtx, mut drx) = mpsc::channel::<opentun::DecryptedPacket>(100);
    let (etx, mut erx) = mpsc::channel::<opentun::EncryptedPacket>(100);

    // --- Outbound Test: Host -> Peer ---
    let payload = b"Hello Peer!";
    let packet = create_ipv4_packet(
        match host_ip { IpAddr::V4(ip) => ip, _ => panic!() },
        match peer_ip { IpAddr::V4(ip) => ip, _ => panic!() },
        payload
    );

    opentun::net::handle_tun_packet(
        packet.clone().try_into().unwrap_or_else(|v: Vec<u8>| {
            let mut a = [0u8; opentun::MTU];
            a[..v.len()].copy_from_slice(&v);
            a
        }),
        packet.len(),
        Arc::clone(&config),
        Arc::clone(&runtime_config),
        etx
    ).await;

    // Verify Encrypted Output
    let (encrypted_packet, dest_addr) = erx.recv().await.expect("Should receive encrypted packet");
    assert_eq!(dest_addr, peer_socket);
    assert_ne!(encrypted_packet, packet); // Should be encrypted
    assert_eq!(encrypted_packet.len(), packet.len() + opentun::ENCRYPTION_OVERHEAD); // Should have exact overhead (nonce + tag)

    // Verify Decryption (simulate Peer receiving it)
    let peer_shared_secret = peer_secret.diffie_hellman(&host_public);
    let peer_cipher = ChaCha20Poly1305::new(peer_shared_secret.as_bytes().into());

    // Extract Nonce (first 12 bytes)
    let nonce = Nonce::from_slice(&encrypted_packet[..12]);
    let ciphertext = &encrypted_packet[12..];

    let decrypted = peer_cipher.decrypt(nonce, ciphertext).expect("Peer failed to decrypt");
    assert_eq!(decrypted, packet);

    // --- Inbound Test: Peer -> Host ---
    let inbound_payload = b"Hello Host!";
    let inbound_packet = create_ipv4_packet(
        match peer_ip { IpAddr::V4(ip) => ip, _ => panic!() },
        match host_ip { IpAddr::V4(ip) => ip, _ => panic!() },
        inbound_payload
    );

    // Encrypt as Peer
    // Use fixed nonce for this direction of the test.
    let nonce_bytes = [1u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_content = peer_cipher.encrypt(nonce, inbound_packet.as_slice()).expect("Peer failed to encrypt");

    let mut udp_buf_vec = Vec::new();
    udp_buf_vec.extend_from_slice(&nonce_bytes);
    udp_buf_vec.extend_from_slice(&encrypted_content);

    let mut udp_buf = [0u8; opentun::MTU + 512];
    udp_buf[..udp_buf_vec.len()].copy_from_slice(&udp_buf_vec);

    opentun::net::handle_udp_packet(
        udp_buf,
        udp_buf_vec.len(),
        peer_socket,
        Arc::clone(&runtime_config),
        dtx
    ).await;

    // Verify Decrypted Input
    let received_packet = drx.recv().await.expect("Should receive decrypted packet");
    assert_eq!(received_packet, inbound_packet);
}

#[tokio::test]
async fn test_unknown_peer() {
    let (_dtx, mut _drx) = mpsc::channel::<opentun::DecryptedPacket>(100);
    let (etx, mut erx) = mpsc::channel::<opentun::EncryptedPacket>(100);

    // Minimal config
    let config = Arc::new(Config {
        name: "test".into(),
        address: "10.0.0.1".into(),
        port: 1111,
        secret: "foo".into(),
        pubkey: "bar".into(),
        peers: HashMap::new(),
    });

    let runtime_config = Arc::new(RuntimeConfig {
        shared_secrets: HashMap::new(),
        ciphers: HashMap::new(),
        ips: HashMap::new(),
    });

    // Create packet for unknown IP
    let packet = create_ipv4_packet(
        Ipv4Addr::new(10,0,0,1),
        Ipv4Addr::new(10,0,0,99), // Unknown
        b"data"
    );

    opentun::net::handle_tun_packet(
        {
            let mut a = [0u8; opentun::MTU];
            a[..packet.len()].copy_from_slice(&packet);
            a
        },
        packet.len(),
        config,
        runtime_config,
        etx
    ).await;

    // Ensure nothing received (timeout or try_recv)
    // using try_recv
    match erx.try_recv() {
        Ok(_) => panic!("Should not receive packet for unknown peer"),
        Err(mpsc::error::TryRecvError::Empty) | Err(mpsc::error::TryRecvError::Disconnected) => {}, // Good
    }
}

#[tokio::test]
async fn test_malformed_packet() {
    let (dtx, mut drx) = mpsc::channel::<opentun::DecryptedPacket>(100);

    let runtime_config = Arc::new(RuntimeConfig {
        shared_secrets: HashMap::new(),
        ciphers: HashMap::new(),
        ips: HashMap::new(),
    });

    // Packet large enough to slice, but invalid content (no key found for peer anyway)
    let packet = vec![0u8; 30];
    let peer_addr: SocketAddr = "1.2.3.4:1234".parse().unwrap();

    opentun::net::handle_udp_packet(
        {
            let mut a = [0u8; opentun::MTU + 512];
            a[..packet.len()].copy_from_slice(&packet);
            a
        },
        packet.len(),
        peer_addr,
        runtime_config,
        dtx
    ).await;

    // Should verify decryption failed (logged) and nothing sent
    match drx.try_recv() {
        Ok(_) => panic!("Should not receive packet"),
        Err(mpsc::error::TryRecvError::Empty) | Err(mpsc::error::TryRecvError::Disconnected) => {},
    }
}
