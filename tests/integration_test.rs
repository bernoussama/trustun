use opentun::config::{Config, RuntimeConfig};
use opentun::Peer;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use x25519_dalek::{PublicKey, StaticSecret};

/// Generates a new X25519 keypair for testing.
///
/// # Returns
///
/// A tuple containing:
/// - `StaticSecret`: The private key
/// - `PublicKey`: The corresponding public key
fn generate_keypair() -> (StaticSecret, PublicKey) {
    let private = StaticSecret::random();
    let public = PublicKey::from(&private);
    (private, public)
}

/// Extracts an IPv4 address from an `IpAddr` enum.
///
/// This helper is used in tests where we explicitly create IPv4 addresses
/// and need to extract the IPv4 variant. The IPv6 case is unreachable in
/// these test contexts.
///
/// # Arguments
///
/// * `addr` - An `IpAddr` that is expected to contain an IPv4 address
///
/// # Returns
///
/// The extracted `Ipv4Addr`
///
/// # Panics
///
/// Panics with `unreachable!()` if the address is IPv6, as this should never
/// occur in the test contexts where this function is used.
fn extract_ipv4(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!("Test only uses IPv4 addresses"),
    }
}

/// Creates a minimal IPv4 packet for testing purposes.
///
/// Constructs a basic IPv4 packet with a 20-byte header and the provided payload.
/// The packet uses simplified values suitable for testing (e.g., zero checksum,
/// UDP protocol).
///
/// # Arguments
///
/// * `src` - Source IPv4 address
/// * `dst` - Destination IPv4 address
/// * `payload` - Data to include in the packet body
///
/// # Returns
///
/// A `Vec<u8>` containing the complete IPv4 packet (header + payload)
fn expect_ipv4(ip: IpAddr) -> Ipv4Addr {
    match ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!("Test uses IPv4 addresses"),
    }
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

/// Tests that configuration files can be loaded correctly.
///
/// Creates a temporary YAML configuration file, loads it, and verifies that
/// all fields (name, address, port, peers) are parsed correctly.
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
    std::fs::write(&path, config_content).expect("Failed to write temp config");

    let result = std::panic::catch_unwind(|| {
        opentun::config::load_config(&path)
    });

    let _ = std::fs::remove_file(path);

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

/// Tests the complete packet flow including encryption and decryption.
///
/// This integration test validates:
/// - Outbound flow: TUN packet → encryption → UDP packet
/// - Inbound flow: UDP packet → decryption → TUN packet
/// - Proper encryption/decryption using ChaCha20Poly1305 with X25519 key exchange
/// - Correct packet routing between host and peer
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
        peers,
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
        extract_ipv4(host_ip),
        extract_ipv4(peer_ip),
        payload
    );

    let mut tun_buf = [0u8; opentun::MTU];
    tun_buf[..packet.len()].copy_from_slice(&packet);

    opentun::net::handle_tun_packet(
        tun_buf,
        packet.len(),
        Arc::clone(&config),
        Arc::clone(&runtime_config),
        etx
    ).await;

    // Verify Encrypted Output
    let (encrypted_packet, dest_addr) = erx.recv().await.expect("Should receive encrypted packet");
    assert_eq!(dest_addr, peer_socket);
    assert_ne!(encrypted_packet, packet); // Should be encrypted
    assert!(encrypted_packet.len() > packet.len()); // Should have overhead (nonce + tag)

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
        extract_ipv4(peer_ip),
        extract_ipv4(host_ip),
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

    let mut udp_buf = [0u8; opentun::CHANNEL_BUFFER_SIZE];
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

/// Tests that packets destined for unknown peers are dropped.
///
/// Verifies that when a packet is sent to an IP address that is not in the
/// peer configuration, it is properly dropped and nothing is transmitted.
#[tokio::test]
async fn test_unknown_peer() {
    let (_dtx, _) = mpsc::channel::<opentun::DecryptedPacket>(100);
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

/// Tests that malformed or invalid packets are handled gracefully.
///
/// Verifies that when an invalid UDP packet is received (e.g., one that cannot
/// be decrypted or is from an unknown peer), it is properly rejected without
/// causing crashes or sending invalid data to the TUN interface.
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
            let mut a = [0u8; opentun::CHANNEL_BUFFER_SIZE];
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

/// Tests YAML serialization and deserialization with serde_yaml.
///
/// Verifies that the Config struct can be successfully serialized to YAML
/// and deserialized back, maintaining all field values correctly.
#[test]
fn test_yaml_serialization_deserialization() {
    let mut peers = HashMap::new();
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    peers.insert(peer_ip, Peer {
        sock_addr: "192.168.1.2:5000".parse().unwrap(),
        pub_key: "TESTKEY123456789ABCDEF==".to_string(),
    });

    let config = Config {
        name: "test_interface".to_string(),
        address: "10.0.0.1".to_string(),
        port: 8080,
        secret: "SECRET_KEY_BASE64==".to_string(),
        pubkey: "PUBLIC_KEY_BASE64==".to_string(),
        peers,
    };

    // Serialize to YAML
    let yaml_str = serde_yaml::to_string(&config).expect("Failed to serialize to YAML");
    assert!(yaml_str.contains("test_interface"));
    assert!(yaml_str.contains("10.0.0.1"));
    assert!(yaml_str.contains("8080"));

    // Deserialize from YAML
    let deserialized: Config = serde_yaml::from_str(&yaml_str).expect("Failed to deserialize from YAML");
    
    assert_eq!(deserialized.name, config.name);
    assert_eq!(deserialized.address, config.address);
    assert_eq!(deserialized.port, config.port);
    assert_eq!(deserialized.secret, config.secret);
    assert_eq!(deserialized.pubkey, config.pubkey);
    assert_eq!(deserialized.peers.len(), 1);
    assert_eq!(deserialized.peers.get(&peer_ip).unwrap().sock_addr, config.peers.get(&peer_ip).unwrap().sock_addr);
}

/// Tests loading a config file with valid YAML content.
///
/// Ensures that the load_config function correctly parses a well-formed
/// YAML configuration file using serde_yaml.
#[test]
fn test_load_config_valid_yaml() {
    let config_content = r#"
name: vpn_interface
address: 172.16.0.1
port: 9999
secret: "dGVzdHNlY3JldGtleTE2Yml0cw=="
pubkey: "dGVzdHB1YmxpY2tleTE2Yml0cw=="
peers:
  172.16.0.2:
    sock_addr: "203.0.113.5:9999"
    pub_key: "cGVlcnB1YmxpY2tleTE2Yml0cw=="
  172.16.0.3:
    sock_addr: "203.0.113.6:9999"
    pub_key: "YW5vdGhlcnB1YmtleTEyMzQ1Ng=="
"#;

    let path = format!("test_valid_yaml_{}.yaml", std::process::id());
    std::fs::write(&path, config_content).expect("Failed to write test config");

    let config = opentun::config::load_config(&path);

    std::fs::remove_file(path).ok();

    assert_eq!(config.name, "vpn_interface");
    assert_eq!(config.address, "172.16.0.1");
    assert_eq!(config.port, 9999);
    assert_eq!(config.peers.len(), 2);

    let peer_ip1: IpAddr = "172.16.0.2".parse().unwrap();
    let peer_ip2: IpAddr = "172.16.0.3".parse().unwrap();
    assert!(config.peers.contains_key(&peer_ip1));
    assert!(config.peers.contains_key(&peer_ip2));
}

/// Tests load_config with missing file creates default config.
///
/// Verifies that when no config file exists, load_config generates a
/// default configuration and writes it to disk using serde_yaml.
#[test]
fn test_load_config_creates_default() {
    let path = format!("test_nonexistent_{}.yaml", std::process::id());
    
    // Ensure file doesn't exist
    std::fs::remove_file(&path).ok();

    let config = opentun::config::load_config(&path);

    // Verify default values
    assert_eq!(config.name, "utun0");
    assert_eq!(config.address, "10.0.0.1");
    assert_eq!(config.port, 1194);
    assert_eq!(config.peers.len(), 0);
    assert!(!config.secret.is_empty());
    assert!(!config.pubkey.is_empty());

    // Verify file was created
    assert!(std::path::Path::new(&path).exists());

    // Verify the created file can be loaded again
    let reloaded = opentun::config::load_config(&path);
    assert_eq!(reloaded.name, config.name);
    assert_eq!(reloaded.secret, config.secret);
    assert_eq!(reloaded.pubkey, config.pubkey);

    std::fs::remove_file(path).ok();
}

/// Tests YAML deserialization with edge case: empty peers map.
///
/// Ensures that a configuration with no peers is handled correctly.
#[test]
fn test_yaml_empty_peers() {
    let config_content = r#"
name: solo_node
address: 192.168.100.1
port: 7777
secret: "ZW1wdHlwZWVyc3Rlc3RrZXk="
pubkey: "ZW1wdHlwZWVyc3B1YmtleQ=="
peers: {}
"#;

    let config: Config = serde_yaml::from_str(config_content).expect("Failed to parse YAML");
    
    assert_eq!(config.name, "solo_node");
    assert_eq!(config.peers.len(), 0);
    assert!(config.peers.is_empty());
}

/// Tests YAML deserialization with multiple peers of various formats.
///
/// Validates that complex peer configurations with different IP addresses
/// and socket addresses are correctly parsed.
#[test]
fn test_yaml_multiple_peers_various_formats() {
    let config_content = r#"
name: multi_peer_node
address: 10.5.5.1
port: 6000
secret: "bXVsdGlwZWVyc2VjcmV0a2V5"
pubkey: "bXVsdGlwZWVycHVia2V5MTIz"
peers:
  10.5.5.2:
    sock_addr: "1.2.3.4:6000"
    pub_key: "cGVlcjFwdWJrZXk="
  10.5.5.3:
    sock_addr: "5.6.7.8:6001"
    pub_key: "cGVlcjJwdWJrZXk="
  10.5.5.100:
    sock_addr: "203.0.113.99:6000"
    pub_key: "cGVlcjNwdWJrZXk="
"#;

    let config: Config = serde_yaml::from_str(config_content).expect("Failed to parse YAML");
    
    assert_eq!(config.peers.len(), 3);
    
    let peer1: IpAddr = "10.5.5.2".parse().unwrap();
    let peer2: IpAddr = "10.5.5.3".parse().unwrap();
    let peer3: IpAddr = "10.5.5.100".parse().unwrap();
    
    assert!(config.peers.contains_key(&peer1));
    assert!(config.peers.contains_key(&peer2));
    assert!(config.peers.contains_key(&peer3));
    
    assert_eq!(config.peers.get(&peer2).unwrap().sock_addr.port(), 6001);
}

/// Tests YAML deserialization error handling with malformed YAML.
///
/// Verifies that serde_yaml properly returns an error when given
/// syntactically invalid YAML content.
#[test]
fn test_yaml_malformed_syntax() {
    let malformed_yaml = r#"
name: broken
address: 10.0.0.1
port: this_should_be_a_number
secret: "test"
pubkey: "test"
peers: {}
"#;

    let result: Result<Config, serde_yaml::Error> = serde_yaml::from_str(malformed_yaml);
    assert!(result.is_err(), "Should fail to parse malformed YAML");
}

/// Tests YAML deserialization with missing required fields.
///
/// Ensures that serde_yaml returns an error when required fields
/// are missing from the configuration.
#[test]
fn test_yaml_missing_required_fields() {
    let incomplete_yaml = r#"
name: incomplete
address: 10.0.0.1
"#;

    let result: Result<Config, serde_yaml::Error> = serde_yaml::from_str(incomplete_yaml);
    assert!(result.is_err(), "Should fail when required fields are missing");
}

/// Tests YAML serialization produces valid YAML structure.
///
/// Verifies that the serialized YAML output has the expected structure
/// and can be parsed by standard YAML parsers.
#[test]
fn test_yaml_serialization_structure() {
    let config = Config {
        name: "structured_test".to_string(),
        address: "10.10.10.1".to_string(),
        port: 5555,
        secret: "c2VjcmV0MTIzNDU2".to_string(),
        pubkey: "cHVia2V5MTIzNDU2".to_string(),
        peers: HashMap::new(),
    };

    let yaml_output = serde_yaml::to_string(&config).expect("Serialization should succeed");
    
    // Verify YAML structure
    assert!(yaml_output.contains("name:"));
    assert!(yaml_output.contains("address:"));
    assert!(yaml_output.contains("port:"));
    assert!(yaml_output.contains("secret:"));
    assert!(yaml_output.contains("pubkey:"));
    assert!(yaml_output.contains("peers:"));
    
    // Verify it can be deserialized again
    let reparsed: Config = serde_yaml::from_str(&yaml_output).expect("Should parse serialized YAML");
    assert_eq!(reparsed.name, config.name);
    assert_eq!(reparsed.port, config.port);
}

/// Tests IpouError::SerdeYaml variant can be created from serde_yaml::Error.
///
/// Validates that the error conversion from serde_yaml::Error to
/// IpouError::SerdeYaml works correctly via the From trait.
#[test]
fn test_serde_yaml_error_conversion() {
    let invalid_yaml = "{ invalid yaml content ][";
    
    let parse_result: Result<Config, serde_yaml::Error> = serde_yaml::from_str(invalid_yaml);
    assert!(parse_result.is_err());
    
    if let Err(yaml_error) = parse_result {
        let ipou_error: opentun::IpouError = yaml_error.into();
        
        // Verify it's the correct error variant
        match ipou_error {
            opentun::IpouError::SerdeYaml(_) => {
                // Success - correct variant
            }
            _ => panic!("Expected SerdeYaml error variant"),
        }
        
        // Verify error message contains useful information
        let error_message = ipou_error.to_string();
        assert!(error_message.contains("YAML parsing error"));
    }
}

/// Tests error display formatting for IpouError::SerdeYaml.
///
/// Ensures that the error message is properly formatted and
/// contains the underlying serde_yaml error details.
#[test]
fn test_serde_yaml_error_display() {
    let invalid_yaml = r#"
name: test
port: "not_a_number"
address: 10.0.0.1
secret: "test"
pubkey: "test"
peers: {}
"#;
    
    let result: Result<Config, serde_yaml::Error> = serde_yaml::from_str(invalid_yaml);
    
    if let Err(e) = result {
        let ipou_error: opentun::IpouError = e.into();
        let error_string = format!("{}", ipou_error);
        
        assert!(error_string.contains("YAML parsing error"));
        // The error should propagate the underlying serde_yaml error information
    }
}

/// Tests YAML roundtrip with special characters in string fields.
///
/// Verifies that special characters, quotes, and other edge cases
/// in string fields are properly escaped and preserved through
/// serialization and deserialization.
#[test]
fn test_yaml_special_characters_roundtrip() {
    let config = Config {
        name: "test-interface_123".to_string(),
        address: "10.0.0.1".to_string(),
        port: 3000,
        secret: "c2VjcmV0K3dpdGgrc3BlY2lhbCtjaGFycw==".to_string(),
        pubkey: "cHVia2V5L3dpdGgvc2xhc2hlcw==".to_string(),
        peers: HashMap::new(),
    };

    let yaml_str = serde_yaml::to_string(&config).expect("Serialization failed");
    let deserialized: Config = serde_yaml::from_str(&yaml_str).expect("Deserialization failed");

    assert_eq!(deserialized.name, config.name);
    assert_eq!(deserialized.secret, config.secret);
    assert_eq!(deserialized.pubkey, config.pubkey);
}

/// Tests YAML parsing with whitespace variations.
///
/// Ensures that different whitespace patterns (spaces, tabs, newlines)
/// don't affect the parsing of configuration files.
#[test]
fn test_yaml_whitespace_tolerance() {
    let config_with_extra_whitespace = r#"

name:    whitespace_test   

address:   10.0.0.1
port:     8080  
secret:   "dGVzdA=="
pubkey:   "dGVzdA=="

peers:   {}

"#;

    let config: Config = serde_yaml::from_str(config_with_extra_whitespace)
        .expect("Should handle extra whitespace");
    
    assert_eq!(config.name.trim(), "whitespace_test");
    assert_eq!(config.port, 8080);
}

/// Tests YAML serialization of config with large peer list.
///
/// Validates that configurations with many peers can be serialized
/// and deserialized without data loss or performance issues.
#[test]
fn test_yaml_large_peer_list() {
    let mut peers = HashMap::new();
    
    // Add 50 peers
    for i in 2..52 {
        let peer_ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
        peers.insert(peer_ip, Peer {
            sock_addr: format!("203.0.113.{}:5000", i).parse().unwrap(),
            pub_key: format!("cGVlcmtleXt9e30=", i),
        });
    }

    let config = Config {
        name: "large_config".to_string(),
        address: "10.0.0.1".to_string(),
        port: 5000,
        secret: "bGFyZ2VzZWNyZXQ=".to_string(),
        pubkey: "bGFyZ2VwdWJrZXk=".to_string(),
        peers,
    };

    let yaml_str = serde_yaml::to_string(&config).expect("Serialization should succeed");
    let deserialized: Config = serde_yaml::from_str(&yaml_str).expect("Deserialization should succeed");

    assert_eq!(deserialized.peers.len(), 50);
    assert_eq!(deserialized.name, config.name);
}

/// Tests YAML parsing with boundary port values.
///
/// Verifies that edge case port numbers (minimum, maximum, common values)
/// are correctly parsed and validated.
#[test]
fn test_yaml_port_boundary_values() {
    // Test maximum valid port
    let config_max_port = r#"
name: max_port_test
address: 10.0.0.1
port: 65535
secret: "dGVzdA=="
pubkey: "dGVzdA=="
peers: {}
"#;

    let config: Config = serde_yaml::from_str(config_max_port).expect("Should parse max port");
    assert_eq!(config.port, 65535);

    // Test minimum valid port (1)
    let config_min_port = r#"
name: min_port_test
address: 10.0.0.1
port: 1
secret: "dGVzdA=="
pubkey: "dGVzdA=="
peers: {}
"#;

    let config: Config = serde_yaml::from_str(config_min_port).expect("Should parse min port");
    assert_eq!(config.port, 1);
}

/// Tests that Config struct properly implements Clone and PartialEq.
///
/// Validates the derived traits work correctly for configuration comparison.
#[test]
fn test_config_clone_and_equality() {
    let mut peers = HashMap::new();
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    peers.insert(peer_ip, Peer {
        sock_addr: "192.168.1.5:5000".parse().unwrap(),
        pub_key: "dGVzdGtleQ==".to_string(),
    });

    let config1 = Config {
        name: "clone_test".to_string(),
        address: "10.0.0.1".to_string(),
        port: 7000,
        secret: "c2VjcmV0".to_string(),
        pubkey: "cHVia2V5".to_string(),
        peers: peers.clone(),
    };

    let config2 = config1.clone();
    
    assert_eq!(config1, config2);
    assert_eq!(config1.name, config2.name);
    assert_eq!(config1.peers.len(), config2.peers.len());
}

/// Tests Peer struct serialization and deserialization.
///
/// Validates that individual Peer objects can be serialized to YAML
/// and deserialized correctly.
#[test]
fn test_peer_serialization() {
    let peer = Peer {
        sock_addr: "198.51.100.42:9000".parse().unwrap(),
        pub_key: "cGVlcnB1YmxpY2tleQ==".to_string(),
    };

    let yaml_str = serde_yaml::to_string(&peer).expect("Failed to serialize Peer");
    assert!(yaml_str.contains("sock_addr"));
    assert!(yaml_str.contains("pub_key"));

    let deserialized: Peer = serde_yaml::from_str(&yaml_str).expect("Failed to deserialize Peer");
    assert_eq!(deserialized.sock_addr, peer.sock_addr);
    assert_eq!(deserialized.pub_key, peer.pub_key);
}

/// Tests load_config handles file write permissions gracefully.
///
/// Verifies behavior when attempting to create a default config file
/// in various scenarios (though actual permission testing is limited
/// in the test environment).
#[test]
fn test_load_config_file_operations() {
    let temp_path = format!("test_file_ops_{}.yaml", std::process::id());
    
    // Remove if exists
    std::fs::remove_file(&temp_path).ok();
    
    // Load config - should create default
    let config1 = opentun::config::load_config(&temp_path);
    assert!(std::path::Path::new(&temp_path).exists());
    
    // Load again - should read existing file
    let config2 = opentun::config::load_config(&temp_path);
    
    // Both should have the same keys (deterministic generation from same file)
    assert_eq!(config1.secret, config2.secret);
    assert_eq!(config1.pubkey, config2.pubkey);
    
    std::fs::remove_file(&temp_path).ok();
}

/// Tests YAML deserialization with IPv4 addresses in various formats.
///
/// Ensures that different valid IPv4 address representations are
/// correctly parsed in both the address and peer configuration fields.
#[test]
fn test_yaml_ipv4_address_formats() {
    let config_content = r#"
name: ipv4_test
address: 192.168.1.1
port: 4000
secret: "aXB2NHRlc3Q="
pubkey: "aXB2NHRlc3Q="
peers:
  0.0.0.0:
    sock_addr: "0.0.0.0:4000"
    pub_key: "emVybw=="
  255.255.255.255:
    sock_addr: "255.255.255.255:4000"
    pub_key: "bWF4"
"#;

    let config: Config = serde_yaml::from_str(config_content).expect("Should parse IPv4 addresses");
    
    assert_eq!(config.address, "192.168.1.1");
    assert_eq!(config.peers.len(), 2);
    
    let zero_ip: IpAddr = "0.0.0.0".parse().unwrap();
    let max_ip: IpAddr = "255.255.255.255".parse().unwrap();
    
    assert!(config.peers.contains_key(&zero_ip));
    assert!(config.peers.contains_key(&max_ip));
}
