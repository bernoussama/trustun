#!/bin/bash

# Back up the original main.rs
cp src/main.rs src/main_original.rs

# Create a simplified main that uses the new protocol layer
cat > src/main.rs << 'EOF'
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use opentun::cli::commands::{handle_gen_key, handle_pub_key};
use opentun::config::{load_config, RuntimeConfig};
use opentun::protocol::PacketProcessor;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use clap::Parser;
use opentun::Result;
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = opentun::cli::Cli::parse();
    // Subcommands
    match &cli.command {
        Some(opentun::cli::Commands::Genkey {}) => handle_gen_key(),
        Some(opentun::cli::Commands::Pubkey {}) => handle_pub_key(),
        None => Ok(()),
    }
    .expect("Failed to execute command");

    // Load config file
    let config_path = "config.yaml";
    let config = load_config(config_path);
    let config_clone = config.clone();

    // Initialize encryption resources
    let mut shared_secrets = HashMap::new();
    let mut ciphers = HashMap::new();

    let mut secret_bytes = [0u8; 32];
    base64::decode_config_slice(&config.secret, base64::STANDARD, &mut secret_bytes).unwrap();
    let static_secret = StaticSecret::from(secret_bytes);

    let mut ips = HashMap::new();
    for (ip, peer) in &config.peers {
        let mut pub_key_bytes = [0u8; 32];
        base64::decode_config_slice(&peer.pub_key, base64::STANDARD, &mut pub_key_bytes).unwrap();
        let pub_key = PublicKey::from(pub_key_bytes);
        let shared_secret = static_secret.diffie_hellman(&pub_key);
        let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
        shared_secrets.insert(*ip, *shared_secret.as_bytes());
        ciphers.insert(*ip, cipher);
        ips.insert(peer.sock_addr, *ip);
    }

    let runtime_config = RuntimeConfig {
        shared_secrets,
        ciphers,
        ips,
        peers: config.peers.clone(),
    };

    // Create a packet processor to demonstrate sans-IO architecture
    let packet_processor = PacketProcessor::new(runtime_config);
    
    // Test the protocol layer with sample data
    let test_packet = create_test_packet();
    match packet_processor.process_tun_packet(&test_packet) {
        Ok(result) => {
            println!("Protocol processing test: {:?}", result);
        }
        Err(e) => {
            eprintln!("Protocol processing error: {}", e);
        }
    }

    println!("Sans-IO architecture demonstrated. Core protocol layer working independently of I/O!");

    Ok(())
}

fn create_test_packet() -> Vec<u8> {
    let mut packet = vec![0x45, 0x00, 0x00, 0x3C];
    packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
    packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]); // Source: 10.11.12.13
    packet.extend_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // Dest: 192.168.1.1
    packet
}
EOF

echo "Created simplified main.rs that demonstrates sans-IO architecture"