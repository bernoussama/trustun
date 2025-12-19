use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use opentun::cli::commands::{handle_gen_key, handle_pub_key};
use opentun::config::{load_config, RuntimeConfig};
use opentun::io::adapters::{TunAdapter, UdpAdapter};
use opentun::protocol::PacketProcessor;
use opentun::runtime::tokio::{LoggingEventHandler, TaskSpawner};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

    // Create I/O devices
    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&config_clone.name)
        .address(config_clone.address.parse::<Ipv4Addr>().unwrap())
        .netmask((255, 255, 255, 0))
        .mtu(opentun::MTU as u16)
        .up();

    let tun_device = tun::create_as_async(&tun_config)
        .expect("Failed to create TUN device");
    let udp_socket = UdpSocket::bind(format!("0.0.0.0:{}", config_clone.port))
        .await
        .expect("Failed to bind UDP socket");

    println!(
        "UDP socket bound to: {}",
        udp_socket.local_addr().expect("Failed to get local address")
    );

    // Create sans-IO components
    let tun_adapter = Arc::new(TunAdapter::new(tun_device));
    let udp_adapter = Arc::new(UdpAdapter::new(udp_socket));
    let packet_processor = PacketProcessor::new(runtime_config);
    let event_handler = Arc::new(LoggingEventHandler::new());

    // Create task spawner
    let task_spawner = TaskSpawner::new();
    let coordinator_arc = Arc::new(opentun::runtime::tokio::RuntimeCoordinator {
        tun_device: tun_adapter.clone(),
        udp_socket: udp_adapter.clone(),
        packet_processor,
        event_handler: event_handler.clone(),
        tun_rx: tokio::sync::mpsc::channel::<opentun::DecryptedPacket>(opentun::CHANNEL_BUFFER_SIZE).1,
        udp_rx: tokio::sync::mpsc::channel::<opentun::EncryptedPacket>(opentun::CHANNEL_BUFFER_SIZE).1,
        tun_tx: tokio::sync::mpsc::channel::<opentun::DecryptedPacket>(opentun::CHANNEL_BUFFER_SIZE).0,
        udp_tx: tokio::sync::mpsc::channel::<opentun::EncryptedPacket>(opentun::CHANNEL_BUFFER_SIZE).0,
        running: true,
    });

    // Spawn async tasks using the new architecture
    let tun_listener = task_spawner.spawn_tun_listener(
        tun_adapter.as_ref().as_ref().clone(),
        coordinator_arc.clone(),
    );

    let udp_listener = task_spawner.spawn_udp_listener(
        udp_adapter.as_ref().as_ref().clone(),
        coordinator_arc.clone(),
    );

    let coordinator_task = tokio::spawn(async move {
        let mut coordinator = coordinator_arc.clone();
        coordinator.run().await
    });

    // Run all tasks concurrently
    tokio::try_join!(tun_listener, udp_listener, coordinator_task)
        .map(|_| ())
        .expect("Error joining tasks");

    Ok(())
}