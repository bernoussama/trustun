use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use opentun::cli::commands::{handle_gen_key, handle_pub_key};
use opentun::config::RuntimeConfig;
use std::sync::Arc;
use std::{collections::HashMap, net::Ipv4Addr};

use clap::Parser;
use opentun::Result;
use opentun::tasks;
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
    let conf = opentun::config::load_config(config_path);
    let config = Arc::new(conf);

    let config_clone = Arc::clone(&config);
    // Initialize once after config load
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

    let runtime_config = Arc::new(RuntimeConfig {
        shared_secrets,
        ciphers,
        ips,
    });

    let runtime_config_clone = Arc::clone(&runtime_config);

    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&config_clone.name)
        .address(config_clone.address.parse::<Ipv4Addr>().unwrap())
        .netmask((255, 255, 255, 0))
        .mtu(opentun::MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config).expect("Failed to create TUN device");
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", Arc::clone(&config).port))
        .await
        .expect("Failed to bind UDP socket");
    println!(
        "UDP socket bound to: {}",
        sock.local_addr().expect("Failed to get local address")
    );
    let dev_arc = Arc::new(dev);
    let sock_arc = Arc::new(sock);

    let tun_worker = tokio::spawn(tasks::tun_worker(
        Arc::clone(&dev_arc),
        Arc::clone(&sock_arc),
        config_clone,
        runtime_config,
    ));
    let udp_worker = tokio::spawn(tasks::udp_worker(
        Arc::clone(&sock_arc),
        Arc::clone(&dev_arc),
        runtime_config_clone,
    ));

    tokio::try_join!(tun_worker, udp_worker)
        .map(|_| ())
        .expect("Error joining tasks");

    Ok(())
}
