use std::sync::Arc;

use clap::Parser;
use opentun::Result;
use opentun::cli::commands::{handle_gen_key, handle_pub_key};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = opentun::cli::Cli::parse();
    match &cli.command {
        Some(opentun::cli::Commands::Genkey {}) => return handle_gen_key(),
        Some(opentun::cli::Commands::Pubkey {}) => return handle_pub_key(),
        None => {}
    }

    let config = opentun::config::load_config("config.yaml").merged_with_cli(&cli);
    let roles = config.resolve_roles(&cli)?;
    config.validate_runtime(roles)?;

    let config = Arc::new(config);
    let mut tasks = JoinSet::new();

    if roles.peer {
        let config = Arc::clone(&config);
        tasks.spawn(async move { opentun::tasks::run_peer(config).await });
    }
    if roles.relay {
        let listen_addr = config.relay_listen_addr.clone().unwrap();
        tasks.spawn(async move { opentun::tasks::run_relay_server(&listen_addr).await });
    }
    if roles.coord {
        let listen_addr = config.coord_listen_addr.clone().unwrap();
        let auth_token = config.coord_auth_token.clone();
        tasks.spawn(async move { opentun::tasks::run_coord_server(&listen_addr, auth_token).await });
    }

    while let Some(result) = tasks.join_next().await {
        result??;
    }

    Ok(())
}
