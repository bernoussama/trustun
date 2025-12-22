use clap::Parser;
use opentun::Result;
use opentun::cli::commands::{handle_gen_key, handle_pub_key};

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

    println!("trustun protocol core ready");
    Ok(())
}
