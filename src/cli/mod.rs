pub mod commands;
use clap::{Parser, Subcommand};

// CLI
#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Optional name to operate on
    #[arg(long)]
    pub peer: bool,

    #[arg(long)]
    pub relay: bool,

    #[arg(long)]
    pub coord: bool,

    #[arg(long)]
    pub relay_listen: Option<String>,

    #[arg(long)]
    pub coord_listen: Option<String>,

    #[arg(long)]
    pub relay_url: Option<String>,

    #[arg(long)]
    pub coord_url: Option<String>,

    pub name: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    // generate private key
    Genkey {},
    Pubkey {},
}
