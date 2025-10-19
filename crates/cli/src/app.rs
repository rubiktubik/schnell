use clap::{Parser, Subcommand};

use crate::commands;

#[derive(Parser, Debug)]
#[command(name = "schnell", author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// App Store Connect API commands
    Ios(commands::ios::IosCommands),
}

pub async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Ios(command) => commands::ios::run(command).await,
    }
}
