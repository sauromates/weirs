use crate::config::Protocol;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "weirs", about = "A minimalist VPN client")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Up(UpArgs),
    Down,
}

#[derive(Parser, Debug)]
pub struct UpArgs {
    #[arg(long)]
    pub protocol: Option<Protocol>,

    #[arg(long)]
    pub host: Option<String>,

    #[arg(short, long)]
    pub username: Option<String>,

    #[arg(short, long)]
    pub password: Option<String>,

    #[arg(long, value_name = "PORT")]
    pub saml_login: Option<Option<u16>>,

    #[arg(long)]
    pub ignore_cert: bool,

    #[arg(short, long)]
    pub config: Option<PathBuf>,
}
