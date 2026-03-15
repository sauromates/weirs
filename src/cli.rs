use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::Protocol;

#[derive(Parser)]
#[command(name = "weirs", about = "A minimalist VPN client")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Up(UpArgs),
    Down,
}

#[derive(Parser, Debug)]
pub struct UpArgs {
    #[arg(short, long)]
    pub protocol: Option<Protocol>,

    #[arg(short, long)]
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
