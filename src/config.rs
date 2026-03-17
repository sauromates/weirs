//! # Config

use crate::cli::UpArgs;
use clap::ValueEnum;
use serde::Deserialize;
use std::path::PathBuf;

const DEFAULT_SAML_PORT: u16 = 8020;

/// List of available protocols.
#[derive(Clone, Debug, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Fortinet,
}

/// Flat structure holding all available app configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub protocol: Option<Protocol>,
    pub host: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub saml_port: Option<u16>,
    pub ignore_certs: Option<bool>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
}

impl Config {
    pub fn from_file(path: &PathBuf) -> Result<Self, ConfigError> {
        let config = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;

        toml::from_str(&config).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    pub fn from_args(args: UpArgs) -> Result<Self, ConfigError> {
        let base = args.config.as_ref().map(Config::from_file).transpose()?;
        Ok(Config::merge(base, args))
    }

    pub fn merge(base: Option<Self>, args: UpArgs) -> Self {
        let saml_port = args
            .saml_login
            .map(|port| port.unwrap_or(DEFAULT_SAML_PORT))
            .or(base.as_ref().and_then(|b| b.saml_port));

        Self {
            protocol: args
                .protocol
                .or(base.as_ref().and_then(|b| b.protocol.clone())),
            host: args.host.or(base.as_ref().and_then(|b| b.host.clone())),
            username: args
                .username
                .or(base.as_ref().and_then(|b| b.username.clone())),
            password: args
                .password
                .or(base.as_ref().and_then(|b| b.password.clone())),
            saml_port,
            ignore_certs: Some(
                args.ignore_cert || base.and_then(|b| b.ignore_certs).unwrap_or(false),
            ),
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "error reading config: {}", e),
            ConfigError::Parse(e) => write!(f, "error parsing config: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}
