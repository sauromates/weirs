use std::path::PathBuf;

use clap::ValueEnum;
use serde::Deserialize;

use crate::cli::UpArgs;

#[derive(Clone, Debug, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Fortinet,
}

#[derive(Debug, Deserialize)]
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

    pub fn merge(base: Option<Self>, args: UpArgs) -> Self {
        let saml_port = args
            .saml_login
            .map(|port| port.unwrap_or(8020))
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
