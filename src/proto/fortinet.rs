//! # Fortinet
//!
//! A parent module to all fortinet-specific implementations.

pub mod auth;

use crate::{
    auth::{AuthError, ClientErrorKind},
    config::Config,
};

use super::Protocol;

pub struct FortinetProtocol;

impl Protocol for FortinetProtocol {}

pub struct FortinetConfig {
    pub host: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub saml_port: Option<u16>,
    pub ignore_cert: bool,
}

impl TryFrom<Config> for FortinetConfig {
    type Error = AuthError;

    fn try_from(config: Config) -> Result<Self, Self::Error> {
        let host = config
            .host
            .ok_or(AuthError::Client(ClientErrorKind::Generic(
                "host is required".into(),
            )))?;

        let password = match (&config.username, config.password) {
            (Some(_), None) => return Err(AuthError::Client(ClientErrorKind::MissingSecret)),
            (_, password) => password,
        };

        Ok(Self {
            host,
            username: config.username,
            password,
            saml_port: config.saml_port,
            ignore_cert: config.ignore_certs.unwrap_or(false),
        })
    }
}
