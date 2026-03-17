//! # Fortinet
//!
//! A parent module to all fortinet-specific implementations.

use super::Protocol;
use crate::{
    Host,
    auth::{AuthError, ClientErrorKind},
    config::Config,
};

pub mod auth;
pub mod driver;

pub struct FortinetProtocol;

impl Protocol for FortinetProtocol {}

pub struct FortinetConfig {
    pub host: Host,
    pub username: Option<String>,
    pub password: Option<String>,
    pub saml_port: Option<u16>,
    pub ignore_cert: bool,
}

impl TryFrom<Config> for FortinetConfig {
    type Error = AuthError;

    fn try_from(config: Config) -> Result<Self, Self::Error> {
        // TODO: replace AuthError-s with config-specific error type
        let host = config
            .host
            .ok_or(AuthError::Client(ClientErrorKind::Generic(
                "host is required".into(),
            )))
            .and_then(|h| {
                Host::parse(&h)
                    .map_err(|e| AuthError::Client(ClientErrorKind::Generic(e.to_string())))
            })?;

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
