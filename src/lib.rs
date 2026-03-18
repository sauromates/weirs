use crate::{
    config::{Config, Protocol as ProtocolKind},
    driver::Driver,
    proto::fortinet::{FortinetConfig, driver::FortinetDriver},
};
use std::error::Error;
use std::net::IpAddr;
use tokio::net::lookup_host;
use url::Url;

pub mod auth;
pub mod cli;
pub mod config;
pub mod conn;
pub mod driver;
pub mod proto;
pub mod tunnel;

pub struct DriverFactory {
    config: Config,
}

impl DriverFactory {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn build(&self) -> Result<Box<dyn Driver>, Box<dyn std::error::Error>> {
        match self.config.protocol.as_ref().ok_or("unknown protocol")? {
            ProtocolKind::Fortinet => {
                let config = FortinetConfig::try_from(self.config.clone())?;
                Ok(Box::new(FortinetDriver { config }))
            }
        }
    }
}

/// A helper struct representing external host.
///
/// A `Host` without `ip` should be considered unresolved.
#[derive(Clone)]
pub struct Host {
    pub url: Url,
    ip: Option<IpAddr>,
}

impl Host {
    /// Parses a string into a Host.
    ///
    /// - NOTE: this function doesn't try to resolve the host.
    /// - NOTE: a hostname without scheme would default to `https`.
    pub fn parse(hostname: &str) -> Result<Self, Box<dyn Error>> {
        let normalized = if hostname.starts_with("http://") || hostname.starts_with("https://") {
            hostname.to_string()
        } else {
            format!("https://{}", hostname)
        };

        Ok(Self {
            url: Url::parse(&normalized)?,
            ip: None,
        })
    }

    /// Plain getter for Host's IP.
    ///
    /// The `ip` field is not public and available only through getter
    /// to ensure that Host can't have unrelated `url` and `ip`.
    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    /// Resolves Host's name into an IP via `tokio::lookup_host`.
    ///
    /// Resolving also modifies Host to keep the result and avoid consecutive
    /// DNS lookups.
    pub async fn resolve(&mut self) -> Result<IpAddr, Box<dyn Error>> {
        // Avoid extra lookups when IP is already resolved
        if let Some(ip) = self.ip {
            return Ok(ip);
        }

        let host = self.url.host_str().ok_or("missing host")?;
        let port = self.url.port().unwrap_or_else(|| {
            if self.url.scheme() == "https" {
                443
            } else {
                80
            }
        });

        let ip = lookup_host(format!("{}:{}", host, port))
            .await?
            .next()
            .ok_or(format!("could not resolve host {}:{}", host, port))?
            .ip();

        self.ip = Some(ip);
        Ok(ip)
    }

    pub fn base_url(&self) -> &str {
        self.url.as_str()
    }
}
