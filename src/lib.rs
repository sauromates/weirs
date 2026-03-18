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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::host_without_scheme("google.com", "https://google.com/")]
    #[case::host_and_port_without_scheme("google.com:10443", "https://google.com:10443/")]
    #[case::https_host("https://google.com", "https://google.com/")]
    #[case::https_host_and_port("https://google.com:10443", "https://google.com:10443/")]
    #[case::http_host("http://google.com", "http://google.com/")]
    #[case::http_host_and_port("http://google.com:8080", "http://google.com:8080/")]
    fn can_parse_string_into_host(#[case] input: &str, #[case] expected: &str) {
        let host = Host::parse(input).unwrap();
        assert_eq!(host.url.as_str(), expected);
    }

    #[rstest]
    #[tokio::test]
    #[case::valid_host("google.com", true)]
    #[case::invalid_host("invalid.invalid", false)]
    async fn host_can_resolve_ip(#[case] host: &str, #[case] should_resolve: bool) {
        let mut host = Host::parse(host).unwrap();
        let result = host.resolve().await;

        if should_resolve {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn host_caches_resolved_ip() {
        let mock_ip = IpAddr::from([1, 2, 3, 4]); // Definitely not Google IP
        let mut host = Host {
            url: Url::parse("https://google.com").unwrap(),
            ip: Some(mock_ip),
        };

        let resolved = host.resolve().await.unwrap();

        // If we receive mock IP then no DNS lookup was performed
        assert_eq!(resolved, mock_ip);
    }
}
