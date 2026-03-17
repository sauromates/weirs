use async_trait::async_trait;
use std::{error::Error, net::IpAddr};

/// A contract for objects responsible for managing protocol-specific connections.
#[async_trait]
pub trait Driver {
    /// Authenticates against VPN server. The result is some authentication token
    /// retrieved in the end of this process (i.e. token, key, cookie).
    async fn authenticate(&self) -> Result<String, Box<dyn Error>>;

    /// Establishes network connection. Typically this means configuring a local
    /// tunnel interface. Returns an address of the interface.
    async fn connect(&self) -> Result<IpAddr, Box<dyn Error>>;

    /// Verifies network connectivity.
    async fn ping(&self) -> Result<(), Box<dyn Error>>;
}
