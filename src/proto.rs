//! # Proto
//!
//! Declares shared contracts and common features for any
//! VPN protocol implementation (i.e. Fortinet, WireGuard, etc).

use std::{net::IpAddr, time::Instant};

pub mod fortinet;

pub trait Protocol {}

/// Defines behavior of Connections.
pub trait Session {
    fn is_alive(&self) -> bool;
}

/// Represents VPN connection state and metadata.
pub struct Connection {
    pub server: IpAddr,
    pub tunnel: IpAddr,
    pub created_at: Instant,
    pub updated_at: Instant,
}
