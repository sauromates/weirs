//! # Proto
//!
//! Declares shared contracts and common features for any
//! VPN protocol implementation (i.e. Fortinet, WireGuard, etc).

pub mod fortinet;

pub trait Protocol {}
