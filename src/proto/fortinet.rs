//! # Fortinet
//!
//! A parent module to all fortinet-specific implementations.

pub mod auth;

use super::Protocol;

pub struct FortinetProtocol;

impl Protocol for FortinetProtocol {}
