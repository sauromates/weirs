use std::{net::IpAddr, time::Instant};

pub mod fortinet;

pub trait Protocol {}

pub trait Session {
    fn is_alive(&self) -> bool;
}

pub struct Connection {
    pub server: IpAddr,
    pub tunnel: IpAddr,
    pub created_at: Instant,
    pub updated_at: Instant,
}
