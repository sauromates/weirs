use crate::{Host, config::Config, driver::Driver};
use std::{error::Error, net::IpAddr};
use tokio::sync::mpsc::Sender;

pub struct Connection {
    state: State,
    config: Config,
    driver: Box<dyn Driver>,
    pub tunnel: Option<IpAddr>,
    pub session: Option<Session>,
}

#[derive(Clone, Debug)]
pub enum State {
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    Invalid(String),
}

pub struct Session {
    pub token: String,
}

#[derive(Debug)]
pub struct TransitionError {
    pub from: State,
    pub to: State,
}

impl Connection {
    pub fn new(config: Config, driver: Box<dyn Driver>) -> Self {
        Self {
            state: State::Disconnected,
            config,
            driver,
            tunnel: None,
            session: None,
        }
    }

    /// Tries to open VPN connection.
    pub async fn up(&mut self, tx: Sender<State>) -> Result<(), TransitionError> {
        self.transition(State::Connecting, &tx).await?;

        if let Err(e) = self.open().await {
            self.transition(State::Invalid(e.to_string()), &tx)
                .await
                .ok();

            return Ok(());
        }

        self.transition(State::Connected, &tx).await?;

        Ok(())
    }

    /// Disconnects from VPN.
    pub async fn down(&mut self, tx: Sender<State>) -> Result<(), TransitionError> {
        self.transition(State::Disconnecting, &tx).await?;

        // TODO: do some driver-specific clean up

        self.transition(State::Disconnected, &tx).await?;

        Ok(())
    }

    /// Orchestrates connection steps of the concrete driver.
    async fn open(&mut self) -> Result<(), Box<dyn Error>> {
        // The first step is to ensure we can even connect to host
        if let Err(e) = self.resolve_host().await {
            return Err(e);
        }

        let token = self.driver.authenticate().await?;
        self.session = Some(Session { token });

        let tunnel = self.driver.connect().await?;
        self.tunnel = Some(tunnel);

        self.driver.ping().await?;

        Ok(())
    }

    async fn resolve_host(&self) -> Result<(), Box<dyn Error>> {
        let hostname = self.config.host.as_deref().ok_or("missing host")?;
        let mut host = Host::parse(&hostname)?;

        host.resolve().await?;

        Ok(())
    }

    /// Moves Connection to specified state and notifies the update through given channel.
    async fn transition(&mut self, next: State, tx: &Sender<State>) -> Result<(), TransitionError> {
        if !self.state.can_transition_to(&next) {
            return Err(TransitionError {
                from: self.state.clone(),
                to: next,
            });
        }

        self.state = next;
        tx.send(self.state.clone()).await.ok();

        Ok(())
    }
}

impl State {
    pub fn can_transition_to(&self, next: &State) -> bool {
        match (self, next) {
            // Allow transition to Invalid from any state
            (_, State::Invalid(_)) => true,
            (State::Disconnected, State::Connecting) => true,
            (State::Connecting, State::Connected) => true,
            (State::Connecting, State::Disconnecting) => true,
            (State::Connected, State::Disconnecting) => true,
            (State::Disconnecting, State::Disconnected) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "transition from {:?} to {:?} is not allowed",
            self.from, self.to
        )
    }
}

impl std::error::Error for TransitionError {}
