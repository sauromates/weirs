use crate::auth::{Auth, Flow};
use crate::driver::Driver;
use crate::proto::fortinet::FortinetConfig;
use crate::proto::fortinet::auth::FortinetAuth;
use async_trait::async_trait;
use std::error::Error;
use std::net::IpAddr;

pub struct FortinetDriver {
    pub config: FortinetConfig,
}

#[async_trait]
impl Driver for FortinetDriver {
    async fn authenticate(&self) -> Result<String, Box<dyn Error>> {
        let auth = FortinetAuth {
            host: self.config.host.clone(),
        };
        let token = auth.authenticate(self.flow()).await?;

        Ok(token.0)
    }

    async fn connect(&self) -> Result<IpAddr, Box<dyn Error>> {
        todo!()
    }

    async fn ping(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}

impl FortinetDriver {
    /// Determines the authentication flow based on driver configuration.
    fn flow(&self) -> Flow {
        if self.config.saml_port.is_some() {
            return Flow::Saml;
        }

        if let Some(username) = &self.config.username {
            return Flow::Password {
                username: username.clone(),
                password: self.config.password.clone().unwrap_or_default(),
            };
        }

        Flow::Password {
            username: String::new(),
            password: String::new(),
        }
    }
}
