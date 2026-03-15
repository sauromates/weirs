//! # Fortinet auth
//!
//! Implements different authentication flows against FortiNet VPN servers.

use crate::auth::{Auth, AuthError, Flow, Token};

pub mod password;

/// Default URL to request authentication form.
const LOGIN_URL: &str = "/remote/login";
/// Default URL to send authentication credentials.
const CHECK_URL: &str = "/remote/logincheck";
/// Default name of the expected authentication cookie.
const COOKIE: &str = "SVPNCOOKIE";

/// Fortinet-specific authenticator.
pub struct FortinetAuth {
    pub host: String,
}

impl Auth for FortinetAuth {
    async fn authenticate(&self, flow: Flow) -> Result<Token, AuthError> {
        match flow {
            Flow::Password { username, password } => {
                password::Authenticator {
                    host: &self.host,
                    username,
                    password,
                }
                .handle()
                .await
            }
            Flow::Saml => todo!(),
        }
    }
}

/// Extracts a cookie from succesfull authentication response.
fn extract_token(response: &reqwest::Response) -> Result<Token, AuthError> {
    response
        .cookies()
        .find(|cookie| cookie.name() == COOKIE)
        .map(|cookie| Token(cookie.value().to_string()))
        .ok_or(AuthError::Client(
            format!("{} is not found in response", COOKIE).into(),
        ))
}
