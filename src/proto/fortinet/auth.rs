//! # Fortinet auth
//!
//! Implements different authentication flows against FortiNet VPN servers.

use crate::auth::{Auth, AuthError, ClientErrorKind, Flow, Token};
use async_trait::async_trait;
use reqwest::{Client, RequestBuilder, Response};

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
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .cookie_store(true)
            .build()
            .map_err(|e| AuthError::Client(ClientErrorKind::Generic(e.to_string())))?;

        match flow {
            Flow::Password { username, password } => {
                password::Authenticator {
                    client: &client,
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

/// Chainable HTTP request handler with simple logic: make request to given endpoint,
/// parse response to detect next step endpoint and return for next handler.
#[async_trait]
pub trait StepHandler: Send {
    /// Handles authentication flow step.
    async fn handle(&self, endpoint: &str) -> Result<String, AuthError>;

    /// Finalizes request prepared by a concrete handler.
    async fn make_request(
        &self,
        request: RequestBuilder,
        url: &str,
    ) -> Result<Response, AuthError> {
        request
            .send()
            .await
            .map_err(AuthError::Network)?
            .error_for_status()
            .map_err(|e| AuthError::Server {
                status: e.status().unwrap().as_u16(),
                url: url.into(),
            })
    }
}

/// Makes first request to VPN server to initiate authentication flow.
struct ProbeServer<'a> {
    client: &'a Client,
    host: &'a str,
}

#[async_trait]
impl StepHandler for ProbeServer<'_> {
    async fn handle(&self, endpoint: &str) -> Result<String, AuthError> {
        let request = self.client.get(endpoint);
        let _response = self.make_request(request, endpoint).await?;

        // TODO: implement response parsing for next URL
        Ok(format!("{}{}", self.host, LOGIN_URL))
    }
}

/// Extracts a cookie from succesfull authentication response.
fn extract_token(response: &reqwest::Response) -> Result<Token, AuthError> {
    response
        .cookies()
        .find(|cookie| cookie.name() == COOKIE)
        .map(|cookie| Token(cookie.value().to_string()))
        .ok_or(AuthError::Client(ClientErrorKind::Generic(
            format!("{} is not found in response", COOKIE).into(),
        )))
}
