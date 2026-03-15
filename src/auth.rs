//! # Auth
//!
//! Shared types and contracts related to authentication process.

/// Common authenticator trait for any protocol to implement.
pub trait Auth {
    /// Runs any logic required to acquire authentication token.
    fn authenticate(&self, flow: Flow) -> impl Future<Output = Result<Token, AuthError>>;
}

/// Authentication flow type.
pub enum Flow {
    Password { username: String, password: String },
    Saml,
}

/// Possible errors that can occur during authentication process.
#[derive(Debug)]
pub enum AuthError {
    /// Client errors represent anything that happened on VPN client side.
    /// This does not include HTTP errors received from server.
    Client(String),
    /// Server errors represent any HTTP error returned from the server.
    Server { status: u16, url: String },
    /// Network errors cover cases where server was unavailable or client network
    /// configuration is invalid.
    Network(reqwest::Error),
}

/// A string representing authentication token - usually a cookie.
#[derive(Debug)]
pub struct Token(pub String);
