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
    Client(ClientErrorKind),
    /// Server errors represent any HTTP error returned from the server.
    Server { status: u16, url: String },
    /// Network errors cover cases where server was unavailable or client network
    /// configuration is invalid.
    Network(reqwest::Error),
}

#[derive(Debug)]
pub enum ClientErrorKind {
    MissingSecret,
    Generic(String),
}

/// A string representing authentication token - usually a cookie.
#[derive(Debug)]
pub struct Token(pub String);

impl From<String> for ClientErrorKind {
    fn from(s: String) -> Self {
        ClientErrorKind::Generic(s)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Client(e) => write!(f, "Client error: {:?}", e),
            AuthError::Server { status, url } => write!(f, "Server error {} at {}", status, url),
            AuthError::Network(e) => write!(f, "Network error: {}", e),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_error_from_string_produces_generic_kind() {
        let e = ClientErrorKind::from("some".to_string());
        assert!(matches!(e, ClientErrorKind::Generic(_)));
    }
}
