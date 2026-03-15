//! ## Fortinet password auth flow handler

use crate::auth::{AuthError, Token};
use reqwest::Client;

/// Handles simple password based authentication flow.
pub struct Authenticator<'a> {
    pub host: &'a str,
    pub username: String,
    pub password: String,
}

impl Authenticator<'_> {
    /// Orchestrates a sequence of HTTP requests to Fortinet server required
    /// to obtain authentication cookie.
    pub async fn handle(&self) -> Result<Token, AuthError> {
        let client = Client::builder()
            // TODO: consider certificate validation later
            .danger_accept_invalid_certs(true)
            .cookie_store(true)
            .build()
            .map_err(|e| AuthError::Client(e.to_string()))?;

        client
            .get(format!("{}{}", self.host, super::LOGIN_URL))
            .send()
            .await
            .map_err(AuthError::Network)?
            .error_for_status()
            .map_err(|e| AuthError::Server {
                status: e.status().unwrap().as_u16(),
                url: format!("{}", super::LOGIN_URL),
            })?;

        #[derive(serde::Serialize)]
        struct LoginForm<'a> {
            username: &'a str,
            credential: &'a str,
        }

        let response = client
            .post(format!("{}{}", self.host, super::CHECK_URL))
            .form(&LoginForm {
                username: &self.username,
                credential: &self.password,
            })
            .send()
            .await
            .map_err(AuthError::Network)?
            .error_for_status()
            .map_err(|e| AuthError::Server {
                status: e.status().unwrap().as_u16(),
                url: format!("{}", super::CHECK_URL),
            })?;

        super::extract_token(&response)
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::AuthError;
    use crate::proto::fortinet::auth::{CHECK_URL, COOKIE, LOGIN_URL};

    use super::Authenticator;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup() -> MockServer {
        MockServer::start().await
    }

    #[tokio::test]
    async fn test_successful_auth() {
        let server = setup().await;

        Mock::given(method("GET"))
            .and(path(LOGIN_URL))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(CHECK_URL))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("Set-Cookie", format!("{}=test_token; Path=/", COOKIE)),
            )
            .mount(&server)
            .await;

        let auth = Authenticator {
            host: &server.uri(),
            username: "testuser".into(),
            password: "testpassword".into(),
        };

        let result = auth.handle().await;

        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(result.unwrap().0, "test_token");
    }

    #[tokio::test]
    async fn test_server_error_on_logincheck() {
        let server = setup().await;

        Mock::given(method("GET"))
            .and(path(LOGIN_URL))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(CHECK_URL))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let auth = Authenticator {
            host: &server.uri(),
            username: "testuser".into(),
            password: "testpassword".into(),
        };

        let result = auth.handle().await;
        assert!(matches!(result, Err(AuthError::Server { status: 401, .. })));
    }

    #[tokio::test]
    async fn test_client_error_on_missing_cookie() {
        let server = setup().await;

        Mock::given(method("GET"))
            .and(path(LOGIN_URL))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(CHECK_URL))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let auth = Authenticator {
            host: &server.uri(),
            username: "testuser".into(),
            password: "testpassword".into(),
        };

        let result = auth.handle().await;
        assert!(matches!(result, Err(AuthError::Client(_))));
    }

    #[tokio::test]
    async fn test_server_error_on_login() {
        let server = setup().await;

        Mock::given(method("GET"))
            .and(path(LOGIN_URL))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let auth = Authenticator {
            host: &server.uri(),
            username: "testuser".into(),
            password: "testpassword".into(),
        };

        let result = auth.handle().await;
        assert!(
            matches!(result, Err(AuthError::Server { status: 500, .. })),
            "{:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_network_error() {
        let auth = Authenticator {
            host: "127.0.0.1:1", // Invalid host should trigger network error
            username: "testuser".into(),
            password: "testpassword".into(),
        };

        let result = auth.handle().await;
        assert!(matches!(result, Err(AuthError::Network(_))));
    }
}
