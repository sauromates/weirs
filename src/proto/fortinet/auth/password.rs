//! ## Fortinet password auth flow handler

use crate::{
    auth::{AuthError, Token},
    proto::fortinet::auth::{CHECK_URL, ProbeServer, StepHandler},
};
use async_trait::async_trait;
use futures::TryStreamExt;
use reqwest::Client;
use url::Url;

/// Handles simple password based authentication flow.
pub struct Authenticator<'a> {
    pub client: &'a Client,
    pub host: &'a Url,
    pub username: String,
    pub password: String,
}

/// Retrieves login endpoint from VPN server.
struct GetLoginForm<'a> {
    client: &'a Client,
    host: &'a Url,
}

/// Exchanges user's credentials for an access token.
struct Authenticate<'a> {
    client: &'a Client,
    username: &'a str,
    password: &'a str,
}

/// Represents form data to wrap user's credentials.
#[derive(serde::Serialize)]
struct FormCredentials<'a> {
    username: &'a str,
    credential: &'a str,
    realm: &'a str,
    ajax: usize,
    just_logged_in: usize,
}

impl<'a> Authenticator<'a> {
    /// Orchestrates a sequence of HTTP requests to Fortinet server required
    /// to obtain authentication cookie.
    pub async fn handle(&self) -> Result<Token, AuthError> {
        let handlers = self.steps().into_iter().map(Ok::<_, AuthError>);
        let start = self.host.to_string();

        let cookie = futures::stream::iter(handlers)
            .try_fold(start, |endpoint, handler| async move {
                handler.handle(&endpoint).await
            })
            .await?;

        Ok(Token(cookie))
    }

    /// Returns a sequence of handlers required to perform authentication flow.
    fn steps(&self) -> Vec<Box<dyn StepHandler + Send + '_>> {
        vec![
            Box::new(ProbeServer {
                client: self.client,
                host: &self.host,
            }),
            Box::new(GetLoginForm {
                client: self.client,
                host: &self.host,
            }),
            Box::new(Authenticate {
                client: self.client,
                username: &self.username,
                password: &self.password,
            }),
        ]
    }
}

#[async_trait]
impl StepHandler for GetLoginForm<'_> {
    async fn handle(&self, endpoint: &str) -> Result<String, AuthError> {
        let request = self.client.get(endpoint);
        let _response = self.make_request(request, endpoint).await?;

        // TODO: implement response parsing for next URL
        Ok(self.host.join(CHECK_URL).unwrap().to_string())
    }
}

#[async_trait]
impl StepHandler for Authenticate<'_> {
    async fn handle(&self, endpoint: &str) -> Result<String, AuthError> {
        let request = self.client.post(endpoint).form(&FormCredentials {
            username: &self.username,
            credential: &self.password,
            realm: "",
            ajax: 1,
            just_logged_in: 1,
        });
        let response = self.make_request(request, endpoint).await?;

        super::extract_token(&response).map(|token| token.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::{AuthError, ClientErrorKind};
    use crate::proto::fortinet::auth::{CHECK_URL, COOKIE, LOGIN_URL};

    use super::Authenticator;
    use reqwest::Client;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup() -> MockServer {
        MockServer::start().await
    }

    fn make_client() -> Client {
        Client::builder()
            .cookie_store(true)
            .build()
            .map_err(|e| AuthError::Client(ClientErrorKind::Generic(e.to_string())))
            .unwrap()
    }

    #[tokio::test]
    async fn successful_auth_returns_cookie() {
        let server = setup().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

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
            client: &make_client(),
            host: &Url::parse(server.uri().as_str()).unwrap(),
            username: "testuser".into(),
            password: "testpassword".into(),
        };

        let result = auth.handle().await;

        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(result.unwrap().0, "test_token");
    }

    #[tokio::test]
    async fn failed_logincheck_is_server_error() {
        let server = setup().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

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
            client: &make_client(),
            host: &Url::parse(server.uri().as_str()).unwrap(),
            username: "testuser".into(),
            password: "testpassword".into(),
        };

        let result = auth.handle().await;
        assert!(matches!(result, Err(AuthError::Server { status: 401, .. })));
    }

    #[tokio::test]
    async fn missing_cookie_is_client_error() {
        let server = setup().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

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
            client: &make_client(),
            host: &Url::parse(server.uri().as_str()).unwrap(),
            username: "testuser".into(),
            password: "testpassword".into(),
        };

        let result = auth.handle().await;
        assert!(matches!(result, Err(AuthError::Client(_))));
    }

    #[tokio::test]
    async fn failed_get_login_form_is_server_error() {
        let server = setup().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(LOGIN_URL))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let auth = Authenticator {
            client: &make_client(),
            host: &Url::parse(server.uri().as_str()).unwrap(),
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
}
