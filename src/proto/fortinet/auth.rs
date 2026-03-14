use crate::auth::{Auth, AuthError, Flow, Token};

pub mod password;

const LOGIN_URL: &str = "/remote/login";
const CHECK_URL: &str = "/remote/logincheck";
const COOKIE: &str = "SVPNCOOKIE";

pub struct FortinetAuth {
    pub host: String,
    pub port: u16,
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

pub trait Handler {
    async fn handle(&self) -> Result<Token, AuthError>;
}

fn extract_token(response: &reqwest::Response) -> Result<Token, AuthError> {
    response
        .cookies()
        .find(|cookie| cookie.name() == COOKIE)
        .map(|cookie| Token(cookie.value().to_string()))
        .ok_or(AuthError::Client(
            "SVPNCOOKIE is not found in response".into(),
        ))
}
