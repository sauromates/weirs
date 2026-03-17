use reqwest::Client;
use url::Url;
use weirs::{
    auth::{AuthError, ClientErrorKind},
    proto::fortinet::auth::password,
};

#[tokio::test]
#[ignore]
async fn test_fortinet_password_auth() {
    let host = std::env::var("FORTI_HOST").expect("FortiNet host is not set");
    let username = std::env::var("FORTI_USERNAME").expect("Username is not set");
    let password = std::env::var("FORTI_PASSWORD").expect("Password is not set");

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .build()
        .map_err(|e| AuthError::Client(ClientErrorKind::Generic(e.to_string())))
        .unwrap();

    let auth = password::Authenticator {
        client: &client,
        host: &Url::parse(host.as_str()).unwrap(),
        username,
        password,
    };
    let result = auth.handle().await;

    assert!(result.is_ok(), "{:?}", result);
}
