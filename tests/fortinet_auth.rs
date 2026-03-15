use weirs::proto::fortinet::auth::password;

#[tokio::test]
#[ignore]
async fn test_fortinet_password_auth() {
    let host = std::env::var("FORTI_HOST").expect("FortiNet host is not set");
    let username = std::env::var("FORTI_USERNAME").expect("Username is not set");
    let password = std::env::var("FORTI_PASSWORD").expect("Password is not set");

    let auth = password::Authenticator {
        host: &host,
        username,
        password,
    };
    let result = auth.handle().await;

    assert!(result.is_ok(), "{:?}", result);
}
