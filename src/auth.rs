#[derive(Debug)]
pub struct Token(pub String);

pub enum Flow {
    Password { username: String, password: String },
    Saml,
}

#[derive(Debug)]
pub enum AuthError {
    Client(String),
    Server { status: u16, url: String },
    Network(reqwest::Error),
}

pub trait Auth {
    fn authenticate(&self, flow: Flow) -> impl Future<Output = Result<Token, AuthError>>;
}
