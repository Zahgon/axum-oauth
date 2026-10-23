use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use axum_oauth::{build_service, serve};
use oxide_auth_actix::WebError;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

pub mod oauth;
pub mod state;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_oauth=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let (app, listener) = build_service(None, 3000).await;
    serve(app, listener).await;
}

#[derive(Debug)]
enum AuthError {
    #[allow(dead_code)]
    WrongCredentials,
    MissingCredentials,
    InvalidToken,
    Unexecpected(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "missing credentials"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "invalid token"),
            AuthError::Unexecpected(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "unknown internal error")
            }
        };
        let body = serde_json::json!({
            "error": error_message,
        });
        HttpResponse::build(status).json(body)
    }
}

impl From<WebError> for AuthError {
    fn from(err: WebError) -> Self {
        match err {
            WebError::Endpoint(_) => {
                AuthError::Unexecpected("internal authorization error".to_string())
            }
            WebError::Header(h) => AuthError::Unexecpected(h.to_string()),
            WebError::Encoding => AuthError::MissingCredentials,
            WebError::Form => AuthError::MissingCredentials,
            WebError::Query => AuthError::MissingCredentials,
            WebError::Body => AuthError::MissingCredentials,
            WebError::Authorization => AuthError::InvalidToken,
            WebError::Canceled => AuthError::Unexecpected("operation canceled".to_string()),
            WebError::Mailbox => AuthError::Unexecpected("mailbox full".to_string()),
            WebError::InternalError(opt) => match opt {
                Some(e) => AuthError::Unexecpected(e),
                None => AuthError::Unexecpected("unknown authentication error".to_string()),
            },
        }
    }
}
