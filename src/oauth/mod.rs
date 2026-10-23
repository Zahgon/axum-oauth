use actix_web::{
    http::header::{HeaderValue, CONTENT_TYPE},
    HttpRequest, HttpResponse, Responder,
};
use oxide_auth_actix::OAuthResponse;
use serde::Deserialize;

pub mod database;
pub mod endpoint;
pub mod error;
pub mod models;
pub mod primitives;
pub mod routes;
pub mod scopes;
pub mod sessions;
pub mod solicitor;
pub mod state;
pub mod templates;

#[derive(Debug, Deserialize)]
#[serde(tag = "consent", rename_all = "lowercase")]
pub enum Consent {
    Allow,
    Deny,
}

/// Turn an [`OAuthResponse`] into an [`HttpResponse`].
///
/// A bodyless `OAuthResponse` — the 302 authorization redirect, the 401
/// challenge emitted by the resource flow — carries no content type of its
/// own, yet it still reaches the wire announcing `text/plain; charset=utf-8`.
/// Reproduce that here so the header set is the one clients already receive.
pub fn into_http_response(response: OAuthResponse, request: &HttpRequest) -> HttpResponse {
    let mut response = response.respond_to(request);
    if !response.headers().contains_key(CONTENT_TYPE) {
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }

    response
}
