use std::borrow::Cow;

use actix_web::{
    dev::{Payload, ServiceRequest},
    error::{InternalError, QueryPayloadError},
    http::{header, Method, StatusCode},
    web, HttpResponse,
};
use serde::{Deserialize, Serialize};

pub use form::Form;
pub use json::Json;
pub use oauth_request::OAuthReq;
pub use session::Session;

pub fn routes(cfg: &mut web::ServiceConfig) {
    oauth::routes(cfg);
    client::routes(cfg);
    signin::routes(cfg);
    signout::routes(cfg);
    signup::routes(cfg);
}

mod client;
mod oauth;
mod signin;
mod signout;
mod signup;

fn text_plain(status: StatusCode, body: String) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body(body)
}

/// The `Allow` list is spelled out because it is part of the wire contract and
/// cannot be derived: `HEAD` is answered by the `GET` guard, not by one of its own.
///
/// The payload is drained for the same reason [`Form`] drains it: a request body
/// nobody reads leaves the connection unreusable and adds `Connection: close`.
pub(crate) async fn method_not_allowed(
    mut payload: web::Payload,
    allow: &'static str,
) -> HttpResponse {
    while let Some(chunk) = futures::StreamExt::next(&mut payload).await {
        if chunk.is_err() {
            break;
        }
    }

    HttpResponse::build(StatusCode::METHOD_NOT_ALLOWED)
        .insert_header((header::ALLOW, allow))
        .finish()
}

/// Restage a `GET` or `HEAD` query string as a urlencoded request body.
///
/// The source framework's form extractor reads `GET` and `HEAD` parameters from
/// the query string instead of from the body, so an OAuth request built on those
/// methods reaches the endpoint with its `urlbody` filled in from the query. That
/// is the only reason `/oauth/refresh` — a `GET`-only route whose flow reads the
/// grant out of the body — can be driven at all. `web::Form`, which
/// `oxide_auth_actix::OAuthRequest` is built on, only ever reads the body, so the
/// query is moved into the payload before the request reaches the extractor.
fn query_as_form(mut req: ServiceRequest) -> ServiceRequest {
    if req.method() == Method::GET || req.method() == Method::HEAD {
        let query = web::Bytes::from(req.query_string().to_owned());
        req.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        req.set_payload(Payload::from(query));
    }

    req
}

pub(crate) fn query_config() -> web::QueryConfig {
    web::QueryConfig::default().error_handler(|err, _req| {
        let QueryPayloadError::Deserialize(inner) = &err else {
            let response = text_plain(
                StatusCode::BAD_REQUEST,
                format!("Failed to deserialize query string: {err}"),
            );
            return InternalError::from_response(err, response).into();
        };
        let response = text_plain(
            StatusCode::BAD_REQUEST,
            format!("Failed to deserialize query string: {inner}"),
        );

        InternalError::from_response(err, response).into()
    })
}

/// A JSON body whose verdict is deferred to the handler.
///
/// Extractors are evaluated in declaration order and the first failure answers
/// the request, so a body extractor that rejects on the spot would out-rank the
/// authorization guard behind it and turn an unauthenticated request into a body
/// error. Reading the body here and reporting the verdict from the handler keeps
/// the guard first while still draining the payload, which is what stops
/// `Connection: close` appearing on the rejection.
mod json {
    use actix_web::{
        dev::Payload,
        error::InternalError,
        http::{header, StatusCode},
        mime,
        web::BytesMut,
        FromRequest, HttpRequest,
    };
    use futures::{future::LocalBoxFuture, StreamExt};
    use serde::de::DeserializeOwned;

    pub struct Json<T>(Result<T, actix_web::Error>);

    impl<T> Json<T> {
        pub fn into_inner(self) -> Result<T, actix_web::Error> {
            self.0
        }
    }

    impl<T: DeserializeOwned + 'static> FromRequest for Json<T> {
        type Error = actix_web::Error;
        type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

        fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
            // The source extractor accepted any `application/*+json` suffix as
            // well as `application/json` itself.
            let is_json = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<mime::Mime>().ok())
                .map(|mime| {
                    mime.type_() == mime::APPLICATION
                        && (mime.subtype() == mime::JSON
                            || mime.suffix().is_some_and(|name| name == mime::JSON))
                })
                .unwrap_or(false);
            let mut payload = payload.take();

            Box::pin(async move {
                let mut body = BytesMut::new();
                while let Some(chunk) = payload.next().await {
                    match chunk {
                        Ok(chunk) => body.extend_from_slice(&chunk),
                        Err(err) => return Ok(Self(Err(err.into()))),
                    }
                }

                if !is_json {
                    return Ok(Self(Err(reject(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        String::from("Expected request with `Content-Type: application/json`"),
                    ))));
                }

                // The source extractor tells a body that is not JSON at all from
                // one that is JSON but not this type, and reports them
                // differently: a syntax error is 400 and names parsing, a data
                // error is 422 and names the target type. Both messages carry the
                // path to the offending field, which is why the deserializer is
                // driven through `serde_path_to_error`.
                let mut deserializer = serde_json::Deserializer::from_slice(&body);

                Ok(Self(
                    serde_path_to_error::deserialize(&mut deserializer).map_err(|err| {
                        match err.inner().classify() {
                            serde_json::error::Category::Data => reject(
                                StatusCode::UNPROCESSABLE_ENTITY,
                                format!(
                                    "Failed to deserialize the JSON body into the target type: {err}"
                                ),
                            ),
                            _ => reject(
                                StatusCode::BAD_REQUEST,
                                format!("Failed to parse the request body as JSON: {err}"),
                            ),
                        }
                    }),
                ))
            })
        }
    }

    fn reject(status: StatusCode, body: String) -> actix_web::Error {
        let response = super::text_plain(status, body.clone());

        InternalError::from_response(body, response).into()
    }
}

mod form {
    use actix_web::{
        dev::Payload,
        error::InternalError,
        http::{header, StatusCode},
        mime,
        web::BytesMut,
        FromRequest, HttpRequest,
    };
    use futures::{future::LocalBoxFuture, StreamExt};
    use serde::de::DeserializeOwned;

    use super::text_plain;

    pub struct Form<T>(pub T);

    impl<T> Form<T> {
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    /// The payload is drained before the content type is judged so that a rejected
    /// request still leaves the connection reusable; rejecting first makes the
    /// framing unrecoverable and forces a `Connection: close` onto the response.
    impl<T: DeserializeOwned + 'static> FromRequest for Form<T> {
        type Error = actix_web::Error;
        type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

        fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
            let urlencoded = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<mime::Mime>().ok())
                .map(|mime| {
                    mime.type_() == mime::APPLICATION && mime.subtype() == mime::WWW_FORM_URLENCODED
                })
                .unwrap_or(false);
            let mut payload = payload.take();

            Box::pin(async move {
                let mut body = BytesMut::new();
                while let Some(chunk) = payload.next().await {
                    let chunk = chunk.map_err(actix_web::Error::from)?;
                    body.extend_from_slice(&chunk);
                }

                if !urlencoded {
                    let message =
                        "Form requests must have `Content-Type: application/x-www-form-urlencoded`";
                    let response =
                        text_plain(StatusCode::UNSUPPORTED_MEDIA_TYPE, String::from(message));
                    return Err(InternalError::from_response(message, response).into());
                }

                serde_urlencoded::from_bytes::<T>(&body)
                    .map(Form)
                    .map_err(|err| {
                        let response = text_plain(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            format!("Failed to deserialize form body: {err}"),
                        );
                        InternalError::from_response(err, response).into()
                    })
            })
        }
    }
}

mod oauth_request {
    use actix_web::{dev::Payload, web::BytesMut, FromRequest, HttpRequest};
    use futures::{future::LocalBoxFuture, StreamExt};
    use oxide_auth_actix::{OAuthRequest, WebError};

    pub struct OAuthReq(pub OAuthRequest);

    /// `OAuthRequest` only reads the body of a urlencoded request, so anything else
    /// leaves the payload unread and forces a `Connection: close`. Draining it here
    /// and replaying the bytes keeps the connection reusable without changing what
    /// the endpoint parses.
    impl FromRequest for OAuthReq {
        type Error = WebError;
        type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

        fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
            let req = req.clone();
            let mut payload = payload.take();

            Box::pin(async move {
                let mut body = BytesMut::new();
                while let Some(chunk) = payload.next().await {
                    let chunk = chunk.map_err(|_| WebError::Body)?;
                    body.extend_from_slice(&chunk);
                }

                OAuthRequest::new(req, Payload::from(body.freeze()))
                    .await
                    .map(OAuthReq)
            })
        }
    }
}

mod session {
    use std::{
        fmt::{Display, Formatter},
        future::{ready, Ready},
    };

    use actix_session::SessionExt;
    use actix_web::{
        error::InternalError,
        http::{header, StatusCode},
        FromRequest, HttpRequest, HttpResponse, ResponseError,
    };

    use crate::oauth::{database::resource::user::AuthUser, routes::Callback};

    #[derive(Debug)]
    pub struct SignInRedirect {
        location: String,
    }

    impl Display for SignInRedirect {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "redirect to {}", self.location)
        }
    }

    impl ResponseError for SignInRedirect {
        fn status_code(&self) -> StatusCode {
            StatusCode::SEE_OTHER
        }

        fn error_response(&self) -> HttpResponse {
            HttpResponse::build(StatusCode::SEE_OTHER)
                .insert_header((header::LOCATION, self.location.clone()))
                .finish()
        }
    }

    pub struct Session {
        pub user: AuthUser,
    }

    impl FromRequest for Session {
        type Error = actix_web::Error;
        type Future = Ready<Result<Self, Self::Error>>;

        fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
            tracing::debug!("Middleware: Session: parts: {:?}", req);
            let user = req
                .get_session()
                .get::<AuthUser>("user")
                .ok()
                .flatten()
                .ok_or_else(|| {
                    let path_and_query = req
                        .uri()
                        .path_and_query()
                        .map(|x| x.as_str())
                        .unwrap_or_default()
                        .trim_start_matches("/oauth")
                        .trim_start_matches('/');
                    let callback = Callback::from_str(path_and_query);
                    let uri = format!(
                        "/oauth/signin?{}",
                        serde_urlencoded::to_string(callback).unwrap()
                    );
                    let redirect = SignInRedirect {
                        location: uri.clone(),
                    };
                    let response = redirect.error_response();

                    actix_web::Error::from(InternalError::from_response(redirect, response))
                });

            ready(user.map(|user| Self { user }))
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct Callback<'a> {
    callback: Cow<'a, str>,
}

impl<'a> Callback<'a> {
    fn as_str(&self) -> &str {
        &self.callback
    }

    fn from_str(callback: &'a str) -> Self {
        Self {
            callback: Cow::from(callback),
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize, Clone)]
pub struct SignUpForm {
    username: String,
    password: String,
    given_name: String,
}
