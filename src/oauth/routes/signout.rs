use actix_web::{cookie::Cookie, http::StatusCode, web, HttpRequest, HttpResponse};

use crate::oauth::sessions::Sessions;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/signout")
            .route(web::post().to(post_signout))
            .default_service(web::to(|payload: web::Payload| super::method_not_allowed(payload, "POST"))),
    );
}

/// The removal cookie is written here rather than by asking the session
/// middleware to purge, because the two disagree about when and how a removal
/// is sent: the middleware emits one only when a session cookie arrived on the
/// request, and stamps it with `Secure` and `SameSite`. Sign-out answers
/// unconditionally, with neither attribute. Leaving the session untouched keeps
/// the middleware silent, so this is the only `Set-Cookie` on the response.
///
/// The server-side record is dropped separately, through the store handle: the
/// source destroyed the session on the server, so a cookie replayed after a
/// sign-out authenticates nobody, and a removal cookie alone would not achieve
/// that.
async fn post_signout(request: HttpRequest, sessions: web::Data<Sessions>) -> HttpResponse {
    sessions.destroy(&request);

    let mut session_cookie = Cookie::build("axum_oauth", "")
        .path("/oauth/")
        .http_only(true)
        .finish();
    session_cookie.make_removal();

    let mut response = HttpResponse::build(StatusCode::OK).finish();
    response.add_cookie(&session_cookie).unwrap();

    response
}
