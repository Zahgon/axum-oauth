use actix_web::{http::StatusCode, web, HttpResponse};
use secrecy::Secret;

use crate::oauth::{
    database::Database,
    error::Error,
    routes::{Callback, Form, SignUpForm},
};

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/signup")
            .app_data(super::query_config())
            .route(web::post().to(post_signup))
            .default_service(web::to(|payload: web::Payload| super::method_not_allowed(payload, "POST"))),
    );
}

async fn post_signup(
    db: web::Data<Database>,
    _query: Option<web::Query<Callback<'static>>>,
    user: Form<SignUpForm>,
) -> Result<HttpResponse, Error> {
    let user = user.into_inner();
    let mut db = db.as_ref().clone();
    if db.contains_user_name(&user.username).await {
        return Err(Error::ResourceConflict);
    }

    db.register_user(
        &user.username,
        Secret::from(user.password),
        &user.given_name,
    )
    .await;

    Ok(HttpResponse::build(StatusCode::CREATED).finish())
}
