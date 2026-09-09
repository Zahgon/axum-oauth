use actix_session::Session as CookieSession;
use actix_web::{
    http::{header, StatusCode},
    web, HttpResponse,
};

use crate::oauth::{
    database::{resource::user::AuthUser, Database},
    error::Error,
    routes::{Callback, Form, LoginForm},
    templates::{render_template, SignIn},
};

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/signin")
            .app_data(super::query_config())
            .route(web::get().to(get_signin))
            .route(web::head().to(get_signin))
            .route(web::post().to(post_signin))
            .default_service(web::to(|payload: web::Payload| super::method_not_allowed(payload, "GET,HEAD,POST"))),
    );
}

async fn get_signin(query: Option<web::Query<Callback<'static>>>) -> HttpResponse {
    let query = query
        .map(|x| serde_urlencoded::to_string(x.into_inner()).ok().unwrap_or_default())
        .unwrap_or_default();

    render_template(&SignIn { query: &query }, StatusCode::OK)
}

async fn post_signin(
    db: web::Data<Database>,
    query: Option<web::Query<Callback<'static>>>,
    session: CookieSession,
    user_form: Form<LoginForm>,
) -> Result<HttpResponse, Error> {
    let user_form = user_form.into_inner();
    let query = query.as_ref().map(|x| x.as_str());

    tracing::debug!("entered -> post_signin()");
    let user_record = match db.get_user_by_name(&user_form.username).await {
        Ok(user_record) => user_record,
        Err(_) => {
            tracing::debug!("        user DOES NOT exist");
            return Ok(render_template(
                &SignIn {
                    query: query.unwrap_or_default(),
                },
                StatusCode::UNAUTHORIZED,
            ));
        }
    };
    let authorized = db
        .verify_password(&user_form.username, &user_form.password)
        .await
        .map_err(|e| Error::Database { source: (e) })?;
    let _ = session.insert(
        "user",
        AuthUser {
            user_id: user_record.id().unwrap(),
            username: user_form.username,
        },
    );

    tracing::debug!("    checking authorization");
    if !authorized {
        tracing::debug!("        NOT authorized");
        return Ok(render_template(
            &SignIn {
                query: query.unwrap_or_default(),
            },
            StatusCode::UNAUTHORIZED,
        ));
    }

    let location = match query.unwrap_or_default() {
        "" => {
            tracing::debug!("    redirect to /oauth/");
            String::from("/oauth/")
        }
        callback => {
            tracing::debug!("    redirect to callback: {}", callback);
            callback.to_string()
        }
    };

    Ok(HttpResponse::build(StatusCode::SEE_OTHER)
        .insert_header((header::LOCATION, location))
        .finish())
}
