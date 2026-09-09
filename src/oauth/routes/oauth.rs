use crate::oauth::{
    database::Database, error::Error, models::ClientId, routes::session::Session,
    solicitor::Solicitor, Consent,
};
use actix_web::{dev::Service, web, HttpRequest, HttpResponse};
use oxide_auth::{
    endpoint::{OwnerConsent, PreGrant, QueryParameter, Solicitation},
    frontends::simple::endpoint::FnSolicitor,
    primitives::scope::Scope,
};
use oxide_auth_actix::{OAuthRequest, WebError};

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/authorize")
            .app_data(super::query_config())
            .wrap_fn(|req, srv| srv.call(super::query_as_form(req)))
            .route(web::get().to(get_authorize))
            .route(web::head().to(get_authorize))
            .route(web::post().to(post_authorize))
            .default_service(web::to(|payload: web::Payload| super::method_not_allowed(payload, "GET,HEAD,POST"))),
    )
    .service(
        web::resource("/refresh")
            .wrap_fn(|req, srv| srv.call(super::query_as_form(req)))
            .route(web::get().to(refresh))
            .route(web::head().to(refresh))
            .default_service(web::to(|payload: web::Payload| super::method_not_allowed(payload, "GET,HEAD"))),
    )
    .service(
        web::resource("/token")
            .route(web::post().to(token))
            .default_service(web::to(|payload: web::Payload| super::method_not_allowed(payload, "POST"))),
    );
}

async fn get_authorize(
    http_request: HttpRequest,
    state: web::Data<crate::oauth::state::State>,
    db: web::Data<Database>,
    Session { user }: Session,
    request: super::OAuthReq,
) -> Result<HttpResponse, Error> {
    tracing::debug!("in get_authorize()");
    tracing::debug!("OAuth Request:\n{:?}", request.0);
    let db = db.as_ref().clone();
    state
        .endpoint()
        .await
        .with_solicitor(Solicitor::new(db, user))
        .authorization_flow()
        .execute(request.0)
        .await
        .map(|response| crate::oauth::into_http_response(response, &http_request))
        .map_err(|e| Error::OAuth { source: e })
}

async fn post_authorize(
    http_request: HttpRequest,
    state: web::Data<crate::oauth::state::State>,
    db: web::Data<Database>,
    consent: web::Query<Consent>,
    Session { user }: Session,
    request: super::OAuthReq,
) -> Result<HttpResponse, Error> {
    tracing::debug!("in post_authorize()");
    tracing::debug!("request:\n{:?}", request.0);
    tracing::debug!("consent:\n{:?}", consent);

    let db = db.as_ref().clone();
    let consent = consent.into_inner();

    state
        .endpoint()
        .await
        .with_solicitor(FnSolicitor(
            move |_: &mut OAuthRequest, solicitation: Solicitation| {
                if let Consent::Allow = consent {
                    let PreGrant {
                        client_id, scope, ..
                    } = solicitation.pre_grant().clone();

                    let current_scope = futures::executor::block_on(get_current_authorization(
                        &db,
                        &user.username,
                        &client_id,
                    ));
                    if current_scope.is_none() || current_scope.unwrap() < scope {
                        futures::executor::block_on(update_authorization(
                            &db,
                            &user.username,
                            &client_id,
                            scope,
                        ));
                    }

                    OwnerConsent::Authorized(user.to_string())
                } else {
                    OwnerConsent::Denied
                }
            },
        ))
        .authorization_flow()
        .execute(request.0)
        .await
        .map(|response| crate::oauth::into_http_response(response, &http_request))
        .map_err(|e| Error::OAuth { source: e })
}

async fn token(
    http_request: HttpRequest,
    state: web::Data<crate::oauth::state::State>,
    request: super::OAuthReq,
) -> Result<HttpResponse, WebError> {
    tracing::debug!("Endpoint: token(), Request:\n{:?}", request.0);
    let grant_type = request
        .0
        .body()
        .and_then(|x| x.unique_value("grant_type"))
        .unwrap_or_default();
    tracing::debug!("Grant Type: {:?}", grant_type);

    match &*grant_type {
        "refresh_token" => refresh(http_request, state, request).await,
        // "client_credentials" => state
        //     .endpoint()
        //     .await
        //     .with_solicitor(FnSolicitor(
        //         move |_: &mut OAuthRequest, solicitation: Solicitation| {
        //             let PreGrant {
        //                 client_id, ..
        //             } = solicitation.pre_grant().clone();
        //             tracing::debug!("Client credentials consent OK: {}", client_id);
        //             OwnerConsent::Authorized(client_id.to_string())
        //         },
        //     ))
        //     .client_credentials_flow()
        //     .execute(request)
        //     .await,
        _ => state
            .endpoint()
            .await
            .access_token_flow()
            .execute(request.0)
            .await
            .map(|response| crate::oauth::into_http_response(response, &http_request)),
    }
}

async fn refresh(
    http_request: HttpRequest,
    state: web::Data<crate::oauth::state::State>,
    request: super::OAuthReq,
) -> Result<HttpResponse, WebError> {
    state
        .endpoint()
        .await
        .refresh_flow()
        .execute(request.0)
        .await
        .map(|response| crate::oauth::into_http_response(response, &http_request))
}

async fn get_current_authorization(
    db: &Database,
    username: &str,
    client_str: &str,
) -> Option<Scope> {
    let user_record = db.get_user_by_name(username).await;
    let client_id = client_str.parse::<ClientId>();
    if user_record.is_err() || client_id.is_err() {
        return None;
    }
    let user_record = user_record.unwrap();
    let client_id = client_id.unwrap();

    db.get_scope(user_record.id().unwrap(), client_id).await
}

async fn update_authorization(db: &Database, username: &str, client_str: &str, new_scope: Scope) {
    let user_record = db.get_user_by_name(username).await;
    let client_id = client_str.parse::<ClientId>();
    if user_record.is_err() || client_id.is_err() {
        return;
    }
    let user_record = user_record.unwrap();
    let client_id = client_id.unwrap();
    let _ = db
        .update_client_scope(user_record.id().unwrap(), client_id, new_scope)
        .await;
}
