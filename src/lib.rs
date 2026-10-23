use actix_session::{
    config::{BrowserSession, CookieContentSecurity},
    SessionMiddleware,
};
use actix_web::{
    body::{BoxBody, MessageBody},
    cookie::{time::Duration, Key, SameSite},
    dev::{Server, Service, ServiceRequest, ServiceResponse},
    middleware::{from_fn, Next},
    web, App, HttpMessage, HttpResponse, HttpServer,
};
use std::net::TcpListener;

mod assets;
pub mod oauth;
pub mod routes;
pub mod state;

use oauth::database::Database as AuthDB;
use oauth::routes::drain;
use oauth::sessions::Sessions;
use secrecy::Secret;
use state::AppState;

pub async fn build_service(
    bind_address: Option<String>,
    server_port: u16,
) -> (AppState, TcpListener) {
    let app_state = get_app_state().await;

    let mut addr = format!("0.0.0.0:{server_port}");
    if bind_address.is_some() {
        addr = bind_address.unwrap();
    }
    let listener = TcpListener::bind(addr)
        .map_err(|e| {
            eprintln!("unable to parse local address: {e}");
        })
        .unwrap();

    (app_state, listener)
}

pub async fn serve(app: AppState, listener: TcpListener) {
    let server = build_server(app, listener);

    server.await.unwrap();
}

fn build_server(app: AppState, listener: TcpListener) -> Server {
    let auth_state = web::Data::new(app.state);
    let database = web::Data::new(app.database);
    // One store and one key for the whole server: the factory below runs once
    // per worker, and a per-worker store or key would scatter sessions across
    // workers.
    let sessions = Sessions::new("axum_oauth", Key::from(nanoid::nanoid!(128).as_bytes()));
    let session_data = web::Data::new(sessions.clone());

    HttpServer::new(move || {
        let session_layer =
            SessionMiddleware::builder(sessions.store.clone(), sessions.key.clone())
                .cookie_name(sessions.cookie_name.clone())
                .cookie_secure(true)
                .cookie_path(String::from("/oauth/"))
                .cookie_same_site(SameSite::Lax)
                // The source's cookie carried a signed session id, so the same
                // session always went out under the same cookie value; a sealed
                // cookie would change on every write.
                .cookie_content_security(CookieContentSecurity::Signed)
                // The source's session layer kept the record for a day and
                // stamped that lifetime onto the cookie as an `Expires` date,
                // with no `Max-Age`. The browser-session lifecycle leaves both
                // off the cookie; `Sessions::shape_cookies` below adds the date.
                .session_lifecycle(BrowserSession::default().state_ttl(Duration::days(1)))
                .build();
        let stamp = sessions.clone();

        App::new()
            .wrap(from_fn(literal_paths))
            .app_data(auth_state.clone())
            .app_data(database.clone())
            .app_data(session_data.clone())
            .service(web::scope("/assets").default_service(web::to(assets::serve)))
            .service(
                web::scope("/oauth")
                    .wrap(session_layer)
                    .wrap_fn(move |mut req, srv| {
                        let stamp = stamp.clone();
                        stamp.keep_first_valid_session_cookie(req.headers_mut());
                        let incoming = req
                            .cookie(&stamp.cookie_name)
                            .map(|cookie| cookie.value().to_owned());
                        let response = srv.call(req);
                        async move {
                            let mut response = response.await?;
                            stamp.shape_cookies(
                                incoming.as_deref(),
                                response.response_mut().headers_mut(),
                            );
                            Ok(response)
                        }
                    })
                    .configure(crate::oauth::routes::routes),
            )
            .service(web::scope("/api").configure(routes::routes))
            .default_service(web::to(not_found))
    })
    .listen(listener)
    .map_err(|e| eprintln!("{e}"))
    .unwrap()
    .run()
}

/// Unrouted requests are a bodiless `404`. The payload is drained first: an
/// unread request body leaves the connection unreusable and would add
/// `Connection: close` to the answer.
async fn not_found(payload: web::Payload) -> HttpResponse {
    drain(payload).await;

    HttpResponse::NotFound().finish()
}

/// The source router matched the request path as it arrived, percent escapes
/// and all, so an escaped character never matched a route even when its decoded
/// form would have. This router decodes unreserved escapes before matching. No
/// route contains a `%`, so an escaped path is unrouted, except below `/assets/`,
/// whose file service decodes the remainder itself.
async fn literal_paths(
    mut req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let path = req.uri().path();
    if path.contains('%') && !path.starts_with("/assets/") {
        drain(req.take_payload()).await;
        return Ok(req.into_response(HttpResponse::NotFound().finish()));
    }

    next.call(req)
        .await
        .map(ServiceResponse::map_into_boxed_body)
}

async fn get_app_state() -> AppState {
    let mut auth_db = AuthDB::new();
    let _ = auth_db
        .register_user("bob", Secret::from("secret".to_string()), "Robert")
        .await;
    let _ = auth_db
        .register_public_client(
            "LocalClient",
            "https://www.thunderclient.com/oauth/callback",
            "account::read",
        )
        .await;
    let state = oauth::state::State::new(auth_db.clone());

    AppState {
        state,
        database: auth_db,
    }
}
