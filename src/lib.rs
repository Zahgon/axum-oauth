use actix_files::Files;
use actix_session::{config::PersistentSession, SessionMiddleware};
use actix_web::{
    cookie::{time::Duration, Key, SameSite},
    dev::Server,
    web, App, HttpServer,
};
use async_session::MemoryStore;
use std::net::TcpListener;

pub mod oauth;
pub mod routes;
pub mod state;

use oauth::database::Database as AuthDB;
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
                // The source framework's session layer defaulted to a one-day time-to-live and
                // wrote it onto the cookie; the target's default is a browser session with no
                // expiry at all, so the lifetime has to be restated here.
                .session_lifecycle(PersistentSession::default().session_ttl(Duration::days(1)))
                .build();

        App::new()
            .app_data(auth_state.clone())
            .app_data(database.clone())
            .app_data(session_data.clone())
            // `prefer_utf8` would append a charset the source's static handler never sent, and
            // the content-disposition and etag headers are additions of this file server alone.
            .service(
                Files::new("/assets", "assets")
                    .prefer_utf8(false)
                    .disable_content_disposition()
                    .use_etag(false),
            )
            .service(
                web::scope("/oauth")
                    .wrap(session_layer)
                    .configure(crate::oauth::routes::routes),
            )
            .service(web::scope("/api").configure(routes::routes))
    })
    .listen(listener)
    .map_err(|e| eprintln!("{e}"))
    .unwrap()
    .run()
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
    let sessions = MemoryStore::new();

    AppState {
        sessions,
        state,
        database: auth_db,
    }
}
