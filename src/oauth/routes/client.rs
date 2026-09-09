use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::oauth::{database::Database, error::Error, routes::Form};

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/client")
            .route(web::post().to(post_client))
            .default_service(web::to(|payload: web::Payload| super::method_not_allowed(payload, "POST"))),
    );
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ClientType {
    Public,
    Confidential,
}

#[derive(Deserialize)]
struct ClientForm {
    name: String,
    redirect_uri: String,
    r#type: ClientType,
}

async fn post_client(
    db: web::Data<Database>,
    client_form: Form<ClientForm>,
) -> Result<HttpResponse, Error> {
    tracing::debug!("POST Handler: post_client()");
    let client_form = client_form.into_inner();
    let mut db = db.as_ref().clone();
    let client_name = client_form.name;
    let (client_id, client_secret) = match client_form.r#type {
        ClientType::Public => db
            .register_public_client(&client_name, &client_form.redirect_uri, "")
            .await
            .map_err(|e| Error::Database { source: (e) })?,
        ClientType::Confidential => db
            .register_confidential_client(&client_name, &client_form.redirect_uri, "")
            .await
            .map_err(|e| Error::Database { source: (e) })?,
    };

    #[derive(Serialize)]
    struct Response {
        client_id: String,
        client_secret: Option<String>,
    }

    tracing::debug!(
        "POST Handler: post_client(): return (id, secret): ({:?},{:?})",
        client_id,
        client_secret
    );

    Ok(HttpResponse::Ok().json(Response {
        client_id,
        client_secret,
    }))
}
