use std::str::FromStr;

use crate::oauth::{
    database::{resource::user::AuthUser, Database},
    error::Error,
    models::{ClientId, UserId},
    primitives::scopes::Grant,
    routes::Json,
    scopes::{Account, Read, Write},
};
use actix_web::web;
use serde::{Deserialize, Serialize};

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/user")
            .route(web::get().to(user))
            .route(web::head().to(user))
            .route(web::post().to(update_account_name))
            .default_service(web::to(|payload: web::Payload| {
                crate::oauth::routes::method_not_allowed(payload, "GET,HEAD,POST")
            })),
    );
}

#[derive(Debug, Serialize)]
pub struct ClientInfo {
    pub id: ClientId,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: UserId,
    pub login: String,
    pub name: String,
    pub authorized_clients: Vec<ClientInfo>,
}

pub async fn user(
    db: web::Data<Database>,
    grant: Grant<Read<Account>>,
) -> Result<web::Json<UserInfo>, Error> {
    tracing::debug!("enter -> user()");
    let u = grant.grant.owner_id;
    let user_record = db
        .get_user_by_id(&AuthUser::from_str(&u).unwrap())
        .await
        .map_err(|e| Error::Database { source: e })?;
    let authorized_clients = user_record.get_authorized_clients();
    let mut clients = Vec::<ClientInfo>::new();
    for cauth in authorized_clients {
        let client_name = db
            .get_client_name(cauth.client_id)
            .await
            .map_err(|e| Error::Database { source: e })?;
        clients.push(ClientInfo {
            id: cauth.client_id,
            name: client_name.inner,
        });
    }

    let user_info = UserInfo {
        id: user_record.id().unwrap(),
        login: user_record.username().unwrap(),
        name: user_record.given_name().unwrap(),
        authorized_clients: clients,
    };

    Ok(web::Json(user_info))
}

#[derive(Debug, Deserialize)]
pub struct ChangeResource {
    pub given_name: String,
}

#[derive(Debug, Default, Serialize)]
pub struct MsgReply {
    pub success: bool,
}

async fn update_account_name(
    db: web::Data<Database>,
    form: Json<ChangeResource>,
    grant: Result<Grant<Write<Account>>, actix_web::Error>,
) -> Result<web::Json<MsgReply>, actix_web::Error> {
    tracing::debug!("enter -> update_account_name()");
    // Both extractors defer their verdict, so neither aborts the other mid-flight:
    // a tuple of extractors resolves the instant one of them fails, dropping the
    // futures still pending, and an abandoned body reader leaves the request
    // payload unread — which puts `Connection: close` on the response. Reporting
    // the grant first here keeps the authorization failure ahead of a body error.
    let grant = grant?;
    let form = form.into_inner()?;
    let mut db = db.as_ref().clone();
    let u = grant.grant.owner_id;
    let success = db
        .update_given_name_by_id(&AuthUser::from_str(&u).unwrap(), &form.given_name)
        .await
        .map_err(|e| Error::Database { source: e })?;

    let res = MsgReply { success };

    Ok(web::Json(res))
}
