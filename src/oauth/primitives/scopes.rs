use crate::oauth::scopes;

pub struct Grant<S = ()> {
    pub grant: oxide_auth::primitives::grant::Grant,
    _type: std::marker::PhantomData<S>,
}

use actix_web::{dev::Payload, error::InternalError, web, FromRequest, HttpRequest};
use futures::future::LocalBoxFuture;
use oxide_auth_actix::{OAuthResource, WebError};

impl<Scope> FromRequest for Grant<Scope>
where
    Scope: scopes::Scope + 'static,
{
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        tracing::debug!("Middleware: Grant<Scope>: parts: {:?}", req);
        let request = req.clone();
        let state = req
            .app_data::<web::Data<crate::oauth::state::State>>()
            .cloned();

        Box::pin(async move {
            let resource = OAuthResource::new(&request)?;

            let state = match state {
                Some(state) => state,
                None => return Err(WebError::InternalError(None).into()),
            };

            let auth = state
                .endpoint()
                .await
                .with_scopes(&[Scope::SCOPE.parse().unwrap()])
                .resource_flow()
                .execute(resource.into())
                .await;

            match auth {
                Ok(grant) => Ok(Self {
                    grant,
                    _type: Default::default(),
                }),
                Err(Ok(response)) => {
                    let response = crate::oauth::into_http_response(response, &request);
                    Err(InternalError::from_response(WebError::Authorization, response).into())
                }
                Err(Err(error)) => Err(error.into()),
            }
        })
    }
}
