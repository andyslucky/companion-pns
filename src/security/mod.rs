use crate::{
    api::ErrorResponse,
    db::{self, FetchUserError},
};
use actix_governor::{
    governor::{clock::QuantaInstant, middleware::NoOpMiddleware},
    GovernorConfig, GovernorConfigBuilder, PeerIpKeyExtractor,
};
use actix_web::body::BoxBody;
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    web::Data,
    Error, HttpMessage, HttpResponse,
};
use actix_web_lab::middleware::Next;
use sqlx::PgPool;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use crate::config::AppConfig;
use crate::{TokenKeys, UserAuthToken};

use self::api_token::ApiToken;

pub mod api_token;
pub mod user_auth_token;

// User token middleware
pub async fn redirect_login_if_already_authenticated(req: ServiceRequest, next: Next<BoxBody>) -> Result<ServiceResponse, Error> {
    let authorized = req.extensions().get::<UserAuthToken>().is_some();
    if authorized && req.path() == "/ui/login" {
        Ok(ServiceResponse::new(
            req.into_parts().0,
            HttpResponse::TemporaryRedirect().append_header(("Location", "/ui/dashboard")).finish(),
        ))
    } else {
        next.call(req).await
    }
}

pub async fn parse_user_auth_token(req: ServiceRequest, next: Next<BoxBody>) -> Result<ServiceResponse, Error> {
    let token_keys: &Data<TokenKeys> = req
        .app_data::<Data<TokenKeys>>()
        .ok_or(actix_web::error::ErrorInternalServerError("An unrecoverable error occurred"))?;
    if let Ok(api_token) = UserAuthToken::from_service_request(&req, &token_keys.decoding_key) {
        req.extensions_mut().insert(api_token);
    }
    next.call(req).await
}

pub async fn require_user_auth(req: ServiceRequest, next: Next<BoxBody>) -> Result<ServiceResponse, Error> {
    let authorized = req.extensions().get::<UserAuthToken>().is_some();
    if authorized {
        next.call(req).await
    } else {
        Ok(ServiceResponse::new(
            req.into_parts().0,
            HttpResponse::TemporaryRedirect().append_header(("Location", "/ui/login")).finish(),
        ))
    }
}

pub fn require_user_auth_excluding_endpoints(
    excluded_endpoints: HashSet<&'static str>,
) -> impl Fn(ServiceRequest, Next<BoxBody>) -> Pin<Box<dyn Future<Output = Result<ServiceResponse, Error>>>> {
    move |req: ServiceRequest, next: Next<BoxBody>| {
        if excluded_endpoints.contains(req.path()) {
            Box::pin(next.call(req))
        } else {
            Box::pin(require_user_auth(req, next))
        }
    }
}

// API Token middleware
pub async fn require_valid_api_token(req: ServiceRequest, next: Next<BoxBody>) -> Result<ServiceResponse, Error> {
    let token_keys: &Data<TokenKeys> = req
        .app_data::<Data<TokenKeys>>()
        .ok_or(ErrorResponse::internal_server_error("An unrecoverable error occurred"))?;
    let db_pool = req
        .app_data::<Data<PgPool>>()
        .cloned()
        .ok_or(ErrorResponse::internal_server_error("An unrecoverable error occurred"))?;
    let api_token = ApiToken::from_service_request(&req, &token_keys.decoding_key).map_err(|_| ErrorResponse::unauthorized("Access denied"))?;

    // Add token to request context
    req.extensions_mut().insert(api_token.clone());

    let user_enabled = db::user_is_enabled(&db_pool, &api_token.sub)
        .await
        .map_err(|e| match e.root_cause().downcast_ref::<FetchUserError>() {
            Some(FetchUserError::UserNotFound) => ErrorResponse::unauthorized("Access denied."),
            _ => ErrorResponse::internal_server_error("An error occurred"),
        })?;
    if user_enabled {
        next.call(req).await
    } else {
        Err(ErrorResponse::unauthorized("Access denied.").into())
    }
}

pub fn create_gov_config(app_config: &AppConfig) -> anyhow::Result<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware<QuantaInstant>>> {
    // TODO Add sub (user_id) check (instead of just ip address) in the governor.
    GovernorConfigBuilder::default()
        .per_second(app_config.request_rate_limit_time)
        .burst_size(app_config.request_rate_limit)
        .finish()
        .ok_or(anyhow::anyhow!("Could not create rate limiter config"))
}
