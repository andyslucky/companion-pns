use crate::{
    api::ErrorResponse,
    db::{self, FetchUserError},
};
use actix_governor::{
    governor::{clock::QuantaInstant, middleware::NoOpMiddleware},
    GovernorConfig, GovernorConfigBuilder, PeerIpKeyExtractor,
};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::StatusCode,
    web::{self, Data},
    HttpMessage,
};
use log::{error, info};
use sqlx::PgPool;
use std::{
    env,
    future::{ready, Ready},
};

use futures::future::LocalBoxFuture;

use crate::{TokenKeys, UserAuthToken};

use self::api_token::ApiToken;

pub mod api_token;
pub mod user_auth_token;

pub struct UserAuthTokenService;

impl UserAuthTokenService {
    pub fn new() -> UserAuthTokenService {
        return UserAuthTokenService {};
    }
}

impl<S, B> Transform<S, ServiceRequest> for UserAuthTokenService
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::error::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::error::Error;
    type InitError = ();
    type Transform = UserAuthTokenServiceMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(UserAuthTokenServiceMiddleware { service }))
    }
}

pub struct UserAuthTokenServiceMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for UserAuthTokenServiceMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::error::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::error::Error;
    type Future = S::Future;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let token_keys: &Data<TokenKeys> = req.app_data::<Data<TokenKeys>>().expect("Could not find token keys");
        match UserAuthToken::from_service_request(&req, &token_keys.decoding_key) {
            Ok(api_token) => {
                req.extensions_mut().insert(api_token);
            }
            Err(e) => {
                error!("Error reading user auth token from cookie {:?}", e);
            }
        }
        self.service.call(req)
    }
}

// API Token middleware

pub struct ApiTokenService;
impl ApiTokenService {
    pub fn new() -> ApiTokenService {
        return ApiTokenService {};
    }
}

impl<S, B> Transform<S, ServiceRequest> for ApiTokenService
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::error::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::error::Error;
    type InitError = ();
    type Transform = ApiTokenServiceMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ApiTokenServiceMiddleware { service }))
    }
}

pub struct ApiTokenServiceMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for ApiTokenServiceMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::error::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::error::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, S::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let token_keys: &Data<TokenKeys> = req.app_data::<Data<TokenKeys>>().expect("Could not find token keys");
        let api_token = ApiToken::from_service_request(&req, &token_keys.decoding_key);

        // Get username from token
        let user: Option<String> = match api_token {
            Ok(token) => {
                req.extensions_mut().insert(token.clone());
                Some(token.sub.clone())
            }
            _ => None,
        };

        // Task to see if user is enabled
        let db_pool = req.app_data::<web::Data<PgPool>>().cloned().unwrap();
        let user_enabled = async move {
            match user {
                Some(val) => {
                    return db::user_is_enabled(&db_pool, &val)
                        .await
                        .map_err(|e| match e.root_cause().downcast_ref::<FetchUserError>() {
                            Some(FetchUserError::UserNotFound) => ErrorResponse::new(StatusCode::UNAUTHORIZED, "Access denied."),
                            _ => ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "An error occurred"),
                        });
                }
                // If there is no username, then the token is missing and the request is Unauthorized
                None => {
                    return Err(ErrorResponse::new(StatusCode::UNAUTHORIZED, "Access denied").into());
                }
            }
        };
        let fut = self.service.call(req);
        return Box::pin(async move {
            if !user_enabled.await? {
                return Err(ErrorResponse::new(StatusCode::UNAUTHORIZED, "Access denied").into());
            } else {
                return Ok(fut.await?);
            }
        });
    }
}

pub fn create_gov_config() -> anyhow::Result<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware<QuantaInstant>>> {
    let rate_limit_time: u64 = env::var("RATE_LIMIT_TIME").ok().map(|val| val.parse().ok()).flatten().unwrap_or(3);

    let rate_limit_burst_size: u32 = env::var("RATE_LIMIT_BURST_SIZE").ok().map(|val| val.parse().ok()).flatten().unwrap_or(20);
    info!("Rate limiting configured to {} requests / {} seconds", rate_limit_burst_size, rate_limit_time);
    // TODO Add sub (user_id) check (instead of just ip address) in the governor.
    GovernorConfigBuilder::default()
        .per_second(rate_limit_time)
        .burst_size(rate_limit_burst_size)
        .finish()
        .ok_or(anyhow::anyhow!("Could not create rate limiter config"))
}
