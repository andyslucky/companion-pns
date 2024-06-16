use std::fmt::Display;

use crate::db;
use actix_web::{post, web, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;

use crate::{api::ErrorResponse, security::api_token::ApiToken};

#[derive(Deserialize, Debug)]
pub enum DevicePlatform {
    IOS,
    ANDROID,
}

impl Display for DevicePlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DeviceRegistrationRequest {
    device_id: String,
    device_platform: DevicePlatform,
}

/// Registers a device
#[post("/devices/register")]
async fn register_user_device(
    db_pool: web::Data<PgPool>,
    request: web::Json<DeviceRegistrationRequest>,
    api_token: web::ReqData<ApiToken>,
) -> actix_web::Result<HttpResponse> {
    db::register_device(&**db_pool, &api_token.sub, &request.device_id, &request.device_platform)
        .await
        .map_err(|e| match e.downcast_ref::<sqlx::error::Error>() {
            Some(sqlx::error::Error::Database(dbe)) if dbe.is_unique_violation() => ErrorResponse::bad_request("Device already registered.").into(),
            _ => actix_web::error::ErrorInternalServerError("An error occurred while registering"),
        })?;
    Ok(HttpResponse::Ok().json("Registered"))
}
