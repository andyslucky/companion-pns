use actix_web::web::ServiceConfig;
use actix_web::{http::StatusCode, HttpResponse};
use serde::Serialize;
use std::fmt::Display;

pub mod devices;
pub mod users;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    #[serde(skip_serializing)]
    status: StatusCode,
    message: String,
}

impl ErrorResponse {
    pub fn new<S: AsRef<str>>(status: StatusCode, message: S) -> ErrorResponse {
        return ErrorResponse {
            status,
            message: String::from(message.as_ref()),
        };
    }

    pub fn internal_server_error<S: AsRef<str>>(msg: S) -> ErrorResponse {
        return ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, msg);
    }

    pub fn unauthorized<S: AsRef<str>>(msg: S) -> ErrorResponse {
        return ErrorResponse::new(StatusCode::UNAUTHORIZED, msg);
    }

    pub fn forbidden<S: AsRef<str>>(msg: S) -> ErrorResponse {
        return ErrorResponse::new(StatusCode::FORBIDDEN, msg);
    }

    pub fn bad_request<S: AsRef<str>>(msg: S) -> ErrorResponse {
        return ErrorResponse::new(StatusCode::BAD_REQUEST, msg);
    }
}

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

impl actix_web::ResponseError for ErrorResponse {
    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        return HttpResponse::build(self.status).json(self);
    }
}

pub fn configure_user_api(service_config: &mut ServiceConfig) {
    service_config
        .service(users::create_api_token)
        .service(users::user_api_tokens)
        .service(users::delete_api_token)
        .service(users::add_admin_user)
        .service(users::register_user)
        .service(users::user_login)
        .service(users::check_username_available);
}

pub fn configure_api(service_config: &mut ServiceConfig) {
    service_config.service(devices::register_user_device);
}
