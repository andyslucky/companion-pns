
use std::fmt::Display;
use actix_web::{HttpResponse, http::StatusCode};
use serde::Serialize;

pub mod users;
pub mod devices;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    #[serde(skip_serializing)]
    status : StatusCode,
    message : String
}

impl ErrorResponse {
    pub fn new<S : AsRef<str>>(status : StatusCode, message : S) -> ErrorResponse {
        return ErrorResponse { status,message:  String::from(message.as_ref())};
    }
}

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

impl actix_web::ResponseError for ErrorResponse {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        return HttpResponse::build(self.status).json(self);
    }
}