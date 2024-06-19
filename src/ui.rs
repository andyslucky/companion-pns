use crate::security::user_auth_token::UserAuthToken;
use actix_web::cookie::Cookie;
use actix_web::web::{Data, ServiceConfig};
use actix_web::{get, route, web, HttpResponse};
use actix_web_lab::middleware::from_fn;
use log::error;
use std::ops::Deref;
use tera::Tera;
use time::OffsetDateTime;

#[route("/", method = "GET", method = "POST")]
async fn home(tera: Data<Tera>, tera_context: web::ReqData<tera::Context>, user_auth_token: Option<web::ReqData<UserAuthToken>>) -> HttpResponse {
    let mut context = tera::Context::new();
    context.extend((*tera_context).clone());
    match user_auth_token {
        Some(token) => {
            context.insert("user_auth", &(*token));
        }
        _ => {}
    }

    match tera.render("home.html", &context) {
        Ok(content) => HttpResponse::Ok().body(content),
        Err(e) => {
            println!("An error occurred while rendering home file: {:?}", e);
            HttpResponse::InternalServerError().body("Sorry for the inconvenience")
        }
    }
}

#[get("/login")]
async fn login(tera: Data<Tera>, tera_context: web::ReqData<tera::Context>) -> HttpResponse {
    match tera.render("login.html", &tera_context) {
        Ok(content) => HttpResponse::Ok().body(content),
        Err(e) => {
            println!("An error occurred while rendering home file: {:?}", e);
            HttpResponse::InternalServerError().body("Sorry for the inconvenience")
        }
    }
}

#[route("/logout", method = "GET", method = "POST")]
async fn logout() -> HttpResponse {
    return HttpResponse::TemporaryRedirect()
        .insert_header(("Location", "/ui/"))
        .cookie(
            Cookie::build("JWT-TOKEN", "")
                .domain("localhost")
                .path("/")
                .expires(OffsetDateTime::UNIX_EPOCH)
                .http_only(true)
                .finish(),
        )
        .finish();
}

#[route("/dashboard", method = "GET", method = "POST", wrap = "from_fn(crate::security::require_user_auth)")]
async fn dashboard(user_auth_token: web::ReqData<UserAuthToken>, tera_context: web::ReqData<tera::Context>, tera: Data<Tera>) -> HttpResponse {
    let mut context = tera::Context::new();
    context.extend((*tera_context).clone());
    context.insert("user_auth", user_auth_token.deref());
    match tera.render("dashboard.html", &context) {
        Ok(content) => HttpResponse::Ok().body(content),
        Err(e) => {
            error!("An error occurred while rendering home file: {:?}", e);
            HttpResponse::InternalServerError().body("Sorry for the inconvenience")
        }
    }
}

pub fn configure_ui(service_config: &mut ServiceConfig) {
    service_config
        .app_data(Data::new(Tera::new("ui/templates/**/*.html").unwrap()))
        .service(home)
        .service(login)
        .service(logout)
        .service(dashboard);
}
