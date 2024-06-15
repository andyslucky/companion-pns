mod api;
mod config;
mod db;
mod security;
mod serialization;
use actix_files::Files;
use actix_web::{
    cookie::{time::OffsetDateTime, Cookie},
    dev::{Service, ServiceResponse},
    error::ErrorUnauthorized,
    get, route, web,
    web::Data,
    App, HttpMessage, HttpResponse, HttpServer,
};
use anyhow::Context;
use config::AppConfig;
use futures::future::{
    ready,
    Either::{Left, Right},
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use log::info;
use security::{user_auth_token::*, ApiTokenService, UserAuthTokenService};
use sqlx::{migrate::Migrator, postgres::PgPool};
use std::{ops::Deref, path::Path};
use tera::Tera;

const ACTIVE_ROUTE: &str = "active_route";

#[derive(Clone)]
pub struct TokenKeys {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
}

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

#[route("/dashboard", method = "GET", method = "POST")]
async fn dashboard(user_auth_token: web::ReqData<UserAuthToken>, tera_context: web::ReqData<tera::Context>, tera: Data<Tera>) -> HttpResponse {
    let mut context = tera::Context::new();
    context.extend((*tera_context).clone());
    context.insert("user_auth", user_auth_token.deref());
    match tera.render("dashboard.html", &context) {
        Ok(content) => HttpResponse::Ok().body(content),
        Err(e) => {
            println!("An error occurred while rendering home file: {:?}", e);
            HttpResponse::InternalServerError().body("Sorry for the inconvenience")
        }
    }
}

async fn init_db_pool(app_config: &AppConfig) -> anyhow::Result<PgPool> {
    let pool = app_config.db_config.create_pool().await?;
    let migrator = Migrator::new(Path::new("db/migrations")).await?;
    migrator.run(&pool).await?;
    if let (Some(admin_user), Some(admin_password)) = (&app_config.db_config.admin_user, &app_config.db_config.admin_password()?) {
        info!("Admin user and password environment variables were found. Creating admin user if it doesn't already exist.");
        db::create_default_admin_user(&pool, admin_user, admin_password).await?;
    }

    Ok(pool)
}

async fn health() -> &'static str {
    "healthy"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    #[cfg(debug_assertions)]
    match dotenvy::dotenv() {
        Err(e) => {
            eprintln!("Failed initializing env from dotenvy {}", e);
        }
        _ => {}
    }
    let app_config = AppConfig::load().map_err(std::io::Error::other)?;

    app_config.log_config.init_logger();

    let pool: PgPool = init_db_pool(&app_config)
        .await
        .context("Failed to connect to database")
        .map_err(std::io::Error::other)?;

    let rate_limit_config = security::create_gov_config().map_err(std::io::Error::other)?;
    let token_keys = app_config.encoding_config.encoding_keys().map_err(std::io::Error::other)?;

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(token_keys.clone()))
            .app_data(Data::new(Tera::new("ui/templates/**/*.html").expect("")))
            .app_data(Data::new(pool.clone()))
            .service(Files::new("/static", "./ui/static").show_files_listing())
            .service(web::redirect("/", "/ui/"))
            .service(web::redirect("", "/ui/"))
            .service(
                web::scope("/ui")
                    .wrap_fn(|req, srv| {
                        let authorized = {
                            let extensions = req.extensions();
                            extensions.get::<UserAuthToken>().is_some()
                        };

                        if !authorized && req.path() == "/ui/dashboard" {
                            Right(ready(Ok(ServiceResponse::new(
                                req.into_parts().0,
                                HttpResponse::TemporaryRedirect().append_header(("Location", "/ui/login")).finish(),
                            ))))
                        } else if authorized && req.path() == "/ui/login" {
                            Right(ready(Ok(ServiceResponse::new(
                                req.into_parts().0,
                                HttpResponse::TemporaryRedirect().append_header(("Location", "/ui/dashboard")).finish(),
                            ))))
                        } else {
                            Left(srv.call(req))
                        }
                    })
                    .wrap_fn(|req, srv| {
                        let mut context = tera::Context::new();
                        context.insert(ACTIVE_ROUTE, req.path());
                        req.extensions_mut().insert(context);
                        srv.call(req)
                    })
                    .wrap(UserAuthTokenService::new())
                    .service(home)
                    .service(login)
                    .service(logout)
                    .service(dashboard),
            )
            .service(
                web::scope("/users")
                    .wrap_fn(|req, srv| {
                        let authorized = {
                            let extensions = req.extensions();
                            extensions.get::<UserAuthToken>().is_some()
                        };
                        if authorized || (req.path() == "/users/login" || req.path() == "/users/register" || req.path() == "/users/username-available") {
                            Left(srv.call(req))
                        } else {
                            Right(ready(Err(ErrorUnauthorized("Access denied"))))
                        }
                    })
                    .wrap(UserAuthTokenService::new())
                    .service(api::users::create_api_token)
                    .service(api::users::user_api_tokens)
                    .service(api::users::delete_api_token)
                    .service(api::users::add_admin_user)
                    .service(api::users::register_user)
                    .service(api::users::user_login)
                    .service(api::users::check_username_available),
            )
            .service(
                web::scope("/api")
                    .wrap(ApiTokenService::new())
                    .wrap(actix_governor::Governor::new(&rate_limit_config))
                    .service(api::devices::register_user_device),
            )
            .route("/health", web::get().to(health))
            .wrap(actix_web::middleware::Logger::new(app_config.log_config.request_log_format.as_ref()))
    })
    .bind(("0.0.0.0", app_config.port))?
    .run()
    .await
}
