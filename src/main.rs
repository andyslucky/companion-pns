mod api;
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
use futures::future::{
    ready,
    Either::{Left, Right},
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use log::info;
use security::{user_auth_token::*, ApiTokenService, UserAuthTokenService};
use sqlx::{
    migrate::Migrator,
    postgres::{PgPool, PgPoolOptions},
};
use std::{env, ops::Deref, path::Path};
use tera::Tera;

const ACTIVE_ROUTE: &str = "active_route";

#[derive(Clone)]
pub struct TokenKeys {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
}

#[route("/", method = "GET", method = "POST")]
async fn home(tera: web::Data<Tera>, tera_context: web::ReqData<tera::Context>, user_auth_token: Option<web::ReqData<UserAuthToken>>) -> HttpResponse {
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
async fn login(tera: web::Data<Tera>, tera_context: web::ReqData<tera::Context>) -> HttpResponse {
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
async fn dashboard(user_auth_token: web::ReqData<UserAuthToken>, tera_context: web::ReqData<tera::Context>, tera: web::Data<Tera>) -> HttpResponse {
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

async fn init_db_pool() -> anyhow::Result<PgPool> {
    let db_host = env::var("DB_HOST").context("Missing DB_HOST environment variable")?;
    let db_name = env::var("DB_NAME").context("Missing DB_NAME environment variable")?;
    let db_user = env::var("DB_USER").context("Missing DB_USER environment variable")?;
    let db_port = env::var("DB_PORT").ok().unwrap_or("5432".to_string());
    let db_pass;
    if let Some(pass) = env::var("DB_PASSWORD_FILE").ok().and_then(|pwfile| std::fs::read_to_string(pwfile).ok()) {
        db_pass = pass;
    } else {
        db_pass = env::var("DB_PASSWORD").context("Missing DB_PASSWORD or DB_PASSWORD_FILE environment variable")?;
    }
    let db_max_connections: u32 = env::var("DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|max_con_str| max_con_str.parse().ok())
        .unwrap_or(10);
    let pool = PgPoolOptions::new()
        .max_connections(db_max_connections)
        .connect(format!("postgress://{}:{}@{}:{}/{}", db_user, db_pass, db_host, db_port, db_name).as_str())
        .await?;
    let migrator = Migrator::new(Path::new("db/migrations")).await?;
    migrator.run(&pool).await?;
    let (admin_user, admin_password) = (env::var("ADMIN_USER"), env::var("ADMIN_PASSWORD"));
    if admin_user.is_ok() && admin_password.is_ok() {
        info!("Admin user and password environment variables were found. Creating admin user if it doesn't already exist.");
        db::create_default_admin_user(&pool, &admin_user?, &admin_password?).await?;
    }

    Ok(pool)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    match dotenvy::dotenv() {
        Err(e) => {
            eprintln!("Failed initializing env from dotenvy {}", e);
        }
        _ => {}
    }
    env_logger::init_from_env(env_logger::Env::new().filter_or("LOG_LEVEL", "info"));

    let pool: PgPool = init_db_pool().await.context("Failed to connect to database").map_err(std::io::Error::other)?;

    let rate_limit_config = security::create_gov_config().map_err(std::io::Error::other)?;
    let token_secret;
    if let Some(secret) = env::var("TOKEN_SECRET_KEY_FILE")
        .ok()
        .and_then(|secret_file| std::fs::read_to_string(secret_file).ok())
    {
        token_secret = secret;
    } else {
        token_secret = env::var("TOKEN_SECRET_KEY")
            .context("Could not find token secret. Please set the TOKEN_SECRET_KEY environment variable")
            .map_err(std::io::Error::other)?;
    }

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(TokenKeys {
                encoding_key: EncodingKey::from_secret(token_secret.as_ref()),
                decoding_key: DecodingKey::from_secret(token_secret.as_ref()),
            }))
            .app_data(web::Data::new(Tera::new("ui/templates/**/*.html").expect("")))
            .app_data(web::Data::new(pool.clone()))
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
                        if authorized || req.path() != "/ui/dashboard" {
                            Left(srv.call(req))
                        } else {
                            Right(ready(Ok(ServiceResponse::new(
                                req.into_parts().0,
                                HttpResponse::TemporaryRedirect().append_header(("Location", "/ui/login")).finish(),
                            ))))
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
            .wrap(actix_web::middleware::Logger::new("%a %r %s %{User-Agent}i"))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
