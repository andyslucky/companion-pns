mod api;
mod config;
mod db;
mod security;
mod serialization;
mod ui;

use actix_files::Files;
use actix_web::{
    dev::Service,
    web::{self, Data},
    App, HttpMessage, HttpServer,
};
use actix_web_lab::middleware::from_fn;
use anyhow::Context;
use config::AppConfig;
use jsonwebtoken::{DecodingKey, EncodingKey};
use log::info;
use security::user_auth_token::*;
use sqlx::{migrate::Migrator, postgres::PgPool};
use std::collections::HashSet;
use std::io::Error as IoError;
use std::net::Ipv4Addr;
use std::path::Path;

const ACTIVE_ROUTE: &str = "active_route";

#[derive(Clone)]
pub struct TokenKeys {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
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
    let app_config = AppConfig::load().map_err(IoError::other)?;

    app_config.log_config.init_logger();

    let pool: PgPool = init_db_pool(&app_config)
        .await
        .context("Failed to connect to database")
        .map_err(IoError::other)?;

    let rate_limit_config = security::create_gov_config(&app_config).map_err(IoError::other)?;
    let token_keys = app_config.encoding_config.encoding_keys().map_err(IoError::other)?;
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(token_keys.clone()))
            .app_data(Data::new(pool.clone()))
            .service(Files::new("/static", "./ui/static").show_files_listing())
            .service(web::redirect("/", "/ui/"))
            .service(web::redirect("", "/ui/"))
            .service(
                web::scope("/ui")
                    .wrap_fn(|req, srv| {
                        let mut context = tera::Context::new();
                        context.insert(ACTIVE_ROUTE, req.path());
                        req.extensions_mut().insert(context);
                        srv.call(req)
                    })
                    .wrap(from_fn(security::redirect_login_if_already_authenticated))
                    .wrap(from_fn(security::parse_user_auth_token))
                    .configure(ui::configure_ui),
            )
            .service(
                web::scope("/users")
                    .wrap(from_fn(security::require_user_auth_excluding_endpoints(HashSet::from([
                        "/users/login",
                        "/users/register",
                        "/users/username-available",
                    ]))))
                    .wrap(from_fn(security::parse_user_auth_token))
                    .configure(api::configure_user_api),
            )
            .service(
                web::scope("/api")
                    .wrap(from_fn(security::require_valid_api_token))
                    .wrap(actix_governor::Governor::new(&rate_limit_config))
                    .configure(api::configure_api),
            )
            .route("/health", web::get().to(health))
            .wrap(actix_web::middleware::Logger::new(app_config.log_config.request_log_format.as_ref()))
    })
    .bind((app_config.address, app_config.port))?
    .run()
    .await
}
