use actix_web::http::StatusCode;
use anyhow::{ensure, Result};
use thiserror::Error;

use sqlx::{postgres::PgRow, query, PgPool, Row};

use crate::{api::devices::DevicePlatform, security::api_token::ApiToken, Role};
pub trait MapActixError<R> {
    fn map_actix_error<S: AsRef<str>>(self, status_code: StatusCode, msg: S) -> actix_web::Result<R>;
}

impl<T> MapActixError<T> for Result<T, sqlx::error::Error> {
    fn map_actix_error<S: AsRef<str>>(self, status_code: StatusCode, msg: S) -> actix_web::Result<T> {
        return self.map_err(|e| {
            log::error!("{}", e);
            crate::api::ErrorResponse::new(status_code, msg).into()
        });
    }
}

pub async fn create_default_admin_user(db_pool: &PgPool, user_id: &String, password: &String) -> Result<()> {
    let phash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    query(
        r#"
        WITH cteNewUser AS (
        INSERT INTO users (user_name, phash) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING user_name
        )
        INSERT INTO user_roles (user_name, role_name)
        SELECT user_name, 'ADMIN' FROM cteNewUser
        UNION ALL
        SELECT user_name, 'USER' FROM cteNewUser;
        "#,
    )
    .bind(user_id)
    .bind(&phash)
    .execute(db_pool)
    .await?;
    Ok(())
}

pub async fn fetch_user_roles(db_pool: &PgPool, user_id: &String) -> Result<Vec<Role>> {
    let roles = query("SELECT role_name FROM user_roles WHERE user_name = $1 ORDER BY role_name")
        .bind(user_id)
        .map(|row: PgRow| {
            let val: &str = row.get("role_name");
            Role::from(val)
        })
        .fetch_all(db_pool)
        .await?;
    Ok(roles)
}

#[derive(Error, Debug)]
pub enum FetchUserError {
    #[error("User does not exist / is disabled.")]
    UserNotFound,
    #[error("Invalid password")]
    InvalidPassword,
}

pub struct User {
    pub user_name: String,
    pub roles: Vec<Role>,
}

pub async fn fetch_user(db_pool: &PgPool, user_name: &String, password: &String) -> Result<User> {
    let existing_phash_fut = query("SELECT phash FROM users WHERE user_name = $1 AND enabled = true LIMIT 1")
        .bind(&user_name)
        .map(|row: PgRow| {
            let res: String = row.get("phash");
            res
        })
        .fetch_optional(db_pool);
    let (phash_res, roles_res) = futures::join!(existing_phash_fut, fetch_user_roles(db_pool, user_name));
    let phash = phash_res?.ok_or(FetchUserError::UserNotFound)?;
    let password_matches = bcrypt::verify(&password, phash.as_ref())?;
    ensure!(password_matches, FetchUserError::InvalidPassword);
    Ok(User {
        user_name: user_name.clone(),
        roles: roles_res?,
    })
}

pub async fn create_user(db_pool: &PgPool, user_name: &String, password: &String) -> Result<User> {
    let phash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    // Insert user into users table
    query(
        r#"
        WITH cteInsertedUser AS (
            INSERT INTO users (user_name, phash) VALUES($1, $2) RETURNING user_name
        )
        INSERT INTO user_roles (user_name, role_name)
        SELECT user_name, 'USER' FROM cteInsertedUser LIMIT 1; 
    "#,
    )
    .bind(user_name)
    .bind(&phash)
    .execute(db_pool)
    .await?;

    Ok(User {
        user_name: user_name.clone(),
        roles: vec![Role::USER],
    })
}

pub async fn user_is_enabled(db_pool: &PgPool, user_name: &String) -> Result<bool> {
    query("SELECT enabled FROM users WHERE user_name = $1")
        .bind(user_name)
        .map(|row: PgRow| {
            let enabled: bool = row.get("enabled");
            enabled
        })
        .fetch_optional(db_pool)
        .await?
        .ok_or(FetchUserError::UserNotFound.into())
}

pub async fn create_api_token(db_pool: &PgPool, user_name: &String, token_name: &String, token_expiration: &time::OffsetDateTime) -> Result<ApiToken> {
    let token_id: i32 = query(
        r#"
        INSERT INTO api_tokens (user_name, token_description, token_expiration)
        VALUES ($1, $2, $3) RETURNING token_id;
    "#,
    )
    .bind(user_name)
    .bind(token_name)
    .bind(token_expiration)
    .map(|row: PgRow| row.get("token_id"))
    .fetch_one(db_pool)
    .await?;
    Ok(ApiToken::new(user_name.clone(), token_expiration.unix_timestamp() as u64, token_id))
}

pub async fn register_device(db_pool: &PgPool, user_name: &String, device_id: &String, device_platform: &DevicePlatform) -> Result<()> {
    query("INSERT INTO user_devices (user_name, device_id, device_platform) VALUES ($1, $2, $3)")
        .bind(user_name)
        .bind(device_id)
        .bind(device_platform.to_string())
        .execute(db_pool)
        .await?;
    Ok(())
}
