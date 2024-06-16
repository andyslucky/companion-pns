use crate::TokenKeys;
use anyhow::anyhow;
use confique::Config;
use jsonwebtoken::{DecodingKey, EncodingKey};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::path::PathBuf;

#[derive(Config)]
pub struct AppConfig {
    #[config(env = "PORT", default = 8080)]
    pub port: u16,

    #[config(env = "REQUEST_RATE_LIMIT", default = 20)]
    pub request_rate_limit: u32,

    #[config(env = "REQUEST_RATE_LIMIT_TIME", default = 3)]
    pub request_rate_limit_time: u64,

    #[config(nested)]
    pub log_config: LogConfig,

    #[config(nested)]
    pub encoding_config: TokenEncodingConfig,

    #[config(nested)]
    pub db_config: DbConfig,
}

impl AppConfig {
    pub fn load() -> anyhow::Result<AppConfig> {
        Ok(AppConfig::builder().env().load()?)
    }
}

#[derive(Config)]
pub struct LogConfig {
    #[config(env = "LOG_LEVEL", default = "info")]
    pub log_legel: String,

    #[config(env = "REQUEST_LOG_FORMAT", default = "Peer: %{r}a Request: %r Status: %s Time-Taken: %T(s)")]
    pub request_log_format: String,
}

impl LogConfig {
    pub fn init_logger(&self) {
        env_logger::init_from_env(env_logger::Env::new().filter_or("LOG_LEVEL", &self.log_legel));
    }
}

#[derive(Config)]
pub struct TokenEncodingConfig {
    #[config(env = "TOKEN_SECRET_KEY")]
    secret: Option<String>,

    #[config(env = "TOKEN_SECRET_KEY_FILE")]
    secret_file: Option<PathBuf>,
}

impl TokenEncodingConfig {
    fn secret_value(&self) -> anyhow::Result<String> {
        return if let Some(file) = &self.secret_file {
            Ok(std::fs::read_to_string(file).map(|s| s.to_string())?)
        } else if let Some(pass) = &self.secret {
            Ok(pass.clone())
        } else {
            Err(anyhow!("No encoding secret / secret file was specified"))
        };
    }
    pub fn encoding_keys(&self) -> anyhow::Result<TokenKeys> {
        let secret_val = self.secret_value()?;
        Ok(TokenKeys {
            encoding_key: EncodingKey::from_secret(secret_val.as_ref()),
            decoding_key: DecodingKey::from_secret(secret_val.as_ref()),
        })
    }
}

#[derive(Config)]
pub struct DbConfig {
    #[config(env = "DB_HOST")]
    host: String,
    #[config(env = "DB_PORT")]
    port: u16,
    #[config(env = "DB_NAME")]
    db_name: String,
    #[config(env = "DB_USER")]
    db_user: String,
    #[config(env = "DB_PASSWORD")]
    db_pass: Option<String>,
    #[config(env = "DB_PASSWORD_FILE")]
    db_pass_file: Option<PathBuf>,
    #[config(env = "DB_MAX_CONNECTIONS", default = 10)]
    max_connections: u32,
    #[config(env = "ADMIN_USER")]
    pub admin_user: Option<String>,
    #[config(env = "ADMIN_PASSWORD")]
    admin_password: Option<String>,
    #[config(env = "ADMIN_PASSWORD_FILE")]
    admin_password_file: Option<PathBuf>,
}

impl DbConfig {
    pub fn admin_password(&self) -> anyhow::Result<Option<String>> {
        return if let Some(file) = &self.admin_password_file {
            Ok(Some(std::fs::read_to_string(file).map(|s| s.to_string())?))
        } else {
            Ok(self.admin_password.clone())
        };
    }

    fn password(&self) -> anyhow::Result<String> {
        return if let Some(file) = &self.db_pass_file {
            Ok(std::fs::read_to_string(file).map(|s| s.to_string())?)
        } else if let Some(pass) = &self.db_pass {
            Ok(pass.clone())
        } else {
            Err(anyhow!("No db password / password file was specified"))
        };
    }

    pub async fn create_pool(&self) -> anyhow::Result<PgPool> {
        let pool = PgPoolOptions::new()
            .max_connections(self.max_connections)
            .connect(format!("postgress://{}:{}@{}:{}/{}", self.db_user, self.password()?, self.host, self.port, self.db_name).as_str())
            .await?;
        Ok(pool)
    }
}
