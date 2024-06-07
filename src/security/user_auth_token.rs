use actix_web::dev::ServiceRequest;
use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserAuthToken {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    // Custom claims
    pub roles: Vec<Role>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub enum Role {
    ADMIN,
    USER,
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::convert::Into<String> for Role {
    fn into(self) -> String {
        match self {
            Role::ADMIN => "ADMIN".to_string(),
            Role::USER => "USER".to_string(),
        }
    }
}

impl std::convert::From<&str> for Role {
    fn from(value: &str) -> Role {
        match value {
            "ADMIN" => Role::ADMIN,
            "USER" => Role::USER,
            _ => panic!("Unrecognized role type {}", value),
        }
    }
}

impl UserAuthToken {
    pub fn new(sub: String, roles: Vec<Role>, exp: u64) -> UserAuthToken {
        return UserAuthToken {
            sub,
            iat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            exp,
            roles,
        };
    }

    pub fn encode(&self, key: &EncodingKey) -> Result<String> {
        let encoded_str = encode(&Header::default(), self, key)?;
        Ok(encoded_str)
    }

    pub fn decode(token: &String, key: &DecodingKey) -> Result<TokenData<UserAuthToken>> {
        let token_data = decode::<UserAuthToken>(token, key, &Validation::default())?;
        Ok(token_data)
    }

    pub fn from_service_request(value: &ServiceRequest, key: &DecodingKey) -> Result<UserAuthToken> {
        let token_text = value.cookie("JWT-TOKEN").ok_or(anyhow!("Missing token cookie"))?.value().to_string();
        Ok(UserAuthToken::decode(&token_text, key)?.claims)
    }
}
