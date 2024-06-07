use actix_web::{dev::ServiceRequest, http::header};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ApiToken {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub token_id : i32
}

impl ApiToken {
    pub fn new(sub: String, exp: u64, token_id : i32) -> ApiToken {
        return ApiToken {
            sub,
            iat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            exp,
            token_id
        };
    }

    pub fn encode(&self, key: &EncodingKey) -> Result<String> {
        let encoded_str = encode(&Header::default(), self, key)?;
        Ok(encoded_str)
    }

    pub fn decode(
        token: &String,
        key: &DecodingKey,
    ) -> Result<TokenData<ApiToken>> {
        let token_data = decode::<ApiToken>(token, key, &Validation::default())?;
        return Ok(token_data)
    }
    
    pub fn from_service_request(value : &ServiceRequest, key : &DecodingKey) -> Result<ApiToken> {
        let token_text : String = value.headers().get(header::AUTHORIZATION).ok_or(anyhow!("Missing bearer token"))?.to_str()?.trim_start_matches("Bearer ").to_string();
        Ok(ApiToken::decode(&token_text, key)?.claims)
    }
}
