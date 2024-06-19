use crate::{
    api::ErrorResponse,
    db::{self, FetchUserError, MapActixError, User},
    security::{api_token::ApiToken, user_auth_token::*},
    TokenKeys,
};
use actix_web::{
    cookie::{time::OffsetDateTime, Cookie},
    get,
    http::StatusCode,
    post, web, HttpResponse, HttpResponseBuilder,
};
use log::error;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, FromRow, PgPool};

use actix_web_lab::middleware::from_fn;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct UserLoginSignUpRequest {
    user_id: String,
    password: String,
}

#[post("/register")]
pub async fn register_user(
    request_body: web::Json<UserLoginSignUpRequest>,
    token_keys: web::Data<TokenKeys>,
    db_pool: web::Data<PgPool>,
) -> actix_web::Result<HttpResponse> {
    let user = db::create_user(&**db_pool, &request_body.user_id, &request_body.password).await.map_err(|e| {
        match e.root_cause().downcast_ref::<sqlx::error::Error>() {
            Some(sqlx::Error::Database(dbe)) if dbe.is_unique_violation() => ErrorResponse::new(StatusCode::BAD_REQUEST, "Please choose a different username"),
            _ => ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "An error occurred while registering"),
        }
    })?;

    Ok(create_token_response(&user, &token_keys).1.finish())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsernameAvailableQueryParams {
    user_name: String,
}

#[get("/username-available")]
async fn check_username_available(query_params: web::Query<UsernameAvailableQueryParams>, db_pool: web::Data<PgPool>) -> actix_web::Result<HttpResponse> {
    let available: bool = sqlx::query("SELECT TRUE as exists FROM users WHERE user_name = $1;")
        .bind(&query_params.user_name)
        .fetch_optional(&**db_pool)
        .await
        .map_actix_error(StatusCode::INTERNAL_SERVER_ERROR, "An error occurred checking if username exists")?
        .is_none();

    Ok(HttpResponse::Ok().json(available))
}

#[post("/login")]
pub async fn user_login(
    request_body: web::Json<UserLoginSignUpRequest>,
    token_keys: web::Data<TokenKeys>,
    db_pool: web::Data<PgPool>,
) -> actix_web::Result<HttpResponse> {
    let user =
        db::fetch_user(&**db_pool, &request_body.user_id, &request_body.password)
            .await
            .map_err(|e| match e.root_cause().downcast_ref::<FetchUserError>() {
                Some(FetchUserError::UserNotFound) | Some(FetchUserError::InvalidPassword) => {
                    ErrorResponse::new(StatusCode::BAD_REQUEST, "Invalid username or password")
                }
                None => ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "An error occurred logging in."),
            })?;

    Ok(create_token_response(&user, &token_keys).1.finish())
}

fn create_token_response(user: &User, token_keys: &TokenKeys) -> (UserAuthToken, HttpResponseBuilder) {
    let expiry = time::OffsetDateTime::now_utc() + time::Duration::minutes(15);
    let user_auth_token = UserAuthToken::new(user.user_name.clone(), user.roles.clone(), expiry.unix_timestamp() as u64);
    let token = user_auth_token.encode(&token_keys.encoding_key).expect("Could not create token");

    let mut redirect_response: HttpResponseBuilder = HttpResponse::Ok();
    redirect_response.cookie(
        Cookie::build("JWT-TOKEN", token)
            .domain("localhost")
            .path("/")
            .expires(expiry)
            .http_only(true)
            .finish(),
    );
    return (user_auth_token, redirect_response);
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiTokenRequest {
    token_name: String,
    #[serde(deserialize_with = "crate::serialization::deserialize_offset_datetime")]
    token_expiration: OffsetDateTime,
}

#[post("/create-api-token")]
async fn create_api_token(
    create_token_request: web::Json<CreateApiTokenRequest>,
    user_auth_token: web::ReqData<UserAuthToken>,
    token_keys: web::Data<TokenKeys>,
    db_pool: web::Data<PgPool>,
) -> actix_web::Result<HttpResponse> {
    let api_token: ApiToken = db::create_api_token(
        &**db_pool,
        &user_auth_token.sub,
        &create_token_request.token_name,
        &create_token_request.token_expiration,
    )
    .await
    .map_err(|e| {
        error!("Failed to create api token {}", e);
        ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create api token.")
    })?;
    Ok(HttpResponse::Ok().json(
        api_token
            .encode(&token_keys.encoding_key)
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?,
    ))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeleteApiTokenRequest {
    token_id: i64,
}

#[post("/delete-api-token")]
async fn delete_api_token(
    delete_api_token_request: web::Json<DeleteApiTokenRequest>,
    user_auth_token: web::ReqData<UserAuthToken>,
    db_pool: web::Data<PgPool>,
) -> actix_web::Result<HttpResponse> {
    sqlx::query(
        r#"
        DELETE FROM api_tokens WHERE user_name = $1 and token_id = $2
    "#,
    )
    .bind(&user_auth_token.sub)
    .bind(&delete_api_token_request.token_id)
    .execute(&**db_pool)
    .await
    .map_actix_error(StatusCode::INTERNAL_SERVER_ERROR, "An error occurred while deleting API token")?;

    Ok(HttpResponse::Ok().finish())
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct ApiTokenInfo {
    token_id: i32,
    token_name: String,
    #[serde(serialize_with = "crate::serialization::serialize_offset_datetime")]
    token_expiration: OffsetDateTime,
}

#[get("/api-tokens")]
async fn user_api_tokens(user_auth_token: web::ReqData<UserAuthToken>, db_pool: web::Data<PgPool>) -> actix_web::Result<HttpResponse> {
    let tokens: Vec<ApiTokenInfo> = sqlx::query(
        r#"
        SELECT token_id, token_description as token_name, token_expiration
        FROM api_tokens
        WHERE user_name = $1
    "#,
    )
    .bind(&user_auth_token.sub)
    .try_map(|row: PgRow| ApiTokenInfo::from_row(&row))
    .fetch_all(&**db_pool)
    .await
    .map_err(|e| {
        error!("An error occurred while fetching tokens: {}", e);
        actix_web::error::ErrorInternalServerError("An error occurred while creating token")
    })?;
    Ok(HttpResponse::Ok().json(tokens))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddAdminRequest {
    user_id: String,
}
#[post("/add-admin", wrap = "from_fn(crate::security::user_is_admin)")]
async fn add_admin_user(request: web::Form<AddAdminRequest>, db_pool: web::Data<PgPool>) -> actix_web::Result<HttpResponse> {
    sqlx::query("INSERT INTO user_roles (user_name, role_name) VALUES($1, $2)")
        .bind(&request.user_id)
        .bind(Role::ADMIN.to_string())
        .execute(&**db_pool)
        .await
        .map_actix_error(StatusCode::INTERNAL_SERVER_ERROR, "An error occurred while setting user to admin")?;
    Ok(HttpResponse::Ok().finish())
}
