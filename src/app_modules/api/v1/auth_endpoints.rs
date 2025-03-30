/*
 This module holds auth endpoints.

 created modules must be registered in routes.rs
*/

use crate::adapters::dtos::LoginRequestDto;
use crate::app_modules::api::v1::schemas::LoginRequestLocal;
use crate::app_modules::app_state::AppState;
use crate::app_modules::auth::AuthMethod;
use actix_web::{HttpResponse, Responder, get, post, web};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::env;
use tracing::{error, info};

#[post("/login")]
pub async fn login(
    app_state: web::Data<AppState>,
    login_request: web::Json<LoginRequestLocal>,
) -> impl Responder {
    // Extract request body
    let login_request = login_request.into_inner();

    // Get authentication strategy
    let strategy = match app_state
        .auth_service
        .strategies
        .get(&AuthMethod::EmailPassword)
    {
        Some(strategy) => strategy,
        None => {
            error!("Authentication method not supported");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Authentication method not supported",
                "code": "AUTH_METHOD_NOT_SUPPORTED"
            }));
        }
    };

    // Authenticate user
    match strategy
        .authenticate(LoginRequestDto {
            email: login_request.email.clone(),
            password: Some(login_request.password),
        })
        .await
    {
        Ok(_) => {
            // Generate JWT Token
            match generate_jwt(&login_request.email.clone()) {
                Ok(token) => HttpResponse::Ok().json(serde_json::json!({
                    "message": "Login successful",
                    "token": token
                })),
                Err(err) => {
                    error!("JWT Generation failed: {:?}", err);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to generate authentication token"
                    }))
                }
            }
        }
        Err(err) => {
            error!("Login failed: {:?}", err);
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid email or password"
            }))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (User ID or Email)
    exp: usize,  // Expiration Time
    iat: usize,  // Issued At
}

/// Generates a JWT token with an expiration time.
fn generate_jwt(email: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "mysecret".to_string());

    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24)) // Token valid for 24 hours
        .expect("Invalid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: email.to_owned(),
        exp: expiration,
        iat: Utc::now().timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}
