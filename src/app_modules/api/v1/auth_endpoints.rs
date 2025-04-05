/*
 This module holds auth endpoints.

 created modules must be registered in routes.rs
*/

use crate::adapters::dtos::LoginRequestDto;
use crate::app_modules::api::v1::schemas::LoginRequestLocal;
use crate::app_modules::app_state::AppState;
use crate::app_modules::auth::AuthMethod;
use crate::app_modules::auth::JwtClaims;
use crate::domain::models::User;
use crate::domain::services::AuthService;
use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::env;
use tracing::{error, info};

#[post("/login")]
pub async fn login(
    req: HttpRequest,
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
        Ok(user) => {
            info!("User authenticated: {:?}", user.id);
            // Generate JWT Token
            match app_state.auth_service.make_session(user, req).await {
                Ok(token) => HttpResponse::Ok().json(serde_json::json!({
                    "message": "Login successful",
                    "token": token
                })),
                Err(err) => {
                    error!("JWT Generation failed: {:?}", err);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Internal server error",
                        "code": "INTERNAL_SERVER_ERROR"
                    }))
                }
            }
        }
        Err(err) => {
            error!("Login failed: {:?}", err);
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid email or password",
                "code": "INVALID_CREDENTIALS"
            }))
        }
    }
}
