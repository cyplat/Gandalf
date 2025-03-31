use crate::domain::models::User;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::error::{AuthError, Result};

type ResourceAccess = HashMap<String, HashMap<String, Vec<String>>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,          // User ID
    pub access_range: String, // Permissions/scope
    pub preferred_username: String,
    pub scope: String,
    pub sid: Uuid,                       // Session ID
    pub iss: String,                     // Issuer (auth server)
    pub aud: String,                     // Audience (client app)
    pub exp: i64,                        // Expiry time
    pub iat: i64,                        // Issued at
    pub jti: String,                     // Unique JWT ID (prevents replay attacks)
    pub nbf: i64,                        // Not before (optional)
    pub auth_time: i64,                  // Last authentication time
    pub resource_access: ResourceAccess, // Resource access permissions
}

impl JwtClaims {
    pub fn to_jwt(&self, secret: &str) -> Result<String> {
        let token = encode(
            &Header::new(Algorithm::HS256),
            &self,
            &EncodingKey::from_secret(secret.as_bytes()),
        )?;
        Ok(token)
    }
}
