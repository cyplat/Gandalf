use crate::domain::models::User;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct LoginRequestLocal {
    pub email: String,
    pub password: String,
}

// User registration with email and password
#[derive(Debug, Deserialize)]
pub struct RegistrationRequestLocal {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub user_id: Uuid,
    pub username: Option<String>,
    pub email: String,
    pub external_id: Option<String>,
    pub email_verified: bool,
    pub auth_provider: String,
    pub user_state: String,
    pub requires_mfa: bool,
    pub data_region: String,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            user_id: user.id,
            username: user.username,
            email: user.email,
            external_id: user.external_id,
            email_verified: user.email_verified,
            auth_provider: user.auth_provider.to_string(),
            user_state: user.user_state.to_string(),
            requires_mfa: user.requires_mfa,
            data_region: user.data_region,
            created_at: user.created_at.to_rfc3339(),
            last_login_at: user.last_login_at.map(|dt| dt.to_rfc3339()),
        }
    }
}
