use actix_web::HttpRequest;
use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::Hash;
use std::sync::Arc;

use crate::adapters::repositories::{
    PgSessionRepository, PgUserRepository, RepositoryTrait, SessionRepository,
};
use crate::app_modules::auth::{AuthMethod, AuthStrategy};
use crate::config::database::PgPool;
use uuid::Uuid;

use crate::app_modules::auth::JwtClaims;
use crate::app_modules::auth::error::{AuthError, Result};
use crate::domain::models::Session;
use crate::domain::models::User;
use chrono::{Duration, Utc};
use tracing::error;

pub struct AuthService {
    session_repository: PgSessionRepository,
    user_repository: PgUserRepository,
    pub strategies: HashMap<AuthMethod, Arc<dyn AuthStrategy + Send + Sync>>,
}

impl AuthService {
    pub fn new(
        auth_strategies: HashMap<AuthMethod, Arc<dyn AuthStrategy + Send + Sync>>,
        db: Arc<PgPool>,
    ) -> Self {
        Self {
            strategies: auth_strategies,
            session_repository: PgSessionRepository::new(db.clone()),
            user_repository: PgUserRepository::new(db.clone()),
        }
    }

    pub async fn make_session(&self, user: User, req: HttpRequest) -> Result<String> {
        // Creates a new session for the user and generates a JWT token
        // This function should be called after the user has been authenticated
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(24)) // Token valid for 24 hours
            .expect("Invalid timestamp")
            .timestamp();

        // Extract User-Agent header
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|val| val.to_str().ok())
            .unwrap_or("Unknown")
            .to_string();

        // Extract IP address from request
        let ip_address = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("Unknown")
            .to_string();

        let now = Utc::now();

        // FIXME: This should be removed and resource access gotten from the DB
        let mut channel_permissions = HashMap::new();
        channel_permissions.insert(
            "channel/test".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );
        channel_permissions.insert(
            "channel/test2".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );
        let mut permissions: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        permissions.insert("test-tets".to_string(), channel_permissions);

        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            refresh_token_hash: "session refresh token ...".to_string(),
            device_identifier: None,
            device_name: None,
            device_type: None,
            ip_address: ip_address.parse().expect("Invalid IP address"),
            user_agent: Some(user_agent),
            expires_at: now,
            created_at: now,
            last_active_at: now,
            is_revoked: false,
            revoked_reason: None,
            revoked_at: None,
        };

        let session_id = self
            .session_repository
            .create_session(&session)
            .await
            .map_err(|e| {
                error!("Failed to create session: {}", e);
                AuthError::InternalError
            })?;

        let token_claims = JwtClaims {
            sub: user.id.to_string(),         // User ID
            access_range: "user".to_string(), // Permissions/scope
            preferred_username: user.username.unwrap_or_default(),
            scope: "user".to_string(),
            sid: session_id,                   // Session ID
            iss: "auth.teta.comm".to_string(), // Issuer (auth server)
            aud: "app.teta".to_string(),       // Audience (client app)
            exp: expiration,                   // Expiry time
            iat: now.timestamp(),              // Issued at
            jti: Uuid::new_v4().to_string(),   // Unique JWT ID (prevents replay attacks)
            nbf: now.timestamp(),              // Not before (optional)
            auth_time: now.timestamp(),        // Last authentication time
            resource_access: permissions,      // Resource access permissions
        };

        let token = token_claims.to_jwt("secret for jwt")?;
        Ok(token)
    }
}
