use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub refresh_token_hash: String,
    pub device_identifier: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub ip_address: IpAddr,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub is_revoked: bool,
    pub revoked_reason: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}
