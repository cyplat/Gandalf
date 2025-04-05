use super::base_repository::{BaseRepository, PgPool, RepositoryTrait};
use crate::domain::errors::UserError;
use crate::domain::models::Session;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio_postgres::types::ToSql;
use uuid::Uuid;

type Result<T> = std::result::Result<T, UserError>;

#[async_trait]
pub trait SessionRepository {
    async fn create_session(&self, session: &Session) -> Result<Uuid>;
    async fn get_session_by_id(&self, session_id: Uuid) -> Result<Option<Session>>;
    async fn revoke_session(&self, session_id: Uuid, reason: Option<String>) -> Result<()>;
    async fn update_last_active(&self, session_id: Uuid) -> Result<()>;
}

pub struct PgSessionRepository {
    base: BaseRepository,
}

impl PgSessionRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self {
            base: BaseRepository::new(pool),
        }
    }
}

#[async_trait]
impl SessionRepository for PgSessionRepository {
    async fn create_session(&self, session: &Session) -> Result<Uuid> {
        let conn = self.base.get_conn().await?;
        let query = "
            INSERT INTO auth.sessions (
                id, user_id, refresh_token_hash, device_identifier,
                device_name, device_type, ip_address, user_agent,
                expires_at, is_revoked, revoked_reason, revoked_at
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7, $8,
                $9, $10, $11, $12
            ) RETURNING id;
        ";
        let params: Vec<&(dyn ToSql + Sync)> = vec![
            &session.id,
            &session.user_id,
            &session.refresh_token_hash,
            &session.device_identifier,
            &session.device_name,
            &session.device_type,
            &session.ip_address,
            &session.user_agent,
            &session.expires_at,
            &session.is_revoked,
            &session.revoked_reason,
            &session.revoked_at,
        ];

        let row = conn.query_one(query, &params).await?;
        Ok(row.get("id"))
    }

    async fn get_session_by_id(&self, session_id: Uuid) -> Result<Option<Session>> {
        let conn = self.base.get_conn().await?;
        let query = "SELECT * FROM auth.sessions WHERE id = $1";

        let row = conn.query_opt(query, &[&session_id]).await?;
        Ok(row.map(Session::from_row))
    }

    async fn revoke_session(&self, session_id: Uuid, reason: Option<String>) -> Result<()> {
        let conn = self.base.get_conn().await?;
        let query = "
            UPDATE auth.sessions 
            SET is_revoked = TRUE, revoked_reason = $1, revoked_at = NOW()
            WHERE id = $2
        ";

        conn.execute(query, &[&reason, &session_id]).await?;
        Ok(())
    }

    async fn update_last_active(&self, session_id: Uuid) -> Result<()> {
        let conn = self.base.get_conn().await?;
        let query = "
            UPDATE auth.sessions 
            SET last_active_at = NOW() 
            WHERE id = $1
        ";

        conn.execute(query, &[&session_id]).await?;
        Ok(())
    }
}

impl Session {
    /// Converts a `tokio_postgres::Row` into a `Session`
    fn from_row(row: tokio_postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            refresh_token_hash: row.get("refresh_token_hash"),
            device_identifier: row.get("device_identifier"),
            device_name: row.get("device_name"),
            device_type: row.get("device_type"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
            last_active_at: row.get("last_active_at"),
            is_revoked: row.get("is_revoked"),
            revoked_reason: row.get("revoked_reason"),
            revoked_at: row.get("revoked_at"),
        }
    }
}
