/*
This module holds user repository
*/
use async_trait::async_trait;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

use crate::domain::errors::UserError;
use crate::domain::models::AuthProvider;
use crate::domain::models::{User, UserState};

use super::base_repository::{BaseRepository, PgPool, RepositoryTrait};

type Result<T> = std::result::Result<T, UserError>;

// Create User Repository
pub struct PgUserRepository {
    base: BaseRepository,
}

impl PgUserRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self {
            base: BaseRepository::new(pool),
        }
    }

    pub async fn create(&self, user: &User) -> Result<User> {
        let conn = self.base.get_conn().await?;
        let query = user.to_insert_sql();
        let row = conn.query_one(&query, &[]).await?;
        Ok(User::from_row(&row))
    }

    pub async fn email_exists(&self, email: &str) -> Result<bool> {
        let conn = self.base.get_conn().await?;

        let query = "
            SELECT EXISTS (
                SELECT 1
                FROM auth.users
                WHERE email = $1
            )
        ";

        let row = conn
            .query_one(query, &[&email])
            .await
            .map_err(UserError::DatabaseError)?;

        let exists: bool = row.get(0);

        Ok(exists)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let conn = self.base.get_conn().await?;

        let query = "
            SELECT 
                id, external_id, username, email, password_hash, 
                password_updated_at, password_reset_required, failed_login_attempts,
                last_failed_attempt, account_locked_until, email_verified,
                email_verification_token, email_verification_sent_at, created_at, updated_at, 
                last_login_at, requires_mfa, auth_provider,user_state,
                last_login_ip, last_user_agent, data_region, deletion_scheduled_at
            FROM auth.users
            WHERE email = $1
        ";

        let row = conn
            .query_opt(query, &[&email])
            .await
            .map_err(UserError::DatabaseError)?;

        match row {
            Some(row) => Ok(Some(User::from_row(&row))),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl RepositoryTrait<User, Uuid> for PgUserRepository {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let conn = self.base.get_conn().await?;

        let query = "
            SELECT 
                id, external_id, username, email, password_hash, 
                password_updated_at, password_reset_required, failed_login_attempts,
                last_failed_attempt, account_locked_until, email_verified,
                email_verification_token, email_verification_sent_at, created_at, updated_at, 
                last_login_at, requires_mfa, auth_provider,user_state,
                last_login_ip, last_user_agent, data_region, deletion_scheduled_at
            FROM auth.users
            WHERE id = $1
        ";

        let row = conn
            .query_opt(query, &[&id])
            .await
            .map_err(UserError::DatabaseError)?;

        match row {
            Some(row) => Ok(Some(User::from_row(&row))),
            None => Ok(None),
        }
    }
}

// Helper functions for converting database rows to domain models
impl User {
    fn from_row(row: &tokio_postgres::Row) -> Self {
        User {
            id: row.get("id"),
            external_id: row.get("external_id"),
            username: row.get("username"),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            password_updated_at: row.get("password_updated_at"),
            password_reset_required: row.get("password_reset_required"),
            failed_login_attempts: row.get("failed_login_attempts"),
            last_failed_attempt: row.get("last_failed_attempt"),
            account_locked_until: row.get("account_locked_until"),
            email_verified: row.get("email_verified"),
            email_verification_token: row.get("email_verification_token"),
            email_verification_sent_at: row.get("email_verification_sent_at"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            last_login_at: row.get("last_login_at"),
            requires_mfa: row.get("requires_mfa"),
            auth_provider: AuthProvider::from_str(row.get("auth_provider"))
                .expect("auth_provider should not be missing"),
            user_state: UserState::from_str(row.get("user_state"))
                .expect("user_state should not be missing"),
            last_login_ip: row.get("last_login_ip"),
            last_user_agent: row.get("last_user_agent"),
            data_region: row.get("data_region"),
            deletion_scheduled_at: row.get("deletion_scheduled_at"),
        }
    }

    fn to_insert_sql(&self) -> String {
        let mut fields = Vec::new();
        let mut values = Vec::new();

        macro_rules! push_field {
            ($field_name:expr, $value:expr) => {
                if let Some(val) = $value {
                    fields.push($field_name);
                    values.push(format!("{}", val));
                }
            };
        }

        // Mandatory fields
        fields.push("id");
        values.push(format!("'{}'", self.id));

        fields.push("email");
        values.push(format!("'{}'", self.email));

        fields.push("password_reset_required");
        values.push(self.password_reset_required.to_string());

        fields.push("failed_login_attempts");
        values.push(self.failed_login_attempts.to_string());

        fields.push("email_verified");
        values.push(self.email_verified.to_string());

        fields.push("created_at");
        values.push(format!("'{}'", self.created_at.to_rfc3339()));

        fields.push("updated_at");
        values.push(format!("'{}'", self.updated_at.to_rfc3339()));

        fields.push("requires_mfa");
        values.push(self.requires_mfa.to_string());

        fields.push("auth_provider");
        values.push(format!("'{}'", self.auth_provider.to_string()));

        fields.push("user_state");
        values.push(format!("'{}'", self.user_state.to_string()));

        fields.push("data_region");
        values.push(format!("'{}'", self.data_region));

        // Optional fields
        push_field!(
            "external_id",
            self.external_id.as_deref().map(|v| format!("'{}'", v))
        );
        push_field!(
            "username",
            self.username.as_deref().map(|v| format!("'{}'", v))
        );
        push_field!(
            "password_hash",
            self.password_hash.as_deref().map(|v| format!("'{}'", v))
        );
        push_field!(
            "password_updated_at",
            self.password_updated_at
                .map(|d| format!("'{}'", d.to_rfc3339()))
        );
        push_field!(
            "last_failed_attempt",
            self.last_failed_attempt
                .map(|d| format!("'{}'", d.to_rfc3339()))
        );
        push_field!(
            "account_locked_until",
            self.account_locked_until
                .map(|d| format!("'{}'", d.to_rfc3339()))
        );
        push_field!(
            "email_verification_token",
            self.email_verification_token
                .as_deref()
                .map(|v| format!("'{}'", v))
        );
        push_field!(
            "email_verification_sent_at",
            self.email_verification_sent_at
                .map(|d| format!("'{}'", d.to_rfc3339()))
        );
        push_field!(
            "last_login_at",
            self.last_login_at.map(|d| format!("'{}'", d.to_rfc3339()))
        );
        push_field!(
            "last_login_ip",
            self.last_login_ip.map(|ip| format!("'{}'", ip))
        );
        push_field!(
            "last_user_agent",
            self.last_user_agent.as_deref().map(|v| format!("'{}'", v))
        );
        push_field!(
            "deletion_scheduled_at",
            self.deletion_scheduled_at
                .map(|d| format!("'{}'", d.to_rfc3339()))
        );

        // Todo: make fields static part of query
        // todo: consider not returning the modified row
        format!(
            "INSERT INTO auth.users ({}) VALUES ({}) RETURNING *;",
            fields.join(", "),
            values.join(", ")
        )
    }
}
