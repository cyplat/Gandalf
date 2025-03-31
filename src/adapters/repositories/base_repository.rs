use std::result::Result;
use std::sync::Arc;

use async_trait::async_trait;
use bb8::{Pool, PooledConnection, RunError};
use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::NoTls;

use crate::domain::errors::UserError;

// Type aliases for cleaner code
pub type PgPool = Pool<PostgresConnectionManager<NoTls>>;
pub type PgConn<'a> = PooledConnection<'a, PostgresConnectionManager<NoTls>>;

// Base repository trait that all repositories will implement
#[async_trait]
pub trait RepositoryTrait<T, ID> {
    async fn find_by_id(&self, id: ID) -> Result<Option<T>, UserError>;
}

// Base repository that provides connection access
pub struct BaseRepository {
    pool: Arc<PgPool>,
}

impl BaseRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub async fn get_conn(&self) -> Result<PgConn, UserError> {
        self.pool.get().await.map_err(|e| match e {
            RunError::User(err) => UserError::DatabaseError(err),
            RunError::TimedOut => UserError::InternalError("Database connection timed out".into()),
        })
    }
}
