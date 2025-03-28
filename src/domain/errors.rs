use std::sync::Arc;
use thiserror::Error;
use tokio_postgres::Error as PgError;
use validator::ValidationErrors;

#[derive(Debug, Error)]
pub enum UserError {
    #[error("Entity not found")]
    NotFound,

    #[error("Validation error: {0}")]
    ValidationError(Arc<ValidationErrors>),

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Invalid email")]
    InvalidEmail,

    #[error("Password hashing error")]
    PasswordHashingError,

    #[error("Database error: {0}")]
    DatabaseError(#[from] PgError),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<ValidationErrors> for UserError {
    fn from(errors: ValidationErrors) -> Self {
        UserError::ValidationError(Arc::new(errors))
    }
}
