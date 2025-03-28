mod auth_config;
mod strategies;

pub use crate::domain::errors::UserError;
pub use auth_config::{AuthMethod, configure_auth_strategies};
pub use strategies::AuthStrategy;
