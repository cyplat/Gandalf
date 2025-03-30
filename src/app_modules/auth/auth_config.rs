use std::collections::HashMap;
use std::sync::Arc;

use crate::app_modules::auth::strategies::{AuthStrategy, EmailPasswordAuthStrategy};
use crate::domain::errors::UserError;
use crate::domain::services::EmailService;
use crate::domain::services::UserService;
use crate::utils::PasswordUtil;

// Authentication Methods Enum
#[derive(Hash, Eq, PartialEq)]
pub enum AuthMethod {
    EmailPassword,
    Google,
    Facebook,
    // Other providers can be added
}

// Configuration for authentication strategies
pub fn configure_auth_strategies(
    user_service: Arc<UserService>,
    email_service: Arc<EmailService>,
    password_util: Arc<PasswordUtil>,
) -> HashMap<AuthMethod, Arc<dyn AuthStrategy + Send + Sync>> {
    let mut strategies: HashMap<AuthMethod, Arc<dyn AuthStrategy + Send + Sync>> = HashMap::new();

    strategies.insert(
        AuthMethod::EmailPassword,
        Arc::new(EmailPasswordAuthStrategy::new(
            user_service,
            email_service,
            password_util,
        )),
    );

    // When ready to add Google Auth
    // strategies.insert(
    //     AuthMethod::Google,
    //     Box::new(GoogleAuthStrategy::new(...))
    // );

    strategies
}
