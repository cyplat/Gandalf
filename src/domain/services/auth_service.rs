use std::collections::HashMap;
use std::sync::Arc;

use crate::app_modules::auth::{AuthMethod, AuthStrategy};

pub struct AuthService {
    pub strategies: HashMap<AuthMethod, Arc<dyn AuthStrategy + Send + Sync>>,
}

impl AuthService {
    pub fn new(auth_strategies: HashMap<AuthMethod, Arc<dyn AuthStrategy + Send + Sync>>) -> Self {
        Self {
            strategies: auth_strategies,
        }
    }
}
