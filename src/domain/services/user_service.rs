use std::sync::Arc;
use uuid::Uuid;

use crate::config::database::PgPool;
use crate::domain::errors::UserError;
use crate::domain::models::User;
use crate::domain::repositories::{RepositoryTrait, UserRepository};
type Result<T> = std::result::Result<T, UserError>;

pub struct UserService {
    user_repo: UserRepository,
}

impl UserService {
    pub fn new(db_pool: Arc<PgPool>) -> Self {
        Self {
            user_repo: UserRepository::new(db_pool),
        }
    }

    pub async fn get_user(&self, user_id: Uuid) -> Result<Option<User>> {
        let user = self.user_repo.find_by_id(user_id).await?;
        Ok(user)
    }

    // takes a new user object and persists it to the database
    pub async fn create_user(&self, user: User) -> Result<User> {
        let user = self.user_repo.create(&user).await?;
        Ok(user)
    }

    // creates a new user with default values and email
    // user not persisted
    pub fn create_user_with_defaults(&self, email: &String) -> User {
        let mut user = User::default();
        user.email = email.to_string();
        user
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = self.user_repo.find_by_email(email).await?;
        Ok(user)
    }

    pub async fn user_exists(&self, email: &str) -> Result<bool> {
        let exists = self.user_repo.email_exists(email).await?;
        Ok(exists)
    }

    pub async fn generate_email_verification_token(&self, user_id: &Uuid) -> Result<String> {
        // Todo: generate a token and save it to the database
        // let token = Uuid::new_v4().to_string();
        Ok("some very long verification token".to_string())
    }
}
