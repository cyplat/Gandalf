// Email/Password Registration Strategy

use crate::adapters::dtos::LoginRequestDto;
use crate::adapters::dtos::RegisteredUserDto;
use crate::adapters::dtos::RegistrationDto;
use crate::app_modules::api::v1::auth_endpoints::login;
use crate::domain::errors::UserError;
use crate::domain::models::AuthProvider;
use crate::domain::services::UserService;

use crate::app_modules::auth::strategies::AuthStrategy;
use crate::domain::services::EmailService;
use crate::utils::PasswordUtil;

use std::sync::Arc;
use tracing::error;

pub struct EmailPasswordAuthStrategy {
    user_service: Arc<UserService>,
    email_service: Arc<EmailService>,
    password_util: Arc<PasswordUtil>,
}

impl EmailPasswordAuthStrategy {
    pub fn new(
        user_service: Arc<UserService>,
        email_service: Arc<EmailService>,
        password_util: Arc<PasswordUtil>,
    ) -> Self {
        Self {
            user_service,
            email_service,
            password_util,
        }
    }
}

#[async_trait::async_trait]
impl AuthStrategy for EmailPasswordAuthStrategy {
    async fn authenticate(&self, login_data: LoginRequestDto) -> Result<bool, UserError> {
        // Check if user exists
        let user = self
            .user_service
            .get_user_by_email(&login_data.email)
            .await?
            .ok_or(UserError::InvalidCredentials)?;

        // Verify password
        if let (Some(hash), Some(password)) = (&user.password_hash, &login_data.password) {
            let verified = self
                .password_util
                .verify_password(password, hash)
                .await
                .map_err(|e| {
                    error!("Password verification failed: {}", e);
                    UserError::InvalidCredentials
                })?;

            if !verified {
                return Err(UserError::InvalidCredentials);
            }
        }

        Ok(true)
    }

    async fn register(
        &self,
        registration_data: RegistrationDto,
    ) -> Result<RegisteredUserDto, UserError> {
        // Validate email format
        self.email_service
            .validate_email(&registration_data.email)?;

        // Check if user already exists
        if self
            .user_service
            .user_exists(&registration_data.email)
            .await?
        {
            return Err(UserError::UserAlreadyExists);
        }

        // Create user with defaults
        let mut new_user = self
            .user_service
            .create_user_with_defaults(&registration_data.email);

        // Hash password if provided
        if let Some(password) = &registration_data.password {
            new_user.password_hash =
                Some(self.password_util.hash_password(password).map_err(|e| {
                    error!("Password hashing failed: {}", e);
                    UserError::PasswordHashingError
                })?);
        }

        new_user.auth_provider = AuthProvider::Local;

        let saved_user = self.user_service.create_user(new_user).await?;

        // Generate verification token
        let verification_token = self
            .user_service
            .generate_email_verification_token(&saved_user.id)
            .await?;

        // Send verification email asynchronously
        let email_clone = saved_user.email.clone();
        tokio::spawn(async move {
            let email_service = EmailService::new();
            if let Err(e) = email_service
                .send_verification_email(email_clone, verification_token)
                .await
            {
                error!("Failed to send verification email: {}", e);
            }
        });

        Ok(RegisteredUserDto {
            id: saved_user.id,
            email: saved_user.email,
            auth_provider: saved_user.auth_provider.to_string(),
        })
    }
}
