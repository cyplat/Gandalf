use argon2::password_hash::Error as Argon2Error;
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use thiserror::Error;

/// Custom error type for password hashing and verification
#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Password hashing failed")]
    PasswordHashingError(#[from] Argon2Error),

    #[error("Password verification failed")]
    PasswordVerificationError,
}

/// Struct to encapsulate password hashing configuration
pub struct PasswordUtil {
    argon2: Argon2<'static>,
}

impl PasswordUtil {
    /// Create a new password utility with default Argon2 parameters
    pub fn new() -> Self {
        let memory_cost = 19_456; // 19 MB (OWASP recommended)
        let time_cost = 2;
        let parallelism = 2; // Use 2 threads for hashing

        let params = Params::new(memory_cost, time_cost, parallelism, None)
            .expect("Failed to initialize Argon2 parameters");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        Self { argon2 }
    }
    /// Hashes a password using Argon2
    pub fn hash_password(&self, password: &str) -> Result<String, PasswordError> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self.argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    /// Verifies a password against a stored hash
    pub async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, PasswordError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|_| PasswordError::PasswordVerificationError)?;
        Ok(self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

/// Example usage and tests
#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{PasswordHash, PasswordVerifier};
    use tokio::test; // For async tests

    #[tokio::test]
    async fn test_hash_password() {
        let util = PasswordUtil::new();
        let password = "secure_password";

        let hash = util.hash_password(password);
        assert!(hash.is_ok(), "Password hashing should succeed");

        let hash = hash.unwrap();
        assert!(
            PasswordHash::new(&hash).is_ok(),
            "Generated hash should be valid Argon2 format"
        );
    }

    #[tokio::test]
    async fn test_verify_password_success() {
        let util = PasswordUtil::new();
        let password = "secure_password";
        let hash = util.hash_password(password).expect("Hashing failed");

        let result = util.verify_password(password, &hash).await;
        assert!(result.is_ok(), "Verification should not return an error");
        assert!(result.unwrap(), "Password should be verified successfully");
    }

    #[tokio::test]
    async fn test_verify_password_failure() {
        let util = PasswordUtil::new();
        let password = "secure_password";
        let wrong_password = "wrong_password";
        let hash = util.hash_password(password).expect("Hashing failed");

        let result = util.verify_password(wrong_password, &hash).await;
        assert!(result.is_ok(), "Verification should not return an error");
        assert!(
            !result.unwrap(),
            "Wrong password should not pass verification"
        );
    }
}
