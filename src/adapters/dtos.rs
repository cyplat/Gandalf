use serde::Serialize;
use uuid::Uuid;

pub struct RegistrationDto {
    pub email: String,
    pub password: Option<String>,
}

pub struct LoginRequestDto {
    pub email: String,
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisteredUserDto {
    pub id: Uuid,
    pub email: String,
    pub auth_provider: String,
}
