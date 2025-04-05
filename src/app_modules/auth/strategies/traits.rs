use crate::adapters::dtos::LoginRequestDto;
use crate::adapters::dtos::RegisteredUserDto;
use crate::adapters::dtos::RegistrationDto;
use crate::domain::errors::UserError;
use crate::domain::models::User;
// Authentication Strategy Trait
#[async_trait::async_trait]
pub trait AuthStrategy {
    async fn register(
        &self,
        registration_data: RegistrationDto,
    ) -> Result<RegisteredUserDto, UserError>;

    async fn authenticate(&self, login_data: LoginRequestDto) -> Result<User, UserError>;
}
