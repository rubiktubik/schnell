use crate::shared::{
    models::{JwtError, JwtValidationError},
    secret_config::AppStoreConnectCredentials,
};
#[cfg(test)]
use mockall::automock;

use super::models::{LoginError, LoginRequest};

#[cfg_attr(test, automock)]
pub trait JwtPort {
    fn create_jwt(&self, credentials: &AppStoreConnectCredentials) -> Result<String, JwtError>;
    fn validate(&self, jwt: &str) -> Result<(), JwtValidationError>;
}

#[cfg_attr(test, automock)]
pub trait LoginServicePort {
    fn login(&self, request: &LoginRequest) -> Result<(), LoginError>;
}
