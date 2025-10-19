use thiserror::Error;

use crate::shared::{
    errors::{ProvisioningProfileApiError, ProvisioningProfileError},
    models::{JwtValidationError, LoadSecretConfigError},
};

#[derive(Debug, Error)]
pub enum EnsureProvisioningProfileError {
    #[error("login required")]
    LoginRequired,
    #[error("invalid jwt token: {0}")]
    InvalidJwtToken(#[from] JwtValidationError),

    #[error("secret config error: {0}")]
    SecretConfig(#[from] LoadSecretConfigError),

    #[error("ASC API error: {0}")]
    Asc(#[from] ProvisioningProfileApiError),

    #[error("provisioning profile error: {0}")]
    Local(#[from] ProvisioningProfileError),
}

pub type Result<T> = std::result::Result<T, EnsureProvisioningProfileError>;
