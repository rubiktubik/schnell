use thiserror::Error;

use crate::shared::{
    errors::{CertificateApiError, KeyGenError, KeychainError},
    models::JwtValidationError,
};

#[derive(Debug, Error)]
pub enum EnsureCertificateError {
    #[error("login required")]
    LoginRequired,
    #[error("invalid jwt token: {0}")]
    InvalidJwtToken(#[from] JwtValidationError),

    #[error("config error: {0}")]
    Config(#[from] crate::shared::models::LoadConfigError),

    #[error("secret config error: {0}")]
    SecretConfig(#[from] crate::shared::models::LoadSecretConfigError),

    #[error("ASC API error: {0}")]
    Asc(#[from] CertificateApiError),

    #[error("Keychain error: {0}")]
    Keychain(#[from] KeychainError),

    #[error("Key generation error: {0}")]
    KeyGeneration(#[from] KeyGenError),

    #[error("private key generation requires explicit confirmation")]
    PrivateKeyGenerationNotApproved,
}

pub type Result<T> = std::result::Result<T, EnsureCertificateError>;
