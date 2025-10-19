use thiserror::Error;

use crate::shared::models::{JwtError, JwtValidationError, LoadSecretConfigError};

#[derive(Debug, Error)]
pub enum EnsureBundleIdExistsError {
    #[error("config repo error: {0}")]
    ConfigRepoError(#[from] LoadSecretConfigError),
    #[error("Credentials Expired, Login again")]
    LoginRequired,
    #[error("invalid jwt token: {0}")]
    InvalidJwtToken(#[from] JwtValidationError),
    #[error("Failed to validate JWT")]
    Jwt(#[from] JwtError),
    #[error("App Store Connect API Error: {0}")]
    ApiError(#[from] BundleIdentiferApiError),
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum BundleIdentiferApiError {
    #[error("Unknown response")]
    Unknown(#[from] anyhow::Error),
    #[error("http request error {0}")]
    HttpRequest(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("no successfull response error,code: {0},reason: {1}")]
    NoSuccesfullResponse(String, String),
}

#[derive(Debug, Error)]
pub enum PromptForBundleIdentifierError {
    #[error("Error on prompting user to input bundle_identifier")]
    ErrorOnInput,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}
