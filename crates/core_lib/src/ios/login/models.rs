use thiserror::Error;

use crate::shared::{
    models::{JwtError, SaveSecretConfigError},
    secret_config::AppStoreConnectCredentials,
};

#[derive(Clone, Debug)]
pub enum LoginRequest {
    NoCredentialsProvided,
    Credentials(AppStoreConnectCredentials),
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("error from appstore connect client")]
    AppStoreConnectError(#[from] JwtError),
    #[error("Could not save config")]
    OnSaveConfig(#[from] SaveSecretConfigError),
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}
