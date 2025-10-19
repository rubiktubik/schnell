#[derive(Debug, thiserror::Error)]
pub enum CertificateApiError {
    #[error("network: {0}")]
    Network(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("unexpected: {0}")]
    Unexpected(String),
    #[error("forbidded: {0}")]
    Forbidden(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
}

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("io: {0}")]
    Io(String),
    #[error("keychain: {0}")]
    Keychain(String),
    #[error("not found")]
    NotFound,
    #[error("invalid certificate")]
    Invalid,
    #[error("unexpected: {0}")]
    Unexpected(String),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyGenError {
    #[error("failed to generate private key: {0}")]
    GenerateKey(String),
    #[error("failed to serialize private key: {0}")]
    SerializePrivateKey(String),
    #[error("failed to resolve private key path: {0}")]
    ResolvePrivateKeyPath(String),
    #[error("failed to persist private key: {0}")]
    PersistPrivateKey(String),
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("failed to build CSR: {0}")]
    CsrGeneration(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ProvisioningProfileApiError {
    #[error("network: {0}")]
    Network(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("unexpected: {0}")]
    Unexpected(String),
}

impl From<CertificateApiError> for ProvisioningProfileApiError {
    fn from(err: CertificateApiError) -> Self {
        match err {
            CertificateApiError::Network(msg) => ProvisioningProfileApiError::Network(msg),
            CertificateApiError::BadRequest(msg) => ProvisioningProfileApiError::BadRequest(msg),
            CertificateApiError::Unauthorized => ProvisioningProfileApiError::Unauthorized,
            CertificateApiError::Unexpected(msg) => ProvisioningProfileApiError::Unexpected(msg),
            CertificateApiError::Forbidden(msg) => {
                ProvisioningProfileApiError::Unexpected(format!("forbidden: {msg}"))
            }
            CertificateApiError::RateLimited(msg) => {
                ProvisioningProfileApiError::Unexpected(format!("rate limited: {msg}"))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProvisioningProfileError {
    #[error("io: {0}")]
    Io(String),
    #[error("invalid provisioning profile")]
    Invalid,
    #[error("not found")]
    NotFound,
    #[error("unexpected: {0}")]
    Unexpected(String),
}
