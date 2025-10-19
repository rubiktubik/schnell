use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoadSecretConfigError {
    #[error("Config directory not found")]
    ConfigDirNotFound,
    #[error("Could not create config directory")]
    CreateConfigDirFailed,
    #[error("Config file not found")]
    ConfigNotFound,
    #[error("Could not load config file")]
    LoadFailed,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum SaveSecretConfigError {
    #[error("Config directory not found")]
    ConfigDirNotFound,
    #[error("Could not create config directory")]
    CreateConfigDirFailed,
    #[error("Could not save config file")]
    SaveFailed,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

impl From<LoadSecretConfigError> for SaveSecretConfigError {
    fn from(e: LoadSecretConfigError) -> Self {
        match e {
            LoadSecretConfigError::ConfigDirNotFound => SaveSecretConfigError::ConfigDirNotFound,
            LoadSecretConfigError::CreateConfigDirFailed => {
                SaveSecretConfigError::CreateConfigDirFailed
            }
            _ => SaveSecretConfigError::SaveFailed,
        }
    }
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("error creating jwt, reason {0}")]
    JwtCreationError(String),
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum JwtValidationError {
    #[error("jwt is malformed: expected 3 segments but got {0}")]
    MalformedSegmentCount(usize),
    #[error("jwt payload is not valid base64url: {0}")]
    InvalidPayloadEncoding(String),
    #[error("jwt payload is not valid JSON: {0}")]
    InvalidPayloadFormat(String),
    #[error("could not obtain current system time for validation")]
    TimeCalculationFailed,
    #[error("jwt expiration {exp} must be greater than issued-at {iat}")]
    ExpirationBeforeIssuedAt { exp: u64, iat: u64 },
    #[error("jwt expired at {exp}, current time is {now}")]
    Expired { exp: u64, now: u64 },
    #[error("jwt has been issued in the future: issued-at {iat}, current time is {now}")]
    NotYetValid { iat: u64, now: u64 },
    #[error("jwt ttl of {ttl_seconds} seconds exceeds maximum of {max_ttl_seconds} seconds")]
    MaxTtlExceeded {
        ttl_seconds: u64,
        max_ttl_seconds: u64,
    },
    #[error("jwt has invalid audience: expected 'appstoreconnect-v1' but was '{audience}'")]
    InvalidAudience { audience: String },
}

#[derive(Clone)]
pub struct BundleIdentifier {
    pub name: String,
    pub identifier: String,
}

#[derive(Debug, Error)]
pub enum LoadConfigError {
    #[error("Config directory not found")]
    ConfigDirNotFound,
    #[error("Could not create config directory")]
    CreateConfigDirFailed,
    #[error("Config file not found")]
    ConfigNotFound,
    #[error("Could not load config file")]
    LoadFailed,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum SaveConfigError {
    #[error("Config directory not found")]
    ConfigDirNotFound,
    #[error("Could not create config directory")]
    CreateConfigDirFailed,
    #[error("Could not save config file")]
    SaveFailed,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

impl From<LoadConfigError> for SaveConfigError {
    fn from(e: LoadConfigError) -> Self {
        match e {
            LoadConfigError::ConfigDirNotFound => SaveConfigError::ConfigDirNotFound,
            LoadConfigError::CreateConfigDirFailed => SaveConfigError::CreateConfigDirFailed,
            _ => SaveConfigError::SaveFailed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateKind {
    AppleDistribution,
    AppleDevelopment,
}

#[derive(Debug, Clone)]
pub struct KeychainCertificateQuery {
    pub team_id_hint: Option<String>,
    pub kind: CertificateKind,
    pub keychain_name: String,
}

#[derive(Debug, Clone)]
pub struct EnsureKeychainRequest {
    pub keychain_name: String,
    pub password: Option<String>,
    /// When running in pipeline, setting to default could be helpful
    pub set_as_default: bool,
}

#[derive(Debug, Clone)]
pub struct PrivateKeyPEM {
    pub content: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct CsrSubject {
    pub country: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub state_or_province: Option<String>,
    pub locality: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateCsrRequest {
    pub private_key_pem: PrivateKeyPEM,
}

#[derive(Debug, Clone)]
pub struct CertificateContent {
    /// Base64-codierter Zertifikatsinhalt (z. B. DER als Base64)
    pub base64_data: String,
}

#[derive(Debug, Clone)]
pub struct InstallCertificateRequest {
    pub keychain_name: String,
    pub certificate_content: CertificateContent,
}

#[derive(Debug, Clone)]
pub struct InstallPrivateKeyRequest {
    pub keychain_name: String,
    pub private_key_pem: PrivateKeyPEM,
}

#[derive(Debug, Clone)]
pub struct TeamId {
    pub value: String,
}
