use crate::shared::{
    errors::{KeyGenError, KeychainError},
    models::{
        CreateCsrRequest, EnsureKeychainRequest, InstallCertificateRequest,
        InstallPrivateKeyRequest, KeychainCertificateQuery, PrivateKeyPEM,
    },
};

use super::{
    config::Config,
    models::{LoadConfigError, LoadSecretConfigError, SaveConfigError, SaveSecretConfigError},
    secret_config::SecretConfig,
};
#[cfg(test)]
use mockall::automock;
use std::path::PathBuf;

#[cfg_attr(test, automock)]
pub trait SecretConfigFileRepository: Send + Sync + 'static {
    fn save(&self, secret: SecretConfig) -> Result<(), SaveSecretConfigError>;
    fn load(&self) -> Result<SecretConfig, LoadSecretConfigError>;
}

#[cfg_attr(test, automock)]
pub trait ConfigFileRepository: Send + Sync + 'static {
    fn save(&self, config: Config) -> Result<(), SaveConfigError>;
    fn load(&self) -> Result<Config, LoadConfigError>;
}

#[cfg_attr(test, automock)]
pub trait KeychainPort: Sync + Send {
    fn has_valid_certificate_installed(
        &self,
        q: &KeychainCertificateQuery,
    ) -> Result<bool, KeychainError>;

    fn custom_keychain_exists(&self, name: &str) -> Result<bool, KeychainError>;

    fn create_custom_keychain(&self, req: &EnsureKeychainRequest) -> Result<(), KeychainError>;

    fn install_certificate(&self, req: &InstallCertificateRequest) -> Result<(), KeychainError>;

    fn install_private_key(&self, req: &InstallPrivateKeyRequest) -> Result<(), KeychainError>;
}

#[cfg_attr(test, automock)]
pub trait KeyGeneratorPort: Sync + Send {
    fn generate_private_key(
        &self,
        output_path: Option<PathBuf>,
    ) -> Result<PrivateKeyPEM, KeyGenError>;

    fn create_csr(&self, req: &CreateCsrRequest) -> Result<String, KeyGenError>;
}
