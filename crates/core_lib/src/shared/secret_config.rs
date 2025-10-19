use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct SecretConfig {
    pub appstore_connect_credentials: Option<AppStoreConnectCredentials>,
    pub certificate: Option<CertificateInfo>,
    pub jwt_token: Option<String>,
    pub provisioning_profile: Option<ProvisioningProfileInfo>,
}

impl SecretConfig {
    pub fn new(jwt_token: String) -> Self {
        Self {
            appstore_connect_credentials: None,
            certificate: None,
            jwt_token: Some(jwt_token),
            provisioning_profile: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CertificateInfo {
    pub certificate_file_name: String,
    pub certificate_expiry: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProvisioningProfileInfo {
    pub provisioning_profile_file_name: String,
    pub provisioning_profile_expiry: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct AppStoreConnectCredentials {
    pub issuer_id: String,
    pub key_id: String,
    pub private_key_file_path: PathBuf,
}
