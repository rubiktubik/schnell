use core_lib::shared::{
    models::{LoadSecretConfigError, SaveSecretConfigError},
    ports::SecretConfigFileRepository,
    secret_config::SecretConfig,
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

const CONFIG_FILE_NAME: &str = ".rutter-secret.toml";
const APP_DIR_NAME: &str = "rutter";

pub struct FileSecretConfigRepository {
    config_path_override: Option<PathBuf>,
}

impl FileSecretConfigRepository {
    pub fn new() -> Self {
        Self {
            config_path_override: None,
        }
    }

    #[cfg(test)]
    fn new_with_path(path: PathBuf) -> Self {
        Self {
            config_path_override: Some(path),
        }
    }

    fn get_config_path(&self) -> Result<PathBuf, LoadSecretConfigError> {
        if let Some(path) = &self.config_path_override {
            return Ok(path.clone());
        }

        let mut config_path = dirs::config_dir().ok_or(LoadSecretConfigError::ConfigDirNotFound)?;
        config_path.push(APP_DIR_NAME);
        fs::create_dir_all(&config_path)
            .map_err(|_| LoadSecretConfigError::CreateConfigDirFailed)?;
        config_path.push(CONFIG_FILE_NAME);
        Ok(config_path)
    }
}

impl Default for FileSecretConfigRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretConfigFileRepository for FileSecretConfigRepository {
    fn save(&self, secret: SecretConfig) -> Result<(), SaveSecretConfigError> {
        let config_path = self.get_config_path()?;
        let mut file = File::create(config_path).map_err(|_| SaveSecretConfigError::SaveFailed)?;
        let secret_toml =
            toml::to_string_pretty(&secret).map_err(|_| SaveSecretConfigError::SaveFailed)?;
        file.write_all(secret_toml.as_bytes())
            .map_err(|_| SaveSecretConfigError::SaveFailed)?;
        Ok(())
    }

    fn load(&self) -> Result<SecretConfig, LoadSecretConfigError> {
        let config_path = self.get_config_path()?;
        if !config_path.exists() {
            return Err(LoadSecretConfigError::ConfigNotFound);
        }
        let mut file = File::open(config_path).map_err(|_| LoadSecretConfigError::LoadFailed)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|_| LoadSecretConfigError::LoadFailed)?;
        let secret: SecretConfig =
            toml::from_str(&contents).map_err(|_| LoadSecretConfigError::LoadFailed)?;
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use core_lib::shared::secret_config::{
        AppStoreConnectCredentials, CertificateInfo, ProvisioningProfileInfo,
    };
    use std::fs;

    fn get_test_config_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push("rutter-test");
        fs::create_dir_all(&path).unwrap();
        path.push(".rutter-secret-test.toml");
        path
    }

    #[test]
    fn test_save_and_load_secret_config() {
        let config_path = get_test_config_path();
        let repo = FileSecretConfigRepository::new_with_path(config_path.clone());
        let now = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();

        let secret = SecretConfig {
            appstore_connect_credentials: Some(AppStoreConnectCredentials {
                issuer_id: "issuer_id".to_string(),
                key_id: "key_id".to_string(),
                private_key_file_path: "/path/to/key".into(),
            }),
            certificate: Some(CertificateInfo {
                certificate_file_name: "cert.p12".to_string(),
                certificate_expiry: now,
            }),
            jwt_token: Some("test_jwt_token".to_string()),
            provisioning_profile: Some(ProvisioningProfileInfo {
                provisioning_profile_file_name: "profile.mobileprovision".to_string(),
                provisioning_profile_expiry: now,
            }),
        };

        // Clean up before test
        let _ = fs::remove_file(&config_path);

        let save_result = repo.save(secret.clone());
        assert!(save_result.is_ok());

        let load_result = repo.load();
        assert!(load_result.is_ok());
        assert_eq!(load_result.unwrap(), secret);

        // Clean up after test
        let _ = fs::remove_file(&config_path);
    }

    #[test]
    fn test_load_non_existent_config() {
        let config_path = get_test_config_path();
        let repo = FileSecretConfigRepository::new_with_path(config_path.clone());

        // Clean up before test
        let _ = fs::remove_file(&config_path);

        let load_result = repo.load();
        assert!(matches!(
            load_result,
            Err(LoadSecretConfigError::ConfigNotFound)
        ));
    }
}
