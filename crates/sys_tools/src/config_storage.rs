use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

use core_lib::shared::{
    config::Config,
    models::{LoadConfigError, SaveConfigError},
    ports::ConfigFileRepository,
};

const CONFIG_FILE_NAME: &str = "rutter.toml";
const APP_DIR_NAME: &str = "rutter";

pub struct FileConfigRepository {
    config_path_override: Option<PathBuf>,
}

impl FileConfigRepository {
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

    fn get_config_path(&self) -> Result<PathBuf, LoadConfigError> {
        if let Some(path) = &self.config_path_override {
            return Ok(path.clone());
        }

        let mut config_path = dirs::config_dir().ok_or(LoadConfigError::ConfigDirNotFound)?;
        config_path.push(APP_DIR_NAME);
        fs::create_dir_all(&config_path).map_err(|_| LoadConfigError::CreateConfigDirFailed)?;
        config_path.push(CONFIG_FILE_NAME);
        Ok(config_path)
    }
}

impl Default for FileConfigRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigFileRepository for FileConfigRepository {
    fn save(&self, secret: Config) -> Result<(), SaveConfigError> {
        let config_path = self.get_config_path()?;
        let mut file = File::create(config_path).map_err(|_| SaveConfigError::SaveFailed)?;
        let secret_toml =
            toml::to_string_pretty(&secret).map_err(|_| SaveConfigError::SaveFailed)?;
        file.write_all(secret_toml.as_bytes())
            .map_err(|_| SaveConfigError::SaveFailed)?;
        Ok(())
    }

    fn load(&self) -> Result<Config, LoadConfigError> {
        let config_path = self.get_config_path()?;
        if !config_path.exists() {
            return Err(LoadConfigError::ConfigNotFound);
        }
        let mut file = File::open(config_path).map_err(|_| LoadConfigError::LoadFailed)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|_| LoadConfigError::LoadFailed)?;
        let secret: Config = toml::from_str(&contents).map_err(|_| LoadConfigError::LoadFailed)?;
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    fn get_test_config_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push("rutter-test");
        fs::create_dir_all(&path).unwrap();
        path.push(format!(".rutter-secret-{name}.toml"));
        path
    }

    #[test]
    fn test_save_and_load_secret_config() {
        let config_path = get_test_config_path("save_and_load");
        let repo = FileConfigRepository::new_with_path(config_path.clone());

        let secret = Config {
            bundle_identifier: Some("de.mycompany.name".to_string()),
        };

        let _ = fs::remove_file(&config_path);

        assert!(repo.save(secret.clone()).is_ok());
        let loaded = repo.load().unwrap();
        assert_eq!(loaded, secret);

        let _ = fs::remove_file(&config_path);
    }

    #[test]
    fn test_load_non_existent_config() {
        let config_path = get_test_config_path("non_existent");
        let repo = FileConfigRepository::new_with_path(config_path.clone());
        let _ = fs::remove_file(&config_path);
        assert!(matches!(repo.load(), Err(LoadConfigError::ConfigNotFound)));
    }
}
