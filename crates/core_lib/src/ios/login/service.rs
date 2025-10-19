use crate::shared::{ports::SecretConfigFileRepository, secret_config::SecretConfig};

use super::{
    models::LoginRequest,
    ports::{JwtPort, LoginServicePort},
};

/// Canonical implementation of the [BlogService] port, through which the blog domain API is
/// consumed.
#[derive(Debug, Clone)]
pub struct LoginService<R, ASC>
where
    R: SecretConfigFileRepository,
    ASC: JwtPort,
{
    repo: R,
    client: ASC,
}

impl<R, ASC> LoginService<R, ASC>
where
    R: SecretConfigFileRepository,
    ASC: JwtPort,
{
    pub fn new(repo: R, client: ASC) -> Self {
        Self { repo, client }
    }
}

impl<R, ASC> LoginServicePort for LoginService<R, ASC>
where
    R: SecretConfigFileRepository,
    ASC: JwtPort,
{
    fn login(
        &self,
        request: &super::models::LoginRequest,
    ) -> Result<(), super::models::LoginError> {
        match request {
            LoginRequest::NoCredentialsProvided => todo!(),
            LoginRequest::Credentials(app_store_connect_credentials) => {
                let jwt = self.client.create_jwt(app_store_connect_credentials)?;
                let config_or_error = self.repo.load();
                if let Ok(mut config) = config_or_error {
                    config.jwt_token = Some(jwt);
                    self.repo.save(config)?;
                    Ok(())
                } else {
                    let created_config = SecretConfig::new(jwt);
                    self.repo.save(created_config)?;
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ios::login::ports::MockJwtPort;
    use crate::shared::ports::MockSecretConfigFileRepository;
    use crate::shared::secret_config::AppStoreConnectCredentials;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_login_credentials_success_existing_config() {
        let mut repo = MockSecretConfigFileRepository::new();
        let mut client = MockJwtPort::new();

        client
            .expect_create_jwt()
            .returning(|_| Ok("test_jwt".to_string()));
        repo.expect_load().returning(|| Ok(SecretConfig::default()));
        repo.expect_save().returning(|_| Ok(()));

        let service = LoginService::new(repo, client);
        let request = LoginRequest::Credentials(AppStoreConnectCredentials {
            issuer_id: "test_issuer".to_string(),
            key_id: "test_key".to_string(),
            private_key_file_path: PathBuf::from("test_path"),
        });

        let result = service.login(&request);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_login_credentials_success_new_config() {
        let mut repo = MockSecretConfigFileRepository::new();
        let mut client = MockJwtPort::new();

        client
            .expect_create_jwt()
            .returning(|_| Ok("test_jwt".to_string()));
        repo.expect_load()
            .returning(|| Err(crate::shared::models::LoadSecretConfigError::ConfigNotFound));
        repo.expect_save().returning(|_| Ok(()));

        let service = LoginService::new(repo, client);
        let request = LoginRequest::Credentials(AppStoreConnectCredentials {
            issuer_id: "test_issuer".to_string(),
            key_id: "test_key".to_string(),
            private_key_file_path: PathBuf::from("test_path"),
        });

        let result = service.login(&request);
        assert!(result.is_ok());
    }
}
