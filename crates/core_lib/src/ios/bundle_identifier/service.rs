use crate::{
    ios::{
        bundle_identifier::models::{CheckIdentifierApiRequest, EnsureBundleIdentifierResult},
        login::ports::JwtPort,
    },
    shared::{
        models::BundleIdentifier,
        ports::{ConfigFileRepository, SecretConfigFileRepository},
    },
};

use super::{
    errors::EnsureBundleIdExistsError,
    models::CheckIdentifierRequest,
    ports::{BundleIdentifierApiPort, BundleIdentifierCliPort, BundleIdentifierServicePort},
};

#[derive(Debug, Clone)]
pub struct BundleIdentifierService<ASC, S, J, Cli, C>
where
    ASC: BundleIdentifierApiPort + Sync,
    S: SecretConfigFileRepository,
    J: JwtPort,
    Cli: BundleIdentifierCliPort,
    C: ConfigFileRepository,
{
    client: ASC,
    secret_config_repo: S,
    jwt_provider: J,
    cli_interface: Cli,
    config_repo: C,
}

impl<ASC, S, J, Cli, C> BundleIdentifierService<ASC, S, J, Cli, C>
where
    ASC: BundleIdentifierApiPort + Sync,
    S: SecretConfigFileRepository,
    J: JwtPort,
    Cli: BundleIdentifierCliPort,
    C: ConfigFileRepository,
{
    pub fn new(
        client: ASC,
        secret_config_repo: S,
        jwt_provider: J,
        cli_interface: Cli,
        config_repo: C,
    ) -> Self {
        Self {
            client,
            secret_config_repo,
            jwt_provider,
            cli_interface,
            config_repo,
        }
    }
}

impl<ASC, S, J, Cli, C> BundleIdentifierServicePort for BundleIdentifierService<ASC, S, J, Cli, C>
where
    ASC: BundleIdentifierApiPort + Sync,
    S: SecretConfigFileRepository,
    J: JwtPort + Sync,
    Cli: BundleIdentifierCliPort + Sync,
    C: ConfigFileRepository,
{
    async fn ensure_bundle_id_exists(
        &self,
        request: &CheckIdentifierRequest,
    ) -> Result<EnsureBundleIdentifierResult, EnsureBundleIdExistsError> {
        let config = self.secret_config_repo.load()?;
        let jwt = config
            .jwt_token
            .ok_or(EnsureBundleIdExistsError::LoginRequired)?;

        self.jwt_provider.validate(&jwt)?;

        let api_request = CheckIdentifierApiRequest {
            bundle_identifier: BundleIdentifier {
                name: request.bundle_identifier.name.clone(),
                identifier: request.bundle_identifier.identifier.clone(),
            },
            jwt,
        };

        if self.client.check_if_identifier_exists(&api_request).await? {
            return Ok(EnsureBundleIdentifierResult::IdentifierAlreadyExists);
        }

        self.client.create_bundle_identifier(&api_request).await?;
        Ok(EnsureBundleIdentifierResult::CreatedNewIdentifier)
    }
}
