use super::{
    errors::{EnsureProvisioningProfileError as E, Result},
    models::{
        CreateProvisioningProfileRequest, EnsureProvisioningProfileRequest,
        EnsureProvisioningProfileResult, EnsureProvisioningProfileStep,
        InstallProvisioningProfileRequest, ListProvisioningProfilesRequest,
        ProvisioningProfileQuery, ProvisioningProfileState, ProvisioningProfileType,
        RemoteProvisioningProfileSummary,
    },
    ports::{ProvisioningProfileApiPort, ProvisioningProfileLocalPort},
    progress::{NoopProvisioningProfileProgressReporter, ProvisioningProfileProgressReporter},
};
use crate::{ios::login::ports::JwtPort, shared::ports::SecretConfigFileRepository};
use chrono::Utc;
use std::future::Future;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteProfileState {
    Existing,
    Created,
}

#[derive(Debug)]
pub struct ProvisioningProfileService<ASC, Local, S, J, P = NoopProvisioningProfileProgressReporter>
where
    ASC: ProvisioningProfileApiPort + Sync,
    Local: ProvisioningProfileLocalPort + Sync,
    S: SecretConfigFileRepository,
    J: JwtPort + Sync,
    P: ProvisioningProfileProgressReporter,
{
    asc: ASC,
    local_profiles: Local,
    secret_config_repo: S,
    jwt_provider: J,
    progress_reporter: P,
}

impl<ASC, Local, S, J>
    ProvisioningProfileService<ASC, Local, S, J, NoopProvisioningProfileProgressReporter>
where
    ASC: ProvisioningProfileApiPort + Sync,
    Local: ProvisioningProfileLocalPort + Sync,
    S: SecretConfigFileRepository,
    J: JwtPort + Sync,
{
    pub fn new(asc: ASC, local_profiles: Local, secret_config_repo: S, jwt_provider: J) -> Self {
        Self {
            asc,
            local_profiles,
            secret_config_repo,
            jwt_provider,
            progress_reporter: NoopProvisioningProfileProgressReporter,
        }
    }
}

impl<ASC, Local, S, J, P> ProvisioningProfileService<ASC, Local, S, J, P>
where
    ASC: ProvisioningProfileApiPort + Sync,
    Local: ProvisioningProfileLocalPort + Sync,
    S: SecretConfigFileRepository,
    J: JwtPort + Sync,
    P: ProvisioningProfileProgressReporter,
{
    pub fn new_with_reporter(
        asc: ASC,
        local_profiles: Local,
        secret_config_repo: S,
        jwt_provider: J,
        progress_reporter: P,
    ) -> Self {
        Self {
            asc,
            local_profiles,
            secret_config_repo,
            jwt_provider,
            progress_reporter,
        }
    }

    pub async fn ensure_provisioning_profile(
        &self,
        req: &EnsureProvisioningProfileRequest,
    ) -> Result<EnsureProvisioningProfileResult> {
        let jwt = self.run_step(EnsureProvisioningProfileStep::LoadSecrets, || {
            let secrets = self.secret_config_repo.load()?;
            secrets.jwt_token.ok_or(E::LoginRequired)
        })?;

        self.run_step(EnsureProvisioningProfileStep::ValidateJwt, || {
            self.jwt_provider.validate(&jwt)?;
            Ok(())
        })?;

        let local_profile_exists =
            self.run_step(EnsureProvisioningProfileStep::CheckLocalProfile, || {
                Ok(self
                    .local_profiles
                    .has_valid_profile(&ProvisioningProfileQuery {
                        bundle_id: req.bundle_id.clone(),
                        profile_type: req.profile_type,
                    })?)
            })?;

        if local_profile_exists {
            let result = EnsureProvisioningProfileResult::AlreadyInstalled;
            self.progress_reporter.on_finished(&result);
            return Ok(result);
        }

        let list_request = ListProvisioningProfilesRequest {
            jwt: jwt.clone(),
            profile_type: req.profile_type,
            bundle_id: req.bundle_id.clone(),
        };

        let remote_profiles = self
            .run_async_step(
                EnsureProvisioningProfileStep::FetchRemoteProfiles,
                async move {
                    self.asc
                        .list_profiles(&list_request)
                        .await
                        .map_err(Into::into)
                },
            )
            .await?;

        let maybe_existing = self
            .run_step(EnsureProvisioningProfileStep::SelectExistingProfile, || {
                Ok(select_valid_remote(remote_profiles))
            })?;

        let (remote_summary, remote_state) = if let Some(summary) = maybe_existing {
            (summary, RemoteProfileState::Existing)
        } else {
            let desired_profile_name = req
                .profile_name
                .clone()
                .unwrap_or_else(|| default_profile_name(&req.bundle_id, req.profile_type));
            let certificate_ids = req.certificate_ids.clone().unwrap_or_default();
            let create_request = CreateProvisioningProfileRequest {
                jwt: jwt.clone(),
                profile_type: req.profile_type,
                bundle_id: req.bundle_id.clone(),
                profile_name: desired_profile_name,
                certificate_ids,
                device_ids: req.device_ids.clone(),
            };

            let created = self
                .run_async_step(
                    EnsureProvisioningProfileStep::CreateRemoteProfile,
                    async move {
                        self.asc
                            .create_profile(&create_request)
                            .await
                            .map_err(Into::into)
                    },
                )
                .await?;
            (created, RemoteProfileState::Created)
        };

        let profile_id = remote_summary.id.clone();
        let install_request = InstallProvisioningProfileRequest {
            profile_id: profile_id.clone(),
            profile_uuid: remote_summary.uuid.clone(),
            profile_name: remote_summary.name.clone(),
            profile_content: remote_summary.profile_content.clone(),
            destination: req.install_destination.clone(),
        };

        self.run_step(EnsureProvisioningProfileStep::InstallProfile, || {
            self.local_profiles.install_profile(&install_request)?;
            Ok(())
        })?;

        let result = match remote_state {
            RemoteProfileState::Existing => {
                EnsureProvisioningProfileResult::DownloadedAndInstalled { profile_id }
            }
            RemoteProfileState::Created => {
                EnsureProvisioningProfileResult::CreatedAndInstalled { profile_id }
            }
        };
        self.progress_reporter.on_finished(&result);
        Ok(result)
    }

    fn run_step<R, F>(&self, step: EnsureProvisioningProfileStep, action: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        self.progress_reporter.on_step_started(step);
        match action() {
            Ok(value) => {
                self.progress_reporter.on_step_completed(step);
                Ok(value)
            }
            Err(err) => Err(err),
        }
    }

    async fn run_async_step<R, Fut>(
        &self,
        step: EnsureProvisioningProfileStep,
        future: Fut,
    ) -> Result<R>
    where
        Fut: Future<Output = Result<R>>,
    {
        self.progress_reporter.on_step_started(step);
        match future.await {
            Ok(value) => {
                self.progress_reporter.on_step_completed(step);
                Ok(value)
            }
            Err(err) => Err(err),
        }
    }
}

fn select_valid_remote(
    list: Vec<RemoteProvisioningProfileSummary>,
) -> Option<RemoteProvisioningProfileSummary> {
    let now = Utc::now().timestamp();
    list.into_iter()
        .filter(|profile| matches!(profile.state, ProvisioningProfileState::Active))
        .filter(|profile| profile.expires_at_epoch.map(|e| e > now).unwrap_or(false))
        .max_by_key(|profile| profile.expires_at_epoch.unwrap_or(0))
}

fn default_profile_name(bundle_id: &str, profile_type: ProvisioningProfileType) -> String {
    let suffix = match profile_type {
        ProvisioningProfileType::IosDevelopment => "iOS Development",
        ProvisioningProfileType::IosAppStore => "iOS App Store",
        ProvisioningProfileType::IosAdHoc => "iOS Ad Hoc",
        ProvisioningProfileType::MacDevelopment => "macOS Development",
        ProvisioningProfileType::MacAppStore => "macOS App Store",
    };

    format!("{bundle_id} {suffix}")
}

#[cfg(test)]
mod tests {
    use super::super::models::{ProvisioningProfileContent, ProvisioningProfileType};
    use super::*;
    use crate::{
        ios::{
            login::ports::MockJwtPort,
            provisioning_profiles::ports::{
                MockProvisioningProfileApiPort, MockProvisioningProfileLocalPort,
            },
        },
        shared::{ports::MockSecretConfigFileRepository, secret_config::SecretConfig},
    };
    use chrono::{Duration, Utc};
    use mockall::predicate::eq;

    fn sample_request() -> EnsureProvisioningProfileRequest {
        EnsureProvisioningProfileRequest {
            bundle_id: "com.example.app".to_string(),
            profile_name: Some("Example App Store".to_string()),
            profile_type: ProvisioningProfileType::IosAppStore,
            certificate_ids: Some(vec!["CERT123".to_string()]),
            device_ids: vec![],
            install_destination: None,
        }
    }

    fn sample_secret_config() -> SecretConfig {
        SecretConfig {
            jwt_token: Some("jwt-token".to_string()),
            ..Default::default()
        }
    }

    fn remote_profile(expiry_offset: Duration) -> RemoteProvisioningProfileSummary {
        RemoteProvisioningProfileSummary {
            id: "PROFILE123".to_string(),
            uuid: "UUID-123".to_string(),
            name: "Example App Store".to_string(),
            expires_at_epoch: Some((Utc::now() + expiry_offset).timestamp()),
            state: ProvisioningProfileState::Active,
            profile_content: ProvisioningProfileContent {
                data: b"profile".to_vec(),
            },
        }
    }

    #[tokio::test]
    async fn returns_already_installed_if_local_profile_is_valid() {
        let mut api = MockProvisioningProfileApiPort::new();
        api.expect_list_profiles().never();
        api.expect_create_profile().never();

        let mut local = MockProvisioningProfileLocalPort::new();
        local
            .expect_has_valid_profile()
            .return_once(|query: &ProvisioningProfileQuery| {
                assert_eq!(query.bundle_id, "com.example.app");
                Ok(true)
            });
        local.expect_install_profile().never();

        let mut secrets = MockSecretConfigFileRepository::new();
        secrets
            .expect_load()
            .return_once(|| Ok(sample_secret_config()));

        let mut jwt = MockJwtPort::new();
        jwt.expect_validate()
            .with(eq("jwt-token"))
            .returning(|_| Ok(()));

        let service = ProvisioningProfileService::new(api, local, secrets, jwt);
        let request = sample_request();

        let result = service
            .ensure_provisioning_profile(&request)
            .await
            .expect("ensure provisioning profile should succeed");

        assert!(matches!(
            result,
            EnsureProvisioningProfileResult::AlreadyInstalled
        ));
    }

    #[tokio::test]
    async fn downloads_existing_remote_profile() {
        let remote = remote_profile(Duration::hours(1));

        let mut api = MockProvisioningProfileApiPort::new();
        api.expect_list_profiles().returning(move |_| {
            let profile = remote.clone();
            Box::pin(async move { Ok(vec![profile]) })
        });
        api.expect_create_profile().never();

        let mut local = MockProvisioningProfileLocalPort::new();
        local.expect_has_valid_profile().return_once(|_| Ok(false));
        local
            .expect_install_profile()
            .return_once(|req: &InstallProvisioningProfileRequest| {
                assert_eq!(req.profile_id, "PROFILE123");
                assert_eq!(req.profile_uuid, "UUID-123");
                assert_eq!(req.profile_content.data, b"profile");
                Ok(())
            });

        let mut secrets = MockSecretConfigFileRepository::new();
        secrets
            .expect_load()
            .return_once(|| Ok(sample_secret_config()));

        let mut jwt = MockJwtPort::new();
        jwt.expect_validate()
            .with(eq("jwt-token"))
            .returning(|_| Ok(()));

        let service = ProvisioningProfileService::new(api, local, secrets, jwt);
        let request = sample_request();

        let result = service
            .ensure_provisioning_profile(&request)
            .await
            .expect("ensure provisioning profile should succeed");

        match result {
            EnsureProvisioningProfileResult::DownloadedAndInstalled { profile_id } => {
                assert_eq!(profile_id, "PROFILE123");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn creates_and_installs_profile_when_remote_missing() {
        let mut api = MockProvisioningProfileApiPort::new();
        api.expect_list_profiles()
            .returning(|_| Box::pin(async { Ok(vec![]) }));
        api.expect_create_profile().returning(|req| {
            assert_eq!(req.profile_name, "Example App Store");
            assert_eq!(req.certificate_ids, vec!["CERT123".to_string()]);
            Box::pin(async {
                Ok(RemoteProvisioningProfileSummary {
                    id: "PROFILE123".to_string(),
                    uuid: "UUID-123".to_string(),
                    name: "Example App Store".to_string(),
                    expires_at_epoch: Some((Utc::now() + Duration::hours(2)).timestamp()),
                    state: ProvisioningProfileState::Active,
                    profile_content: ProvisioningProfileContent {
                        data: b"profile".to_vec(),
                    },
                })
            })
        });

        let mut local = MockProvisioningProfileLocalPort::new();
        local.expect_has_valid_profile().return_once(|_| Ok(false));
        local.expect_install_profile().returning(|_| Ok(()));

        let mut secrets = MockSecretConfigFileRepository::new();
        secrets
            .expect_load()
            .return_once(|| Ok(sample_secret_config()));

        let mut jwt = MockJwtPort::new();
        jwt.expect_validate()
            .with(eq("jwt-token"))
            .returning(|_| Ok(()));

        let service = ProvisioningProfileService::new(api, local, secrets, jwt);
        let request = sample_request();

        let result = service
            .ensure_provisioning_profile(&request)
            .await
            .expect("ensure provisioning profile should succeed");

        match result {
            EnsureProvisioningProfileResult::CreatedAndInstalled { profile_id } => {
                assert_eq!(profile_id, "PROFILE123");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn creates_profile_with_default_name_when_missing() {
        let mut api = MockProvisioningProfileApiPort::new();
        api.expect_list_profiles()
            .returning(|_| Box::pin(async { Ok(vec![]) }));
        api.expect_create_profile().returning(|req| {
            assert_eq!(req.profile_name, "com.example.app iOS App Store");
            assert!(req.certificate_ids.is_empty());
            Box::pin(async {
                Ok(RemoteProvisioningProfileSummary {
                    id: "PROFILE123".to_string(),
                    uuid: "UUID-123".to_string(),
                    name: "com.example.app iOS App Store".to_string(),
                    expires_at_epoch: Some((Utc::now() + Duration::hours(2)).timestamp()),
                    state: ProvisioningProfileState::Active,
                    profile_content: ProvisioningProfileContent {
                        data: b"profile".to_vec(),
                    },
                })
            })
        });

        let mut local = MockProvisioningProfileLocalPort::new();
        local.expect_has_valid_profile().return_once(|_| Ok(false));
        local.expect_install_profile().returning(|_| Ok(()));

        let mut secrets = MockSecretConfigFileRepository::new();
        secrets
            .expect_load()
            .return_once(|| Ok(sample_secret_config()));

        let mut jwt = MockJwtPort::new();
        jwt.expect_validate()
            .with(eq("jwt-token"))
            .returning(|_| Ok(()));

        let service = ProvisioningProfileService::new(api, local, secrets, jwt);
        let mut request = sample_request();
        request.profile_name = None;
        request.certificate_ids = None;

        let result = service
            .ensure_provisioning_profile(&request)
            .await
            .expect("ensure provisioning profile should succeed");

        match result {
            EnsureProvisioningProfileResult::CreatedAndInstalled { profile_id } => {
                assert_eq!(profile_id, "PROFILE123");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
