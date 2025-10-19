use super::{
    errors::{EnsureCertificateError as E, Result},
    ports::CertificateApiPort,
    progress::{CertificateProgressReporter, NoopCertificateProgressReporter},
};
use crate::{
    ios::{
        certificates::models::{
            CheckCertificateApiRequest, CreateCertificateApiRequest, EnsureCertificateRequest,
            EnsureCertificateResult, EnsureCertificateStep,
        },
        login::ports::JwtPort,
    },
    shared::{
        models::{
            CertificateContent, CreateCsrRequest, EnsureKeychainRequest, InstallCertificateRequest,
            InstallPrivateKeyRequest, KeychainCertificateQuery, PrivateKeyPEM,
        },
        ports::{KeyGeneratorPort, KeychainPort, SecretConfigFileRepository},
    },
};
use chrono::Utc;
use std::cmp::Ordering;

#[derive(Debug)]
struct ObtainedCertificate {
    certificate_id: String,
    certificate_content: CertificateContent,
    remote_state: RemoteCertificateState,
    new_private_key: Option<PrivateKeyPEM>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteCertificateState {
    Existing,
    Created,
}

#[derive(Debug)]
struct CsrArtifacts {
    csr: String,
    new_private_key: Option<PrivateKeyPEM>,
}

#[derive(Debug)]
pub struct CertificateService<ASC, KC, S, J, G, P = NoopCertificateProgressReporter>
where
    ASC: CertificateApiPort + Sync,
    KC: KeychainPort + Sync,
    S: SecretConfigFileRepository,
    J: JwtPort + Sync,
    G: KeyGeneratorPort,
    P: CertificateProgressReporter,
{
    asc: ASC,
    keychain: KC,
    secret_config_repo: S,
    jwt_provider: J,
    key_generator: G,
    progress_reporter: P,
}

impl<ASC, KC, S, J, G> CertificateService<ASC, KC, S, J, G, NoopCertificateProgressReporter>
where
    ASC: CertificateApiPort + Sync,
    KC: KeychainPort + Sync,
    S: SecretConfigFileRepository,
    J: JwtPort + Sync,
    G: KeyGeneratorPort,
{
    pub fn new(
        asc: ASC,
        keychain: KC,
        secret_config_repo: S,
        jwt_provider: J,
        key_generator: G,
    ) -> Self {
        Self {
            asc,
            keychain,
            secret_config_repo,
            jwt_provider,
            key_generator,
            progress_reporter: NoopCertificateProgressReporter,
        }
    }
}

impl<ASC, KC, S, J, G, P> CertificateService<ASC, KC, S, J, G, P>
where
    ASC: CertificateApiPort + Sync,
    KC: KeychainPort + Sync,
    S: SecretConfigFileRepository,
    J: JwtPort + Sync,
    G: KeyGeneratorPort,
    P: CertificateProgressReporter,
{
    pub fn new_with_reporter(
        asc: ASC,
        keychain: KC,
        secret_config_repo: S,
        jwt_provider: J,
        key_generator: G,
        progress_reporter: P,
    ) -> Self {
        Self {
            asc,
            keychain,
            secret_config_repo,
            jwt_provider,
            key_generator,
            progress_reporter,
        }
    }

    pub async fn ensure_certificate(
        &self,
        req: &EnsureCertificateRequest,
    ) -> Result<EnsureCertificateResult> {
        self.progress_reporter
            .on_step_started(EnsureCertificateStep::LoadSecrets);
        let secrets = match self.secret_config_repo.load() {
            Ok(secrets) => secrets,
            Err(err) => return Err(err.into()),
        };
        let jwt = match secrets.jwt_token {
            Some(jwt) => jwt,
            None => return Err(E::LoginRequired),
        };
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::LoadSecrets);

        self.progress_reporter
            .on_step_started(EnsureCertificateStep::ValidateJwt);
        if let Err(err) = self.jwt_provider.validate(&jwt) {
            return Err(err.into());
        }
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::ValidateJwt);

        self.progress_reporter
            .on_step_started(EnsureCertificateStep::CheckLocalCertificate);
        let local_ok =
            match self
                .keychain
                .has_valid_certificate_installed(&KeychainCertificateQuery {
                    team_id_hint: Some(req.team_id.value.clone()),
                    kind: req.kind.clone(),
                    keychain_name: req.keychain_name.clone(),
                }) {
                Ok(value) => value,
                Err(err) => return Err(err.into()),
            };
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::CheckLocalCertificate);
        if local_ok {
            let result = EnsureCertificateResult::AlreadyInstalled;
            self.progress_reporter.on_finished(&result);
            return Ok(result);
        }

        self.progress_reporter
            .on_step_started(EnsureCertificateStep::FetchRemoteCertificates);
        let remote_certs = match self
            .asc
            .list_certificates(&CheckCertificateApiRequest {
                jwt: jwt.clone(),
                kind: req.kind.clone(),
            })
            .await
        {
            Ok(certs) => certs,
            Err(err) => return Err(err.into()),
        };
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::FetchRemoteCertificates);

        let ObtainedCertificate {
            certificate_id,
            certificate_content,
            remote_state,
            new_private_key,
        } = self.obtain_certificate(&jwt, req, remote_certs).await?;

        self.progress_reporter
            .on_step_started(EnsureCertificateStep::EnsureKeychain);
        let keychain_exists = match self.keychain.custom_keychain_exists(&req.keychain_name) {
            Ok(exists) => exists,
            Err(err) => return Err(err.into()),
        };
        let created_keychain = if !keychain_exists {
            if let Err(err) = self
                .keychain
                .create_custom_keychain(&EnsureKeychainRequest {
                    keychain_name: req.keychain_name.clone(),
                    password: req.keychain_password.clone(),
                    set_as_default: req.set_key_chain_as_default,
                })
            {
                return Err(err.into());
            }
            true
        } else {
            false
        };
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::EnsureKeychain);

        if let Some(private_key) = new_private_key {
            self.progress_reporter
                .on_step_started(EnsureCertificateStep::InstallPrivateKey);
            if let Err(err) = self
                .keychain
                .install_private_key(&InstallPrivateKeyRequest {
                    keychain_name: req.keychain_name.clone(),
                    private_key_pem: private_key,
                })
            {
                return Err(err.into());
            }
            self.progress_reporter
                .on_step_completed(EnsureCertificateStep::InstallPrivateKey);
        }

        self.progress_reporter
            .on_step_started(EnsureCertificateStep::InstallCertificate);
        if let Err(err) = self
            .keychain
            .install_certificate(&InstallCertificateRequest {
                keychain_name: req.keychain_name.clone(),
                certificate_content,
            })
        {
            return Err(err.into());
        }
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::InstallCertificate);

        let result = if created_keychain {
            EnsureCertificateResult::CreatedKeychainAndInstalled {
                certificate_id: certificate_id.clone(),
            }
        } else if matches!(remote_state, RemoteCertificateState::Created) {
            EnsureCertificateResult::CreatedAndInstalled {
                certificate_id: certificate_id.clone(),
            }
        } else {
            EnsureCertificateResult::DownloadedAndInstalled { certificate_id }
        };
        self.progress_reporter.on_finished(&result);
        Ok(result)
    }

    async fn obtain_certificate(
        &self,
        jwt: &str,
        req: &EnsureCertificateRequest,
        remote_certs: Vec<crate::ios::certificates::models::RemoteCertificateSummary>,
    ) -> Result<ObtainedCertificate> {
        self.progress_reporter
            .on_step_started(EnsureCertificateStep::SelectExistingCertificate);
        if let Some(selected) = select_valid_remote(remote_certs) {
            self.progress_reporter
                .on_step_completed(EnsureCertificateStep::SelectExistingCertificate);
            return Ok(ObtainedCertificate {
                certificate_id: selected.id,
                certificate_content: selected.certificate_content,
                remote_state: RemoteCertificateState::Existing,
                new_private_key: None,
            });
        }
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::SelectExistingCertificate);

        let csr_artifacts = self.build_csr(req)?;
        self.progress_reporter
            .on_step_started(EnsureCertificateStep::RequestCertificate);
        let created = match self
            .asc
            .create_certificate(&CreateCertificateApiRequest {
                jwt: jwt.to_string(),
                team_id: req.team_id.value.clone(),
                kind: req.kind.clone(),
                csr_string: csr_artifacts.csr,
            })
            .await
        {
            Ok(certificate) => certificate,
            Err(err) => return Err(err.into()),
        };
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::RequestCertificate);
        Ok(ObtainedCertificate {
            certificate_id: created.id,
            certificate_content: created.certificate_content,
            remote_state: RemoteCertificateState::Created,
            new_private_key: csr_artifacts.new_private_key,
        })
    }

    fn build_csr(&self, req: &EnsureCertificateRequest) -> Result<CsrArtifacts> {
        if let Some(ref private_key_pem) = req.private_key_pem {
            self.progress_reporter
                .on_step_started(EnsureCertificateStep::CreateCsr);
            let csr = match self.key_generator.create_csr(&CreateCsrRequest {
                private_key_pem: private_key_pem.clone(),
            }) {
                Ok(csr) => csr,
                Err(err) => return Err(err.into()),
            };
            self.progress_reporter
                .on_step_completed(EnsureCertificateStep::CreateCsr);
            return Ok(CsrArtifacts {
                csr,
                new_private_key: None,
            });
        }

        if !req.allow_private_key_generation {
            return Err(E::PrivateKeyGenerationNotApproved);
        }

        self.progress_reporter
            .on_step_started(EnsureCertificateStep::GeneratePrivateKey);
        let generated_private_key = match self
            .key_generator
            .generate_private_key(req.private_key_output_path.clone())
        {
            Ok(key) => key,
            Err(err) => return Err(err.into()),
        };
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::GeneratePrivateKey);

        self.progress_reporter
            .on_step_started(EnsureCertificateStep::CreateCsr);
        let csr = match self.key_generator.create_csr(&CreateCsrRequest {
            private_key_pem: generated_private_key.clone(),
        }) {
            Ok(csr) => csr,
            Err(err) => return Err(err.into()),
        };
        self.progress_reporter
            .on_step_completed(EnsureCertificateStep::CreateCsr);
        Ok(CsrArtifacts {
            csr,
            new_private_key: Some(generated_private_key),
        })
    }
}
fn select_valid_remote(
    list: Vec<crate::ios::certificates::models::RemoteCertificateSummary>,
) -> Option<crate::ios::certificates::models::RemoteCertificateSummary> {
    let now = Utc::now().timestamp();
    // Bevorzugt das mit der spätesten Ablaufzeit
    list.into_iter()
        .filter(|c| c.expires_at_epoch.map(|e| e > now).unwrap_or(false))
        .max_by(|a, b| match (a.expires_at_epoch, b.expires_at_epoch) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal,
        })
}

// CSR-Erzeugung aus DER wird in den Adapter (KeyGeneratorPort) ausgelagert.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ios::{
            certificates::{
                models::{
                    EnsureCertificateRequest, EnsureCertificateResult, RemoteCertificateSummary,
                },
                ports::MockCertificateApiPort,
            },
            login::ports::MockJwtPort,
        },
        shared::{
            models::{
                CertificateContent, CertificateKind, CreateCsrRequest, EnsureKeychainRequest,
                InstallCertificateRequest, InstallPrivateKeyRequest, KeychainCertificateQuery,
                PrivateKeyPEM, TeamId,
            },
            ports::{MockKeyGeneratorPort, MockKeychainPort, MockSecretConfigFileRepository},
            secret_config::SecretConfig,
        },
    };
    use chrono::{Duration, Utc};
    use mockall::predicate::eq;
    use std::path::PathBuf;

    fn sample_request() -> EnsureCertificateRequest {
        EnsureCertificateRequest {
            team_id: TeamId {
                value: "TEAMID123".to_string(),
            },
            kind: CertificateKind::AppleDistribution,
            keychain_name: "rutter".to_string(),
            keychain_password: Some("secret".to_string()),
            private_key_pem: None,
            set_key_chain_as_default: false,
            private_key_output_path: None,
            allow_private_key_generation: false,
        }
    }

    fn sample_secret_config() -> SecretConfig {
        SecretConfig {
            jwt_token: Some("jwt-token".to_string()),
            ..Default::default()
        }
    }

    fn sample_certificate_content() -> CertificateContent {
        CertificateContent {
            base64_data: "certificate-data".to_string(),
        }
    }

    #[tokio::test]
    async fn returns_already_installed_when_keychain_matches() {
        let mut asc = MockCertificateApiPort::new();
        asc.expect_list_certificates().never();
        asc.expect_create_certificate().never();

        let mut keychain = MockKeychainPort::new();
        keychain
            .expect_has_valid_certificate_installed()
            .return_once(|query: &KeychainCertificateQuery| {
                assert_eq!(query.team_id_hint.as_deref(), Some("TEAMID123"));
                Ok(true)
            });
        keychain.expect_custom_keychain_exists().never();
        keychain.expect_create_custom_keychain().never();
        keychain.expect_install_certificate().never();
        keychain.expect_install_private_key().never();

        let mut secret_repo = MockSecretConfigFileRepository::new();
        secret_repo
            .expect_load()
            .return_once(|| Ok(sample_secret_config()));

        let mut jwt = MockJwtPort::new();
        jwt.expect_validate()
            .with(eq("jwt-token"))
            .returning(|_| Ok(()));

        let mut key_generator = MockKeyGeneratorPort::new();
        key_generator.expect_generate_private_key().never();
        key_generator.expect_create_csr().never();

        let service = CertificateService::new(asc, keychain, secret_repo, jwt, key_generator);

        let request = sample_request();
        let result = service.ensure_certificate(&request).await.unwrap();

        assert!(matches!(result, EnsureCertificateResult::AlreadyInstalled));
    }

    #[tokio::test]
    async fn downloads_existing_remote_certificate() {
        let future_expiry = (Utc::now() + Duration::hours(1)).timestamp();
        let remote_cert = RemoteCertificateSummary {
            id: "CERT123".to_string(),
            serial: Some("SER123".to_string()),
            expires_at_epoch: Some(future_expiry),
            common_name: Some("Apple Distribution: Example (TEAMID123)".to_string()),
            certificate_content: sample_certificate_content(),
        };

        let mut asc = MockCertificateApiPort::new();
        asc.expect_list_certificates().returning(move |_req| {
            let cert = remote_cert.clone();
            Box::pin(async move { Ok(vec![cert]) })
        });
        asc.expect_create_certificate().never();

        let mut keychain = MockKeychainPort::new();
        keychain
            .expect_has_valid_certificate_installed()
            .return_once(|_| Ok(false));
        keychain
            .expect_custom_keychain_exists()
            .return_once(|name: &str| {
                assert_eq!(name, "rutter");
                Ok(true)
            });
        keychain.expect_create_custom_keychain().never();
        keychain.expect_install_private_key().never();
        keychain
            .expect_install_certificate()
            .return_once(|req: &InstallCertificateRequest| {
                assert_eq!(req.keychain_name, "rutter");
                assert_eq!(req.certificate_content.base64_data, "certificate-data");
                Ok(())
            });

        let mut secret_repo = MockSecretConfigFileRepository::new();
        secret_repo
            .expect_load()
            .return_once(|| Ok(sample_secret_config()));

        let mut jwt = MockJwtPort::new();
        jwt.expect_validate()
            .with(eq("jwt-token"))
            .returning(|_| Ok(()));

        let mut key_generator = MockKeyGeneratorPort::new();
        key_generator.expect_generate_private_key().never();
        key_generator.expect_create_csr().never();

        let service = CertificateService::new(asc, keychain, secret_repo, jwt, key_generator);

        let request = sample_request();
        let result = service.ensure_certificate(&request).await.unwrap();

        match result {
            EnsureCertificateResult::DownloadedAndInstalled { certificate_id } => {
                assert_eq!(certificate_id, "CERT123");
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[tokio::test]
    async fn creates_certificate_when_remote_missing() {
        let mut asc = MockCertificateApiPort::new();
        asc.expect_list_certificates()
            .returning(|_req| Box::pin(async { Ok(Vec::new()) }));
        asc.expect_create_certificate().returning(|req| {
            assert_eq!(req.team_id, "TEAMID123");
            assert_eq!(req.csr_string, "CSR-DATA");
            Box::pin(async {
                Ok(RemoteCertificateSummary {
                    id: "NEWCERT".to_string(),
                    serial: None,
                    expires_at_epoch: None,
                    common_name: None,
                    certificate_content: CertificateContent {
                        base64_data: "certificate-data".to_string(),
                    },
                })
            })
        });

        let mut keychain = MockKeychainPort::new();
        keychain
            .expect_has_valid_certificate_installed()
            .return_once(|_| Ok(false));
        keychain
            .expect_custom_keychain_exists()
            .return_once(|name: &str| {
                assert_eq!(name, "rutter");
                Ok(true)
            });
        keychain.expect_create_custom_keychain().never();
        keychain
            .expect_install_private_key()
            .return_once(|req: &InstallPrivateKeyRequest| {
                assert_eq!(req.keychain_name, "rutter");
                assert_eq!(req.private_key_pem.content, "PRIVATE-KEY");
                Ok(())
            });
        keychain
            .expect_install_certificate()
            .return_once(|req: &InstallCertificateRequest| {
                assert_eq!(req.keychain_name, "rutter");
                assert_eq!(req.certificate_content.base64_data, "certificate-data");
                Ok(())
            });

        let mut secret_repo = MockSecretConfigFileRepository::new();
        secret_repo
            .expect_load()
            .return_once(|| Ok(sample_secret_config()));

        let mut jwt = MockJwtPort::new();
        jwt.expect_validate()
            .with(eq("jwt-token"))
            .returning(|_| Ok(()));

        let mut key_generator = MockKeyGeneratorPort::new();
        key_generator
            .expect_generate_private_key()
            .return_once(|path| {
                assert_eq!(path, Some(PathBuf::from("custom-dir")));
                Ok(PrivateKeyPEM {
                    content: "PRIVATE-KEY".to_string(),
                    path: "private-key-path".to_string(),
                })
            });
        key_generator
            .expect_create_csr()
            .returning(|req: &CreateCsrRequest| {
                assert_eq!(req.private_key_pem.content, "PRIVATE-KEY");
                Ok("CSR-DATA".to_string())
            });

        let service = CertificateService::new(asc, keychain, secret_repo, jwt, key_generator);

        let mut request = sample_request();
        request.private_key_output_path = Some(PathBuf::from("custom-dir"));
        request.allow_private_key_generation = true;
        let result = service.ensure_certificate(&request).await.unwrap();

        match result {
            EnsureCertificateResult::CreatedAndInstalled { certificate_id } => {
                assert_eq!(certificate_id, "NEWCERT");
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[tokio::test]
    async fn creates_keychain_when_missing() {
        let mut asc = MockCertificateApiPort::new();
        asc.expect_list_certificates()
            .returning(|_| Box::pin(async { Ok(Vec::new()) }));
        asc.expect_create_certificate().returning(|_| {
            Box::pin(async {
                Ok(RemoteCertificateSummary {
                    id: "KEYCHAINCERT".to_string(),
                    serial: None,
                    expires_at_epoch: None,
                    common_name: None,
                    certificate_content: CertificateContent {
                        base64_data: "certificate-data".to_string(),
                    },
                })
            })
        });

        let mut keychain = MockKeychainPort::new();
        keychain
            .expect_has_valid_certificate_installed()
            .return_once(|_| Ok(false));
        keychain
            .expect_custom_keychain_exists()
            .return_once(|name: &str| {
                assert_eq!(name, "rutter");
                Ok(false)
            });
        keychain
            .expect_create_custom_keychain()
            .return_once(|req: &EnsureKeychainRequest| {
                assert_eq!(req.keychain_name, "rutter");
                assert_eq!(req.password.as_deref(), Some("secret"));
                Ok(())
            });
        keychain
            .expect_install_private_key()
            .return_once(|req: &InstallPrivateKeyRequest| {
                assert_eq!(req.private_key_pem.content, "PRIVATE-KEY");
                Ok(())
            });
        keychain
            .expect_install_certificate()
            .return_once(|req: &InstallCertificateRequest| {
                assert_eq!(req.certificate_content.base64_data, "certificate-data");
                Ok(())
            });

        let mut secret_repo = MockSecretConfigFileRepository::new();
        secret_repo
            .expect_load()
            .return_once(|| Ok(sample_secret_config()));

        let mut jwt = MockJwtPort::new();
        jwt.expect_validate()
            .with(eq("jwt-token"))
            .returning(|_| Ok(()));

        let mut key_generator = MockKeyGeneratorPort::new();
        key_generator
            .expect_generate_private_key()
            .return_once(|path| {
                assert!(path.is_none());
                Ok(PrivateKeyPEM {
                    content: "PRIVATE-KEY".to_string(),
                    path: "private-key-path".to_string(),
                })
            });
        key_generator
            .expect_create_csr()
            .returning(|req: &CreateCsrRequest| {
                assert_eq!(req.private_key_pem.content, "PRIVATE-KEY");
                Ok("CSR-DATA".to_string())
            });

        let service = CertificateService::new(asc, keychain, secret_repo, jwt, key_generator);

        let mut request = sample_request();
        request.allow_private_key_generation = true;
        let result = service.ensure_certificate(&request).await.unwrap();

        match result {
            EnsureCertificateResult::CreatedKeychainAndInstalled { certificate_id } => {
                assert_eq!(certificate_id, "KEYCHAINCERT");
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[tokio::test]
    async fn errors_when_private_key_generation_not_allowed() {
        let mut asc = MockCertificateApiPort::new();
        asc.expect_list_certificates()
            .returning(|_| Box::pin(async { Ok(Vec::new()) }));
        asc.expect_create_certificate().never();

        let mut keychain = MockKeychainPort::new();
        keychain
            .expect_has_valid_certificate_installed()
            .return_once(|_| Ok(false));
        keychain
            .expect_custom_keychain_exists()
            .return_once(|_| Ok(true));
        keychain.expect_create_custom_keychain().never();
        keychain.expect_install_private_key().never();
        keychain.expect_install_certificate().never();

        let mut secret_repo = MockSecretConfigFileRepository::new();
        secret_repo
            .expect_load()
            .return_once(|| Ok(sample_secret_config()));

        let mut jwt = MockJwtPort::new();
        jwt.expect_validate()
            .with(eq("jwt-token"))
            .returning(|_| Ok(()));

        let mut key_generator = MockKeyGeneratorPort::new();
        key_generator.expect_generate_private_key().never();
        key_generator.expect_create_csr().never();

        let service = CertificateService::new(asc, keychain, secret_repo, jwt, key_generator);

        let request = sample_request();
        let err = service.ensure_certificate(&request).await.unwrap_err();

        match err {
            E::PrivateKeyGenerationNotApproved => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
