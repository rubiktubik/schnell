use crate::{
    ios::provisioning_profiles::models::ProvisioningProfileType,
    shared::models::{CertificateContent, CertificateKind, PrivateKeyPEM, TeamId},
};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RemoteCertificateSummary {
    pub id: String,
    pub serial: Option<String>,
    pub expires_at_epoch: Option<i64>,
    pub common_name: Option<String>,
    pub certificate_content: CertificateContent,
}

#[derive(Debug, Clone)]
pub struct CheckCertificateApiRequest {
    pub jwt: String,
    pub kind: CertificateKind,
}

#[derive(Debug, Clone)]
pub struct CreateCertificateApiRequest {
    pub jwt: String,
    pub team_id: String,
    pub kind: CertificateKind,
    pub csr_string: String,
}

#[derive(Debug, Clone)]
pub struct DownloadCertificateApiRequest {
    pub jwt: String,
    pub team_id: String,
    pub certificate_id: String,
}

#[derive(Debug, Clone)]
pub struct EnsureCertificateRequest {
    pub team_id: TeamId,
    pub kind: CertificateKind,
    /// Name des Custom-Keychains (z. B. "rutter")
    pub keychain_name: String,
    /// Optional: Passwort für Custom-Keychain (falls neu erzeugt)
    pub keychain_password: Option<String>,
    pub set_key_chain_as_default: bool,
    pub private_key_pem: Option<PrivateKeyPEM>,
    /// Optionaler Pfad, in dem ein neuer Private Key abgelegt werden soll
    pub private_key_output_path: Option<PathBuf>,
    /// Explicit consent to generate a new private key when no existing key is supplied.
    pub allow_private_key_generation: bool,
}

#[derive(Debug, Clone)]
pub enum EnsureCertificateResult {
    /// Gültiges, passendes Zertifikat ist lokal bereits installiert
    AlreadyInstalled,

    /// In ASC vorhanden, lokal heruntergeladen und installiert
    DownloadedAndInstalled { certificate_id: String },

    /// In ASC neu erzeugt (CSR), heruntergeladen und installiert
    CreatedAndInstalled { certificate_id: String },

    /// Zusätzlich Custom-Keychain neu angelegt
    CreatedKeychainAndInstalled { certificate_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnsureCertificateStep {
    LoadSecrets,
    ValidateJwt,
    CheckLocalCertificate,
    FetchRemoteCertificates,
    SelectExistingCertificate,
    GeneratePrivateKey,
    CreateCsr,
    RequestCertificate,
    EnsureKeychain,
    InstallPrivateKey,
    InstallCertificate,
}

impl From<ProvisioningProfileType> for CertificateKind {
    fn from(profile_type: ProvisioningProfileType) -> Self {
        match profile_type {
            ProvisioningProfileType::IosDevelopment | ProvisioningProfileType::MacDevelopment => {
                CertificateKind::AppleDevelopment
            }
            ProvisioningProfileType::IosAppStore
            | ProvisioningProfileType::IosAdHoc
            | ProvisioningProfileType::MacAppStore => CertificateKind::AppleDistribution,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_development_profiles_to_development_certificate() {
        assert_eq!(
            CertificateKind::from(ProvisioningProfileType::IosDevelopment),
            CertificateKind::AppleDevelopment
        );
        assert_eq!(
            CertificateKind::from(ProvisioningProfileType::MacDevelopment),
            CertificateKind::AppleDevelopment
        );
    }

    #[test]
    fn converts_distribution_profiles_to_distribution_certificate() {
        assert_eq!(
            CertificateKind::from(ProvisioningProfileType::IosAppStore),
            CertificateKind::AppleDistribution
        );
        assert_eq!(
            CertificateKind::from(ProvisioningProfileType::IosAdHoc),
            CertificateKind::AppleDistribution
        );
        assert_eq!(
            CertificateKind::from(ProvisioningProfileType::MacAppStore),
            CertificateKind::AppleDistribution
        );
    }
}
