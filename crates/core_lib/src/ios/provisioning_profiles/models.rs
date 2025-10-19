use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProvisioningProfileType {
    IosDevelopment,
    IosAppStore,
    IosAdHoc,
    MacDevelopment,
    MacAppStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProvisioningProfileState {
    Active,
    Inactive,
}

#[derive(Debug, Clone)]
pub struct RemoteProvisioningProfileSummary {
    pub id: String,
    pub uuid: String,
    pub name: String,
    pub expires_at_epoch: Option<i64>,
    pub state: ProvisioningProfileState,
    pub profile_content: ProvisioningProfileContent,
}

#[derive(Debug, Clone)]
pub struct ProvisioningProfileContent {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProvisioningProfileQuery {
    pub bundle_id: String,
    pub profile_type: ProvisioningProfileType,
}

#[derive(Debug, Clone)]
pub struct ListProvisioningProfilesRequest {
    pub jwt: String,
    pub profile_type: ProvisioningProfileType,
    pub bundle_id: String,
}

#[derive(Debug, Clone)]
pub struct CreateProvisioningProfileRequest {
    pub jwt: String,
    pub profile_type: ProvisioningProfileType,
    pub bundle_id: String,
    pub profile_name: String,
    pub certificate_ids: Vec<String>,
    pub device_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EnsureProvisioningProfileRequest {
    pub bundle_id: String,
    pub profile_name: Option<String>,
    pub profile_type: ProvisioningProfileType,
    pub certificate_ids: Option<Vec<String>>,
    pub device_ids: Vec<String>,
    pub install_destination: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct InstallProvisioningProfileRequest {
    pub profile_id: String,
    pub profile_uuid: String,
    pub profile_name: String,
    pub profile_content: ProvisioningProfileContent,
    pub destination: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum EnsureProvisioningProfileResult {
    AlreadyInstalled,
    DownloadedAndInstalled { profile_id: String },
    CreatedAndInstalled { profile_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnsureProvisioningProfileStep {
    LoadSecrets,
    ValidateJwt,
    CheckLocalProfile,
    FetchRemoteProfiles,
    SelectExistingProfile,
    CreateRemoteProfile,
    InstallProfile,
}
