use std::path::PathBuf;

use asc_client::client::AppStoreConnectClient;
use clap::{Args, ValueEnum};
use core_lib::ios::provisioning_profiles::{
    models::{
        EnsureProvisioningProfileRequest, EnsureProvisioningProfileResult, ProvisioningProfileType,
    },
    service::ProvisioningProfileService,
};
use sys_tools::{
    provisioning_profile_local::ProvisioningProfileLocalAdapter,
    secret_config_storage::FileSecretConfigRepository,
};

use crate::commands::{CliResult, ios::progress::CliProvisioningProfileProgressReporter};

#[derive(Args, Debug)]
pub struct EnsureProvisioningProfileArgs {
    /// Bundle identifier the provisioning profile should cover
    #[arg(long)]
    pub bundle_id: String,
    /// Name that should be assigned to the provisioning profile when creating it
    #[arg(long)]
    pub profile_name: Option<String>,
    /// Desired provisioning profile type
    #[arg(long, value_enum, default_value_t = ProvisioningProfileTypeArg::IosAppStore)]
    pub profile_type: ProvisioningProfileTypeArg,
    /// Certificate identifiers to attach to the profile (repeat or comma-separate)
    #[arg(long = "certificate-id", value_delimiter = ',', num_args = 1..)]
    pub certificate_ids: Option<Vec<String>>,
    /// Device identifiers to assign to the profile (repeat or comma-separate)
    #[arg(long = "device-id", value_delimiter = ',')]
    pub device_ids: Vec<String>,
    /// Optional location where the profile should be installed
    #[arg(long)]
    pub install_destination: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ProvisioningProfileTypeArg {
    IosDevelopment,
    IosAppStore,
    IosAdHoc,
    MacDevelopment,
    MacAppStore,
}

impl From<ProvisioningProfileTypeArg> for ProvisioningProfileType {
    fn from(value: ProvisioningProfileTypeArg) -> Self {
        match value {
            ProvisioningProfileTypeArg::IosDevelopment => ProvisioningProfileType::IosDevelopment,
            ProvisioningProfileTypeArg::IosAppStore => ProvisioningProfileType::IosAppStore,
            ProvisioningProfileTypeArg::IosAdHoc => ProvisioningProfileType::IosAdHoc,
            ProvisioningProfileTypeArg::MacDevelopment => ProvisioningProfileType::MacDevelopment,
            ProvisioningProfileTypeArg::MacAppStore => ProvisioningProfileType::MacAppStore,
        }
    }
}

pub async fn ensure_provisioning_profile(
    args: &EnsureProvisioningProfileArgs,
) -> CliResult<EnsureProvisioningProfileResult> {
    let asc_client = AppStoreConnectClient::new();
    let progress_reporter = CliProvisioningProfileProgressReporter::new();

    let service = ProvisioningProfileService::new_with_reporter(
        asc_client.clone(),
        ProvisioningProfileLocalAdapter::new(),
        FileSecretConfigRepository::new(),
        asc_client,
        progress_reporter,
    );

    let request = EnsureProvisioningProfileRequest {
        bundle_id: args.bundle_id.clone(),
        profile_name: args.profile_name.clone(),
        profile_type: args.profile_type.into(),
        certificate_ids: args.certificate_ids.clone(),
        device_ids: args.device_ids.clone(),
        install_destination: args.install_destination.clone(),
    };

    service
        .ensure_provisioning_profile(&request)
        .await
        .map_err(|err| format!("Failed to ensure provisioning profile: {err}"))
}
