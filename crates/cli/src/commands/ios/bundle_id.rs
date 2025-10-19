use asc_client::client::AppStoreConnectClient;
use clap::Args;
use core_lib::{
    ios::bundle_identifier::{
        models::{CheckIdentifierRequest, EnsureBundleIdentifierResult},
        ports::BundleIdentifierServicePort,
        service::BundleIdentifierService,
    },
    shared::models::BundleIdentifier,
};
use sys_tools::{
    config_storage::FileConfigRepository, secret_config_storage::FileSecretConfigRepository,
};

use crate::{commands::CliResult, dummy_cli::DummyBundleIdentifierCli};

#[derive(Args, Debug)]
pub struct EnsureBundleIdArgs {
    /// The bundle identifier
    #[arg(long)]
    pub id: String,
    /// An alphanumeric name
    #[arg(long)]
    pub name: String,
}

pub async fn ensure_bundle_id(
    args: &EnsureBundleIdArgs,
) -> CliResult<EnsureBundleIdentifierResult> {
    let asc_client = AppStoreConnectClient::new();
    let service = BundleIdentifierService::new(
        asc_client.clone(),
        FileSecretConfigRepository::new(),
        asc_client,
        DummyBundleIdentifierCli,
        FileConfigRepository::new(),
    );

    let request = CheckIdentifierRequest {
        bundle_identifier: BundleIdentifier {
            name: args.name.clone(),
            identifier: args.id.clone(),
        },
    };

    service
        .ensure_bundle_id_exists(&request)
        .await
        .map_err(|err| format!("Failed to ensure bundle ID: {err}"))
}
