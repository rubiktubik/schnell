use std::path::PathBuf;

use asc_client::client::AppStoreConnectClient;
use clap::Args;
use core_lib::{
    ios::login::{models::LoginRequest, ports::LoginServicePort, service::LoginService},
    shared::secret_config::AppStoreConnectCredentials,
};
use sys_tools::secret_config_storage::FileSecretConfigRepository;

use crate::commands::CliResult;

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// The issuer ID
    #[arg(long)]
    pub issuer_id: Option<String>,
    /// The key ID
    #[arg(long)]
    pub key_id: Option<String>,
    /// The path to the private key file
    #[arg(long)]
    pub private_key: Option<PathBuf>,
}

pub fn handle_login(args: &LoginArgs) -> CliResult<()> {
    let login_service = LoginService::new(
        FileSecretConfigRepository::new(),
        AppStoreConnectClient::new(),
    );

    let login_request = if let (Some(issuer_id), Some(key_id), Some(private_key)) = (
        args.issuer_id.as_ref(),
        args.key_id.as_ref(),
        args.private_key.as_ref(),
    ) {
        LoginRequest::Credentials(AppStoreConnectCredentials {
            issuer_id: issuer_id.to_string(),
            key_id: key_id.to_string(),
            private_key_file_path: private_key.clone(),
        })
    } else {
        LoginRequest::NoCredentialsProvided
    };

    login_service
        .login(&login_request)
        .map_err(|err| format!("Login failed: {err}"))
}
