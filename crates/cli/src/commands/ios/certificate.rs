use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

use asc_client::client::AppStoreConnectClient;
use clap::{Args, ValueEnum};
use core_lib::{
    ios::certificates::{
        models::{EnsureCertificateRequest, EnsureCertificateResult},
        service::CertificateService,
    },
    shared::models::{CertificateKind, PrivateKeyPEM, TeamId},
};
use csr::PlaceholderKeyGenerator;
use sys_tools::{
    keychain_adapter::KeyChainAdapter, secret_config_storage::FileSecretConfigRepository,
};

use crate::commands::{CliResult, ios::progress::CliCertificateProgressReporter};

#[derive(Args, Debug)]
pub struct EnsureCertificateArgs {
    /// The App Store Connect team identifier (e.g. 9XXXXXXXXX)
    #[arg(long)]
    pub team_id: String,
    /// The certificate kind to ensure
    #[arg(long, value_enum, default_value_t = CertificateKindArg::AppleDistribution)]
    pub kind: CertificateKindArg,
    /// The keychain name to inspect or create (without extension)
    #[arg(long, default_value = "schnell")]
    pub keychain_name: String,
    /// Optional password for the keychain when creating or unlocking
    #[arg(long)]
    pub keychain_password: Option<String>,
    /// Set the keychain as default after ensuring it exists
    #[arg(long, default_value_t = false)]
    pub set_default_keychain: bool,
    /// Use an existing private key PEM file instead of generating a new one
    #[arg(long)]
    pub private_key_pem: Option<PathBuf>,
    /// Directory or file path where a generated private key should be stored
    #[arg(long)]
    pub private_key_output_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CertificateKindArg {
    AppleDistribution,
    AppleDevelopment,
}

impl From<CertificateKindArg> for CertificateKind {
    fn from(value: CertificateKindArg) -> Self {
        match value {
            CertificateKindArg::AppleDistribution => CertificateKind::AppleDistribution,
            CertificateKindArg::AppleDevelopment => CertificateKind::AppleDevelopment,
        }
    }
}

pub async fn ensure_certificate(
    args: &EnsureCertificateArgs,
) -> CliResult<EnsureCertificateResult> {
    let asc_client = AppStoreConnectClient::new();
    let mut progress_reporter = CliCertificateProgressReporter::new();

    let private_key_selection = resolve_private_key(args)?;
    if let Some(selection) = private_key_selection.as_ref() {
        progress_reporter.set_existing_private_key_path(selection.display_path.clone());
    }

    let allow_private_key_generation = if private_key_selection.is_some() {
        false
    } else {
        let confirmed = prompt_for_private_key_generation(args.private_key_output_path.as_deref())?;
        if !confirmed {
            return Err(
                "Aborted: refusing to generate a new private key without confirmation.".to_string(),
            );
        }
        true
    };

    let service = CertificateService::new_with_reporter(
        asc_client.clone(),
        KeyChainAdapter,
        FileSecretConfigRepository::new(),
        asc_client,
        PlaceholderKeyGenerator::new(),
        progress_reporter,
    );

    let request = EnsureCertificateRequest {
        team_id: TeamId {
            value: args.team_id.clone(),
        },
        kind: args.kind.into(),
        keychain_name: args.keychain_name.clone(),
        keychain_password: args.keychain_password.clone(),
        set_key_chain_as_default: args.set_default_keychain,
        private_key_pem: private_key_selection.map(|selection| selection.pem),
        private_key_output_path: args.private_key_output_path.clone(),
        allow_private_key_generation,
    };

    service
        .ensure_certificate(&request)
        .await
        .map_err(|err| format!("Failed to ensure certificate: {err}"))
}

struct PrivateKeySelection {
    pem: PrivateKeyPEM,
    display_path: String,
}

fn resolve_private_key(args: &EnsureCertificateArgs) -> CliResult<Option<PrivateKeySelection>> {
    if let Some(path) = args.private_key_pem.as_ref() {
        return load_private_key(path);
    }

    let discovered = find_private_key_in_working_dir()?;
    match discovered {
        Some(path) => load_private_key(&path),
        None => Ok(None),
    }
}

fn load_private_key(path: &Path) -> CliResult<Option<PrivateKeySelection>> {
    let content = fs::read_to_string(path).map_err(|err| {
        format!(
            "Failed to read private key PEM from {}: {err}",
            path.display()
        )
    })?;
    let display_path = path.display().to_string();
    let pem = PrivateKeyPEM {
        content,
        path: path.to_string_lossy().into_owned(),
    };
    Ok(Some(PrivateKeySelection { pem, display_path }))
}

fn prompt_for_private_key_generation(output_path: Option<&Path>) -> CliResult<bool> {
    use std::io::Write;

    let destination = match output_path {
        Some(path) if path.extension().is_some() => format!("at {}", path.display()),
        Some(path) => format!("in directory {}", path.display()),
        None => match env::current_dir() {
            Ok(dir) => format!("in directory {}", dir.display()),
            Err(_) => "in the current working directory".to_string(),
        },
    };

    println!("No private key PEM was provided or discovered.");
    print!("Generate a new private key and save it {destination}? [y/N]: ");
    io::stdout()
        .flush()
        .map_err(|err| format!("Failed to render prompt: {err}"))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|err| format!("Failed to read confirmation: {err}"))?;
    let decision = input.trim().to_ascii_lowercase();
    Ok(matches!(decision.as_str(), "y" | "yes"))
}

fn find_private_key_in_working_dir() -> CliResult<Option<PathBuf>> {
    let current_dir =
        env::current_dir().map_err(|err| format!("Failed to resolve current directory: {err}"))?;
    let entries = fs::read_dir(&current_dir)
        .map_err(|err| format!("Failed to inspect {}: {err}", current_dir.display()))?;

    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("Failed to inspect directory entry: {err}"))?;
        let file_type = entry
            .file_type()
            .map_err(|err| format!("Failed to inspect file type for {:?}: {err}", entry.path()))?;
        if !file_type.is_file() {
            continue;
        }

        let file_name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };

        if is_private_key_filename(&file_name) {
            let timestamp =
                file_name["private_key_".len()..file_name.len() - ".key".len()].to_string();
            candidates.push((timestamp, entry.path()));
        }
    }

    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(candidates.into_iter().map(|(_, path)| path).next())
}

fn is_private_key_filename(name: &str) -> bool {
    let prefix = "private_key_";
    let suffix = ".key";
    if !name.starts_with(prefix) || !name.ends_with(suffix) {
        return false;
    }

    let timestamp_part = &name[prefix.len()..name.len() - suffix.len()];
    timestamp_part.len() == 14 && timestamp_part.chars().all(|c| c.is_ascii_digit())
}
