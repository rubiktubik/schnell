use clap::{Args, Subcommand};
use core_lib::ios::{
    bundle_identifier::models::EnsureBundleIdentifierResult,
    certificates::models::EnsureCertificateResult,
    provisioning_profiles::models::EnsureProvisioningProfileResult,
};

use crate::commands::{
    CliResult,
    ios::{
        bundle_id::{EnsureBundleIdArgs, ensure_bundle_id},
        certificate::{EnsureCertificateArgs, ensure_certificate},
        login::{LoginArgs, handle_login},
        provisioning_profile::{EnsureProvisioningProfileArgs, ensure_provisioning_profile},
    },
};

mod bundle_id;
mod certificate;
mod login;
mod progress;
mod provisioning_profile;

#[derive(Args, Debug)]
pub struct IosCommands {
    #[command(subcommand)]
    pub command: IosSubCommands,
}

#[derive(Subcommand, Debug)]
pub enum IosSubCommands {
    /// Login to App Store Connect
    Login(LoginArgs),
    /// Ensures a bundle identifier exists on App Store Connect
    EnsureBundleId(EnsureBundleIdArgs),
    /// Ensures a certificate is available and installed locally
    EnsureCertificate(EnsureCertificateArgs),
    /// Ensures a provisioning profile exists remotely and locally
    EnsureProvisioningProfile(EnsureProvisioningProfileArgs),
}

pub async fn run(commands: IosCommands) -> CliResult<()> {
    match commands.command {
        IosSubCommands::Login(args) => {
            handle_login(&args)?;
            println!("Login successful");
            Ok(())
        }
        IosSubCommands::EnsureBundleId(args) => {
            let result = ensure_bundle_id(&args).await?;
            match result {
                EnsureBundleIdentifierResult::CreatedNewIdentifier => {
                    println!("New Bundle ID {} created.", args.id)
                }
                EnsureBundleIdentifierResult::IdentifierAlreadyExists => {
                    println!("Bundle ID already exists. Nothing to do")
                }
            }
            Ok(())
        }
        IosSubCommands::EnsureCertificate(args) => {
            let result = ensure_certificate(&args).await?;
            match result {
                EnsureCertificateResult::AlreadyInstalled => {
                    println!("Certificate already installed in target keychain")
                }
                EnsureCertificateResult::DownloadedAndInstalled { certificate_id } => {
                    println!("Downloaded existing certificate {certificate_id} and installed it")
                }
                EnsureCertificateResult::CreatedAndInstalled { certificate_id } => {
                    println!("Created new certificate {certificate_id} and installed it")
                }
                EnsureCertificateResult::CreatedKeychainAndInstalled { certificate_id } => {
                    println!("Created keychain and installed certificate {certificate_id}")
                }
            }
            Ok(())
        }
        IosSubCommands::EnsureProvisioningProfile(args) => {
            let result = ensure_provisioning_profile(&args).await?;
            match result {
                EnsureProvisioningProfileResult::AlreadyInstalled => {
                    println!("Provisioning profile already installed locally")
                }
                EnsureProvisioningProfileResult::DownloadedAndInstalled { profile_id } => {
                    println!("Downloaded provisioning profile {profile_id} and installed it")
                }
                EnsureProvisioningProfileResult::CreatedAndInstalled { profile_id } => {
                    println!("Created provisioning profile {profile_id} and installed it")
                }
            }
            Ok(())
        }
    }
}
