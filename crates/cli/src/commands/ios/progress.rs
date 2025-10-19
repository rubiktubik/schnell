use console::style;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use core_lib::ios::{
    certificates::{
        models::{EnsureCertificateResult, EnsureCertificateStep},
        progress::CertificateProgressReporter,
    },
    provisioning_profiles::{
        models::{EnsureProvisioningProfileResult, EnsureProvisioningProfileStep},
        progress::ProvisioningProfileProgressReporter,
    },
};

pub(crate) struct CliCertificateProgressReporter {
    step_counter: AtomicUsize,
    current_step: AtomicUsize,
    spinner: Mutex<Option<ProgressBar>>,
    existing_private_key_path: Option<String>,
}

impl CliCertificateProgressReporter {
    pub(crate) fn new() -> Self {
        Self {
            step_counter: AtomicUsize::new(0),
            current_step: AtomicUsize::new(0),
            spinner: Mutex::new(None),
            existing_private_key_path: None,
        }
    }

    pub(crate) fn set_existing_private_key_path(&mut self, path: String) {
        self.existing_private_key_path = Some(path);
    }

    fn start_caption(&self, step: EnsureCertificateStep) -> (&'static str, String) {
        match step {
            EnsureCertificateStep::LoadSecrets => {
                ("🔐", "Loading App Store Connect secrets".to_string())
            }
            EnsureCertificateStep::ValidateJwt => ("🪪", "Validating stored JWT token".to_string()),
            EnsureCertificateStep::CheckLocalCertificate => (
                "🔍",
                "Checking the local keychain for a valid certificate".to_string(),
            ),
            EnsureCertificateStep::FetchRemoteCertificates => (
                "🌐",
                "Fetching certificates from App Store Connect".to_string(),
            ),
            EnsureCertificateStep::SelectExistingCertificate => (
                "🗃️",
                "Selecting or preparing the appropriate certificate".to_string(),
            ),
            EnsureCertificateStep::GeneratePrivateKey => {
                ("🛠️", "Generating a new private key".to_string())
            }
            EnsureCertificateStep::CreateCsr => {
                if let Some(path) = self.existing_private_key_path.as_ref() {
                    (
                        "📝",
                        format!("Creating a certificate signing request using {path}"),
                    )
                } else {
                    ("📝", "Creating a certificate signing request".to_string())
                }
            }
            EnsureCertificateStep::RequestCertificate => (
                "📨",
                "Requesting certificate issuance from App Store Connect".to_string(),
            ),
            EnsureCertificateStep::EnsureKeychain => {
                ("🗝️", "Ensuring the target keychain exists".to_string())
            }
            EnsureCertificateStep::InstallPrivateKey => (
                "📥",
                "Installing the private key into the keychain".to_string(),
            ),
            EnsureCertificateStep::InstallCertificate => (
                "📄",
                "Installing the certificate into the keychain".to_string(),
            ),
        }
    }

    fn completion_caption(&self, step: EnsureCertificateStep) -> (&'static str, String) {
        match step {
            EnsureCertificateStep::LoadSecrets => ("✅", "Loaded secrets".to_string()),
            EnsureCertificateStep::ValidateJwt => ("✅", "JWT validated".to_string()),
            EnsureCertificateStep::CheckLocalCertificate => {
                ("✅", "Local keychain checked".to_string())
            }
            EnsureCertificateStep::FetchRemoteCertificates => {
                ("✅", "Fetched remote certificates".to_string())
            }
            EnsureCertificateStep::SelectExistingCertificate => {
                ("✅", "Certificate ready".to_string())
            }
            EnsureCertificateStep::GeneratePrivateKey => {
                ("✨", "Private key generated".to_string())
            }
            EnsureCertificateStep::CreateCsr => {
                if let Some(path) = self.existing_private_key_path.as_ref() {
                    ("✨", format!("CSR created using {path}"))
                } else {
                    ("✨", "CSR created".to_string())
                }
            }
            EnsureCertificateStep::RequestCertificate => ("📬", "Certificate issued".to_string()),
            EnsureCertificateStep::EnsureKeychain => ("🔓", "Keychain ensured".to_string()),
            EnsureCertificateStep::InstallPrivateKey => ("🔐", "Private key installed".to_string()),
            EnsureCertificateStep::InstallCertificate => {
                ("🎉", "Certificate installed".to_string())
            }
        }
    }
}

impl CertificateProgressReporter for CliCertificateProgressReporter {
    fn on_step_started(&self, step: EnsureCertificateStep) {
        let index = self.step_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let (emoji, message) = self.start_caption(step);
        self.current_step.store(index, Ordering::SeqCst);

        let spinner = ProgressBar::new_spinner();
        spinner.set_draw_target(ProgressDrawTarget::stdout_with_hz(60));
        spinner.set_style(spinner_style());
        spinner.set_prefix(format!("[{index:02}]"));
        spinner.set_message(format!("{emoji} {message}…"));
        spinner.enable_steady_tick(Duration::from_millis(120));

        let mut guard = self.spinner.lock().unwrap();
        if let Some(existing) = guard.take() {
            existing.finish_and_clear();
        }
        *guard = Some(spinner);
    }

    fn on_step_completed(&self, step: EnsureCertificateStep) {
        let (emoji, message) = self.completion_caption(step);
        let index = self.current_step.load(Ordering::SeqCst);

        if let Some(spinner) = self.spinner.lock().unwrap().take() {
            spinner.finish_and_clear();
        }

        let bullet = style("└─").dim();
        let prefix = style(format!("[{index:02}]")).bold().dim();
        let status = style(emoji).green();
        let message_text = style(message).dim();
        println!("   {} {} {} {}", bullet, prefix, status, message_text);
    }

    fn on_finished(&self, _result: &EnsureCertificateResult) {
        if let Some(spinner) = self.spinner.lock().unwrap().take() {
            spinner.finish_and_clear();
        }
        println!();
    }
}

pub(crate) struct CliProvisioningProfileProgressReporter {
    step_counter: AtomicUsize,
    current_step: AtomicUsize,
    spinner: Mutex<Option<ProgressBar>>,
}

impl CliProvisioningProfileProgressReporter {
    pub(crate) fn new() -> Self {
        Self {
            step_counter: AtomicUsize::new(0),
            current_step: AtomicUsize::new(0),
            spinner: Mutex::new(None),
        }
    }

    fn start_caption(&self, step: EnsureProvisioningProfileStep) -> (&'static str, String) {
        match step {
            EnsureProvisioningProfileStep::LoadSecrets => {
                ("🔐", "Loading App Store Connect secrets".to_string())
            }
            EnsureProvisioningProfileStep::ValidateJwt => {
                ("🪪", "Validating stored JWT token".to_string())
            }
            EnsureProvisioningProfileStep::CheckLocalProfile => {
                ("🔍", "Checking local provisioning profiles".to_string())
            }
            EnsureProvisioningProfileStep::FetchRemoteProfiles => (
                "🌐",
                "Fetching provisioning profiles from App Store Connect".to_string(),
            ),
            EnsureProvisioningProfileStep::SelectExistingProfile => {
                ("🗃️", "Selecting existing provisioning profile".to_string())
            }
            EnsureProvisioningProfileStep::CreateRemoteProfile => (
                "🛠️",
                "Creating provisioning profile on App Store Connect".to_string(),
            ),
            EnsureProvisioningProfileStep::InstallProfile => {
                ("📥", "Installing provisioning profile locally".to_string())
            }
        }
    }

    fn completion_caption(&self, step: EnsureProvisioningProfileStep) -> (&'static str, String) {
        match step {
            EnsureProvisioningProfileStep::LoadSecrets => ("✅", "Loaded secrets".to_string()),
            EnsureProvisioningProfileStep::ValidateJwt => ("✅", "JWT validated".to_string()),
            EnsureProvisioningProfileStep::CheckLocalProfile => {
                ("✅", "Local profiles checked".to_string())
            }
            EnsureProvisioningProfileStep::FetchRemoteProfiles => {
                ("✅", "Fetched remote profiles".to_string())
            }
            EnsureProvisioningProfileStep::SelectExistingProfile => {
                ("✅", "Profile ready".to_string())
            }
            EnsureProvisioningProfileStep::CreateRemoteProfile => {
                ("✨", "Provisioning profile created".to_string())
            }
            EnsureProvisioningProfileStep::InstallProfile => {
                ("🎉", "Provisioning profile installed".to_string())
            }
        }
    }
}

impl ProvisioningProfileProgressReporter for CliProvisioningProfileProgressReporter {
    fn on_step_started(&self, step: EnsureProvisioningProfileStep) {
        let index = self.step_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let (emoji, message) = self.start_caption(step);
        self.current_step.store(index, Ordering::SeqCst);

        let spinner = ProgressBar::new_spinner();
        spinner.set_draw_target(ProgressDrawTarget::stdout_with_hz(60));
        spinner.set_style(spinner_style());
        spinner.set_prefix(format!("[{index:02}]"));
        spinner.set_message(format!("{emoji} {message}…"));
        spinner.enable_steady_tick(Duration::from_millis(120));

        let mut guard = self.spinner.lock().unwrap();
        if let Some(existing) = guard.take() {
            existing.finish_and_clear();
        }
        *guard = Some(spinner);
    }

    fn on_step_completed(&self, step: EnsureProvisioningProfileStep) {
        let (emoji, message) = self.completion_caption(step);
        let index = self.current_step.load(Ordering::SeqCst);

        if let Some(spinner) = self.spinner.lock().unwrap().take() {
            spinner.finish_and_clear();
        }

        let bullet = style("└─").dim();
        let prefix = style(format!("[{index:02}]")).bold().dim();
        let status = style(emoji).green();
        let message_text = style(message).dim();
        println!("   {} {} {} {}", bullet, prefix, status, message_text);
    }

    fn on_finished(&self, _result: &EnsureProvisioningProfileResult) {
        if let Some(spinner) = self.spinner.lock().unwrap().take() {
            spinner.finish_and_clear();
        }
        println!();
    }
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{prefix:.dim} {spinner:.cyan} {msg}")
        .unwrap()
        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
}
