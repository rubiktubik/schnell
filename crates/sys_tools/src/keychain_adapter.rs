use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use core_lib::shared::{
    errors::KeychainError,
    models::{
        EnsureKeychainRequest, InstallCertificateRequest, InstallPrivateKeyRequest,
        KeychainCertificateQuery,
    },
    ports::KeychainPort,
};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

const APPLE_WWDR_CERT_COMMON_NAME: &str =
    "Apple Worldwide Developer Relations Certification Authority";
const APPLE_WWDR_SYSTEM_KEYCHAINS: [&str; 2] = [
    "/Library/Keychains/System.keychain",
    "/System/Library/Keychains/SystemRootCertificates.keychain",
];

fn run_security(args: &[&str]) -> Result<(i32, String, String), KeychainError> {
    let output = Command::new("security")
        .args(args)
        .output()
        .map_err(|e| KeychainError::Io(format!("failed to spawn security: {e}")))?;
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok((code, stdout, stderr))
}

fn user_keychains_dir() -> PathBuf {
    if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home).join("Library/Keychains")
    } else {
        // Fallback to relative path; most operations rely on security's search list anyway
        PathBuf::from("Library/Keychains")
    }
}

fn keychain_paths_for_name(name: &str) -> [PathBuf; 2] {
    let dir = user_keychains_dir();
    [
        dir.join(format!("{name}.keychain")),
        dir.join(format!("{name}.keychain-db")),
    ]
}

fn pick_existing_keychain_path(name: &str) -> Option<PathBuf> {
    let candidates = keychain_paths_for_name(name);
    for p in &candidates {
        if p.exists() {
            return Some(p.clone());
        }
    }
    None
}

fn keychain_display_path(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn list_keychains() -> Result<Vec<String>, KeychainError> {
    let (code, out, err) = run_security(&["list-keychains", "-d", "user"])?;
    if code != 0 {
        return Err(KeychainError::Keychain(format!(
            "list-keychains failed: {err}",
        )));
    }
    // Lines like: "\t\"/Users/you/Library/Keychains/login.keychain-db\""
    let mut list = Vec::new();
    for line in out.lines() {
        let trimmed = line.trim();
        let trimmed = trimmed.trim_matches('"');
        if !trimmed.is_empty() {
            list.push(trimmed.to_string());
        }
    }
    Ok(list)
}

fn ensure_in_keychain_list(path: &Path) -> Result<(), KeychainError> {
    let path_str = keychain_display_path(path);
    let mut current = list_keychains()?;
    if !current.iter().any(|p| p == &path_str) {
        current.push(path_str.clone());
        let mut args: Vec<&str> = vec!["list-keychains", "-d", "user", "-s"];
        for p in &current {
            args.push(p.as_str());
        }
        let (code, _out, err) = run_security(args.as_slice())?;
        if code != 0 {
            return Err(KeychainError::Keychain(format!(
                "failed to add keychain to search list: {err}"
            )));
        }
    }
    Ok(())
}

fn unlock_keychain(path: &Path, password: &str) -> Result<(), KeychainError> {
    let path_str = keychain_display_path(path);
    let args = vec!["unlock-keychain", "-p", password, path_str.as_str()];
    let (code, _out, err) = run_security(args.as_slice())?;
    if code != 0 {
        return Err(KeychainError::Keychain(format!(
            "unlock-keychain failed: {err}"
        )));
    }
    Ok(())
}

fn set_default_keychain(path: &Path) -> Result<(), KeychainError> {
    let path_str = keychain_display_path(path);
    let args = vec!["default-keychain", "-s", path_str.as_str()];
    let (code, _out, err) = run_security(args.as_slice())?;
    if code != 0 {
        return Err(KeychainError::Keychain(format!(
            "set default keychain failed: {err}"
        )));
    }
    Ok(())
}

fn set_partition_list(path: &Path, password: &str) -> Result<(), KeychainError> {
    // Allow common Apple tools to access keys without UI prompts
    // -s to suppress UI, -k to specify keychain password
    let path_str = keychain_display_path(path);
    let args = vec![
        "set-key-partition-list",
        "-S",
        "apple-tool:,apple:,codesign:",
        "-s",
        "-k",
        password,
        path_str.as_str(),
    ];
    let (code, _out, err) = run_security(args.as_slice())?;
    if code != 0 {
        // Not fatal for creation, but report as error here to keep behavior clear
        return Err(KeychainError::Keychain(format!(
            "set-key-partition-list failed: {err}"
        )));
    }
    Ok(())
}

fn find_certificate_pem(
    keychain: &Path,
    name_match: &str,
) -> Result<Option<String>, KeychainError> {
    let keychain_str = keychain_display_path(keychain);
    let args = [
        "find-certificate",
        "-c",
        name_match,
        "-a",
        "-p",
        keychain_str.as_str(),
    ];
    let (code, out, err) = run_security(&args)?;
    if code != 0 {
        return Err(KeychainError::Keychain(format!(
            "find-certificate failed for {keychain_str}: {err}",
        )));
    }

    if out.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

fn certificate_exists_in_keychain(
    keychain: &Path,
    name_match: &str,
) -> Result<bool, KeychainError> {
    Ok(find_certificate_pem(keychain, name_match)?.is_some())
}

fn import_certificate_from_pem(keychain: &Path, pem_data: &str) -> Result<(), KeychainError> {
    let mut tmp = env::temp_dir();
    tmp.push("rutter_apple_wwdr.pem");
    {
        let mut file = fs::File::create(&tmp)
            .map_err(|e| KeychainError::Io(format!("temp file create failed: {e}")))?;
        file.write_all(pem_data.as_bytes())
            .map_err(|e| KeychainError::Io(format!("temp file write failed: {e}")))?;
    }

    let tmp_str = keychain_display_path(&tmp);
    let keychain_str = keychain_display_path(keychain);
    let args = [
        "import",
        tmp_str.as_str(),
        "-k",
        keychain_str.as_str(),
        "-T",
        "/usr/bin/codesign",
    ];
    let (code, _out, err) = run_security(&args)?;
    let _ = fs::remove_file(&tmp);

    if code != 0 {
        return Err(KeychainError::Keychain(format!(
            "import apple wwdr certificate failed: {err}",
        )));
    }

    Ok(())
}

fn ensure_apple_wwdr_certificate_installed(keychain: &Path) -> Result<(), KeychainError> {
    if certificate_exists_in_keychain(keychain, APPLE_WWDR_CERT_COMMON_NAME)? {
        return Ok(());
    }

    let mut last_error: Option<KeychainError> = None;

    for system_keychain in APPLE_WWDR_SYSTEM_KEYCHAINS.iter() {
        let system_path = Path::new(system_keychain);
        match find_certificate_pem(system_path, APPLE_WWDR_CERT_COMMON_NAME) {
            Ok(Some(pem)) => match import_certificate_from_pem(keychain, pem.as_str()) {
                Ok(_) => {
                    if certificate_exists_in_keychain(keychain, APPLE_WWDR_CERT_COMMON_NAME)? {
                        return Ok(());
                    }
                }
                Err(e) => {
                    if certificate_exists_in_keychain(keychain, APPLE_WWDR_CERT_COMMON_NAME)? {
                        return Ok(());
                    }
                    last_error = Some(e);
                }
            },
            Ok(None) => continue,
            Err(e) => last_error = Some(e),
        }
    }

    if certificate_exists_in_keychain(keychain, APPLE_WWDR_CERT_COMMON_NAME)? {
        return Ok(());
    }

    Err(last_error.unwrap_or_else(|| {
        KeychainError::Keychain(
            "apple wwdr certificate not found in system keychains; install it manually.".into(),
        )
    }))
}

pub struct KeyChainAdapter;

impl KeychainPort for KeyChainAdapter {
    fn has_valid_certificate_installed(
        &self,
        q: &KeychainCertificateQuery,
    ) -> Result<bool, KeychainError> {
        let Some(path) = pick_existing_keychain_path(&q.keychain_name) else {
            return Ok(false);
        };

        // Query valid code signing identities within the specified keychain
        let keychain_arg = keychain_display_path(&path);
        let args = vec![
            "find-identity",
            "-v",
            "-p",
            "codesigning",
            keychain_arg.as_str(),
        ];
        let (code, out, err) = run_security(args.as_slice())?;
        if code != 0 {
            return Err(KeychainError::Keychain(format!(
                "find-identity failed: {err}"
            )));
        }

        // Filter by hints and kind
        let kind_match = match q.kind {
            core_lib::shared::models::CertificateKind::AppleDevelopment => "Apple Development",
            core_lib::shared::models::CertificateKind::AppleDistribution => "Apple Distribution",
        };

        let mut found = false;
        'outer: for line in out.lines() {
            // Expected line: "  1) <hash> \"Apple Development: Name (TEAMID)\""
            if !line.contains(kind_match) {
                continue;
            }
            if let Some(team) = &q.team_id_hint
                && !line.contains(team)
            {
                continue;
            }
            // If we got here, this identity matches constraints
            // Note: find-identity lists only identities with valid certificate+private key
            // and not expired unless -p ssl or different policy; codesigning should be fine.
            // Additional certificate validity checks could be added by parsing certificates.
            // For now, accept as valid.
            found = true;
            break 'outer;
        }
        Ok(found)
    }

    fn custom_keychain_exists(&self, name: &str) -> Result<bool, KeychainError> {
        // First check if present in keychain search list
        let list = list_keychains()?;
        let candidates = keychain_paths_for_name(name)
            .into_iter()
            .map(|p| keychain_display_path(&p))
            .collect::<Vec<_>>();
        if list
            .iter()
            .any(|p| candidates.iter().any(|c| p.ends_with(c)))
        {
            return Ok(true);
        }
        // Fallback: check if file exists under user's Keychains dir
        Ok(pick_existing_keychain_path(name).is_some())
    }

    fn create_custom_keychain(&self, req: &EnsureKeychainRequest) -> Result<(), KeychainError> {
        let password = req.password.clone().unwrap_or_default();
        let target_path = user_keychains_dir().join(format!("{}.keychain", req.keychain_name));

        // Create keychain non-interactively
        let target_path_str = keychain_display_path(&target_path);
        let args = vec![
            "create-keychain",
            "-p",
            password.as_str(),
            target_path_str.as_str(),
        ];
        let (code, _out, err) = run_security(args.as_slice())?;
        if code != 0 {
            return Err(KeychainError::Keychain(format!(
                "create-keychain failed: {err}"
            )));
        }

        if req.set_as_default {
            set_default_keychain(&target_path).map_err(|err| {
                KeychainError::Keychain(format!("set keychain as default failed: {err}"))
            })?;
        }

        // Ensure it is in the search list
        ensure_in_keychain_list(&target_path)?;

        // Unlock and set partition list to avoid UI prompts from tools
        unlock_keychain(&target_path, &password)?;
        // Partition list might fail on brand new keychain without any keys; best effort
        if let Err(e) = set_partition_list(&target_path, &password) {
            // Loggable error: for now, convert to Unexpected but do not fail creation
            let _ = e;
        }

        Ok(())
    }

    fn install_certificate(&self, req: &InstallCertificateRequest) -> Result<(), KeychainError> {
        let mut tmp = env::temp_dir();
        tmp.push("rutter_cert.key");
        {
            let certificate_der = BASE64_STANDARD
                .decode(&req.certificate_content.base64_data)
                .map_err(|e| {
                    KeychainError::Unexpected(format!("failed to decode certificate content: {e}"))
                })?;
            let mut f = fs::File::create(&tmp)
                .map_err(|e| KeychainError::Io(format!("temp file create failed: {e}")))?;
            f.write_all(&certificate_der)
                .map_err(|e| KeychainError::Io(format!("temp file write failed: {e}")))?;
        }

        // Resolve keychain path
        let keychain_path = pick_existing_keychain_path(&req.keychain_name).unwrap_or_else(|| {
            user_keychains_dir().join(format!("{}.keychain", req.keychain_name))
        });

        ensure_apple_wwdr_certificate_installed(&keychain_path).map_err(|err| {
            KeychainError::Keychain(format!(
                "failed to ensure apple wwdr certificate is installed: {err}"
            ))
        })?;

        // Falscher Befehl, sollte security import my.cer -k path_to_key_chain/name.keychain -T /usr/bin/codesign
        // Import certificate into target keychain
        let tmp_str = keychain_display_path(&tmp);
        let kc_str = keychain_display_path(&keychain_path);
        let args = vec![
            "import",
            tmp_str.as_str(),
            "-k",
            kc_str.as_str(),
            "-T",
            "/usr/bin/codesign",
        ];
        let (code, _out, err) = run_security(args.as_slice())?;
        // Cleanup temp file (best-effort)
        let _ = fs::remove_file(&tmp);

        if code != 0 {
            return Err(KeychainError::Keychain(format!(
                "import certificate failed: {err}"
            )));
        }
        Ok(())
    }

    fn install_private_key(&self, req: &InstallPrivateKeyRequest) -> Result<(), KeychainError> {
        let keychain_path = pick_existing_keychain_path(&req.keychain_name).unwrap_or_else(|| {
            user_keychains_dir().join(format!("{}.keychain", req.keychain_name))
        });

        let kc_str = keychain_display_path(&keychain_path);
        let args = vec![
            "import",
            req.private_key_pem.path.as_str(),
            "-k",
            kc_str.as_str(),
            "-T",
            "/usr/bin/codesign",
        ];
        let (code, _out, err) = run_security(args.as_slice())?;

        if code != 0 {
            return Err(KeychainError::Keychain(format!(
                "import private key failed: {err}"
            )));
        }

        Ok(())
    }
}
