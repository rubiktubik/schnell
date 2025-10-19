use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::{DateTime, Utc};
use core_lib::{
    ios::provisioning_profiles::{
        models::{
            InstallProvisioningProfileRequest, ProvisioningProfileContent,
            ProvisioningProfileQuery, ProvisioningProfileType,
        },
        ports::ProvisioningProfileLocalPort,
    },
    shared::errors::ProvisioningProfileError,
};
use plist::from_bytes;
use serde::Deserialize;

const DEFAULT_PROFILE_DIRECTORY_SUFFIX: &str =
    "Library/Developer/Xcode/UserData/Provisioning Profiles";

#[derive(Debug, Deserialize)]
struct RawProvisioningProfile {
    #[serde(rename = "UUID")]
    uuid: String,
    #[serde(rename = "Name")]
    #[allow(dead_code)]
    name: Option<String>,
    #[serde(rename = "Entitlements")]
    entitlements: RawEntitlements,
    #[serde(rename = "ExpirationDate")]
    expiration_date: DateTime<Utc>,
    #[serde(rename = "Platform", default)]
    platforms: Vec<String>,
    #[serde(rename = "ProvisionedDevices")]
    provisioned_devices: Option<Vec<String>>,
    #[serde(rename = "ProvisionsAllDevices")]
    provisions_all_devices: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawEntitlements {
    #[serde(rename = "application-identifier")]
    application_identifier: String,
    #[serde(rename = "get-task-allow")]
    get_task_allow: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct DecodedProvisioningProfile {
    uuid: String,
    application_identifier: String,
    expiration: DateTime<Utc>,
    get_task_allow: bool,
    has_provisioned_devices: bool,
    provisions_all_devices: bool,
    platforms: Vec<String>,
}

pub trait ProfileDecoder: Send + Sync {
    fn decode(&self, path: &Path) -> Result<DecodedProvisioningProfile, ProvisioningProfileError>;
}

#[derive(Default)]
pub struct SecurityCmsDecoder;

impl ProfileDecoder for SecurityCmsDecoder {
    fn decode(&self, path: &Path) -> Result<DecodedProvisioningProfile, ProvisioningProfileError> {
        let output = Command::new("security")
            .args(["cms", "-D", "-i"])
            .arg(path)
            .output()
            .map_err(|err| {
                ProvisioningProfileError::Io(format!("failed to run security cms: {err}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ProvisioningProfileError::Unexpected(format!(
                "security cms failed: {stderr}"
            )));
        }

        let parsed = parse_profile_plist(&output.stdout)?;
        Ok(parsed)
    }
}

fn parse_profile_plist(
    data: &[u8],
) -> Result<DecodedProvisioningProfile, ProvisioningProfileError> {
    let raw: RawProvisioningProfile = from_bytes(data).map_err(|err| {
        ProvisioningProfileError::Unexpected(format!(
            "failed to parse provisioning profile plist: {err}"
        ))
    })?;

    Ok(DecodedProvisioningProfile {
        uuid: raw.uuid,
        application_identifier: raw.entitlements.application_identifier,
        expiration: raw.expiration_date,
        get_task_allow: raw.entitlements.get_task_allow.unwrap_or(false),
        has_provisioned_devices: raw
            .provisioned_devices
            .map(|devices| !devices.is_empty())
            .unwrap_or(false),
        provisions_all_devices: raw.provisions_all_devices.unwrap_or(false),
        platforms: raw.platforms,
    })
}

pub struct ProvisioningProfileLocalAdapter<D = SecurityCmsDecoder> {
    decoder: D,
}

impl ProvisioningProfileLocalAdapter {
    pub fn new() -> Self {
        Self {
            decoder: SecurityCmsDecoder,
        }
    }
}

impl Default for ProvisioningProfileLocalAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl<D> ProvisioningProfileLocalAdapter<D>
where
    D: ProfileDecoder,
{
    #[cfg(test)]
    pub(crate) fn new_with_decoder(decoder: D) -> Self {
        Self { decoder }
    }

    fn has_matching_profile_at(
        &self,
        path: &Path,
        query: &ProvisioningProfileQuery,
        now: DateTime<Utc>,
    ) -> Result<bool, ProvisioningProfileError> {
        if !path.exists() {
            return Ok(false);
        }

        let decoded = self.decoder.decode(path)?;

        if decoded.expiration <= now {
            return Ok(false);
        }

        if !application_identifier_matches(&decoded.application_identifier, &query.bundle_id) {
            return Ok(false);
        }

        if !matches_profile_type(&decoded, query.profile_type) {
            return Ok(false);
        }

        Ok(true)
    }

    fn default_profiles_dir(&self) -> Result<PathBuf, ProvisioningProfileError> {
        dirs::home_dir()
            .map(|home| home.join(DEFAULT_PROFILE_DIRECTORY_SUFFIX))
            .ok_or_else(|| ProvisioningProfileError::Io("could not resolve home directory".into()))
    }

    fn write_profile_contents(
        &self,
        path: &Path,
        content: &ProvisioningProfileContent,
    ) -> Result<(), ProvisioningProfileError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                ProvisioningProfileError::Io(format!(
                    "failed to create provisioning profile directory {parent:?}: {err}"
                ))
            })?;
        }

        fs::write(path, &content.data).map_err(|err| {
            ProvisioningProfileError::Io(format!(
                "failed to write provisioning profile {path:?}: {err}"
            ))
        })
    }
}

impl<D> ProvisioningProfileLocalPort for ProvisioningProfileLocalAdapter<D>
where
    D: ProfileDecoder,
{
    fn has_valid_profile(
        &self,
        query: &ProvisioningProfileQuery,
    ) -> Result<bool, ProvisioningProfileError> {
        let now = Utc::now();
        let default_dir = self.default_profiles_dir()?;

        if !default_dir.exists() {
            return Ok(false);
        }

        let entries = fs::read_dir(&default_dir).map_err(|err| {
            ProvisioningProfileError::Io(format!(
                "failed to read provisioning profiles directory {default_dir:?}: {err}"
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|err| {
                ProvisioningProfileError::Io(format!(
                    "failed to iterate provisioning profiles directory: {err}"
                ))
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(ext) = path.extension().and_then(|ext| ext.to_str()) {
                if ext != "mobileprovision" {
                    continue;
                }
            } else {
                continue;
            }

            if self.has_matching_profile_at(&path, query, now)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn install_profile(
        &self,
        req: &InstallProvisioningProfileRequest,
    ) -> Result<(), ProvisioningProfileError> {
        let target_path = match &req.destination {
            Some(dest) if is_mobileprovision_file_path(dest) => dest.clone(),
            Some(dest) => {
                let mut dir = dest.clone();
                if dir.as_os_str().is_empty() {
                    dir = self.default_profiles_dir()?;
                }
                dir.join(format!("{}.mobileprovision", req.profile_uuid))
            }
            None => self
                .default_profiles_dir()?
                .join(format!("{}.mobileprovision", req.profile_uuid)),
        };

        self.write_profile_contents(&target_path, &req.profile_content)?;

        let decoded = match self.decoder.decode(&target_path) {
            Ok(decoded) => decoded,
            Err(err) => {
                let _ = fs::remove_file(&target_path);
                return Err(err);
            }
        };

        if decoded.uuid != req.profile_uuid {
            let _ = fs::remove_file(&target_path);
            return Err(ProvisioningProfileError::Invalid);
        }

        if decoded.expiration <= Utc::now() {
            let _ = fs::remove_file(&target_path);
            return Err(ProvisioningProfileError::Invalid);
        }

        Ok(())
    }
}

fn is_mobileprovision_file_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("mobileprovision"))
        .unwrap_or(false)
}

fn application_identifier_matches(identifier: &str, bundle_id: &str) -> bool {
    fn wildcard_match(pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if let Some(stripped) = pattern.strip_suffix(".*") {
            let stripped = stripped.trim_end_matches('.');
            if stripped.is_empty() {
                true
            } else {
                value.starts_with(stripped)
            }
        } else {
            pattern == value
        }
    }

    if wildcard_match(identifier, bundle_id) {
        return true;
    }

    let without_team = identifier
        .split_once('.')
        .map(|(_, rest)| rest)
        .unwrap_or(identifier);

    wildcard_match(without_team, bundle_id)
}

fn matches_profile_type(
    profile: &DecodedProvisioningProfile,
    profile_type: ProvisioningProfileType,
) -> bool {
    let is_ios_platform = profile.platforms.iter().any(|platform| {
        matches!(
            platform.as_str(),
            "iOS" | "tvOS" | "watchOS" | "xrOS" | "visionOS"
        )
    });

    let is_mac_platform = profile
        .platforms
        .iter()
        .any(|platform| platform.eq_ignore_ascii_case("macOS") || platform == "OSX");

    let has_devices = profile.has_provisioned_devices || profile.provisions_all_devices;

    match profile_type {
        ProvisioningProfileType::IosDevelopment => is_ios_platform && profile.get_task_allow,
        ProvisioningProfileType::IosAppStore => {
            is_ios_platform && !profile.get_task_allow && !has_devices
        }
        ProvisioningProfileType::IosAdHoc => {
            is_ios_platform && !profile.get_task_allow && has_devices
        }
        ProvisioningProfileType::MacDevelopment => is_mac_platform && profile.get_task_allow,
        ProvisioningProfileType::MacAppStore => is_mac_platform && !profile.get_task_allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct TestDecoder {
        profile: DecodedProvisioningProfile,
        last_path: Arc<Mutex<Vec<PathBuf>>>,
    }

    impl TestDecoder {
        fn new(profile: DecodedProvisioningProfile) -> Self {
            Self {
                profile,
                last_path: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl ProfileDecoder for TestDecoder {
        fn decode(
            &self,
            path: &Path,
        ) -> Result<DecodedProvisioningProfile, ProvisioningProfileError> {
            self.last_path.lock().unwrap().push(path.to_path_buf());
            Ok(self.profile.clone())
        }
    }

    fn sample_profile(expiry_offset_days: i64) -> DecodedProvisioningProfile {
        DecodedProvisioningProfile {
            uuid: "FAKE-UUID".into(),
            application_identifier: "TEAMID.com.example.app".into(),
            expiration: Utc::now() + Duration::days(expiry_offset_days),
            get_task_allow: false,
            has_provisioned_devices: false,
            provisions_all_devices: false,
            platforms: vec!["iOS".into()],
        }
    }

    #[test]
    fn application_identifier_matching_handles_wildcards() {
        assert!(application_identifier_matches(
            "TEAMID.com.example.app",
            "com.example.app"
        ));
        assert!(application_identifier_matches(
            "TEAMID.com.example.*",
            "com.example.app"
        ));
        assert!(application_identifier_matches(
            "TEAMID.*",
            "com.example.app"
        ));
        assert!(application_identifier_matches("*", "com.example.app"));
        assert!(!application_identifier_matches(
            "TEAMID.com.other.app",
            "com.example.app"
        ));
    }

    #[test]
    fn matches_profile_type_distinguishes_ios_variants() {
        let base = sample_profile(1);
        let mut dev = base.clone();
        dev.get_task_allow = true;
        assert!(matches_profile_type(
            &dev,
            ProvisioningProfileType::IosDevelopment
        ));

        let mut adhoc = base.clone();
        adhoc.has_provisioned_devices = true;
        assert!(matches_profile_type(
            &adhoc,
            ProvisioningProfileType::IosAdHoc
        ));

        assert!(matches_profile_type(
            &base,
            ProvisioningProfileType::IosAppStore
        ));
    }

    #[test]
    fn install_profile_writes_file_and_updates_config() {
        let decoder = TestDecoder::new(sample_profile(10));
        let adapter = ProvisioningProfileLocalAdapter::new_with_decoder(decoder.clone());

        let temp_dir = std::env::temp_dir()
            .join("rutter-test-profiles")
            .join(format!("{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let request = InstallProvisioningProfileRequest {
            profile_id: "REMOTE-ID".into(),
            profile_uuid: "FAKE-UUID".into(),
            profile_name: "Example".into(),
            profile_content: ProvisioningProfileContent {
                data: vec![1, 2, 3],
            },
            destination: Some(temp_dir.clone()),
        };

        adapter.install_profile(&request).expect("install profile");

        let expected_path = temp_dir.join("FAKE-UUID.mobileprovision");
        assert!(expected_path.exists(), "profile file should exist");

        // Clean up test artifacts
        let _ = fs::remove_file(expected_path);
    }

    #[test]
    fn has_valid_profile_checks_configured_path() {
        let decoder = TestDecoder::new(sample_profile(5));
        let adapter = ProvisioningProfileLocalAdapter::new_with_decoder(decoder.clone());

        let temp_dir = std::env::temp_dir()
            .join("rutter-test-profiles-valid")
            .join(format!("{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let profile_path = temp_dir.join("FAKE-UUID.mobileprovision");
        fs::write(&profile_path, b"stub").unwrap();

        let query = ProvisioningProfileQuery {
            bundle_id: "com.example.app".into(),
            profile_type: ProvisioningProfileType::IosAppStore,
        };

        let result = adapter
            .has_valid_profile(&query)
            .expect("has_valid_profile executes");

        assert!(result, "profile should be reported as valid");

        let _ = fs::remove_file(profile_path);
    }

    #[test]
    fn has_valid_profile_returns_false_for_expired_profiles() {
        let mut expired_profile = sample_profile(-1);
        expired_profile.expiration = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let decoder = TestDecoder::new(expired_profile);
        let adapter = ProvisioningProfileLocalAdapter::new_with_decoder(decoder.clone());

        let temp_dir = std::env::temp_dir()
            .join("rutter-test-profiles-expired")
            .join(format!("{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let profile_path = temp_dir.join("FAKE-UUID.mobileprovision");
        fs::write(&profile_path, b"stub").unwrap();

        let query = ProvisioningProfileQuery {
            bundle_id: "com.example.app".into(),
            profile_type: ProvisioningProfileType::IosAppStore,
        };

        let result = adapter
            .has_valid_profile(&query)
            .expect("has_valid_profile executes");

        assert!(!result, "expired profile should not be considered valid");

        let _ = fs::remove_file(profile_path);
    }
}
