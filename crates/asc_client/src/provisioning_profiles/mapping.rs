use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Utc};
use core_lib::ios::provisioning_profiles::models::{
    ProvisioningProfileContent, ProvisioningProfileState, ProvisioningProfileType,
    RemoteProvisioningProfileSummary,
};
use core_lib::shared::errors::ProvisioningProfileApiError;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct ProfileListResponse {
    pub(super) data: Vec<ProfileData>,
    pub(super) links: DocumentLinks,
}

#[derive(Debug, Deserialize)]
pub(super) struct ProfileResponse {
    pub(super) data: ProfileData,
}

#[derive(Debug, Deserialize)]
pub(super) struct DocumentLinks {
    #[serde(rename = "self")]
    pub(super) _self_link: Option<String>,
    pub(super) next: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ProfileData {
    pub(super) id: String,
    pub(super) attributes: ProfileAttributes,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProfileAttributes {
    pub(super) name: String,
    pub(super) profile_type: String,
    pub(super) profile_state: Option<String>,
    pub(super) profile_content: Option<String>,
    pub(super) uuid: Option<String>,
    pub(super) expiration_date: Option<String>,
}

pub(super) fn profile_type_code(profile_type: ProvisioningProfileType) -> &'static str {
    match profile_type {
        ProvisioningProfileType::IosDevelopment => "IOS_APP_DEVELOPMENT",
        ProvisioningProfileType::IosAppStore => "IOS_APP_STORE",
        ProvisioningProfileType::IosAdHoc => "IOS_APP_ADHOC",
        ProvisioningProfileType::MacDevelopment => "MAC_APP_DEVELOPMENT",
        ProvisioningProfileType::MacAppStore => "MAC_APP_STORE",
    }
}

pub(super) fn map_profile(
    profile: ProfileData,
) -> Result<RemoteProvisioningProfileSummary, ProvisioningProfileApiError> {
    let ProfileData { id, attributes, .. } = profile;
    let ProfileAttributes {
        name,
        profile_state,
        profile_content,
        uuid,
        expiration_date,
        ..
    } = attributes;

    let profile_content = profile_content.ok_or_else(|| {
        ProvisioningProfileApiError::Unexpected("missing profile content".to_string())
    })?;

    let uuid = uuid.ok_or_else(|| {
        ProvisioningProfileApiError::Unexpected("missing profile uuid".to_string())
    })?;

    let content_bytes = BASE64_STANDARD
        .decode(profile_content)
        .map_err(|err| ProvisioningProfileApiError::Unexpected(err.to_string()))?;

    let expires_at_epoch = expiration_date
        .as_deref()
        .and_then(|value| parse_expiration(value).ok());

    let state = match profile_state.as_deref() {
        Some("ACTIVE") => ProvisioningProfileState::Active,
        _ => ProvisioningProfileState::Inactive,
    };

    Ok(RemoteProvisioningProfileSummary {
        id,
        uuid,
        name,
        expires_at_epoch,
        state,
        profile_content: ProvisioningProfileContent {
            data: content_bytes,
        },
    })
}

fn parse_expiration(value: &str) -> Result<i64, ProvisioningProfileApiError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|err| ProvisioningProfileApiError::Unexpected(err.to_string()))?;
    Ok(parsed.with_timezone(&Utc).timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_profile_successfully_converts() {
        let profile = ProfileData {
            id: "123".to_string(),
            attributes: ProfileAttributes {
                name: "Example".to_string(),
                profile_type: "IOS_APP_STORE".to_string(),
                profile_state: Some("ACTIVE".to_string()),
                profile_content: Some(BASE64_STANDARD.encode(b"content")),
                uuid: Some("UUID-123".to_string()),
                expiration_date: Some("2024-08-01T12:00:00Z".to_string()),
            },
        };

        let summary = map_profile(profile).expect("map profile should succeed");
        assert_eq!(summary.id, "123");
        assert_eq!(summary.uuid, "UUID-123");
        assert_eq!(summary.name, "Example");
        assert_eq!(summary.state, ProvisioningProfileState::Active);
        assert_eq!(summary.profile_content.data, b"content");
        assert!(summary.expires_at_epoch.is_some());
    }

    #[test]
    fn map_profile_missing_content_fails() {
        let profile = ProfileData {
            id: "123".to_string(),
            attributes: ProfileAttributes {
                name: "Example".to_string(),
                profile_type: "IOS_APP_STORE".to_string(),
                profile_state: Some("ACTIVE".to_string()),
                profile_content: None,
                uuid: Some("UUID-123".to_string()),
                expiration_date: Some("2024-08-01T12:00:00Z".to_string()),
            },
        };

        let error = map_profile(profile).expect_err("map profile should error");
        assert!(matches!(error, ProvisioningProfileApiError::Unexpected(_)));
    }
}
