use core_lib::ios::provisioning_profiles::models::CreateProvisioningProfileRequest;
use serde::Serialize;

use super::mapping::profile_type_code;

pub(super) fn build_create_profile_payload(
    req: &CreateProvisioningProfileRequest,
    bundle_id_id: &str,
) -> CreateProfileRequestPayload {
    let bundle_relationship = ToOneRelationship {
        data: RelationshipIdentifier {
            type_name: "bundleIds",
            id: bundle_id_id.to_string(),
        },
    };

    let certificate_relationship = ToManyRelationship {
        data: req
            .certificate_ids
            .iter()
            .map(|id| RelationshipIdentifier {
                type_name: "certificates",
                id: id.clone(),
            })
            .collect(),
    };

    let device_relationship = if req.device_ids.is_empty() {
        None
    } else {
        Some(ToManyRelationship {
            data: req
                .device_ids
                .iter()
                .map(|id| RelationshipIdentifier {
                    type_name: "devices",
                    id: id.clone(),
                })
                .collect(),
        })
    };

    CreateProfileRequestPayload {
        data: CreateProfileRequestData {
            type_name: "profiles",
            attributes: CreateProfileAttributes {
                name: req.profile_name.clone(),
                profile_type: profile_type_code(req.profile_type),
            },
            relationships: CreateProfileRelationships {
                bundle_id: bundle_relationship,
                certificates: certificate_relationship,
                devices: device_relationship,
            },
        },
    }
}

#[derive(Debug, Serialize)]
pub(super) struct CreateProfileRequestPayload {
    pub(super) data: CreateProfileRequestData,
}

#[derive(Debug, Serialize)]
pub(super) struct CreateProfileRequestData {
    #[serde(rename = "type")]
    pub(super) type_name: &'static str,
    pub(super) attributes: CreateProfileAttributes,
    pub(super) relationships: CreateProfileRelationships,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateProfileAttributes {
    pub(super) name: String,
    pub(super) profile_type: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct CreateProfileRelationships {
    #[serde(rename = "bundleId")]
    pub(super) bundle_id: ToOneRelationship,
    pub(super) certificates: ToManyRelationship,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) devices: Option<ToManyRelationship>,
}

#[derive(Debug, Serialize)]
pub(super) struct ToOneRelationship {
    pub(super) data: RelationshipIdentifier,
}

#[derive(Debug, Serialize)]
pub(super) struct ToManyRelationship {
    pub(super) data: Vec<RelationshipIdentifier>,
}

#[derive(Debug, Serialize)]
pub(super) struct RelationshipIdentifier {
    #[serde(rename = "type")]
    pub(super) type_name: &'static str,
    pub(super) id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_lib::ios::provisioning_profiles::models::ProvisioningProfileType;

    #[test]
    fn build_payload_omits_devices_when_empty() {
        let req = CreateProvisioningProfileRequest {
            jwt: "jwt".to_string(),
            profile_type: ProvisioningProfileType::IosAppStore,
            bundle_id: "BUNDLE-ID".to_string(),
            profile_name: "Profile".to_string(),
            certificate_ids: vec!["CERT".to_string()],
            device_ids: vec![],
        };

        let payload = build_create_profile_payload(&req, "BUNDLE-ID-ID");
        let json = serde_json::to_value(&payload).expect("serialize payload");
        let relationships = json
            .get("data")
            .and_then(|d| d.get("relationships"))
            .and_then(|r| r.as_object())
            .expect("relationships object");

        assert!(relationships.contains_key("bundleId"));
        assert!(relationships.contains_key("certificates"));
        assert!(!relationships.contains_key("devices"));
    }

    #[test]
    fn build_payload_includes_devices_when_present() {
        let req = CreateProvisioningProfileRequest {
            jwt: "jwt".to_string(),
            profile_type: ProvisioningProfileType::IosAdHoc,
            bundle_id: "BUNDLE-ID".to_string(),
            profile_name: "Profile".to_string(),
            certificate_ids: vec!["CERT".to_string()],
            device_ids: vec!["DEVICE".to_string()],
        };

        let payload = build_create_profile_payload(&req, "BUNDLE-ID-ID");
        let json = serde_json::to_value(&payload).expect("serialize payload");
        let devices = json
            .get("data")
            .and_then(|d| d.get("relationships"))
            .and_then(|r| r.get("devices"))
            .and_then(|d| d.get("data"))
            .and_then(|d| d.as_array())
            .expect("devices array");

        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0]
                .get("id")
                .and_then(|id| id.as_str())
                .expect("device id"),
            "DEVICE"
        );
    }
}
