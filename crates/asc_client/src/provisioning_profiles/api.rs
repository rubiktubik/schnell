use core_lib::ios::{
    certificates::models::CheckCertificateApiRequest,
    provisioning_profiles::{
        models::{
            CreateProvisioningProfileRequest, ListProvisioningProfilesRequest,
            RemoteProvisioningProfileSummary,
        },
        ports::ProvisioningProfileApiPort,
    },
};
use core_lib::shared::errors::ProvisioningProfileApiError;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::Deserialize;

use crate::{certificates::get_certificate_list, client::AppStoreConnectClient};

use super::{
    mapping::{ProfileListResponse, ProfileResponse, map_profile},
    payload::build_create_profile_payload,
};

async fn resolve_bundle_id_id(
    client: &reqwest::Client,
    base_url: &str,
    jwt: &str,
    bundle_identifier: &str,
) -> Result<String, ProvisioningProfileApiError> {
    #[derive(Debug, Deserialize)]
    struct BundleIdsListResponse {
        data: Vec<BundleIdData>,
    }

    #[derive(Debug, Deserialize)]
    struct BundleIdData {
        id: String,
    }

    let resp = client
        .get(format!("{base_url}/v1/bundleIds"))
        .query(&[
            ("filter[identifier]", bundle_identifier.to_string()),
            ("limit", "1".to_string()),
            // Optional, aber nett fürs Debugging/Antwortgröße:
            ("fields[bundleIds]", "identifier".to_string()),
        ])
        .bearer_auth(jwt)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| ProvisioningProfileApiError::Network(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_else(|_| "<unreadable>".into());
        return Err(ProvisioningProfileApiError::Unexpected(format!(
            "bundleIds lookup failed status {}: {}",
            status, body
        )));
    }

    let payload: BundleIdsListResponse = resp
        .json()
        .await
        .map_err(|e| ProvisioningProfileApiError::Unexpected(e.to_string()))?;

    let id = payload
        .data
        .into_iter()
        .next()
        .ok_or_else(|| {
            ProvisioningProfileApiError::BadRequest(format!(
                "No bundleId found for identifier '{}'",
                bundle_identifier
            ))
        })?
        .id;

    Ok(id)
}

fn normalize_next_url(base_url: &str, next: String) -> String {
    if next.starts_with("http://") || next.starts_with("https://") {
        next
    } else {
        format!("{base_url}{next}")
    }
}

impl ProvisioningProfileApiPort for AppStoreConnectClient {
    async fn list_profiles(
        &self,
        req: &ListProvisioningProfilesRequest,
    ) -> Result<Vec<RemoteProvisioningProfileSummary>, ProvisioningProfileApiError> {
        let client = reqwest::Client::new();

        // 1) bundleIds-ID auflösen (aus z.B. "com.example.app")
        let bundle_id_id = self
            .resolve_bundle_identifier_id(&client, &req.jwt, &req.bundle_id)
            .await?;

        // 2) Erste Seite vom Relationship-Endpoint vorbereiten
        let base = format!("{}/v1/bundleIds/{}/profiles", self.base_url, bundle_id_id,);
        let query_params = vec![
            (
                "fields[profiles]",
                "name,profileType,profileState,profileContent,uuid,expirationDate".to_string(),
            ),
            ("limit", "200".to_string()),
        ];

        let mut collected: Vec<RemoteProvisioningProfileSummary> = Vec::new();
        let mut next_url: Option<String> = Some(base);
        let mut first_page = true;

        while let Some(url) = next_url.take() {
            let mut rb = client.get(&url);

            // Nur für die erste Seite die Query anhängen.
            if first_page {
                rb = rb.query(&query_params);
            }

            let response = rb
                .bearer_auth(&req.jwt)
                .header(ACCEPT, "application/json")
                .send()
                .await
                .map_err(|err| ProvisioningProfileApiError::Network(err.to_string()))?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable>".to_string());
                return match status.as_u16() {
                    400 => Err(ProvisioningProfileApiError::BadRequest(body)),
                    401 => Err(ProvisioningProfileApiError::Unauthorized),
                    _ => Err(ProvisioningProfileApiError::Unexpected(format!(
                        "status {}: {}",
                        status, body
                    ))),
                };
            }

            let payload: ProfileListResponse = response
                .json()
                .await
                .map_err(|err| ProvisioningProfileApiError::Unexpected(err.to_string()))?;

            // Kein Bundle-Mapping/Filter mehr nötig: Endpoint ist bereits auf die Bundle-ID gescoped.
            for profile in payload.data.into_iter() {
                collected.push(map_profile(profile)?);
            }

            // Pagination
            if let Some(next) = payload.links.next {
                next_url = Some(normalize_next_url(&self.base_url.clone(), next));
                first_page = false;
            }
        }

        Ok(collected)
    }

    async fn create_profile(
        &self,
        req: &CreateProvisioningProfileRequest,
    ) -> Result<RemoteProvisioningProfileSummary, ProvisioningProfileApiError> {
        let client = reqwest::Client::new();
        let mut request = req.clone();

        self.determine_matching_certificate_ids(&mut request)
            .await?;

        let bundle_id_id = self
            .resolve_bundle_identifier_id(&client, &request.jwt, &request.bundle_id)
            .await?;

        let payload = build_create_profile_payload(&request, &bundle_id_id);

        let response = client
            .post(format!("{}/v1/profiles", self.base_url))
            .bearer_auth(&request.jwt)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|err| ProvisioningProfileApiError::Network(err.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return match status.as_u16() {
                400 => Err(ProvisioningProfileApiError::BadRequest(body)),
                401 => Err(ProvisioningProfileApiError::Unauthorized),
                _ => Err(ProvisioningProfileApiError::Unexpected(format!(
                    "status {}: {}",
                    status, body
                ))),
            };
        }

        let payload: ProfileResponse = response
            .json()
            .await
            .map_err(|err| ProvisioningProfileApiError::Unexpected(err.to_string()))?;

        map_profile(payload.data)
    }
}

impl AppStoreConnectClient {
    async fn resolve_bundle_identifier_id(
        &self,
        client: &reqwest::Client,
        jwt: &str,
        bundle_identifier: &str,
    ) -> Result<String, ProvisioningProfileApiError> {
        resolve_bundle_id_id(client, &self.base_url, jwt, bundle_identifier).await
    }

    async fn determine_matching_certificate_ids(
        &self,
        request: &mut CreateProvisioningProfileRequest,
    ) -> Result<(), ProvisioningProfileApiError> {
        if request.certificate_ids.is_empty() {
            let certificate_summaries = get_certificate_list(
                &CheckCertificateApiRequest {
                    jwt: request.jwt.clone(),
                    kind: request.profile_type.into(),
                },
                &self.base_url,
            )
            .await?;

            request.certificate_ids = certificate_summaries
                .into_iter()
                .map(|cert| cert.id)
                .collect();
        };
        Ok(())
    }
}
