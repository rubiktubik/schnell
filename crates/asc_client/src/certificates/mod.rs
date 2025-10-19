use chrono::DateTime;
use core_lib::ios::certificates::{
    models::{CheckCertificateApiRequest, RemoteCertificateSummary},
    ports::CertificateApiPort,
};
use core_lib::shared::{
    errors::CertificateApiError,
    models::{CertificateContent, CertificateKind},
};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

use crate::client::AppStoreConnectClient;

const BASE_URL: &str = "https://api.appstoreconnect.apple.com";

impl CertificateApiPort for AppStoreConnectClient {
    async fn list_certificates(
        &self,
        req: &CheckCertificateApiRequest,
    ) -> Result<Vec<RemoteCertificateSummary>, CertificateApiError> {
        get_certificate_list(req, &self.base_url).await
    }

    async fn create_certificate(
        &self,
        req: &core_lib::ios::certificates::models::CreateCertificateApiRequest,
    ) -> Result<RemoteCertificateSummary, CertificateApiError> {
        let certificate_type = match req.kind {
            CertificateKind::AppleDistribution => "DISTRIBUTION",
            CertificateKind::AppleDevelopment => "DEVELOPMENT",
        };

        let csr_content = prepare_csr_content(&req.csr_string)?;

        let payload = CreateCertificateRequest {
            data: CreateCertificateRequestData {
                type_name: "certificates",
                attributes: CreateCertificateAttributes {
                    certificate_type,
                    csr_content,
                },
            },
        };

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{BASE_URL}/v1/certificates"))
            .bearer_auth(req.jwt.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| CertificateApiError::Network(e.to_string()))?;

        if response.status().is_success() {
            let payload: CertificateResponse = response
                .json()
                .await
                .map_err(|e| CertificateApiError::Unexpected(e.to_string()))?;

            let data = payload.data;
            map_certificate(data.clone())
                .or_else(|| map_certificate(data))
                .ok_or_else(|| {
                    CertificateApiError::Unexpected(
                        "missing certificate details in response".to_string(),
                    )
                })
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            match status.as_u16() {
                400 => Err(CertificateApiError::BadRequest(body)),
                401 => Err(CertificateApiError::Unauthorized),
                _ => Err(CertificateApiError::Unexpected(format!(
                    "status {}: {}",
                    status, body
                ))),
            }
        }
    }
}

pub(crate) async fn get_certificate_list(
    req: &CheckCertificateApiRequest,
    base_url: &str,
) -> Result<Vec<RemoteCertificateSummary>, CertificateApiError> {
    let client = reqwest::Client::new();
    let certificate_type = match req.kind {
        CertificateKind::AppleDistribution => "DISTRIBUTION",
        CertificateKind::AppleDevelopment => "DEVELOPMENT",
    };

    // Basis-Query mit Sparse Fields & Limit (max 200)
    let mut url = format!(
        "{base_url}/v1/certificates?filter[certificateType]={certificate_type}&fields[certificates]=serialNumber,displayName,name,expirationDate,certificateContent&limit=200"
    );

    let mut all = Vec::<RemoteCertificateSummary>::new();

    loop {
        let response = client
            .get(&url)
            .bearer_auth(req.jwt.clone())
            .header(ACCEPT, "application/json") // Content-Type bei GET weglassen
            .send()
            .await
            .map_err(|e| CertificateApiError::Network(e.to_string()))?;

        // 403/429 etc. separat behandeln
        if response.status().is_client_error() || response.status().is_server_error() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return match status.as_u16() {
                400 => Err(CertificateApiError::BadRequest(body)),
                401 => Err(CertificateApiError::Unauthorized),
                403 => Err(CertificateApiError::Forbidden(body)),
                429 => Err(CertificateApiError::RateLimited(body)),
                _ => Err(CertificateApiError::Unexpected(format!(
                    "status {}: {}",
                    status, body
                ))),
            };
        }

        // Paging-Response mit links.next
        #[derive(serde::Deserialize)]
        struct Paged<T> {
            data: Vec<T>,
            links: Option<Links>,
        }
        #[derive(serde::Deserialize)]
        struct Links {
            next: Option<String>,
        }

        let payload: Paged<CertificateData> = response
            .json()
            .await
            .map_err(|e| CertificateApiError::Unexpected(e.to_string()))?;

        all.extend(payload.data.into_iter().filter_map(map_certificate));
        if let Some(next) = payload.links.and_then(|l| l.next) {
            url = next;
        } else {
            break;
        }
    }

    Ok(all)
}

#[derive(Debug, Deserialize, Clone)]
struct CertificateData {
    id: String,
    attributes: CertificateAttributes,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CertificateAttributes {
    serial_number: Option<String>,
    expiration_date: Option<String>,
    display_name: Option<String>,
    name: Option<String>,
    certificate_content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CertificateResponse {
    data: CertificateData,
}

#[derive(Debug, Serialize)]
struct CreateCertificateRequest<'a> {
    data: CreateCertificateRequestData<'a>,
}

#[derive(Debug, Serialize)]
struct CreateCertificateRequestData<'a> {
    #[serde(rename = "type")]
    type_name: &'a str,
    attributes: CreateCertificateAttributes<'a>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateCertificateAttributes<'a> {
    certificate_type: &'a str,
    csr_content: String,
}

fn map_certificate(certificate: CertificateData) -> Option<RemoteCertificateSummary> {
    let CertificateData { id, attributes } = certificate;

    let expires_at_epoch = attributes
        .expiration_date
        .as_deref()
        .and_then(parse_expiration_timestamp);

    Some(RemoteCertificateSummary {
        id,
        serial: attributes.serial_number,
        expires_at_epoch,
        common_name: attributes.display_name.or(attributes.name),
        certificate_content: CertificateContent {
            base64_data: attributes.certificate_content?, // falls nicht mit angefordert, None
        },
    })
}

fn parse_expiration_timestamp(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.timestamp())
        .ok()
}

fn prepare_csr_content(csr: &str) -> Result<String, CertificateApiError> {
    let trimmed = csr.trim();
    if trimmed.is_empty() {
        return Err(CertificateApiError::Unexpected(
            "csr content is empty".to_string(),
        ));
    }

    if trimmed.contains("-----BEGIN") {
        let mut body = String::new();
        for line in trimmed.lines() {
            let line = line.trim();
            if line.starts_with("-----") {
                continue;
            }
            body.push_str(line);
        }

        if body.is_empty() {
            return Err(CertificateApiError::Unexpected(
                "csr content missing body".to_string(),
            ));
        }

        Ok(body)
    } else {
        Ok(trimmed.replace(['\r', '\n'], ""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    #[test]
    fn maps_certificate_when_team_matches() {
        let data: CertificateData = serde_json::from_str(
            r#"{
                "id": "CERT123",
                "attributes": {
                    "serialNumber": "SERIAL123",
                    "expirationDate": "2025-01-10T12:00:00Z",
                    "displayName": "Apple Distribution: Example (TEAMID123)",
                    "certificateContent": "BASE64DATA"
                }
            }"#,
        )
        .unwrap();

        let summary = map_certificate(data).expect("expected certificate");

        assert_eq!(summary.id, "CERT123");
        assert_eq!(summary.serial.as_deref(), Some("SERIAL123"));
        assert_eq!(
            summary.common_name.as_deref(),
            Some("Apple Distribution: Example (TEAMID123)")
        );
        assert_eq!(summary.certificate_content.base64_data, "BASE64DATA");

        let expected_epoch = DateTime::parse_from_rfc3339("2025-01-10T12:00:00Z")
            .map(|dt| dt.timestamp())
            .unwrap();
        assert_eq!(summary.expires_at_epoch, Some(expected_epoch));
    }
}
