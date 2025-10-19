use core_lib::ios::bundle_identifier::{
    errors::BundleIdentiferApiError, models::CheckIdentifierApiRequest,
    ports::BundleIdentifierApiPort,
};
use reqwest::header::{ACCEPT, CONTENT_TYPE};

use crate::{
    bundle_identifer::{
        error_mapping::HttpRequestError,
        models::{
            BundleIdList, CreateBundleIdRequest, CreateBundleIdRequestAttributes,
            CreateBundleIdRequestData,
        },
    },
    client::AppStoreConnectClient,
};

impl BundleIdentifierApiPort for AppStoreConnectClient {
    async fn check_if_identifier_exists(
        &self,
        request: &CheckIdentifierApiRequest,
    ) -> Result<bool, BundleIdentiferApiError> {
        let base_url = "https://api.appstoreconnect.apple.com";
        let client = reqwest::Client::new();
        let url = format!("{base_url}/v1/bundleIds");

        let response = client
            .get(url)
            .bearer_auth(request.jwt.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await
            .map_err(HttpRequestError::from) // reqwest → HttpError
            .map_err(BundleIdentiferApiError::from)?;

        if response.status().is_success() {
            let BundleIdList { data }: BundleIdList = response
                .json::<BundleIdList>()
                .await
                .map_err(HttpRequestError::from)
                .map_err(BundleIdentiferApiError::from)?;
            let bundle_id_names: Vec<String> = data
                .iter()
                .map(|b| b.attributes.identifier.clone())
                .collect();
            Ok(bundle_id_names.contains(&request.bundle_identifier.identifier))
        } else {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .map_err(HttpRequestError::from)
                .map_err(BundleIdentiferApiError::from)?;
            Err(BundleIdentiferApiError::NoSuccesfullResponse(
                status.to_string(),
                error_body,
            ))
        }
    }

    async fn create_bundle_identifier(
        &self,
        request: &CheckIdentifierApiRequest,
    ) -> Result<(), BundleIdentiferApiError> {
        let base_url = "https://api.appstoreconnect.apple.com";
        let client = reqwest::Client::new();
        let url = format!("{base_url}/v1/bundleIds");

        let bundle_id_request = CreateBundleIdRequest {
            data: CreateBundleIdRequestData {
                type_name: "bundleIds",
                attributes: CreateBundleIdRequestAttributes {
                    identifier: &request.bundle_identifier.identifier,
                    name: &request.bundle_identifier.name,
                    platform: "IOS",
                },
            },
        };

        let response = client
            .post(url)
            .bearer_auth(request.jwt.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&bundle_id_request)
            .send()
            .await
            .map_err(HttpRequestError::from)
            .map_err(BundleIdentiferApiError::from)?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .map_err(HttpRequestError::from)
                .map_err(BundleIdentiferApiError::from)?;
            Err(BundleIdentiferApiError::NoSuccesfullResponse(
                status.to_string(),
                error_body,
            ))
        }
    }
}
