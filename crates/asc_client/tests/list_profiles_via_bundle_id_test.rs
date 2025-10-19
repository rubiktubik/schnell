use asc_client::client::AppStoreConnectClient;
use core_lib::ios::provisioning_profiles::{
    models::{ListProvisioningProfilesRequest, ProvisioningProfileType},
    ports::ProvisioningProfileApiPort,
};
use std::fs;
use std::path::PathBuf;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    fs::read_to_string(p).expect("fixture readable")
}

#[tokio::test]
async fn lists_profiles_for_bundle_id_with_pagination_and_decodes_profile_content() {
    let server = MockServer::start().await;

    // --- Mock 1: /v1/bundleIds?filter[identifier]=...&limit=1 ---
    let bundle_ids_json = fixture("bundleIds_list.json");
    Mock::given(method("GET"))
        .and(path("/v1/bundleIds"))
        .and(query_param("filter[identifier]", "com.example.app"))
        .and(query_param("limit", "1"))
        .and(query_param("fields[bundleIds]", "identifier"))
        .and(header("authorization", "Bearer dummy-jwt"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(bundle_ids_json, "application/json"))
        .expect(1)
        .mount(&server)
        .await;

    // --- Mock 2: Erste Seite Profile ---
    let page1_json = fixture("bundleId_profiles_page1.json");
    Mock::given(method("GET"))
        .and(path("/v1/bundleIds/BUNDLE123/profiles"))
        // Erste Seite enthält unsere vollständigen Query-Parameter:
        .and(query_param(
            "fields[profiles]",
            "name,profileType,profileState,profileContent,uuid,expirationDate",
        ))
        .and(query_param("limit", "200"))
        .and(header("authorization", "Bearer dummy-jwt"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(page1_json, "application/json"))
        .expect(1)
        .mount(&server)
        .await;

    // --- Mock 3: Zweite Seite via cursor ---
    let page2_json = fixture("bundleId_profiles_page2.json");
    Mock::given(method("GET"))
        .and(path("/v1/bundleIds/BUNDLE123/profiles"))
        .and(query_param("cursor", "abc"))
        .and(header("authorization", "Bearer dummy-jwt"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(page2_json, "application/json"))
        .expect(1)
        .mount(&server)
        .await;

    // System Under Test
    let api = AppStoreConnectClient::with_base_url_for_test(server.uri());
    let req = ListProvisioningProfilesRequest {
        jwt: "dummy-jwt".to_string(),
        profile_type: ProvisioningProfileType::IosDevelopment,
        bundle_id: "com.example.app".to_string(),
    };

    let result = api.list_profiles(&req).await.expect("ok");
    assert_eq!(result.len(), 3);

    // Ergebnis-Checks (Name/UUID/Decoded-Bytes, Ablaufdatum geparst etc.)
    assert_eq!(result[0].name, "Dev Profile 1");
    assert_eq!(result[0].uuid, "UUID-1");
    assert_eq!(result[0].profile_content.data, b"profile-data-1");

    assert_eq!(result[1].name, "Dev Profile 2");
    assert_eq!(result[1].uuid, "UUID-2");
    assert_eq!(result[1].profile_content.data, b"profile-data-2");

    assert_eq!(result[2].name, "Dev Profile 3");
    assert_eq!(result[2].uuid, "UUID-3");
    assert_eq!(result[2].profile_content.data, b"profile-data-3");

    // Ablaufdatum (nur Beispielhafte Plausibilitätsprüfung)
    assert!(result[0].expires_at_epoch.is_some());
    assert!(result[1].expires_at_epoch.is_some());
    assert!(result[2].expires_at_epoch.is_some());
}
