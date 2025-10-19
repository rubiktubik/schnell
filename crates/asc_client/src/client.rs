const PROD_BASE_URL: &str = "https://api.appstoreconnect.apple.com";
#[derive(Clone, Default)]
pub struct AppStoreConnectClient {
    pub base_url: String,
}

impl AppStoreConnectClient {
    pub fn new() -> Self {
        Self {
            base_url: PROD_BASE_URL.to_string(),
        }
    }

    pub fn with_base_url_for_test(url: impl Into<String>) -> Self {
        Self {
            base_url: url.into(),
        }
    }
}
