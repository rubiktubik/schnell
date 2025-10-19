use core_lib::ios::bundle_identifier::errors::BundleIdentiferApiError;
use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct HttpRequestError(#[from] reqwest::Error);

impl From<HttpRequestError> for BundleIdentiferApiError {
    fn from(e: HttpRequestError) -> Self {
        BundleIdentiferApiError::HttpRequest(Box::new(e))
    }
}
