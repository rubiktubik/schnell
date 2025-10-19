#[cfg(test)]
use mockall::automock;

use crate::{
    ios::bundle_identifier::models::{CheckIdentifierApiRequest, EnsureBundleIdentifierResult},
    shared::models::BundleIdentifier,
};

use super::{
    errors::{BundleIdentiferApiError, EnsureBundleIdExistsError, PromptForBundleIdentifierError},
    models::{CheckIdentifierRequest, PromptForIdentifierRequest},
};

#[cfg_attr(test, automock)]
pub trait BundleIdentifierCliPort {
    fn prompt_for_bundle_id(
        &self,
        request: &PromptForIdentifierRequest,
    ) -> Result<BundleIdentifier, PromptForBundleIdentifierError>;
}

#[cfg_attr(test, automock)]
pub trait BundleIdentifierApiPort {
    fn check_if_identifier_exists(
        &self,
        request: &CheckIdentifierApiRequest,
    ) -> impl std::future::Future<Output = Result<bool, BundleIdentiferApiError>> + Send;
    fn create_bundle_identifier(
        &self,
        request: &CheckIdentifierApiRequest,
    ) -> impl std::future::Future<Output = Result<(), BundleIdentiferApiError>> + Send;
}

#[cfg_attr(test, automock)]
pub trait BundleIdentifierServicePort {
    fn ensure_bundle_id_exists(
        &self,
        request: &CheckIdentifierRequest,
    ) -> impl std::future::Future<
        Output = Result<EnsureBundleIdentifierResult, EnsureBundleIdExistsError>,
    > + Send;
}
