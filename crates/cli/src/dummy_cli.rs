use core_lib::{
    ios::bundle_identifier::{
        errors::PromptForBundleIdentifierError, models::PromptForIdentifierRequest,
        ports::BundleIdentifierCliPort,
    },
    shared::models::BundleIdentifier,
};

#[derive(Debug, Clone)]
pub struct DummyBundleIdentifierCli;

impl BundleIdentifierCliPort for DummyBundleIdentifierCli {
    fn prompt_for_bundle_id(
        &self,
        _request: &PromptForIdentifierRequest,
    ) -> Result<BundleIdentifier, PromptForBundleIdentifierError> {
        unimplemented!("This is a dummy implementation and should not be called.")
    }
}
