use crate::shared::models::BundleIdentifier;

pub struct CheckIdentifierRequest {
    pub bundle_identifier: BundleIdentifier,
}

pub struct CheckIdentifierApiRequest {
    pub bundle_identifier: BundleIdentifier,
    pub jwt: String,
}

pub struct PromptForIdentifierRequest {
    pub bundle_identifier: BundleIdentifier,
}

pub enum EnsureBundleIdentifierResult {
    IdentifierAlreadyExists,
    CreatedNewIdentifier,
}
