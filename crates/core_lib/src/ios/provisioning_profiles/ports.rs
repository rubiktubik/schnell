#[cfg(test)]
use mockall::automock;

use crate::{
    ios::provisioning_profiles::models::{
        CreateProvisioningProfileRequest, InstallProvisioningProfileRequest,
        ListProvisioningProfilesRequest, ProvisioningProfileQuery,
        RemoteProvisioningProfileSummary,
    },
    shared::errors::{ProvisioningProfileApiError, ProvisioningProfileError},
};

#[cfg_attr(test, automock)]
pub trait ProvisioningProfileApiPort: Send + Sync {
    fn list_profiles(
        &self,
        req: &ListProvisioningProfilesRequest,
    ) -> impl std::future::Future<
        Output = Result<Vec<RemoteProvisioningProfileSummary>, ProvisioningProfileApiError>,
    > + Send;

    fn create_profile(
        &self,
        req: &CreateProvisioningProfileRequest,
    ) -> impl std::future::Future<
        Output = Result<RemoteProvisioningProfileSummary, ProvisioningProfileApiError>,
    > + Send;
}

#[cfg_attr(test, automock)]
pub trait ProvisioningProfileLocalPort: Send + Sync {
    fn has_valid_profile(
        &self,
        query: &ProvisioningProfileQuery,
    ) -> Result<bool, ProvisioningProfileError>;

    fn install_profile(
        &self,
        req: &InstallProvisioningProfileRequest,
    ) -> Result<(), ProvisioningProfileError>;
}
