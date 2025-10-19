#[cfg(test)]
use mockall::automock;

use crate::{
    ios::certificates::models::{
        CheckCertificateApiRequest, CreateCertificateApiRequest, RemoteCertificateSummary,
    },
    shared::errors::CertificateApiError,
};

#[cfg_attr(test, automock)]
pub trait CertificateApiPort: Sync + Send {
    fn list_certificates(
        &self,
        req: &CheckCertificateApiRequest,
    ) -> impl std::future::Future<
        Output = Result<Vec<RemoteCertificateSummary>, CertificateApiError>,
    > + Send;

    fn create_certificate(
        &self,
        req: &CreateCertificateApiRequest,
    ) -> impl std::future::Future<Output = Result<RemoteCertificateSummary, CertificateApiError>> + Send;
}
