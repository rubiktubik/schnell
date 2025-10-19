use crate::ios::certificates::models::{EnsureCertificateResult, EnsureCertificateStep};

/// Reports progress while ensuring a certificate.
pub trait CertificateProgressReporter: Send + Sync {
    /// Fired when a step starts executing.
    fn on_step_started(&self, step: EnsureCertificateStep);

    /// Fired when a step completed successfully.
    fn on_step_completed(&self, step: EnsureCertificateStep);

    /// Fired once the overall workflow produced a final result.
    fn on_finished(&self, result: &EnsureCertificateResult);
}

/// Default progress reporter that does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopCertificateProgressReporter;

impl CertificateProgressReporter for NoopCertificateProgressReporter {
    fn on_step_started(&self, _step: EnsureCertificateStep) {}
    fn on_step_completed(&self, _step: EnsureCertificateStep) {}
    fn on_finished(&self, _result: &EnsureCertificateResult) {}
}
