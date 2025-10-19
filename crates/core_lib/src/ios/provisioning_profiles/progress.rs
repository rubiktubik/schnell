use crate::ios::provisioning_profiles::models::{
    EnsureProvisioningProfileResult, EnsureProvisioningProfileStep,
};

/// Reports progress while ensuring a provisioning profile.
pub trait ProvisioningProfileProgressReporter: Send + Sync {
    /// Fired when a step starts executing.
    fn on_step_started(&self, step: EnsureProvisioningProfileStep);

    /// Fired when a step completed successfully.
    fn on_step_completed(&self, step: EnsureProvisioningProfileStep);

    /// Fired once the overall workflow produced a final result.
    fn on_finished(&self, result: &EnsureProvisioningProfileResult);
}

/// Default progress reporter that does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopProvisioningProfileProgressReporter;

impl ProvisioningProfileProgressReporter for NoopProvisioningProfileProgressReporter {
    fn on_step_started(&self, _step: EnsureProvisioningProfileStep) {}
    fn on_step_completed(&self, _step: EnsureProvisioningProfileStep) {}
    fn on_finished(&self, _result: &EnsureProvisioningProfileResult) {}
}
