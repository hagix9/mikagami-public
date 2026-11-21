//! Synchronous composition of authority checkpoints and resource primitives.

#![allow(dead_code)]

use crate::node_lease_authority::{AuthorityCheckpoint, MonotonicClock, NodeAuthorityController};
use crate::node_mutation::{NodeMutationError, OutstandingWitnessMutation};
use crate::resource_executor::{
    ActionDiagnostic, GarpOutcome, NetworkBackend, ResourceExecutor, ServiceBackend,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromotionWorkflowOutcome {
    ReadyForActiveCommit,
    PromotionBlocked,
    CleanupRequired,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CleanupWorkflowOutcome {
    CleanStandbyEligible,
    LeaseReleasePending(OutstandingWitnessMutation),
    CleanupRequired,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResourceWorkflowError {
    Mutation(NodeMutationError),
}

/// Proof that this workflow observed both local cleanup postconditions.
///
/// The constructor is private so a crate-local caller cannot start a cleanup
/// LeaseRelease without passing through this module's trusted executor path.
pub(crate) struct CleanupProvenance {
    _private: (),
}

impl CleanupProvenance {
    fn established() -> Self {
        Self { _private: () }
    }
}

impl From<NodeMutationError> for ResourceWorkflowError {
    fn from(error: NodeMutationError) -> Self {
        Self::Mutation(error)
    }
}

pub(crate) struct ResourceWorkflow<'a, N, S, C>
where
    N: NetworkBackend,
    S: ServiceBackend,
    C: MonotonicClock,
{
    controller: &'a mut NodeAuthorityController<C>,
    executor: &'a mut ResourceExecutor<N, S>,
}

impl<'a, N, S, C> ResourceWorkflow<'a, N, S, C>
where
    N: NetworkBackend,
    S: ServiceBackend,
    C: MonotonicClock,
{
    pub(crate) fn new(
        controller: &'a mut NodeAuthorityController<C>,
        executor: &'a mut ResourceExecutor<N, S>,
    ) -> Self {
        Self {
            controller,
            executor,
        }
    }

    pub(crate) fn promote(&mut self) -> PromotionWorkflowOutcome {
        let vip_permission = match self
            .controller
            .checkpoint(AuthorityCheckpoint::BeforeVipAcquire)
        {
            Ok(permission) => permission,
            Err(_) => return PromotionWorkflowOutcome::PromotionBlocked,
        };
        let vip = self.executor.acquire_vip();
        let vip_present = vip.observation().is_present();
        if vip_present {
            self.controller.mark_resource_ownership_started();
        }
        if self
            .controller
            .complete_checkpoint(vip_permission, AuthorityCheckpoint::BeforeVipAcquire)
            .is_err()
        {
            if !vip.observation().is_absent() {
                self.controller.mark_ownership_uncertain();
            }
            return PromotionWorkflowOutcome::CleanupRequired;
        }
        if !vip_present {
            if vip.observation().is_unknown() {
                self.controller.mark_ownership_uncertain();
                return PromotionWorkflowOutcome::CleanupRequired;
            }
            return PromotionWorkflowOutcome::PromotionBlocked;
        }
        if matches!(vip.diagnostic(), ActionDiagnostic::Interrupted) {
            self.controller.mark_ownership_uncertain();
            return PromotionWorkflowOutcome::CleanupRequired;
        }

        let service_permission = match self
            .controller
            .checkpoint(AuthorityCheckpoint::BeforeServiceStart)
        {
            Ok(permission) => permission,
            Err(_) => return PromotionWorkflowOutcome::CleanupRequired,
        };
        let service = self.executor.start_service();
        let service_running = service.observation().is_running();
        if service_running {
            self.controller.mark_resource_ownership_started();
        }
        if self
            .controller
            .complete_checkpoint(service_permission, AuthorityCheckpoint::BeforeServiceStart)
            .is_err()
        {
            if !service.observation().is_stopped() {
                self.controller.mark_ownership_uncertain();
            }
            return PromotionWorkflowOutcome::CleanupRequired;
        }
        if !service_running || !matches!(service.diagnostic(), ActionDiagnostic::Success) {
            if !service.observation().is_stopped() {
                self.controller.mark_ownership_uncertain();
            }
            return PromotionWorkflowOutcome::CleanupRequired;
        }

        let health_permission = match self
            .controller
            .checkpoint(AuthorityCheckpoint::BeforeHealthAdvance)
        {
            Ok(permission) => permission,
            Err(_) => return PromotionWorkflowOutcome::CleanupRequired,
        };
        let health = self.executor.observe_health();
        if self
            .controller
            .complete_checkpoint(health_permission, AuthorityCheckpoint::BeforeHealthAdvance)
            .is_err()
        {
            return PromotionWorkflowOutcome::CleanupRequired;
        }
        if !health.is_healthy() {
            return PromotionWorkflowOutcome::CleanupRequired;
        }

        let garp_permission = match self.controller.checkpoint(AuthorityCheckpoint::BeforeGarp) {
            Ok(permission) => permission,
            Err(_) => return PromotionWorkflowOutcome::CleanupRequired,
        };
        let garp = self.executor.send_garp();
        if self
            .controller
            .complete_checkpoint(garp_permission, AuthorityCheckpoint::BeforeGarp)
            .is_err()
        {
            return PromotionWorkflowOutcome::CleanupRequired;
        }
        if garp.outcome() != GarpOutcome::Succeeded {
            return PromotionWorkflowOutcome::CleanupRequired;
        }

        let active_permission = match self
            .controller
            .checkpoint(AuthorityCheckpoint::BeforeActiveCommit)
        {
            Ok(permission) => permission,
            Err(_) => return PromotionWorkflowOutcome::CleanupRequired,
        };
        if self
            .controller
            .complete_checkpoint(active_permission, AuthorityCheckpoint::BeforeActiveCommit)
            .is_err()
        {
            return PromotionWorkflowOutcome::CleanupRequired;
        }
        PromotionWorkflowOutcome::ReadyForActiveCommit
    }

    pub(crate) fn cleanup(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<CleanupWorkflowOutcome, ResourceWorkflowError> {
        self.cleanup_guarded(reason, &|| true)
    }

    /// Cleanup with the live control-lock safety contract. The guard is
    /// sampled before each new protected effect: before service stop, before
    /// VIP release, and again before beginning a durable LeaseRelease. A
    /// `false` result stops the workflow at its current boundary and returns
    /// `CleanupRequired`; it never claims a clean or unknown result.
    pub(crate) fn cleanup_guarded(
        &mut self,
        reason: impl Into<String>,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Result<CleanupWorkflowOutcome, ResourceWorkflowError> {
        if !control_lock_safe() {
            return Ok(CleanupWorkflowOutcome::CleanupRequired);
        }
        let Some(provenance) = self.cleanup_local_resources_inner_guarded(control_lock_safe) else {
            return Ok(CleanupWorkflowOutcome::CleanupRequired);
        };
        self.controller.complete_local_cleanup(&provenance);

        if !control_lock_safe() {
            return Ok(CleanupWorkflowOutcome::CleanupRequired);
        }
        if !self.controller.requires_lease_release()
            || !self.controller.release_obligation_present()?
        {
            return Ok(CleanupWorkflowOutcome::CleanStandbyEligible);
        }
        // A retained Renew must never delay local cleanup and must not be
        // overwritten by Release.  The foreground post-cleanup owner will
        // reconcile this exact record first, then re-run verified cleanup to
        // begin Release with a free slot.
        if let Some(outstanding) = self.controller.outstanding_mutation()? {
            return Ok(CleanupWorkflowOutcome::LeaseReleasePending(outstanding));
        }
        let mutation = self
            .controller
            .begin_lease_release_for_cleanup(&provenance, reason.into())?;
        Ok(CleanupWorkflowOutcome::LeaseReleasePending(mutation))
    }

    /// Recovery-only cleanup. It proves local resource absence without
    /// attempting to acquire or release Witness authority. The caller still
    /// has to pass the normal recovery gate before entering Standby.
    pub(crate) fn cleanup_local_resources(&mut self) -> CleanupWorkflowOutcome {
        self.cleanup_local_resources_guarded(&|| true)
    }

    /// Recovery/shutdown local cleanup with the live control-lock contract.
    /// The guard is sampled before service stop and again before VIP release,
    /// so a loss after the service transition cannot start a second protected
    /// effect. The result is `CleanupRequired` on a denied boundary.
    pub(crate) fn cleanup_local_resources_guarded(
        &mut self,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> CleanupWorkflowOutcome {
        let Some(provenance) = self.cleanup_local_resources_inner_guarded(control_lock_safe) else {
            return CleanupWorkflowOutcome::CleanupRequired;
        };
        self.controller.complete_local_cleanup(&provenance);
        CleanupWorkflowOutcome::CleanStandbyEligible
    }

    fn cleanup_local_resources_inner_guarded(
        &mut self,
        control_lock_safe: &dyn Fn() -> bool,
    ) -> Option<CleanupProvenance> {
        if !control_lock_safe() {
            return None;
        }
        let stopped = self.executor.stop_service();
        if stopped.observation().is_running() {
            self.controller.mark_resource_ownership_started();
        } else if stopped.observation().is_unknown() {
            self.controller.mark_ownership_uncertain();
        }
        if !stopped.observation().is_stopped() {
            return None;
        }

        // The service stop may have taken long enough for another controller
        // to replace the lock. Never start the VIP release after that.
        if !control_lock_safe() {
            return None;
        }
        let released = self.executor.release_vip();
        if released.observation().is_present() {
            self.controller.mark_resource_ownership_started();
        } else if released.observation().is_unknown() {
            self.controller.mark_ownership_uncertain();
        }
        if !released.observation().is_absent() {
            return None;
        }

        Some(CleanupProvenance::established())
    }
}
