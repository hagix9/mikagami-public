//! Ephemeral authorization boundary for a future promotion attempt.

use crate::failover_policy::{
    FailoverEligibility, FailoverEligibilityInput, FailoverEligibilityPolicy,
    FailoverIndeterminacy, FailoverIneligibility, LocalSafetyReadiness,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionAttemptAuthorization {
    Authorized,
    Blocked(PromotionAttemptBlocker),
    Indeterminate(PromotionAttemptIndeterminacy),
}

impl PromotionAttemptAuthorization {
    pub const fn is_authorized(self) -> bool {
        matches!(self, Self::Authorized)
    }

    /// Re-evaluate current safety and peer evidence for one attempt.
    pub const fn evaluate(input: FailoverEligibilityInput) -> Self {
        match FailoverEligibilityPolicy::evaluate(input) {
            FailoverEligibility::Eligible => Self::Authorized,
            FailoverEligibility::Ineligible(FailoverIneligibility::LocalStateUnsafe)
                if matches!(
                    input.local.readiness,
                    LocalSafetyReadiness::AuthorityPresent
                ) =>
            {
                Self::Blocked(PromotionAttemptBlocker::AuthorityPresent)
            }
            FailoverEligibility::Ineligible(reason) => {
                Self::Blocked(PromotionAttemptBlocker::from_ineligibility(reason))
            }
            FailoverEligibility::Indeterminate(reason) => {
                Self::Indeterminate(PromotionAttemptIndeterminacy::from_indeterminacy(reason))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionAttemptBlocker {
    PeerNotObserved,
    PeerNotLost,
    PeerEvidenceInsufficient,
    LocalStateUnsafe,
    AuthorityPresent,
    OperationInProgress,
    DemotionRequired,
    ShutdownInProgress,
    RecoveryBlocked,
    LocalSafetyUnresolved,
    RecoveryPending,
    Maintenance,
}

impl PromotionAttemptBlocker {
    const fn from_ineligibility(reason: FailoverIneligibility) -> Self {
        match reason {
            FailoverIneligibility::PeerNotObserved => Self::PeerNotObserved,
            FailoverIneligibility::PeerNotLost => Self::PeerNotLost,
            FailoverIneligibility::PeerEvidenceInsufficient => Self::PeerEvidenceInsufficient,
            FailoverIneligibility::LocalFailed
            | FailoverIneligibility::AlreadyActive
            | FailoverIneligibility::LocalStateUnsafe => Self::LocalStateUnsafe,
            FailoverIneligibility::PromotionInProgress => Self::OperationInProgress,
            FailoverIneligibility::DemotionRequired => Self::DemotionRequired,
            FailoverIneligibility::ShutdownInProgress => Self::ShutdownInProgress,
            FailoverIneligibility::RecoveryBlocked => Self::RecoveryBlocked,
            FailoverIneligibility::OwnershipUncertain
            | FailoverIneligibility::ResourceStateUnsafe => Self::LocalSafetyUnresolved,
            FailoverIneligibility::RecoveryPending => Self::RecoveryPending,
            FailoverIneligibility::Maintenance => Self::Maintenance,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionAttemptIndeterminacy {
    AmbiguousPartition,
    InconsistentEvidence,
    LocalSafetyUnknown,
}

impl PromotionAttemptIndeterminacy {
    const fn from_indeterminacy(reason: FailoverIndeterminacy) -> Self {
        match reason {
            FailoverIndeterminacy::PartitionAmbiguous => Self::AmbiguousPartition,
            FailoverIndeterminacy::InconsistentEvidence => Self::InconsistentEvidence,
            FailoverIndeterminacy::LocalSafetyUnknown => Self::LocalSafetyUnknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_fusion::EvidenceFusionState;
    use crate::failover_policy::{LocalSafetyReadiness, LocalSafetySnapshot};
    use crate::failure_assessment::PeerFailureAssessment;
    use crate::state_machine::{DemotionPhase, NodeState, OperationPhase, PromotionPhase};

    const SAFE_INPUT: FailoverEligibilityInput = FailoverEligibilityInput {
        peer_assessment: PeerFailureAssessment::CommunicationLost,
        evidence_state: EvidenceFusionState::FailoverEvidenceReady,
        local: LocalSafetySnapshot {
            node_state: NodeState::Standby,
            operation_phase: None,
            readiness: LocalSafetyReadiness::Safe,
        },
    };

    #[test]
    fn current_eligible_and_safe_is_authorized() {
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(SAFE_INPUT),
            PromotionAttemptAuthorization::Authorized
        );
    }

    #[test]
    fn ineligible_policy_result_is_blocked() {
        let mut input = SAFE_INPUT;
        input.peer_assessment = PeerFailureAssessment::Healthy;
        input.evidence_state = EvidenceFusionState::Unproven;
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(input),
            PromotionAttemptAuthorization::Blocked(PromotionAttemptBlocker::PeerNotLost)
        );
    }

    #[test]
    fn indeterminate_policy_result_is_not_authorized() {
        let mut input = SAFE_INPUT;
        input.evidence_state = EvidenceFusionState::AmbiguousPartition;
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(input),
            PromotionAttemptAuthorization::Indeterminate(
                PromotionAttemptIndeterminacy::AmbiguousPartition
            )
        );
    }

    #[test]
    fn shutdown_after_previous_eligibility_is_blocked() {
        assert!(PromotionAttemptAuthorization::evaluate(SAFE_INPUT).is_authorized());
        let mut current = SAFE_INPUT;
        current.local.readiness = LocalSafetyReadiness::ShutdownInProgress;
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(current),
            PromotionAttemptAuthorization::Blocked(PromotionAttemptBlocker::ShutdownInProgress)
        );
    }

    #[test]
    fn authority_present_after_previous_eligibility_is_blocked() {
        assert!(PromotionAttemptAuthorization::evaluate(SAFE_INPUT).is_authorized());
        let mut current = SAFE_INPUT;
        current.local.readiness = LocalSafetyReadiness::AuthorityPresent;
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(current),
            PromotionAttemptAuthorization::Blocked(PromotionAttemptBlocker::AuthorityPresent)
        );
    }

    #[test]
    fn demotion_latch_after_previous_eligibility_is_blocked() {
        let mut current = SAFE_INPUT;
        current.local.readiness = LocalSafetyReadiness::DemotionRequired;
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(current),
            PromotionAttemptAuthorization::Blocked(PromotionAttemptBlocker::DemotionRequired)
        );
    }

    #[test]
    fn resource_drift_after_previous_eligibility_is_blocked() {
        let mut current = SAFE_INPUT;
        current.local.readiness = LocalSafetyReadiness::ResourceStateUnresolved;
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(current),
            PromotionAttemptAuthorization::Blocked(PromotionAttemptBlocker::LocalSafetyUnresolved)
        );
    }

    #[test]
    fn peer_recovery_after_previous_eligibility_is_blocked() {
        let mut current = SAFE_INPUT;
        current.peer_assessment = PeerFailureAssessment::Healthy;
        assert!(!PromotionAttemptAuthorization::evaluate(current).is_authorized());
    }

    #[test]
    fn evidence_expiry_after_previous_eligibility_is_blocked() {
        let mut current = SAFE_INPUT;
        current.evidence_state = EvidenceFusionState::Unproven;
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(current),
            PromotionAttemptAuthorization::Blocked(
                PromotionAttemptBlocker::PeerEvidenceInsufficient
            )
        );
    }

    #[test]
    fn operation_in_progress_is_blocked() {
        let mut current = SAFE_INPUT;
        current.local.operation_phase = Some(OperationPhase::Promotion(
            PromotionPhase::CheckPromotionGuard,
        ));
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(current),
            PromotionAttemptAuthorization::Blocked(PromotionAttemptBlocker::OperationInProgress)
        );

        current.local.operation_phase = Some(OperationPhase::Demotion(DemotionPhase::StopService));
        assert_eq!(
            PromotionAttemptAuthorization::evaluate(current),
            PromotionAttemptAuthorization::Blocked(PromotionAttemptBlocker::DemotionRequired)
        );
    }

    #[test]
    fn restart_default_state_is_blocked() {
        let mut current = SAFE_INPUT;
        current.local.node_state = NodeState::Init;
        current.local.readiness = LocalSafetyReadiness::Unknown;
        current.peer_assessment = PeerFailureAssessment::Unobserved;
        current.evidence_state = EvidenceFusionState::Unproven;
        assert!(!PromotionAttemptAuthorization::evaluate(current).is_authorized());
    }

    #[test]
    fn ambiguous_partition_never_authorizes() {
        let mut current = SAFE_INPUT;
        current.evidence_state = EvidenceFusionState::AmbiguousPartition;
        assert!(!PromotionAttemptAuthorization::evaluate(current).is_authorized());
    }
}
