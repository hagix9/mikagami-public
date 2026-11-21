//! Pure failover eligibility policy.
//!
//! This module consumes already-derived peer, Witness, and local state
//! observations. It does not own timers, perform I/O, or mutate HA state.

use crate::evidence_fusion::EvidenceFusionState;
use crate::failure_assessment::PeerFailureAssessment;
use crate::state_machine::{NodeState, OperationPhase, StateMachine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverEligibility {
    Eligible,
    Ineligible(FailoverIneligibility),
    Indeterminate(FailoverIndeterminacy),
}

impl FailoverEligibility {
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverIneligibility {
    PeerNotObserved,
    PeerNotLost,
    PeerEvidenceInsufficient,
    LocalFailed,
    AlreadyActive,
    PromotionInProgress,
    DemotionRequired,
    ShutdownInProgress,
    RecoveryBlocked,
    OwnershipUncertain,
    ResourceStateUnsafe,
    RecoveryPending,
    Maintenance,
    LocalStateUnsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverIndeterminacy {
    PartitionAmbiguous,
    InconsistentEvidence,
    LocalSafetyUnknown,
}

/// Immutable local readiness derived from the daemon and node runtime.
///
/// The policy consumes this value only; it never queries runtime owners or
/// infers readiness from the absence of a state-machine operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalSafetyReadiness {
    Safe,
    ShutdownInProgress,
    RecoveryBlocked,
    DemotionRequired,
    OwnershipUncertain,
    ResourceStateUnresolved,
    AuthorityPresent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalSafetySnapshot {
    pub node_state: NodeState,
    pub operation_phase: Option<OperationPhase>,
    pub readiness: LocalSafetyReadiness,
}

impl LocalSafetySnapshot {
    pub const fn from_state_machine(machine: &StateMachine) -> Self {
        Self {
            node_state: machine.node_state(),
            operation_phase: machine.operation_phase(),
            readiness: LocalSafetyReadiness::Unknown,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn from_state_machine_with_readiness(
        machine: &StateMachine,
        readiness: LocalSafetyReadiness,
    ) -> Self {
        Self {
            node_state: machine.node_state(),
            operation_phase: machine.operation_phase(),
            readiness,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailoverEligibilityInput {
    pub peer_assessment: PeerFailureAssessment,
    pub evidence_state: EvidenceFusionState,
    pub local: LocalSafetySnapshot,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FailoverEligibilityPolicy;

impl FailoverEligibilityPolicy {
    pub const fn evaluate(input: FailoverEligibilityInput) -> FailoverEligibility {
        match local_safety(input.local) {
            Some(result) => result,
            None => evaluate_evidence(input.peer_assessment, input.evidence_state),
        }
    }
}

const fn local_safety(local: LocalSafetySnapshot) -> Option<FailoverEligibility> {
    let state_result = match local.node_state {
        NodeState::Failed => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::LocalFailed,
        )),
        NodeState::Active => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::AlreadyActive,
        )),
        NodeState::Candidate => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::PromotionInProgress,
        )),
        NodeState::RecoveryPending => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::RecoveryPending,
        )),
        NodeState::Maintenance => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::Maintenance,
        )),
        NodeState::Init | NodeState::Isolated | NodeState::Degraded | NodeState::QuorumUnknown => {
            Some(FailoverEligibility::Ineligible(
                FailoverIneligibility::LocalStateUnsafe,
            ))
        }
        NodeState::Standby => None,
    };
    if state_result.is_some() {
        return state_result;
    }

    let operation_result = match local.operation_phase {
        Some(OperationPhase::Promotion(_)) => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::PromotionInProgress,
        )),
        Some(OperationPhase::Demotion(_)) => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::DemotionRequired,
        )),
        None => None,
    };
    if operation_result.is_some() {
        return operation_result;
    }

    match local.readiness {
        LocalSafetyReadiness::Safe => None,
        LocalSafetyReadiness::ShutdownInProgress => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::ShutdownInProgress,
        )),
        LocalSafetyReadiness::RecoveryBlocked => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::RecoveryBlocked,
        )),
        LocalSafetyReadiness::DemotionRequired => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::DemotionRequired,
        )),
        LocalSafetyReadiness::OwnershipUncertain => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::OwnershipUncertain,
        )),
        LocalSafetyReadiness::ResourceStateUnresolved => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::ResourceStateUnsafe,
        )),
        LocalSafetyReadiness::AuthorityPresent => Some(FailoverEligibility::Ineligible(
            FailoverIneligibility::LocalStateUnsafe,
        )),
        LocalSafetyReadiness::Unknown => Some(FailoverEligibility::Indeterminate(
            FailoverIndeterminacy::LocalSafetyUnknown,
        )),
    }
}

const fn evaluate_evidence(
    peer: PeerFailureAssessment,
    evidence: EvidenceFusionState,
) -> FailoverEligibility {
    match (peer, evidence) {
        (PeerFailureAssessment::CommunicationLost, EvidenceFusionState::FailoverEvidenceReady) => {
            FailoverEligibility::Eligible
        }
        (PeerFailureAssessment::CommunicationLost, EvidenceFusionState::AmbiguousPartition) => {
            FailoverEligibility::Indeterminate(FailoverIndeterminacy::PartitionAmbiguous)
        }
        (PeerFailureAssessment::CommunicationLost, _) => {
            FailoverEligibility::Ineligible(FailoverIneligibility::PeerEvidenceInsufficient)
        }
        (PeerFailureAssessment::Unobserved, EvidenceFusionState::Unproven) => {
            FailoverEligibility::Ineligible(FailoverIneligibility::PeerNotObserved)
        }
        (PeerFailureAssessment::Healthy, EvidenceFusionState::Unproven) => {
            FailoverEligibility::Ineligible(FailoverIneligibility::PeerNotLost)
        }
        (PeerFailureAssessment::Suspect, EvidenceFusionState::PeerDegraded) => {
            FailoverEligibility::Ineligible(FailoverIneligibility::PeerEvidenceInsufficient)
        }
        (PeerFailureAssessment::Unobserved, _) => {
            FailoverEligibility::Indeterminate(FailoverIndeterminacy::InconsistentEvidence)
        }
        (PeerFailureAssessment::Healthy, _) => {
            FailoverEligibility::Indeterminate(FailoverIndeterminacy::InconsistentEvidence)
        }
        (PeerFailureAssessment::Suspect, _) => {
            FailoverEligibility::Indeterminate(FailoverIndeterminacy::InconsistentEvidence)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAFE_STANDBY: LocalSafetySnapshot = LocalSafetySnapshot {
        node_state: NodeState::Standby,
        operation_phase: None,
        readiness: LocalSafetyReadiness::Safe,
    };

    const STRONG_LOSS: FailoverEligibilityInput = FailoverEligibilityInput {
        peer_assessment: PeerFailureAssessment::CommunicationLost,
        evidence_state: EvidenceFusionState::FailoverEvidenceReady,
        local: SAFE_STANDBY,
    };

    fn evaluate(
        peer_assessment: PeerFailureAssessment,
        evidence_state: EvidenceFusionState,
    ) -> FailoverEligibility {
        FailoverEligibilityPolicy::evaluate(FailoverEligibilityInput {
            peer_assessment,
            evidence_state,
            local: SAFE_STANDBY,
        })
    }

    #[test]
    fn unobserved_and_unproven_are_not_eligible() {
        assert_eq!(
            evaluate(
                PeerFailureAssessment::Unobserved,
                EvidenceFusionState::Unproven
            ),
            FailoverEligibility::Ineligible(FailoverIneligibility::PeerNotObserved)
        );
    }

    #[test]
    fn healthy_and_unproven_are_not_eligible() {
        assert_eq!(
            evaluate(
                PeerFailureAssessment::Healthy,
                EvidenceFusionState::Unproven
            ),
            FailoverEligibility::Ineligible(FailoverIneligibility::PeerNotLost)
        );
    }

    #[test]
    fn suspect_and_peer_degraded_are_not_eligible() {
        assert_eq!(
            evaluate(
                PeerFailureAssessment::Suspect,
                EvidenceFusionState::PeerDegraded
            ),
            FailoverEligibility::Ineligible(FailoverIneligibility::PeerEvidenceInsufficient)
        );
    }

    #[test]
    fn communication_lost_requires_corroborated_loss() {
        for evidence in [
            EvidenceFusionState::Unproven,
            EvidenceFusionState::PeerDegraded,
        ] {
            assert_eq!(
                evaluate(PeerFailureAssessment::CommunicationLost, evidence),
                FailoverEligibility::Ineligible(FailoverIneligibility::PeerEvidenceInsufficient)
            );
        }
    }

    #[test]
    fn ambiguous_partition_is_indeterminate_and_not_eligible() {
        assert_eq!(
            evaluate(
                PeerFailureAssessment::CommunicationLost,
                EvidenceFusionState::AmbiguousPartition
            ),
            FailoverEligibility::Indeterminate(FailoverIndeterminacy::PartitionAmbiguous)
        );
    }

    #[test]
    fn strong_loss_and_safe_standby_are_eligible() {
        assert_eq!(
            FailoverEligibilityPolicy::evaluate(STRONG_LOSS),
            FailoverEligibility::Eligible
        );
    }

    #[test]
    fn failed_local_node_is_never_eligible() {
        let mut input = STRONG_LOSS;
        input.local.node_state = NodeState::Failed;
        assert_eq!(
            FailoverEligibilityPolicy::evaluate(input),
            FailoverEligibility::Ineligible(FailoverIneligibility::LocalFailed)
        );
    }

    #[test]
    fn active_local_node_is_not_a_promotion_candidate() {
        let mut input = STRONG_LOSS;
        input.local.node_state = NodeState::Active;
        assert_eq!(
            FailoverEligibilityPolicy::evaluate(input),
            FailoverEligibility::Ineligible(FailoverIneligibility::AlreadyActive)
        );
    }

    #[test]
    fn candidate_and_promotion_operation_are_not_eligible() {
        let mut candidate = STRONG_LOSS;
        candidate.local.node_state = NodeState::Candidate;
        assert_eq!(
            FailoverEligibilityPolicy::evaluate(candidate),
            FailoverEligibility::Ineligible(FailoverIneligibility::PromotionInProgress)
        );

        let mut operation = STRONG_LOSS;
        operation.local.operation_phase = Some(OperationPhase::Promotion(
            crate::state_machine::PromotionPhase::CheckPromotionGuard,
        ));
        assert_eq!(
            FailoverEligibilityPolicy::evaluate(operation),
            FailoverEligibility::Ineligible(FailoverIneligibility::PromotionInProgress)
        );
    }

    #[test]
    fn demotion_operation_is_a_cleanup_obligation() {
        let mut input = STRONG_LOSS;
        input.local.operation_phase = Some(OperationPhase::Demotion(
            crate::state_machine::DemotionPhase::StopService,
        ));
        assert_eq!(
            FailoverEligibilityPolicy::evaluate(input),
            FailoverEligibility::Ineligible(FailoverIneligibility::DemotionRequired)
        );
    }

    #[test]
    fn recovery_pending_maintenance_and_unsafe_states_are_blocked() {
        for state in [
            NodeState::RecoveryPending,
            NodeState::Maintenance,
            NodeState::Init,
            NodeState::Isolated,
            NodeState::Degraded,
            NodeState::QuorumUnknown,
        ] {
            let mut input = STRONG_LOSS;
            input.local.node_state = state;
            assert!(!FailoverEligibilityPolicy::evaluate(input).is_eligible());
        }
    }

    #[test]
    fn inconsistent_peer_and_fusion_snapshots_fail_closed() {
        for peer in [
            PeerFailureAssessment::Unobserved,
            PeerFailureAssessment::Healthy,
            PeerFailureAssessment::Suspect,
        ] {
            assert!(matches!(
                evaluate(peer, EvidenceFusionState::FailoverEvidenceReady),
                FailoverEligibility::Indeterminate(FailoverIndeterminacy::InconsistentEvidence)
            ));
        }
        assert!(matches!(
            evaluate(
                PeerFailureAssessment::CommunicationLost,
                EvidenceFusionState::PeerDegraded
            ),
            FailoverEligibility::Ineligible(FailoverIneligibility::PeerEvidenceInsufficient)
        ));
    }

    #[test]
    fn eligibility_is_recomputed_when_evidence_changes() {
        assert!(FailoverEligibilityPolicy::evaluate(STRONG_LOSS).is_eligible());
        let mut current = STRONG_LOSS;
        current.evidence_state = EvidenceFusionState::Unproven;
        assert!(!FailoverEligibilityPolicy::evaluate(current).is_eligible());
        current.peer_assessment = PeerFailureAssessment::Healthy;
        assert!(!FailoverEligibilityPolicy::evaluate(current).is_eligible());
    }

    #[test]
    fn restart_default_snapshot_is_not_eligible() {
        let machine = StateMachine::new();
        let result = FailoverEligibilityPolicy::evaluate(FailoverEligibilityInput {
            peer_assessment: PeerFailureAssessment::Unobserved,
            evidence_state: EvidenceFusionState::Unproven,
            local: LocalSafetySnapshot::from_state_machine(&machine),
        });
        assert!(!result.is_eligible());
    }

    #[test]
    fn policy_evaluation_does_not_mutate_input_state() {
        let machine = StateMachine::new();
        let local = LocalSafetySnapshot::from_state_machine(&machine);
        let input = FailoverEligibilityInput {
            peer_assessment: PeerFailureAssessment::CommunicationLost,
            evidence_state: EvidenceFusionState::FailoverEvidenceReady,
            local,
        };
        let before = input;
        let _ = FailoverEligibilityPolicy::evaluate(input);
        assert_eq!(input, before);
        assert_eq!(machine.node_state(), NodeState::Init);
        assert_eq!(machine.operation_phase(), None);
    }

    #[test]
    fn every_non_safe_local_readiness_blocks_strong_loss() {
        for readiness in [
            LocalSafetyReadiness::ShutdownInProgress,
            LocalSafetyReadiness::RecoveryBlocked,
            LocalSafetyReadiness::DemotionRequired,
            LocalSafetyReadiness::OwnershipUncertain,
            LocalSafetyReadiness::ResourceStateUnresolved,
            LocalSafetyReadiness::AuthorityPresent,
        ] {
            let mut input = STRONG_LOSS;
            input.local.readiness = readiness;
            assert!(!FailoverEligibilityPolicy::evaluate(input).is_eligible());
        }
    }

    #[test]
    fn unknown_local_readiness_is_indeterminate() {
        let mut input = STRONG_LOSS;
        input.local.readiness = LocalSafetyReadiness::Unknown;
        assert_eq!(
            FailoverEligibilityPolicy::evaluate(input),
            FailoverEligibility::Indeterminate(FailoverIndeterminacy::LocalSafetyUnknown)
        );
    }

    #[test]
    fn explicit_safe_readiness_is_required_for_eligibility() {
        assert!(FailoverEligibilityPolicy::evaluate(STRONG_LOSS).is_eligible());
        let machine = StateMachine::new();
        let mut local = LocalSafetySnapshot::from_state_machine(&machine);
        local.node_state = NodeState::Standby;
        assert!(
            !FailoverEligibilityPolicy::evaluate(FailoverEligibilityInput {
                local,
                ..STRONG_LOSS
            })
            .is_eligible()
        );
    }
}
