#![allow(dead_code)]

use crate::node_lease_authority::{AuthorityContext, AuthorityGate};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum NodeState {
    Init,
    Standby,
    Candidate,
    Active,
    Degraded,
    Isolated,
    QuorumUnknown,
    RecoveryPending,
    Maintenance,
    Failed,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum PromotionPhase {
    CheckPromotionGuard,
    AcquireLease,
    AcquireVip,
    StartService,
    WaitForHealth,
    AnnounceGratuitousArp,
    CommitActive,
    Rollback,
}

impl PromotionPhase {
    pub fn next(self) -> Option<Self> {
        match self {
            Self::CheckPromotionGuard => Some(Self::AcquireLease),
            Self::AcquireLease => Some(Self::AcquireVip),
            Self::AcquireVip => Some(Self::StartService),
            Self::StartService => Some(Self::WaitForHealth),
            Self::WaitForHealth => Some(Self::AnnounceGratuitousArp),
            Self::AnnounceGratuitousArp => Some(Self::CommitActive),
            Self::CommitActive | Self::Rollback => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum DemotionPhase {
    StopService,
    ConfirmServiceStopped,
    ReleaseVip,
    ConfirmVipReleased,
    ReleaseLease,
    CommitStandby,
}

impl DemotionPhase {
    pub fn next(self) -> Option<Self> {
        match self {
            Self::StopService => Some(Self::ConfirmServiceStopped),
            Self::ConfirmServiceStopped => Some(Self::ReleaseVip),
            Self::ReleaseVip => Some(Self::ConfirmVipReleased),
            Self::ConfirmVipReleased => Some(Self::ReleaseLease),
            Self::ReleaseLease => Some(Self::CommitStandby),
            Self::CommitStandby => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum OperationPhase {
    Promotion(PromotionPhase),
    Demotion(DemotionPhase),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateMachine {
    node_state: NodeState,
    operation_phase: Option<OperationPhase>,
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachine {
    pub const fn new() -> Self {
        Self {
            node_state: NodeState::Init,
            operation_phase: None,
        }
    }

    pub const fn node_state(&self) -> NodeState {
        self.node_state
    }

    pub const fn operation_phase(&self) -> Option<OperationPhase> {
        self.operation_phase
    }

    pub fn transition_to(&mut self, target: NodeState) -> Result<(), TransitionError> {
        if self.operation_phase.is_some() {
            return Err(TransitionError::OperationInProgress);
        }
        if !node_transition_allowed(self.node_state, target) {
            return Err(TransitionError::InvalidNodeTransition {
                from: self.node_state,
                to: target,
            });
        }
        if target == NodeState::Active {
            return Err(TransitionError::AuthorityUnavailable);
        }
        self.transition_to_unchecked(target)
    }

    fn transition_to_unchecked(&mut self, target: NodeState) -> Result<(), TransitionError> {
        if self.operation_phase.is_some() {
            return Err(TransitionError::OperationInProgress);
        }

        if !node_transition_allowed(self.node_state, target) {
            return Err(TransitionError::InvalidNodeTransition {
                from: self.node_state,
                to: target,
            });
        }

        self.node_state = target;
        Ok(())
    }

    pub(crate) fn transition_to_with_authority<G: AuthorityGate>(
        &mut self,
        target: NodeState,
        gate: &mut G,
        context: AuthorityContext,
    ) -> Result<(), TransitionError> {
        if target == NodeState::Active {
            gate.ensure_usable_for_step(context)
                .map_err(|_| TransitionError::AuthorityUnavailable)?;
        }
        self.transition_to_unchecked(target)
    }

    pub fn begin_promotion(&mut self) -> Result<(), TransitionError> {
        if self.node_state != NodeState::Candidate {
            return Err(TransitionError::PromotionRequiresCandidate {
                state: self.node_state,
            });
        }
        if self.operation_phase.is_some() {
            return Err(TransitionError::OperationInProgress);
        }

        self.operation_phase = Some(OperationPhase::Promotion(
            PromotionPhase::CheckPromotionGuard,
        ));
        Ok(())
    }

    pub fn advance_promotion(&mut self) -> Result<PromotionPhase, TransitionError> {
        let current = match self.operation_phase {
            Some(OperationPhase::Promotion(phase)) => phase,
            _ => return Err(TransitionError::PromotionNotInProgress),
        };
        let next = current
            .next()
            .ok_or(TransitionError::PromotionCannotAdvance { phase: current })?;
        if current != PromotionPhase::CheckPromotionGuard {
            return Err(TransitionError::AuthorityUnavailable);
        }
        self.operation_phase = Some(OperationPhase::Promotion(next));
        Ok(next)
    }

    pub(crate) fn advance_promotion_with_authority<G: AuthorityGate>(
        &mut self,
        gate: &mut G,
        context: AuthorityContext,
    ) -> Result<PromotionPhase, TransitionError> {
        let current = match self.operation_phase {
            Some(OperationPhase::Promotion(phase)) => phase,
            _ => return Err(TransitionError::PromotionNotInProgress),
        };
        let next = current
            .next()
            .ok_or(TransitionError::PromotionCannotAdvance { phase: current })?;
        if current != PromotionPhase::CheckPromotionGuard {
            gate.ensure_usable_for_step(context)
                .map_err(|_| TransitionError::AuthorityUnavailable)?;
        }
        self.operation_phase = Some(OperationPhase::Promotion(next));
        Ok(next)
    }

    pub fn rollback_promotion(&mut self) -> Result<(), TransitionError> {
        let current = match self.operation_phase {
            Some(OperationPhase::Promotion(phase)) => phase,
            _ => return Err(TransitionError::PromotionNotInProgress),
        };
        if matches!(
            current,
            PromotionPhase::CheckPromotionGuard | PromotionPhase::Rollback
        ) {
            return Err(TransitionError::PromotionRollbackNotAllowed { phase: current });
        }

        self.operation_phase = Some(OperationPhase::Promotion(PromotionPhase::Rollback));
        Ok(())
    }

    pub fn complete_promotion(&mut self) -> Result<(), TransitionError> {
        match self.operation_phase {
            Some(OperationPhase::Promotion(PromotionPhase::CommitActive)) => {
                Err(TransitionError::AuthorityUnavailable)
            }
            Some(OperationPhase::Promotion(phase)) => {
                Err(TransitionError::PromotionCommitRequiresPhase { phase })
            }
            _ => Err(TransitionError::PromotionNotInProgress),
        }
    }

    fn complete_promotion_unchecked(&mut self) -> Result<(), TransitionError> {
        match self.operation_phase {
            Some(OperationPhase::Promotion(PromotionPhase::CommitActive)) => {
                self.node_state = NodeState::Active;
                self.operation_phase = None;
                Ok(())
            }
            Some(OperationPhase::Promotion(phase)) => {
                Err(TransitionError::PromotionCommitRequiresPhase { phase })
            }
            _ => Err(TransitionError::PromotionNotInProgress),
        }
    }

    pub(crate) fn complete_promotion_with_authority<G: AuthorityGate>(
        &mut self,
        gate: &mut G,
        context: AuthorityContext,
    ) -> Result<(), TransitionError> {
        {
            gate.ensure_usable_for_step(context)
                .map_err(|_| TransitionError::AuthorityUnavailable)?;
        }
        self.complete_promotion_unchecked()
    }

    pub fn complete_promotion_rollback(
        &mut self,
        cleanup_confirmed: bool,
    ) -> Result<(), TransitionError> {
        if self.operation_phase != Some(OperationPhase::Promotion(PromotionPhase::Rollback)) {
            return Err(TransitionError::PromotionRollbackNotInProgress);
        }

        self.node_state = if cleanup_confirmed {
            NodeState::Standby
        } else {
            NodeState::Failed
        };
        self.operation_phase = None;
        Ok(())
    }

    pub fn begin_demotion(&mut self) -> Result<(), TransitionError> {
        if !matches!(
            self.node_state,
            NodeState::Active | NodeState::Degraded | NodeState::QuorumUnknown
        ) {
            return Err(TransitionError::DemotionRequiresActive {
                state: self.node_state,
            });
        }
        if self.operation_phase.is_some() {
            return Err(TransitionError::OperationInProgress);
        }

        self.operation_phase = Some(OperationPhase::Demotion(DemotionPhase::StopService));
        Ok(())
    }

    /// Enter local cleanup from RecoveryPending without reacquiring authority.
    pub fn begin_recovery_cleanup(&mut self) -> Result<(), TransitionError> {
        if self.node_state != NodeState::RecoveryPending {
            return Err(TransitionError::RecoveryCleanupRequiresPending {
                state: self.node_state,
            });
        }
        if self.operation_phase.is_some() {
            return Err(TransitionError::OperationInProgress);
        }
        self.operation_phase = Some(OperationPhase::Demotion(DemotionPhase::StopService));
        Ok(())
    }

    pub fn advance_demotion(&mut self) -> Result<DemotionPhase, TransitionError> {
        let current = match self.operation_phase {
            Some(OperationPhase::Demotion(phase)) => phase,
            _ => return Err(TransitionError::DemotionNotInProgress),
        };
        let next = current
            .next()
            .ok_or(TransitionError::DemotionCannotAdvance { phase: current })?;
        self.operation_phase = Some(OperationPhase::Demotion(next));
        Ok(next)
    }

    pub fn mark_cleanup_failed(&mut self) -> Result<(), TransitionError> {
        match self.operation_phase {
            Some(OperationPhase::Demotion(_)) => {
                self.node_state = NodeState::Failed;
                self.operation_phase = None;
                Ok(())
            }
            _ => Err(TransitionError::DemotionNotInProgress),
        }
    }

    pub fn complete_demotion(&mut self) -> Result<(), TransitionError> {
        match self.operation_phase {
            Some(OperationPhase::Demotion(DemotionPhase::CommitStandby)) => {
                self.node_state = NodeState::Standby;
                self.operation_phase = None;
                Ok(())
            }
            Some(OperationPhase::Demotion(phase)) => {
                Err(TransitionError::DemotionCommitRequiresPhase { phase })
            }
            _ => Err(TransitionError::DemotionNotInProgress),
        }
    }

    pub fn complete_demotion_to_maintenance(&mut self) -> Result<(), TransitionError> {
        match self.operation_phase {
            Some(OperationPhase::Demotion(DemotionPhase::CommitStandby)) => {
                self.node_state = NodeState::Maintenance;
                self.operation_phase = None;
                Ok(())
            }
            Some(OperationPhase::Demotion(phase)) => {
                Err(TransitionError::DemotionCommitRequiresPhase { phase })
            }
            _ => Err(TransitionError::DemotionNotInProgress),
        }
    }

    pub fn reset_for_recovery(&mut self) -> Result<(), TransitionError> {
        if self.node_state != NodeState::Failed {
            return Err(TransitionError::RecoveryRequiresFailed {
                state: self.node_state,
            });
        }
        self.node_state = NodeState::RecoveryPending;
        self.operation_phase = None;
        Ok(())
    }
}

fn node_transition_allowed(from: NodeState, to: NodeState) -> bool {
    matches!(
        (from, to),
        (
            NodeState::Init,
            NodeState::Standby | NodeState::RecoveryPending | NodeState::Failed
        ) | (
            NodeState::Standby,
            NodeState::Candidate
                | NodeState::Isolated
                | NodeState::QuorumUnknown
                | NodeState::Maintenance
        ) | (
            NodeState::Candidate,
            NodeState::Standby | NodeState::Isolated
        ) | (
            NodeState::Active,
            NodeState::Degraded | NodeState::QuorumUnknown | NodeState::Failed
        ) | (NodeState::Degraded, NodeState::Active | NodeState::Failed)
            | (
                NodeState::Isolated,
                NodeState::Standby | NodeState::Candidate
            )
            | (
                NodeState::QuorumUnknown,
                NodeState::Standby | NodeState::Candidate | NodeState::Failed
            )
            | (
                NodeState::RecoveryPending,
                NodeState::Standby | NodeState::Failed
            )
            | (NodeState::Maintenance, NodeState::RecoveryPending)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    InvalidNodeTransition { from: NodeState, to: NodeState },
    OperationInProgress,
    PromotionRequiresCandidate { state: NodeState },
    PromotionNotInProgress,
    PromotionCannotAdvance { phase: PromotionPhase },
    PromotionRollbackNotAllowed { phase: PromotionPhase },
    PromotionCommitRequiresPhase { phase: PromotionPhase },
    PromotionRollbackNotInProgress,
    DemotionRequiresActive { state: NodeState },
    RecoveryCleanupRequiresPending { state: NodeState },
    DemotionNotInProgress,
    DemotionCannotAdvance { phase: DemotionPhase },
    DemotionCommitRequiresPhase { phase: DemotionPhase },
    RecoveryRequiresFailed { state: NodeState },
    AuthorityUnavailable,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeTransition { from, to } => {
                write!(f, "invalid node transition: {from:?} -> {to:?}")
            }
            Self::OperationInProgress => write!(f, "another operation is already in progress"),
            Self::PromotionRequiresCandidate { state } => {
                write!(f, "promotion requires Candidate, got {state:?}")
            }
            Self::PromotionNotInProgress => write!(f, "promotion is not in progress"),
            Self::PromotionCannotAdvance { phase } => {
                write!(f, "promotion cannot advance from {phase:?}")
            }
            Self::PromotionRollbackNotAllowed { phase } => {
                write!(f, "promotion rollback is not allowed from {phase:?}")
            }
            Self::PromotionCommitRequiresPhase { phase } => {
                write!(f, "promotion commit requires CommitActive, got {phase:?}")
            }
            Self::PromotionRollbackNotInProgress => {
                write!(f, "promotion rollback is not in progress")
            }
            Self::DemotionRequiresActive { state } => {
                write!(
                    f,
                    "demotion requires Active, Degraded, or QuorumUnknown, got {state:?}"
                )
            }
            Self::RecoveryCleanupRequiresPending { state } => {
                write!(
                    f,
                    "recovery cleanup requires RecoveryPending, got {state:?}"
                )
            }
            Self::DemotionNotInProgress => write!(f, "demotion is not in progress"),
            Self::DemotionCannotAdvance { phase } => {
                write!(f, "demotion cannot advance from {phase:?}")
            }
            Self::DemotionCommitRequiresPhase { phase } => {
                write!(f, "demotion commit requires CommitStandby, got {phase:?}")
            }
            Self::RecoveryRequiresFailed { state } => {
                write!(f, "recovery reset requires Failed, got {state:?}")
            }
            Self::AuthorityUnavailable => write!(f, "lease authority is not usable"),
        }
    }
}

impl std::error::Error for TransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate_machine() -> StateMachine {
        let mut machine = StateMachine::new();
        machine.transition_to(NodeState::Standby).unwrap();
        machine.transition_to(NodeState::Candidate).unwrap();
        machine
    }

    struct AllowGate;

    impl AuthorityGate for AllowGate {
        fn ensure_usable_for_step(
            &mut self,
            _context: AuthorityContext,
        ) -> Result<(), crate::node_lease_authority::AuthorityError> {
            Ok(())
        }
    }

    struct DenyGate;

    impl AuthorityGate for DenyGate {
        fn ensure_usable_for_step(
            &mut self,
            _context: AuthorityContext,
        ) -> Result<(), crate::node_lease_authority::AuthorityError> {
            Err(crate::node_lease_authority::AuthorityError::AuthorityLost)
        }
    }

    fn promoted_machine() -> StateMachine {
        let mut machine = candidate_machine();
        machine.begin_promotion().unwrap();
        for _ in 0..6 {
            advance_for_availability(&mut machine).unwrap();
        }
        let mut gate = AllowGate;
        machine
            .complete_promotion_with_authority(&mut gate, AuthorityContext::availability())
            .unwrap();
        machine
    }

    fn advance_for_availability(
        machine: &mut StateMachine,
    ) -> Result<PromotionPhase, TransitionError> {
        let mut gate = AllowGate;
        machine.advance_promotion_with_authority(&mut gate, AuthorityContext::availability())
    }

    fn demoting_machine() -> StateMachine {
        let mut machine = promoted_machine();
        machine.begin_demotion().unwrap();
        machine
    }

    #[test]
    fn promotion_advances_in_fixed_order() {
        let mut machine = candidate_machine();
        machine.begin_promotion().unwrap();
        let phases = (0..6)
            .map(|_| advance_for_availability(&mut machine).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            phases,
            vec![
                PromotionPhase::AcquireLease,
                PromotionPhase::AcquireVip,
                PromotionPhase::StartService,
                PromotionPhase::WaitForHealth,
                PromotionPhase::AnnounceGratuitousArp,
                PromotionPhase::CommitActive,
            ]
        );
        assert_eq!(
            machine.operation_phase(),
            Some(OperationPhase::Promotion(PromotionPhase::CommitActive))
        );
    }

    #[test]
    fn promotion_cannot_skip_or_reverse_phase() {
        let mut machine = candidate_machine();
        machine.begin_promotion().unwrap();
        assert_eq!(
            advance_for_availability(&mut machine).unwrap(),
            PromotionPhase::AcquireLease
        );
        assert_eq!(
            advance_for_availability(&mut machine).unwrap(),
            PromotionPhase::AcquireVip
        );
        assert_eq!(
            advance_for_availability(&mut machine).unwrap(),
            PromotionPhase::StartService
        );
        assert_eq!(
            advance_for_availability(&mut machine).unwrap(),
            PromotionPhase::WaitForHealth
        );
        assert_eq!(
            advance_for_availability(&mut machine).unwrap(),
            PromotionPhase::AnnounceGratuitousArp
        );
        assert_eq!(
            advance_for_availability(&mut machine).unwrap(),
            PromotionPhase::CommitActive
        );
        assert!(matches!(
            advance_for_availability(&mut machine),
            Err(TransitionError::PromotionCannotAdvance {
                phase: PromotionPhase::CommitActive
            })
        ));
    }

    #[test]
    fn promotion_commit_requires_completion() {
        let mut machine = candidate_machine();
        machine.begin_promotion().unwrap();
        assert!(matches!(
            machine.complete_promotion(),
            Err(TransitionError::PromotionCommitRequiresPhase { .. })
        ));
        assert!(matches!(
            machine.transition_to(NodeState::Active),
            Err(TransitionError::OperationInProgress)
        ));
    }

    #[test]
    fn conservative_promotion_stops_at_first_resource_authority_boundary() {
        let mut machine = candidate_machine();
        machine.begin_promotion().unwrap();
        let mut deny = DenyGate;
        assert_eq!(
            machine
                .advance_promotion_with_authority(&mut deny, AuthorityContext::availability())
                .unwrap(),
            PromotionPhase::AcquireLease
        );
        assert_eq!(
            machine.advance_promotion_with_authority(&mut deny, AuthorityContext::availability()),
            Err(TransitionError::AuthorityUnavailable)
        );
    }

    #[test]
    fn degraded_to_active_requires_a_current_authority_gate() {
        let mut machine = promoted_machine();
        machine.transition_to(NodeState::Degraded).unwrap();
        let mut deny = DenyGate;
        assert_eq!(
            machine.transition_to_with_authority(
                NodeState::Active,
                &mut deny,
                AuthorityContext::availability()
            ),
            Err(TransitionError::AuthorityUnavailable)
        );
    }

    #[test]
    fn promotion_rollback_requires_an_in_progress_phase() {
        let mut machine = candidate_machine();
        machine.begin_promotion().unwrap();
        assert!(matches!(
            machine.rollback_promotion(),
            Err(TransitionError::PromotionRollbackNotAllowed {
                phase: PromotionPhase::CheckPromotionGuard
            })
        ));
        advance_for_availability(&mut machine).unwrap();
        machine.rollback_promotion().unwrap();
        assert_eq!(
            machine.operation_phase(),
            Some(OperationPhase::Promotion(PromotionPhase::Rollback))
        );
        machine.complete_promotion_rollback(true).unwrap();
        assert_eq!(machine.node_state(), NodeState::Standby);
    }

    #[test]
    fn promotion_rollback_cleanup_failure_enters_failed() {
        let mut machine = candidate_machine();
        machine.begin_promotion().unwrap();
        advance_for_availability(&mut machine).unwrap();
        machine.rollback_promotion().unwrap();
        machine.complete_promotion_rollback(false).unwrap();
        assert_eq!(machine.node_state(), NodeState::Failed);
    }

    #[test]
    fn demotion_advances_in_fixed_order() {
        let mut machine = demoting_machine();
        let phases = (0..5)
            .map(|_| machine.advance_demotion().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            phases,
            vec![
                DemotionPhase::ConfirmServiceStopped,
                DemotionPhase::ReleaseVip,
                DemotionPhase::ConfirmVipReleased,
                DemotionPhase::ReleaseLease,
                DemotionPhase::CommitStandby,
            ]
        );
    }

    #[test]
    fn quorum_unknown_can_begin_local_demotion_without_reacquiring_authority() {
        let mut machine = promoted_machine();
        machine.transition_to(NodeState::QuorumUnknown).unwrap();

        machine.begin_demotion().unwrap();

        assert_eq!(machine.node_state(), NodeState::QuorumUnknown);
        assert_eq!(
            machine.operation_phase(),
            Some(OperationPhase::Demotion(DemotionPhase::StopService))
        );
        let phases = (0..5)
            .map(|_| machine.advance_demotion().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                DemotionPhase::ConfirmServiceStopped,
                DemotionPhase::ReleaseVip,
                DemotionPhase::ConfirmVipReleased,
                DemotionPhase::ReleaseLease,
                DemotionPhase::CommitStandby,
            ]
        );
        machine.complete_demotion().unwrap();
        assert_eq!(machine.node_state(), NodeState::Standby);
    }

    #[test]
    fn demotion_commit_requires_all_confirmation_phases() {
        let mut machine = demoting_machine();
        assert!(matches!(
            machine.complete_demotion(),
            Err(TransitionError::DemotionCommitRequiresPhase {
                phase: DemotionPhase::StopService
            })
        ));
        for _ in 0..5 {
            machine.advance_demotion().unwrap();
        }
        machine.complete_demotion().unwrap();
        assert_eq!(machine.node_state(), NodeState::Standby);
        assert_eq!(machine.operation_phase(), None);
    }

    #[test]
    fn demotion_cleanup_failure_enters_failed() {
        let mut machine = demoting_machine();
        machine.advance_demotion().unwrap();
        machine.mark_cleanup_failed().unwrap();
        assert_eq!(machine.node_state(), NodeState::Failed);
        assert_eq!(machine.operation_phase(), None);
    }

    #[test]
    fn graceful_demotion_can_enter_maintenance_after_commit() {
        let mut machine = demoting_machine();
        for _ in 0..5 {
            machine.advance_demotion().unwrap();
        }
        machine.complete_demotion_to_maintenance().unwrap();
        assert_eq!(machine.node_state(), NodeState::Maintenance);
        assert_eq!(machine.operation_phase(), None);
    }

    #[test]
    fn node_state_transitions_follow_documented_rules() {
        let mut machine = StateMachine::new();
        machine.transition_to(NodeState::Standby).unwrap();
        machine.transition_to(NodeState::Isolated).unwrap();
        machine.transition_to(NodeState::Candidate).unwrap();
        machine.transition_to(NodeState::Standby).unwrap();
        machine.transition_to(NodeState::QuorumUnknown).unwrap();
        machine.transition_to(NodeState::Candidate).unwrap();
        assert!(matches!(
            machine.transition_to(NodeState::Active),
            Err(TransitionError::InvalidNodeTransition { .. })
        ));
    }

    #[test]
    fn forbidden_node_state_transitions_are_rejected() {
        let mut machine = StateMachine::new();
        assert!(machine.transition_to(NodeState::Active).is_err());
        machine.transition_to(NodeState::Failed).unwrap();
        assert!(machine.transition_to(NodeState::Active).is_err());
        machine.reset_for_recovery().unwrap();
        assert!(machine.transition_to(NodeState::Active).is_err());
    }

    #[test]
    fn demotion_is_not_allowed_from_non_resource_holding_states() {
        for state in [
            NodeState::Init,
            NodeState::Standby,
            NodeState::Candidate,
            NodeState::Isolated,
            NodeState::RecoveryPending,
            NodeState::Maintenance,
            NodeState::Failed,
        ] {
            let mut machine = StateMachine::new();
            match state {
                NodeState::Init => {}
                NodeState::Standby => machine.transition_to(NodeState::Standby).unwrap(),
                NodeState::Candidate => {
                    machine.transition_to(NodeState::Standby).unwrap();
                    machine.transition_to(NodeState::Candidate).unwrap();
                }
                NodeState::Isolated => {
                    machine.transition_to(NodeState::Standby).unwrap();
                    machine.transition_to(NodeState::Isolated).unwrap();
                }
                NodeState::RecoveryPending => {
                    machine.transition_to(NodeState::Failed).unwrap();
                    machine.reset_for_recovery().unwrap();
                }
                NodeState::Maintenance => {
                    machine.transition_to(NodeState::Standby).unwrap();
                    machine.transition_to(NodeState::Maintenance).unwrap();
                }
                NodeState::Failed => machine.transition_to(NodeState::Failed).unwrap(),
                NodeState::Active | NodeState::Degraded | NodeState::QuorumUnknown => {
                    unreachable!()
                }
            }
            assert!(matches!(
                machine.begin_demotion(),
                Err(TransitionError::DemotionRequiresActive { state: actual })
                    if actual == state
            ));
        }
    }

    #[test]
    fn failed_recovery_starts_at_recovery_pending() {
        let mut machine = StateMachine::new();
        machine.transition_to(NodeState::Failed).unwrap();
        machine.reset_for_recovery().unwrap();
        assert_eq!(machine.node_state(), NodeState::RecoveryPending);
        assert_eq!(machine.operation_phase(), None);
    }

    #[test]
    fn recovery_pending_can_enter_local_cleanup_without_authority() {
        let mut machine = StateMachine::new();
        machine.transition_to(NodeState::Failed).unwrap();
        machine.reset_for_recovery().unwrap();
        machine.begin_recovery_cleanup().unwrap();
        assert_eq!(machine.node_state(), NodeState::RecoveryPending);
        assert_eq!(
            machine.operation_phase(),
            Some(OperationPhase::Demotion(DemotionPhase::StopService))
        );
    }

    #[test]
    fn maintenance_requires_standby() {
        let mut machine = StateMachine::new();
        assert!(machine.transition_to(NodeState::Maintenance).is_err());
        machine.transition_to(NodeState::Standby).unwrap();
        machine.transition_to(NodeState::Maintenance).unwrap();
        assert_eq!(machine.node_state(), NodeState::Maintenance);
    }
}
