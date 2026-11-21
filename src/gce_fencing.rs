//! v0.6 Phase C: GCE VM fencing backend design as an executable model.
//!
//! This module is **not wired into promotion**. It exists so the safety rules
//! of a GCE backend can be stated, tested deterministically and audited before
//! any IAM change or any real VM stop. `FENCING_BACKEND_DESIGN.md` and
//! `FENCING_IAM_PROPOSAL.md` describe the intended production wiring; this code
//! is the contract that wiring must satisfy.
//!
//! Safety rules encoded here (see the design document for the rationale):
//!
//! 1. A sent API request is never fencing proof. Only an observed terminal
//!    state of the **identified** target can be proof.
//! 2. A timeout is never success. It is at most "the request may have been
//!    accepted", which requires re-observation.
//! 3. `UNKNOWN` never promotes. With the default policy, a stop operation that
//!    cannot be correlated to `DONE` blocks the failover even if the instance
//!    happens to read `TERMINATED`; the stricter reading is used because the
//!    caller must not have to trust an unproven side effect.
//! 4. The target is identified by `(project, zone, name)` **and** the numeric
//!    instance id learned from a describe. An id mismatch is a hard block: the
//!    name may have been reused by a recreated VM.
//! 5. Every verdict carries the binding (term, lease id, attempt generation)
//!    it was computed for, so a stale fence cannot clear a newer attempt, and
//!    a newer attempt cannot clear an older incident.
//! 6. Retries are bounded (`max_actions`); exhaustion is a block, never a
//!    success.
//!
//! IAM (not changed in v0.6): the model assumes a control identity that may
//! call `compute.instances.get`, `compute.instances.stop` and
//! `compute.zoneOperations.get` on exactly the two HA instances. The design
//! document records the least-privilege proposal and why the current
//! project-level default service account is not acceptable for real fencing.

#![allow(dead_code)]

use std::fmt;

/// Everything that identifies one fencing target. `instance_id` is the numeric
/// GCE id observed from a describe; it is the identity anchor that survives a
/// name reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FenceTarget {
    pub(crate) project: String,
    pub(crate) zone: String,
    pub(crate) instance: String,
    pub(crate) instance_id: String,
}

impl FenceTarget {
    pub(crate) fn new(
        project: impl Into<String>,
        zone: impl Into<String>,
        instance: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            project: project.into(),
            zone: zone.into(),
            instance: instance.into(),
            instance_id: instance_id.into(),
        }
    }

    /// Exact identity match. Never a fuzzy name comparison: `zone` and the
    /// numeric id must agree, because a recreated instance reuses the name.
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.project == other.project
            && self.zone == other.zone
            && self.instance == other.instance
            && self.instance_id == other.instance_id
    }
}

impl fmt::Display for FenceTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/{}/{}#{}",
            self.project, self.zone, self.instance, self.instance_id
        )
    }
}

/// The attempt a fence belongs to. A fence verdict is only usable by the exact
/// binding it was computed for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FenceBinding {
    pub(crate) term: u64,
    pub(crate) lease_id: String,
    pub(crate) attempt_generation: u64,
}

impl FenceBinding {
    pub(crate) fn new(term: u64, lease_id: impl Into<String>, attempt_generation: u64) -> Self {
        Self {
            term,
            lease_id: lease_id.into(),
            attempt_generation,
        }
    }
}

/// What the control identity received for one stop request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StopRequestOutcome {
    Accepted {
        operation_id: String,
    },
    PermissionDenied {
        detail: String,
    },
    RateLimited {
        detail: String,
    },
    ServerError {
        status: u16,
        detail: String,
    },
    /// The request may or may not have been accepted. Never success.
    Timeout,
    TransportError {
        detail: String,
    },
}

/// The state of a named zone operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OperationObservation {
    Pending,
    Running,
    Done,
    /// Not visible (yet). Eventual consistency is not proof.
    NotFound,
    Unknown {
        detail: String,
    },
}

/// The state of the target instance as reported by a fresh describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstanceObservation {
    Running,
    Stopping,
    Terminated,
    Other(String),
    NotFound,
    Unknown {
        detail: String,
    },
    /// The describe answered for a different numeric id (name reuse).
    IdentityMismatch {
        actual_instance_id: String,
    },
}

/// A control-plane driver. Production wiring would implement this with the
/// GCE API; tests implement it with a scripted sequence so every branch is
/// deterministic and no API call is made.
pub(crate) trait GceControl {
    fn stop(&mut self, target: &FenceTarget) -> StopRequestOutcome;
    fn operation(&mut self, operation_id: &str) -> OperationObservation;
    fn instance(&mut self, target: &FenceTarget) -> InstanceObservation;
}

/// Policy. Conservative by construction: the permissive branch exists only to
/// make the trade-off explicit and testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FencePolicy {
    /// Maximum stop requests (and bounded re-observations) per attempt.
    pub(crate) max_actions: u32,
    /// `false` (default/production): an operation that never correlates to
    /// `DONE` blocks, even if the instance reads `TERMINATED`. `true` accepts
    /// a post-request terminal instance observation as the only evidence; it
    /// must never be enabled without an explicit Owner decision.
    pub(crate) allow_instance_terminal_only: bool,
}

impl Default for FencePolicy {
    fn default() -> Self {
        Self {
            max_actions: 1,
            allow_instance_terminal_only: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FenceBlockReason {
    PermissionDenied { detail: String },
    RateLimited { detail: String },
    ServerError { status: u16, detail: String },
    ApiTimeout,
    TransportError { detail: String },
    OperationUnknown { detail: String },
    OperationNotFound,
    OperationFailed { detail: String },
    TargetIdentityMismatch { expected: String, actual: String },
    TargetNotFound,
    InstanceNotTerminated { observed: String },
    InstanceStateUnknown { detail: String },
    AttemptsExhausted,
}

impl fmt::Display for FenceBlockReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied { detail } => write!(formatter, "permission denied: {detail}"),
            Self::RateLimited { detail } => write!(formatter, "rate limited: {detail}"),
            Self::ServerError { status, detail } => {
                write!(formatter, "server error {status}: {detail}")
            }
            Self::ApiTimeout => write!(formatter, "the stop request timed out (outcome unknown)"),
            Self::TransportError { detail } => write!(formatter, "transport error: {detail}"),
            Self::OperationUnknown { detail } => {
                write!(formatter, "the zone operation is UNKNOWN: {detail}")
            }
            Self::OperationNotFound => write!(formatter, "the zone operation is not visible"),
            Self::OperationFailed { detail } => {
                write!(formatter, "the zone operation failed: {detail}")
            }
            Self::TargetIdentityMismatch { expected, actual } => write!(
                formatter,
                "instance identity mismatch: expected {expected}, observed {actual}"
            ),
            Self::TargetNotFound => write!(formatter, "the target instance does not exist"),
            Self::InstanceNotTerminated { observed } => {
                write!(
                    formatter,
                    "the target is not terminated (observed {observed})"
                )
            }
            Self::InstanceStateUnknown { detail } => {
                write!(formatter, "the instance state is unknown: {detail}")
            }
            Self::AttemptsExhausted => write!(formatter, "the bounded fence actions are exhausted"),
        }
    }
}

/// Which evidence the proof rests on. `OperationAndInstance` is the only class
/// the default policy produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FenceEvidenceKind {
    OperationAndInstance,
    InstanceTerminalOnly,
}

/// Fencing proof for exactly one binding and one target identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FenceProof {
    target: FenceTarget,
    binding: FenceBinding,
    operation_id: Option<String>,
    evidence: FenceEvidenceKind,
}

impl FenceProof {
    pub(crate) fn target(&self) -> &FenceTarget {
        &self.target
    }
    pub(crate) fn binding(&self) -> &FenceBinding {
        &self.binding
    }
    pub(crate) fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_deref()
    }
    pub(crate) fn evidence(&self) -> FenceEvidenceKind {
        self.evidence
    }

    /// A proof is usable by a promotion only for the same target identity and
    /// the same binding. This is the fencing-token check: a proof from an
    /// earlier attempt can never clear a later one.
    pub(crate) fn usable_for(&self, target: &FenceTarget, binding: &FenceBinding) -> bool {
        self.target.same_identity(target) && &self.binding == binding
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FenceVerdict {
    Fenced(FenceProof),
    Blocked(FenceBlockReason),
}

/// One bounded fencing attempt. Constructing it performs no I/O; `run` drives
/// the supplied driver synchronously (the production wiring would do the same
/// with an absolute deadline per step).
#[derive(Debug)]
pub(crate) struct FenceAttempt {
    target: FenceTarget,
    binding: FenceBinding,
    policy: FencePolicy,
}

impl FenceAttempt {
    pub(crate) fn new(target: FenceTarget, binding: FenceBinding, policy: FencePolicy) -> Self {
        Self {
            target,
            binding,
            policy,
        }
    }

    pub(crate) fn run(&self, driver: &mut impl GceControl) -> FenceVerdict {
        let mut actions = 0u32;
        let mut last_retryable: Option<FenceBlockReason> = None;
        while actions < self.policy.max_actions.max(1) {
            actions += 1;
            match driver.stop(&self.target) {
                StopRequestOutcome::Accepted { operation_id } => {
                    // The request is not proof. Correlate the named operation
                    // and then require a fresh terminal instance observation.
                    match self.await_operation(driver, &operation_id) {
                        Ok(()) => return self.confirm_instance(driver, Some(operation_id)),
                        Err(reason @ FenceBlockReason::RateLimited { .. })
                        | Err(reason @ FenceBlockReason::ServerError { .. }) => {
                            last_retryable = Some(reason);
                            continue;
                        }
                        Err(reason) => return FenceVerdict::Blocked(reason),
                    }
                }
                StopRequestOutcome::RateLimited { detail } => {
                    last_retryable = Some(FenceBlockReason::RateLimited { detail });
                    continue;
                }
                StopRequestOutcome::ServerError { status, detail } => {
                    last_retryable = Some(FenceBlockReason::ServerError { status, detail });
                    continue;
                }
                // A timeout may have been accepted, so the instance is
                // re-observed; the timeout itself never counts as success.
                StopRequestOutcome::Timeout => {
                    if self.policy.allow_instance_terminal_only {
                        return self.confirm_instance(driver, None);
                    }
                    return FenceVerdict::Blocked(FenceBlockReason::ApiTimeout);
                }
                StopRequestOutcome::PermissionDenied { detail } => {
                    return FenceVerdict::Blocked(FenceBlockReason::PermissionDenied { detail });
                }
                StopRequestOutcome::TransportError { detail } => {
                    return FenceVerdict::Blocked(FenceBlockReason::TransportError { detail });
                }
            }
        }
        FenceVerdict::Blocked(last_retryable.unwrap_or(FenceBlockReason::AttemptsExhausted))
    }

    /// Bounded operation polling. `NotFound` is retried (eventual consistency)
    /// but remains "not proof": if it never becomes `DONE` the attempt blocks.
    fn await_operation(
        &self,
        driver: &mut impl GceControl,
        operation_id: &str,
    ) -> Result<(), FenceBlockReason> {
        let mut polls = 0;
        loop {
            polls += 1;
            match driver.operation(operation_id) {
                OperationObservation::Done => return Ok(()),
                OperationObservation::Pending | OperationObservation::Running => {
                    if polls >= 8 {
                        return Err(FenceBlockReason::OperationUnknown {
                            detail: "the operation did not finish within the observation bound"
                                .to_string(),
                        });
                    }
                }
                OperationObservation::NotFound => {
                    if polls >= 8 {
                        return Err(FenceBlockReason::OperationNotFound);
                    }
                }
                OperationObservation::Unknown { detail } => {
                    return Err(FenceBlockReason::OperationUnknown { detail });
                }
            }
        }
    }

    /// The only place a `Fenced` verdict is minted. The identity must match the
    /// numeric id learned before the request, and the state must be
    /// `TERMINATED`.
    fn confirm_instance(
        &self,
        driver: &mut impl GceControl,
        operation_id: Option<String>,
    ) -> FenceVerdict {
        let evidence = if operation_id.is_some() {
            FenceEvidenceKind::OperationAndInstance
        } else {
            FenceEvidenceKind::InstanceTerminalOnly
        };
        match driver.instance(&self.target) {
            InstanceObservation::Terminated => FenceVerdict::Fenced(FenceProof {
                target: self.target.clone(),
                binding: self.binding.clone(),
                operation_id,
                evidence,
            }),
            InstanceObservation::IdentityMismatch { actual_instance_id } => {
                FenceVerdict::Blocked(FenceBlockReason::TargetIdentityMismatch {
                    expected: self.target.instance_id.clone(),
                    actual: actual_instance_id,
                })
            }
            InstanceObservation::NotFound => {
                FenceVerdict::Blocked(FenceBlockReason::TargetNotFound)
            }
            InstanceObservation::Unknown { detail } => {
                FenceVerdict::Blocked(FenceBlockReason::InstanceStateUnknown { detail })
            }
            InstanceObservation::Running => {
                FenceVerdict::Blocked(FenceBlockReason::InstanceNotTerminated {
                    observed: "RUNNING".to_string(),
                })
            }
            InstanceObservation::Stopping => {
                FenceVerdict::Blocked(FenceBlockReason::InstanceNotTerminated {
                    observed: "STOPPING".to_string(),
                })
            }
            InstanceObservation::Other(state) => {
                FenceVerdict::Blocked(FenceBlockReason::InstanceNotTerminated { observed: state })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Scripted driver: each queue answers one call; an empty queue answers
    /// with a conservative "unknown".
    #[derive(Default)]
    struct FakeGce {
        stops: VecDeque<StopRequestOutcome>,
        operations: VecDeque<OperationObservation>,
        instances: VecDeque<InstanceObservation>,
        stop_calls: u32,
        operation_calls: u32,
        instance_calls: u32,
    }

    impl GceControl for FakeGce {
        fn stop(&mut self, _target: &FenceTarget) -> StopRequestOutcome {
            self.stop_calls += 1;
            self.stops
                .pop_front()
                .unwrap_or(StopRequestOutcome::Timeout)
        }
        fn operation(&mut self, _operation_id: &str) -> OperationObservation {
            self.operation_calls += 1;
            self.operations
                .pop_front()
                .unwrap_or(OperationObservation::Unknown {
                    detail: "scripted exhaustion".to_string(),
                })
        }
        fn instance(&mut self, _target: &FenceTarget) -> InstanceObservation {
            self.instance_calls += 1;
            self.instances
                .pop_front()
                .unwrap_or(InstanceObservation::Unknown {
                    detail: "scripted exhaustion".to_string(),
                })
        }
    }

    fn target() -> FenceTarget {
        FenceTarget::new("p", "z", "node-a", "111")
    }

    fn binding() -> FenceBinding {
        FenceBinding::new(7, "lease-1", 3)
    }

    fn attempt(policy: FencePolicy) -> FenceAttempt {
        FenceAttempt::new(target(), binding(), policy)
    }

    fn accepted() -> StopRequestOutcome {
        StopRequestOutcome::Accepted {
            operation_id: "op-1".to_string(),
        }
    }

    #[test]
    fn accepted_done_and_terminated_is_the_only_default_proof() {
        let mut gce = FakeGce {
            stops: VecDeque::from([accepted()]),
            operations: VecDeque::from([OperationObservation::Done]),
            instances: VecDeque::from([InstanceObservation::Terminated]),
            ..Default::default()
        };
        let FenceVerdict::Fenced(proof) = attempt(FencePolicy::default()).run(&mut gce) else {
            panic!("expected a fenced verdict");
        };
        assert_eq!(proof.evidence(), FenceEvidenceKind::OperationAndInstance);
        assert_eq!(proof.operation_id(), Some("op-1"));
        assert!(proof.usable_for(&target(), &binding()));
        assert!(!proof.usable_for(&target(), &FenceBinding::new(8, "lease-2", 4)));
        assert!(!proof.usable_for(&FenceTarget::new("p", "z", "node-a", "222"), &binding()));
        assert_eq!(gce.stop_calls, 1);
    }

    #[test]
    fn a_sent_request_alone_is_never_proof() {
        let mut gce = FakeGce {
            stops: VecDeque::from([accepted()]),
            operations: VecDeque::from([OperationObservation::Done]),
            instances: VecDeque::from([InstanceObservation::Running]),
            ..Default::default()
        };
        assert_eq!(
            attempt(FencePolicy::default()).run(&mut gce),
            FenceVerdict::Blocked(FenceBlockReason::InstanceNotTerminated {
                observed: "RUNNING".to_string()
            })
        );
    }

    #[test]
    fn a_timeout_is_never_success_and_blocks_by_default() {
        let mut gce = FakeGce {
            stops: VecDeque::from([StopRequestOutcome::Timeout]),
            instances: VecDeque::from([InstanceObservation::Terminated]),
            ..Default::default()
        };
        assert_eq!(
            attempt(FencePolicy::default()).run(&mut gce),
            FenceVerdict::Blocked(FenceBlockReason::ApiTimeout)
        );
        // The instance was not even consulted: a timeout is not re-used as
        // evidence under the default policy.
        assert_eq!(gce.instance_calls, 0);
    }

    #[test]
    fn unknown_operation_blocks_even_when_the_instance_reads_terminated() {
        let mut gce = FakeGce {
            stops: VecDeque::from([accepted()]),
            operations: VecDeque::from([OperationObservation::Unknown {
                detail: "operation UNKNOWN".to_string(),
            }]),
            instances: VecDeque::from([InstanceObservation::Terminated]),
            ..Default::default()
        };
        assert!(matches!(
            attempt(FencePolicy::default()).run(&mut gce),
            FenceVerdict::Blocked(FenceBlockReason::OperationUnknown { .. })
        ));
        assert_eq!(gce.instance_calls, 0);
    }

    #[test]
    fn a_permissive_policy_can_use_a_fresh_terminal_observation() {
        let policy = FencePolicy {
            max_actions: 1,
            allow_instance_terminal_only: true,
        };
        let mut gce = FakeGce {
            stops: VecDeque::from([StopRequestOutcome::Timeout]),
            instances: VecDeque::from([InstanceObservation::Terminated]),
            ..Default::default()
        };
        let FenceVerdict::Fenced(proof) = attempt(policy).run(&mut gce) else {
            panic!("permissive policy should accept the terminal observation");
        };
        assert_eq!(proof.evidence(), FenceEvidenceKind::InstanceTerminalOnly);
        assert_eq!(proof.operation_id(), None);
    }

    #[test]
    fn permission_denied_blocks_without_retry() {
        let mut gce = FakeGce {
            stops: VecDeque::from([
                StopRequestOutcome::PermissionDenied {
                    detail: "403".to_string(),
                },
                accepted(),
            ]),
            ..Default::default()
        };
        assert!(matches!(
            attempt(FencePolicy::default()).run(&mut gce),
            FenceVerdict::Blocked(FenceBlockReason::PermissionDenied { .. })
        ));
        assert_eq!(gce.stop_calls, 1, "403 is never retried");
    }

    #[test]
    fn retryable_api_errors_are_bounded_and_never_succeed() {
        let policy = FencePolicy {
            max_actions: 2,
            allow_instance_terminal_only: false,
        };
        let mut gce = FakeGce {
            stops: VecDeque::from([
                StopRequestOutcome::RateLimited {
                    detail: "429".to_string(),
                },
                StopRequestOutcome::ServerError {
                    status: 503,
                    detail: "backend".to_string(),
                },
            ]),
            ..Default::default()
        };
        assert!(matches!(
            attempt(policy).run(&mut gce),
            FenceVerdict::Blocked(FenceBlockReason::ServerError { status: 503, .. })
        ));
        assert_eq!(gce.stop_calls, 2);
        assert_eq!(gce.instance_calls, 0);
    }

    #[test]
    fn an_operation_for_another_instance_is_a_hard_block() {
        let mut gce = FakeGce {
            stops: VecDeque::from([accepted()]),
            operations: VecDeque::from([OperationObservation::Done]),
            instances: VecDeque::from([InstanceObservation::IdentityMismatch {
                actual_instance_id: "222".to_string(),
            }]),
            ..Default::default()
        };
        assert!(matches!(
            attempt(FencePolicy::default()).run(&mut gce),
            FenceVerdict::Blocked(FenceBlockReason::TargetIdentityMismatch { .. })
        ));
    }

    #[test]
    fn a_late_operation_becomes_visible_and_still_needs_the_instance() {
        let mut gce = FakeGce {
            stops: VecDeque::from([accepted()]),
            operations: VecDeque::from([
                OperationObservation::NotFound,
                OperationObservation::Pending,
                OperationObservation::Done,
            ]),
            instances: VecDeque::from([InstanceObservation::Terminated]),
            ..Default::default()
        };
        assert!(matches!(
            attempt(FencePolicy::default()).run(&mut gce),
            FenceVerdict::Fenced(_)
        ));
    }

    #[test]
    fn an_operation_that_never_finishes_blocks() {
        let mut gce = FakeGce {
            stops: VecDeque::from([accepted()]),
            operations: VecDeque::from(vec![OperationObservation::Running; 8]),
            instances: VecDeque::from([InstanceObservation::Terminated]),
            ..Default::default()
        };
        assert!(matches!(
            attempt(FencePolicy::default()).run(&mut gce),
            FenceVerdict::Blocked(FenceBlockReason::OperationUnknown { .. })
        ));
        assert_eq!(gce.instance_calls, 0);
    }

    #[test]
    fn a_stopping_instance_is_not_terminated_yet() {
        let mut gce = FakeGce {
            stops: VecDeque::from([accepted()]),
            operations: VecDeque::from([OperationObservation::Done]),
            instances: VecDeque::from([InstanceObservation::Stopping]),
            ..Default::default()
        };
        assert_eq!(
            attempt(FencePolicy::default()).run(&mut gce),
            FenceVerdict::Blocked(FenceBlockReason::InstanceNotTerminated {
                observed: "STOPPING".to_string()
            })
        );
    }

    #[test]
    fn a_missing_target_is_not_fenced() {
        let mut gce = FakeGce {
            stops: VecDeque::from([accepted()]),
            operations: VecDeque::from([OperationObservation::Done]),
            instances: VecDeque::from([InstanceObservation::NotFound]),
            ..Default::default()
        };
        assert_eq!(
            attempt(FencePolicy::default()).run(&mut gce),
            FenceVerdict::Blocked(FenceBlockReason::TargetNotFound)
        );
    }
}
