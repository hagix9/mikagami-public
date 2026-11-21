//! Bootstrap Admission (BA): the pure decisions (Owner decision A-1, contract
//! K-1..K-6, `MIKAGAMI_V1_BA_CONTRACT_AMENDMENT.md`).
//!
//! BA is an *order-based* admission for a cold start in which the peer is
//! healthy. It never claims the peer is fenced, and nothing here uses elapsed
//! time, a heartbeat age or a round-trip time as safety evidence:
//!
//! 1. attempt 1 anchors the Witness term `T` (`CompatibleNoHolder`) and opens
//!    a runtime-only session bound to the current peer connection;
//! 2. only *after* the anchor, a nonce-carrying probe asks the peer to
//!    re-observe itself; the peer answers from the tick that read the probe;
//! 3. attempt 2 re-reads the Witness, requires the very same term `T` and the
//!    same connection, mints a one-shot [`BootstrapClearance`], and the
//!    ordinary lease chain runs with `observed_term = T`.
//!
//! The module performs no I/O, reads no clock and spawns nothing (guard BG-3).

use crate::evidence_fusion::adapter::AuthorityViewCompatibility;
use crate::failover_policy::{LocalSafetyReadiness, LocalSafetySnapshot};
use crate::failure_assessment::PeerFailureAssessment;
use crate::protocol::{SessionId, Term};
use crate::state_machine::NodeState;
use crate::tcp_runtime::ConnectionToken;

/// The probe `reason` (defined once; guard BG-4).
pub(crate) const PROBE_REASON: &str = "mkm-bootstrap-probe/1";
/// `operation_id = "ba-" + 128 random bits as 32 lowercase hex digits`.
pub(crate) const OPERATION_ID_PREFIX: &str = "ba-";
pub(crate) const OPERATION_ID_HEX_LEN: usize = 32;

/// The peer's answer to a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeVerdict {
    /// Standby, zero resource, nothing outstanding — observed in the tick that
    /// read the probe.
    Ack,
    /// The peer is not in that state (Active, promoting, resources, O or M,
    /// not reconciled, shutting down …).
    Block,
    /// The peer could not tell (failed observation, unknown resource, unknown
    /// probe reason).
    Unknown,
}

/// Whether `value` has the exact shape of a BA operation id.
pub(crate) fn is_valid_operation_id(value: &str) -> bool {
    value.strip_prefix(OPERATION_ID_PREFIX).is_some_and(|hex| {
        hex.len() == OPERATION_ID_HEX_LEN
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// What the daemon (not the node runtime) knows at the tick that answers a
/// probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DaemonFacts {
    pub(crate) running: bool,
    pub(crate) shutdown_requested: bool,
    pub(crate) attempt_in_flight: bool,
}

/// Contract K-2: the responder's verdict. The local part is exactly the
/// existing `failover_local_safety_snapshot` result — `Safe` already means
/// reconciled, no demotion latched, ownership `ZeroResource`, no O, no M, no
/// runtime lease authority, VIP absent and service stopped — plus Standby with
/// no operation phase, a running daemon, no shutdown request and no attempt in
/// flight. `None` (no successful observation in this tick) and every unknown
/// are `Unknown`; nothing unknown is ever `Ack`.
pub(crate) fn responder_verdict(
    local: Option<LocalSafetySnapshot>,
    daemon: DaemonFacts,
) -> ProbeVerdict {
    let Some(local) = local else {
        return ProbeVerdict::Unknown;
    };
    if matches!(
        local.readiness,
        LocalSafetyReadiness::Unknown | LocalSafetyReadiness::OwnershipUncertain
    ) {
        return ProbeVerdict::Unknown;
    }
    if !daemon.running || daemon.shutdown_requested || daemon.attempt_in_flight {
        return ProbeVerdict::Block;
    }
    if local.node_state != NodeState::Standby || local.operation_phase.is_some() {
        return ProbeVerdict::Block;
    }
    if local.readiness == LocalSafetyReadiness::Safe {
        ProbeVerdict::Ack
    } else {
        ProbeVerdict::Block
    }
}

/// What a BA session and a probe are bound to: the exact peer connection, the
/// peer's process session and this process's own observer session. Any
/// reconnect, peer restart or local restart changes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BootstrapStamp {
    pub(crate) connection: ConnectionToken,
    pub(crate) peer_session: SessionId,
    pub(crate) observer_session: SessionId,
}

/// The outcome of a probe as the peer runtime reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// An authenticated response whose nonce, connection and peer session all
    /// matched the outstanding probe.
    Response {
        stamp: BootstrapStamp,
        verdict: ProbeVerdict,
    },
    /// The probe cannot be answered any more (connection lost, send failed,
    /// response did not match): the session must be dropped.
    Invalid,
}

/// The runtime-only BA session (never persisted, never `Clone`).
#[derive(Debug)]
pub(crate) struct BootstrapSession {
    anchor_term: Term,
    stamp: BootstrapStamp,
    attested: bool,
}

impl BootstrapSession {
    pub(crate) const fn anchor_term(&self) -> Term {
        self.anchor_term
    }

    pub(crate) fn stamp(&self) -> &BootstrapStamp {
        &self.stamp
    }

    pub(crate) const fn is_attested(&self) -> bool {
        self.attested
    }
}

/// Apply a probe outcome. Only an `Ack` that matches the session's stamp
/// attests it; every other outcome (Block, Unknown, a mismatch, a lost
/// connection) drops the session (BAP-5, fail-closed).
pub(crate) fn apply_probe_outcome(
    session: Option<BootstrapSession>,
    outcome: &ProbeOutcome,
) -> Option<BootstrapSession> {
    let mut session = session?;
    match outcome {
        ProbeOutcome::Response {
            stamp,
            verdict: ProbeVerdict::Ack,
        } if *stamp == session.stamp => {
            session.attested = true;
            Some(session)
        }
        _ => None,
    }
}

/// A probe that has not been answered after this long ends the session.
pub(crate) const PROBE_WAIT_LIMIT_MS: u64 = 5_000;
/// A session never lives longer than this.
pub(crate) const SESSION_LIMIT_MS: u64 = 60_000;

/// What one hygiene poll knows (plain data; time is injected in milliseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HygieneInputs {
    pub(crate) now_ms: u64,
    pub(crate) session_open: bool,
    pub(crate) session_attested: bool,
    /// The local node is a Standby with readiness `Safe`. `None`: not known
    /// this poll (nothing is concluded from it).
    pub(crate) local_safe: Option<bool>,
    /// The peer assessment is `Healthy`. `None`: not known this poll.
    pub(crate) peer_healthy: Option<bool>,
}

/// BAP-7 hygiene: bound how long a session may wait or live, and drop one
/// whose preconditions are gone. It belongs to the session, not to the
/// automatic trigger, so it runs whether or not `[failover] auto` is on.
///
/// These limits are cleanliness only. [`decide`] never reads them: a session
/// that outlived a limit by a poll is still fully re-checked (fresh term,
/// Safe, Healthy, token, CAS, K) at attempt 2, and an expired one is simply
/// anchored again by a new attempt 1.
#[derive(Debug, Default)]
pub(crate) struct SessionHygiene {
    seen_ms: Option<u64>,
    unattested_since_ms: Option<u64>,
}

impl SessionHygiene {
    /// `Some(reason)`: the caller drops the session now.
    pub(crate) fn poll(&mut self, inputs: &HygieneInputs) -> Option<&'static str> {
        if !inputs.session_open {
            *self = Self::default();
            return None;
        }
        let reason = self.expiry(inputs).or(if inputs.local_safe == Some(false) {
            Some("the local node is no longer a safe standby")
        } else if inputs.peer_healthy == Some(false) {
            Some("the peer is no longer healthy")
        } else {
            None
        });
        if reason.is_some() {
            *self = Self::default();
        }
        reason
    }

    fn expiry(&mut self, inputs: &HygieneInputs) -> Option<&'static str> {
        let seen = *self.seen_ms.get_or_insert(inputs.now_ms);
        if inputs.session_attested {
            self.unattested_since_ms = None;
        } else {
            let since = *self.unattested_since_ms.get_or_insert(inputs.now_ms);
            if inputs.now_ms.saturating_sub(since) >= PROBE_WAIT_LIMIT_MS {
                return Some("no probe response within 5 s");
            }
        }
        if inputs.now_ms.saturating_sub(seen) >= SESSION_LIMIT_MS {
            return Some("session older than 60 s");
        }
        None
    }
}

/// The one-shot admission token of attempt 2: not `Clone`, not serializable,
/// minted at exactly one site ([`decide`]) and consumed by the BA ARM+promote
/// handoff (guard BG-2). It is evidence of an *order*, not authority and not
/// a fencing clearance.
#[derive(Debug)]
pub(crate) struct BootstrapClearance {
    anchor_term: Term,
    stamp: BootstrapStamp,
}

impl BootstrapClearance {
    pub(crate) const fn anchor_term(&self) -> Term {
        self.anchor_term
    }

    pub(crate) fn stamp(&self) -> &BootstrapStamp {
        &self.stamp
    }
}

/// Why an attempt did not proceed (operator-facing text; never evidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapBlock {
    NotConservative,
    ShutdownRequested,
    PeerNotHealthy,
    LocalNotSafe,
    WitnessNotFree,
    NoPeerConnection,
    ProbePending,
    TermMoved,
    ConnectionChanged,
}

impl BootstrapBlock {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::NotConservative => "bootstrap admission requires conservative mode",
            Self::ShutdownRequested => "bootstrap admission: shutdown requested",
            Self::PeerNotHealthy => "bootstrap admission: peer is not healthy",
            Self::LocalNotSafe => "bootstrap admission: local state is not safe",
            Self::WitnessNotFree => "bootstrap admission: the Witness has a lease holder",
            Self::NoPeerConnection => "bootstrap admission: no established peer connection",
            Self::ProbePending => "bootstrap admission: waiting for the peer's probe response",
            Self::TermMoved => "bootstrap admission: the Witness term moved since the anchor",
            Self::ConnectionChanged => "bootstrap admission: the peer connection changed",
        }
    }
}

/// Everything one attempt knows when it decides (all plain data).
pub(crate) struct AdmissionInputs<'a> {
    /// The runtime runs the Conservative authority mode (K-5).
    pub(crate) conservative: bool,
    pub(crate) shutdown_requested: bool,
    pub(crate) peer: PeerFailureAssessment,
    pub(crate) local_readiness: LocalSafetyReadiness,
    /// This attempt's own GET_TERM: holder classification and term.
    pub(crate) witness: AuthorityViewCompatibility,
    pub(crate) witness_term: Term,
    /// The established peer connection right now, if any.
    pub(crate) current_stamp: Option<&'a BootstrapStamp>,
}

/// One attempt's admission step.
#[derive(Debug)]
pub(crate) enum Admission {
    /// Attempt 1: the anchor was taken. The caller keeps the session, asks the
    /// runtime to send the probe, and ends the attempt without any mutation.
    Anchored(BootstrapSession),
    /// Attempt 2: the probe was attested and nothing moved. The lease chain
    /// may run with `observed_term = clearance.anchor_term()`.
    Cleared(BootstrapClearance),
    /// No admission. `keep` is the session to retain (only while a probe
    /// response is still outstanding), `None` otherwise (the session, if any,
    /// is consumed or dropped).
    Blocked {
        block: BootstrapBlock,
        keep: Option<BootstrapSession>,
    },
}

/// The admission decision of one attempt. `session` is the session in the
/// daemon (if any); it is always consumed here and handed back only through
/// `Admission`. No time, heartbeat age or RTT is read.
pub(crate) fn decide(inputs: &AdmissionInputs<'_>, session: Option<BootstrapSession>) -> Admission {
    let drop_with = |block| Admission::Blocked { block, keep: None };
    if !inputs.conservative {
        return drop_with(BootstrapBlock::NotConservative);
    }
    if inputs.shutdown_requested {
        return drop_with(BootstrapBlock::ShutdownRequested);
    }
    if inputs.peer != PeerFailureAssessment::Healthy {
        return drop_with(BootstrapBlock::PeerNotHealthy);
    }
    if inputs.local_readiness != LocalSafetyReadiness::Safe {
        return drop_with(BootstrapBlock::LocalNotSafe);
    }
    match session {
        None => {
            // Attempt 1: anchor.
            if inputs.witness != AuthorityViewCompatibility::CompatibleNoHolder {
                return drop_with(BootstrapBlock::WitnessNotFree);
            }
            let Some(stamp) = inputs.current_stamp else {
                return drop_with(BootstrapBlock::NoPeerConnection);
            };
            Admission::Anchored(BootstrapSession {
                anchor_term: inputs.witness_term,
                stamp: stamp.clone(),
                attested: false,
            })
        }
        Some(session) if !session.attested => {
            // The probe response has not arrived (or was never accepted).
            if inputs.current_stamp != Some(&session.stamp) {
                return drop_with(BootstrapBlock::ConnectionChanged);
            }
            Admission::Blocked {
                block: BootstrapBlock::ProbePending,
                keep: Some(session),
            }
        }
        Some(session) => {
            // Attempt 2: the session is consumed whatever happens below.
            if inputs.witness != AuthorityViewCompatibility::CompatibleNoHolder
                || inputs.witness_term != session.anchor_term
            {
                return drop_with(BootstrapBlock::TermMoved);
            }
            if inputs.current_stamp != Some(&session.stamp) {
                return drop_with(BootstrapBlock::ConnectionChanged);
            }
            Admission::Cleared(BootstrapClearance::mint(session))
        }
    }
}

impl BootstrapClearance {
    /// The only construction site. Consumes the attested session.
    fn mint(session: BootstrapSession) -> Self {
        Self {
            anchor_term: session.anchor_term,
            stamp: session.stamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::{OperationPhase, PromotionPhase};

    fn local(
        node_state: NodeState,
        operation_phase: Option<OperationPhase>,
        readiness: LocalSafetyReadiness,
    ) -> Option<LocalSafetySnapshot> {
        Some(LocalSafetySnapshot {
            node_state,
            operation_phase,
            readiness,
        })
    }

    const RUNNING: DaemonFacts = DaemonFacts {
        running: true,
        shutdown_requested: false,
        attempt_in_flight: false,
    };

    // ---- BA-T1: the responder verdict table (contract K-2) ---------------

    #[test]
    fn responder_acks_only_a_safe_standby_in_a_running_daemon() {
        assert_eq!(
            responder_verdict(
                local(NodeState::Standby, None, LocalSafetyReadiness::Safe),
                RUNNING
            ),
            ProbeVerdict::Ack
        );
    }

    #[test]
    fn responder_never_acks_when_any_single_condition_is_flipped() {
        use LocalSafetyReadiness as R;
        let promotion = Some(OperationPhase::Promotion(PromotionPhase::AcquireVip));
        let cases: [(&str, Option<LocalSafetySnapshot>, DaemonFacts, ProbeVerdict); 16] = [
            ("no observation", None, RUNNING, ProbeVerdict::Unknown),
            (
                "readiness unknown",
                local(NodeState::Standby, None, R::Unknown),
                RUNNING,
                ProbeVerdict::Unknown,
            ),
            (
                "ownership uncertain (Unknown/ResourceOwning)",
                local(NodeState::Standby, None, R::OwnershipUncertain),
                RUNNING,
                ProbeVerdict::Unknown,
            ),
            (
                "resource state unresolved (O, M or VIP/service)",
                local(NodeState::Standby, None, R::ResourceStateUnresolved),
                RUNNING,
                ProbeVerdict::Block,
            ),
            (
                "runtime lease authority present",
                local(NodeState::Standby, None, R::AuthorityPresent),
                RUNNING,
                ProbeVerdict::Block,
            ),
            (
                "recovery not reconciled",
                local(NodeState::Standby, None, R::RecoveryBlocked),
                RUNNING,
                ProbeVerdict::Block,
            ),
            (
                "demotion required",
                local(NodeState::Standby, None, R::DemotionRequired),
                RUNNING,
                ProbeVerdict::Block,
            ),
            (
                "shutdown in progress (runtime)",
                local(NodeState::Standby, None, R::ShutdownInProgress),
                RUNNING,
                ProbeVerdict::Block,
            ),
            (
                "Active",
                local(NodeState::Active, None, R::Safe),
                RUNNING,
                ProbeVerdict::Block,
            ),
            (
                "Candidate",
                local(NodeState::Candidate, None, R::Safe),
                RUNNING,
                ProbeVerdict::Block,
            ),
            (
                "Failed",
                local(NodeState::Failed, None, R::Safe),
                RUNNING,
                ProbeVerdict::Block,
            ),
            (
                "operation phase",
                local(NodeState::Standby, promotion, R::Safe),
                RUNNING,
                ProbeVerdict::Block,
            ),
            (
                "daemon not running",
                local(NodeState::Standby, None, R::Safe),
                DaemonFacts {
                    running: false,
                    ..RUNNING
                },
                ProbeVerdict::Block,
            ),
            (
                "shutdown requested",
                local(NodeState::Standby, None, R::Safe),
                DaemonFacts {
                    shutdown_requested: true,
                    ..RUNNING
                },
                ProbeVerdict::Block,
            ),
            (
                "attempt in flight",
                local(NodeState::Standby, None, R::Safe),
                DaemonFacts {
                    attempt_in_flight: true,
                    ..RUNNING
                },
                ProbeVerdict::Block,
            ),
            (
                "recovery pending state",
                local(NodeState::RecoveryPending, None, R::Safe),
                RUNNING,
                ProbeVerdict::Block,
            ),
        ];
        for (name, snapshot, daemon, expected) in cases {
            assert_eq!(responder_verdict(snapshot, daemon), expected, "{name}");
            assert_ne!(
                responder_verdict(snapshot, daemon),
                ProbeVerdict::Ack,
                "{name}"
            );
        }
    }

    #[test]
    fn operation_id_has_the_exact_shape() {
        let good = format!("ba-{}", "0123456789abcdef".repeat(2));
        assert!(is_valid_operation_id(&good));
        for bad in [
            "".to_string(),
            "ba-".to_string(),
            format!("BA-{}", "0".repeat(32)),
            format!("ba-{}", "0".repeat(31)),
            format!("ba-{}", "0".repeat(33)),
            format!("ba-{}", "G".repeat(32)),
            format!("ba-{}", "A".repeat(32)),
            format!("xx-{}", "0".repeat(32)),
        ] {
            assert!(!is_valid_operation_id(&bad), "{bad}");
        }
    }

    // ---- admission decisions --------------------------------------------------

    fn stamp(connection: u64, peer: &str) -> BootstrapStamp {
        BootstrapStamp {
            connection: crate::tcp_runtime::test_connection_token(connection),
            peer_session: SessionId::new(peer),
            observer_session: SessionId::new("observer"),
        }
    }

    fn inputs<'a>(current: Option<&'a BootstrapStamp>) -> AdmissionInputs<'a> {
        AdmissionInputs {
            conservative: true,
            shutdown_requested: false,
            peer: PeerFailureAssessment::Healthy,
            local_readiness: LocalSafetyReadiness::Safe,
            witness: AuthorityViewCompatibility::CompatibleNoHolder,
            witness_term: Term(5),
            current_stamp: current,
        }
    }

    fn anchored(stamp: &BootstrapStamp) -> BootstrapSession {
        match decide(&inputs(Some(stamp)), None) {
            Admission::Anchored(session) => session,
            other => panic!("expected an anchor, got {other:?}"),
        }
    }

    fn attested(stamp: &BootstrapStamp) -> BootstrapSession {
        apply_probe_outcome(
            Some(anchored(stamp)),
            &ProbeOutcome::Response {
                stamp: stamp.clone(),
                verdict: ProbeVerdict::Ack,
            },
        )
        .expect("attested")
    }

    #[test]
    fn attempt_one_anchors_the_term_and_the_connection_and_mutates_nothing() {
        let stamp = stamp(1, "peer-1");
        let session = anchored(&stamp);
        assert_eq!(session.anchor_term(), Term(5));
        assert_eq!(session.stamp(), &stamp);
        assert!(!session.is_attested());
    }

    #[test]
    fn attempt_one_needs_every_precondition() {
        let stamp = stamp(1, "peer-1");
        let blocked = |mutate: fn(&mut AdmissionInputs<'_>), expected: BootstrapBlock| {
            let mut inputs = inputs(Some(&stamp));
            mutate(&mut inputs);
            match decide(&inputs, None) {
                Admission::Blocked { block, keep: None } => assert_eq!(block, expected),
                other => panic!("expected {expected:?}, got {other:?}"),
            }
        };
        blocked(|i| i.conservative = false, BootstrapBlock::NotConservative);
        blocked(
            |i| i.shutdown_requested = true,
            BootstrapBlock::ShutdownRequested,
        );
        for peer in [
            PeerFailureAssessment::Unobserved,
            PeerFailureAssessment::Suspect,
            PeerFailureAssessment::CommunicationLost,
        ] {
            let mut input = inputs(Some(&stamp));
            input.peer = peer;
            assert!(matches!(
                decide(&input, None),
                Admission::Blocked {
                    block: BootstrapBlock::PeerNotHealthy,
                    ..
                }
            ));
        }
        for readiness in [
            LocalSafetyReadiness::ShutdownInProgress,
            LocalSafetyReadiness::RecoveryBlocked,
            LocalSafetyReadiness::DemotionRequired,
            LocalSafetyReadiness::OwnershipUncertain,
            LocalSafetyReadiness::ResourceStateUnresolved,
            LocalSafetyReadiness::AuthorityPresent,
            LocalSafetyReadiness::Unknown,
        ] {
            let mut input = inputs(Some(&stamp));
            input.local_readiness = readiness;
            assert!(matches!(
                decide(&input, None),
                Admission::Blocked {
                    block: BootstrapBlock::LocalNotSafe,
                    ..
                }
            ));
        }
        for witness in [
            AuthorityViewCompatibility::CompatibleSelfUnexpired,
            AuthorityViewCompatibility::ConflictingHolder,
            AuthorityViewCompatibility::ExpiredButUnprocessed,
            AuthorityViewCompatibility::InconsistentAuthorityView,
        ] {
            let mut input = inputs(Some(&stamp));
            input.witness = witness;
            assert!(matches!(
                decide(&input, None),
                Admission::Blocked {
                    block: BootstrapBlock::WitnessNotFree,
                    ..
                }
            ));
        }
        assert!(matches!(
            decide(&inputs(None), None),
            Admission::Blocked {
                block: BootstrapBlock::NoPeerConnection,
                ..
            }
        ));
    }

    #[test]
    fn only_a_matching_ack_attests_every_other_outcome_drops_the_session() {
        let stamp = stamp(1, "peer-1");
        let ack = |stamp: &BootstrapStamp| ProbeOutcome::Response {
            stamp: stamp.clone(),
            verdict: ProbeVerdict::Ack,
        };
        assert!(
            apply_probe_outcome(Some(anchored(&stamp)), &ack(&stamp))
                .expect("attested")
                .is_attested()
        );
        // Block / Unknown / Invalid
        for verdict in [ProbeVerdict::Block, ProbeVerdict::Unknown] {
            let outcome = ProbeOutcome::Response {
                stamp: stamp.clone(),
                verdict,
            };
            assert!(apply_probe_outcome(Some(anchored(&stamp)), &outcome).is_none());
        }
        assert!(apply_probe_outcome(Some(anchored(&stamp)), &ProbeOutcome::Invalid).is_none());
        // an ACK from another connection / another peer session
        for other in [stamp_other_connection(&stamp), stamp_other_peer(&stamp)] {
            assert!(apply_probe_outcome(Some(anchored(&stamp)), &ack(&other)).is_none());
        }
        // no session: nothing to attest
        assert!(apply_probe_outcome(None, &ack(&stamp)).is_none());
    }

    fn stamp_other_connection(base: &BootstrapStamp) -> BootstrapStamp {
        BootstrapStamp {
            connection: crate::tcp_runtime::test_connection_token(99),
            ..base.clone()
        }
    }

    fn stamp_other_peer(base: &BootstrapStamp) -> BootstrapStamp {
        BootstrapStamp {
            peer_session: SessionId::new("peer-restarted"),
            ..base.clone()
        }
    }

    #[test]
    fn an_unattested_session_waits_and_is_kept_only_while_the_connection_is_the_same() {
        let stamp = stamp(1, "peer-1");
        match decide(&inputs(Some(&stamp)), Some(anchored(&stamp))) {
            Admission::Blocked {
                block: BootstrapBlock::ProbePending,
                keep: Some(session),
            } => assert!(!session.is_attested()),
            other => panic!("expected to wait, got {other:?}"),
        }
        let other = stamp_other_connection(&stamp);
        assert!(matches!(
            decide(&inputs(Some(&other)), Some(anchored(&stamp))),
            Admission::Blocked {
                block: BootstrapBlock::ConnectionChanged,
                keep: None
            }
        ));
        assert!(matches!(
            decide(&inputs(None), Some(anchored(&stamp))),
            Admission::Blocked {
                block: BootstrapBlock::ConnectionChanged,
                keep: None
            }
        ));
    }

    #[test]
    fn attempt_two_mints_one_clearance_bound_to_the_anchor_and_the_connection() {
        let stamp = stamp(1, "peer-1");
        match decide(&inputs(Some(&stamp)), Some(attested(&stamp))) {
            Admission::Cleared(clearance) => {
                assert_eq!(clearance.anchor_term(), Term(5));
                assert_eq!(clearance.stamp(), &stamp);
            }
            other => panic!("expected a clearance, got {other:?}"),
        }
    }

    /// Anchor equality: a Witness term different from the anchor — larger
    /// (a grant happened) or smaller (rollback) — never clears.
    #[test]
    fn attempt_two_refuses_any_term_other_than_the_anchor() {
        let stamp = stamp(1, "peer-1");
        for term in [Term(4), Term(6), Term(0), Term(u64::MAX)] {
            let mut input = inputs(Some(&stamp));
            input.witness_term = term;
            assert!(
                matches!(
                    decide(&input, Some(attested(&stamp))),
                    Admission::Blocked {
                        block: BootstrapBlock::TermMoved,
                        keep: None
                    }
                ),
                "{term:?}"
            );
        }
        for witness in [
            AuthorityViewCompatibility::CompatibleSelfUnexpired,
            AuthorityViewCompatibility::ConflictingHolder,
            AuthorityViewCompatibility::ExpiredButUnprocessed,
        ] {
            let mut input = inputs(Some(&stamp));
            input.witness = witness;
            assert!(matches!(
                decide(&input, Some(attested(&stamp))),
                Admission::Blocked {
                    block: BootstrapBlock::TermMoved,
                    keep: None
                }
            ));
        }
    }

    #[test]
    fn attempt_two_refuses_a_changed_connection_peer_session_or_state() {
        let stamp = stamp(1, "peer-1");
        for current in [stamp_other_connection(&stamp), stamp_other_peer(&stamp)] {
            assert!(matches!(
                decide(&inputs(Some(&current)), Some(attested(&stamp))),
                Admission::Blocked {
                    block: BootstrapBlock::ConnectionChanged,
                    keep: None
                }
            ));
        }
        let mut input = inputs(Some(&stamp));
        input.peer = PeerFailureAssessment::Suspect;
        assert!(matches!(
            decide(&input, Some(attested(&stamp))),
            Admission::Blocked {
                block: BootstrapBlock::PeerNotHealthy,
                keep: None
            }
        ));
        let mut input = inputs(Some(&stamp));
        input.local_readiness = LocalSafetyReadiness::ResourceStateUnresolved;
        assert!(matches!(
            decide(&input, Some(attested(&stamp))),
            Admission::Blocked {
                block: BootstrapBlock::LocalNotSafe,
                keep: None
            }
        ));
        let mut input = inputs(Some(&stamp));
        input.conservative = false;
        assert!(matches!(
            decide(&input, Some(attested(&stamp))),
            Admission::Blocked {
                block: BootstrapBlock::NotConservative,
                keep: None
            }
        ));
    }

    /// The session is consumed by attempt 2 whatever happens: a second
    /// decision starts again from the anchor step.
    #[test]
    fn a_clearance_cannot_be_reused_by_a_second_attempt() {
        let stamp = stamp(1, "peer-1");
        let Admission::Cleared(_clearance) = decide(&inputs(Some(&stamp)), Some(attested(&stamp)))
        else {
            panic!("expected a clearance");
        };
        // The daemon holds no session any more: the next decision anchors.
        assert!(matches!(
            decide(&inputs(Some(&stamp)), None),
            Admission::Anchored(_)
        ));
    }

    /// Two sides racing to the same anchor both get a clearance candidate; the
    /// Witness CAS (not this module) lets exactly one LeaseRequest win. What
    /// this module guarantees is that the two clearances carry the same term.
    #[test]
    fn both_nodes_anchor_the_same_term() {
        let a = stamp(1, "b-session");
        let b = stamp(1, "a-session");
        let session_a = anchored(&a);
        let session_b = anchored(&b);
        assert_eq!(session_a.anchor_term(), session_b.anchor_term());
    }

    // ---- BG-3 / BG-5 in miniature ------------------------------------------------

    #[test]
    fn this_module_reads_no_clock_and_no_heartbeat_age() {
        let source = include_str!("bootstrap_admission.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production part");
        for forbidden in [
            "Instant",
            "SystemTime",
            "Duration",
            "std::process",
            "std::thread",
            "std::fs",
            "std::net",
            "last_received",
            "elapsed",
            "rtt",
        ] {
            for line in production.lines() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                assert!(
                    !code.contains(forbidden),
                    "bootstrap_admission.rs uses `{forbidden}`: {line}"
                );
            }
        }
    }

    // ---- session hygiene (BAP-7, independent of the automatic trigger) ----

    fn hygiene(now_ms: u64, attested: bool) -> HygieneInputs {
        HygieneInputs {
            now_ms,
            session_open: true,
            session_attested: attested,
            local_safe: Some(true),
            peer_healthy: Some(true),
        }
    }

    #[test]
    fn hygiene_limits_probe_wait_and_session_age() {
        let mut machine = SessionHygiene::default();
        assert_eq!(machine.poll(&hygiene(0, false)), None);
        assert_eq!(machine.poll(&hygiene(4_999, false)), None);
        assert_eq!(
            machine.poll(&hygiene(5_000, false)),
            Some("no probe response within 5 s")
        );
        // An attested session may live until 60 s.
        let mut machine = SessionHygiene::default();
        assert_eq!(machine.poll(&hygiene(0, true)), None);
        assert_eq!(machine.poll(&hygiene(59_999, true)), None);
        assert_eq!(
            machine.poll(&hygiene(60_000, true)),
            Some("session older than 60 s")
        );
        // The probe wait is counted from the unattested stretch only.
        let mut machine = SessionHygiene::default();
        assert_eq!(machine.poll(&hygiene(0, false)), None);
        assert_eq!(machine.poll(&hygiene(3_000, true)), None);
        assert_eq!(machine.poll(&hygiene(30_000, true)), None);
    }

    #[test]
    fn hygiene_forgets_a_closed_session_and_starts_afresh() {
        let mut machine = SessionHygiene::default();
        assert_eq!(machine.poll(&hygiene(0, true)), None);
        let closed = HygieneInputs {
            session_open: false,
            ..hygiene(50_000, true)
        };
        assert_eq!(machine.poll(&closed), None);
        // A new session is timed from its own first sighting, not the old one.
        assert_eq!(machine.poll(&hygiene(70_000, true)), None);
        assert_eq!(machine.poll(&hygiene(129_999, true)), None);
        assert_eq!(
            machine.poll(&hygiene(130_000, true)),
            Some("session older than 60 s")
        );
        // After a drop the same machine times the next session afresh too.
        assert_eq!(machine.poll(&hygiene(131_000, false)), None);
    }

    #[test]
    fn hygiene_drops_a_session_when_safe_or_healthy_is_lost() {
        for (inputs, reason) in [
            (
                HygieneInputs {
                    local_safe: Some(false),
                    ..hygiene(1, true)
                },
                "the local node is no longer a safe standby",
            ),
            (
                HygieneInputs {
                    peer_healthy: Some(false),
                    ..hygiene(1, true)
                },
                "the peer is no longer healthy",
            ),
        ] {
            let mut machine = SessionHygiene::default();
            assert_eq!(machine.poll(&inputs), Some(reason));
        }
        // Not knowing is not a loss.
        let mut machine = SessionHygiene::default();
        let unknown = HygieneInputs {
            local_safe: None,
            peer_healthy: None,
            ..hygiene(1, true)
        };
        assert_eq!(machine.poll(&unknown), None);
    }
}
