//! Stage 14 fencing incident data and state model (Design Revision 5 §12,
//! §13, §15, §19.1, §26).
//!
//! Pure data and pure functions only. These types describe what the Node v3
//! document records about one fencing incident and which §13.2 transitions,
//! §26 continuity checks, and `FencingClearance` mints are legal. They perform
//! no I/O, own no runtime state, and carry no authority: a `FencingIncident`
//! (in any state, including `Confirmed`) never grants Witness authority,
//! local-loss evidence, ARM eligibility, or promotion, and a
//! `FencingClearance` only lets an already-authorized attempt continue past
//! the fencing gate. The durable writes live in `NodeMutationStore`; the gate,
//! fencing-step, ingestion, and ARM call sites belong to later dependency
//! units (§41 steps 5-8), so several entry points have no production caller
//! yet.

use crate::failure_assessment::LocalLossEvidence;
use crate::node_mutation::DurableIncident;
use crate::protocol::{NodeId, SessionId, Term};
use serde::{Deserialize, Serialize};

/// Durable incident identity half: a canonical lowercase UUIDv4 (§12.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentId(String);

/// Operator attestation identity: a canonical lowercase UUIDv4 (§18.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationId(String);

macro_rules! uuid_id {
    ($name:ident) => {
        impl $name {
            #[cfg(test)]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

uuid_id!(IncidentId);
uuid_id!(AttestationId);

impl IncidentId {
    /// v0.7 G-2: the step label of a route-handoff step (the clearance's incident, or the
    /// synthetic observation-only id). Only a canonical lowercase UUIDv4 is accepted. A label,
    /// never evidence: it cannot build a durable incident or a clearance.
    pub(crate) fn route_step_label(value: &str) -> Option<Self> {
        crate::node_mutation::is_canonical_uuid_v4(value).then(|| Self(value.to_string()))
    }
}

impl IncidentId {
    /// A store-generated incident identity (§12.2: CSPRNG UUIDv4). The Node
    /// store validates the canonical form before any write.
    pub(crate) fn generated(value: String) -> Self {
        Self(value)
    }
}

impl AttestationId {
    /// A fresh CLI-generated attestation identity (§18.4: UUIDv4). The daemon
    /// validates the canonical form at ingestion and the Node store again
    /// before any write.
    pub(crate) fn generated(value: String) -> Self {
        Self(value)
    }
}

/// One open fencing incident (§12.2). At most one exists per Node document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencingIncident {
    pub incident_seq: u64,
    pub incident_id: IncidentId,
    pub target_node_id: NodeId,
    pub anchor_term: Term,
    pub observer_session_id: SessionId,
    pub observer_loss_generation: u64,
    pub attempt_token_high_water: u64,
    pub state: FencingState,
}

/// Exactly the five stored fencing states (§13.1). Absence of an incident is
/// not a state; there is no stored `NotRequired`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum FencingState {
    Unknown(UnknownReason),
    Requested {
        attempt_token: u64,
    },
    Verifying {
        attempt_token: u64,
        action_outcome: ActionOutcome,
    },
    Confirmed(ConfirmedBy),
    Failed {
        attempt_token: u64,
    },
}

/// `unknown { reason: "not-attempted" | "verify-inconclusive", kind? }`.
/// The kind exists only for `verify-inconclusive`, so it is required there
/// and unrepresentable for `not-attempted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case", deny_unknown_fields)]
pub enum UnknownReason {
    NotAttempted {},
    VerifyInconclusive { kind: InconclusiveKind },
}

/// The inconclusive verification kinds of §13.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InconclusiveKind {
    Timeout,
    NonzeroExit,
    Signal,
    SpawnFailed,
    OutputOverflow,
    MalformedOutput,
    Integrity,
}

/// Fence-action provenance (§13.1). Never evidence of isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionOutcome {
    ReportedSuccess,
    ReportedFailure,
    TimedOut,
    SpawnFailed,
    Signal,
}

/// `confirmed { by: "backend", attempt_token } | { by: "operator",
/// attestation_id }` (§19.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "by", rename_all = "lowercase", deny_unknown_fields)]
pub enum ConfirmedBy {
    Backend { attempt_token: u64 },
    Operator { attestation_id: AttestationId },
}

/// The durable incident identity `(incident_seq, incident_id)` (§12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentRef {
    pub incident_seq: u64,
    pub incident_id: IncidentId,
}

/// §25.1 `incident_ref`: the durable binding an attempt's clearance was
/// minted from — `(incident_seq, incident_id, observer_session_id,
/// observer_loss_generation)`. It names the incident the post-grant abort
/// cleanup must retire; it is the *durable* binding, never the current
/// episode (the abort may be caused by the episode ending). Plain data: it
/// grants nothing, cannot mint a clearance, and cannot ARM for promotion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentBinding {
    pub incident: IncidentRef,
    pub observer_session_id: SessionId,
    pub observer_loss_generation: u64,
}

/// The configured fencing backend `B` of §13.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencingBackend {
    None,
    Command,
}

/// What the fencing gate supplies to open an incident (§12.2, T1/T2). The
/// store allocates `incident_seq` and `incident_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentOpening {
    pub target_node_id: NodeId,
    pub anchor_term: Term,
    pub observer_session_id: SessionId,
    pub observer_loss_generation: u64,
    pub backend: FencingBackend,
}

/// A rejected §13.2 (state, event) pair. Rejection never mutates anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencingTransitionError {
    /// The event is not legal in the current state.
    Illegal {
        state: &'static str,
        event: &'static str,
    },
    /// The event names an attempt token other than the current one.
    AttemptTokenMismatch,
    /// `attempt_token_high_water` cannot be incremented (no wrap).
    AttemptTokenExhausted,
    /// T3 requires `B = command`.
    BackendNotCommand,
}

/// One legal §13.2 state change: the exact current incident and its
/// successor. Only this module constructs it, so the Node store can persist
/// nothing but a legal transition, and it persists it only while the durable
/// incident still equals `from` exactly.
#[derive(Debug)]
pub struct FencingTransition {
    from: FencingIncident,
    to: FencingIncident,
}

impl FencingTransition {
    pub fn from(&self) -> &FencingIncident {
        &self.from
    }

    pub fn to(&self) -> &FencingIncident {
        &self.to
    }
}

/// The result of an event that §13.2 permits: a transition to persist, or an
/// idempotent no-op that requires no durable write.
#[derive(Debug)]
pub enum FencingEventOutcome {
    Transition(FencingTransition),
    NoOp,
}

/// The current facts the §26 continuity rules R1-R3 are checked against.
pub struct ContinuityContext<'a> {
    /// `config.peer.id` (R1).
    pub configured_peer: &'a NodeId,
    /// This process's own `ProcessSession` id (R2).
    pub current_session: &'a SessionId,
    /// The detector's live loss episode (R3): `loss_evidence()`, which exists
    /// only at `CommunicationLost` with `lost_at = Some`.
    pub live_episode: Option<&'a LocalLossEvidence>,
}

/// The Witness fact available at each §26 R4 checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessEpoch {
    /// Gate G: the fresh `Authorized` view's `current_term`; must equal
    /// `anchor_term`.
    GateView(Term),
    /// Fencing step / ingestion: the newest authenticated TermStatus term
    /// observed since the incident opened, if any; any term other than
    /// `anchor_term` fails.
    LatestObserved(Option<Term>),
    /// I / K / ARM: the validated grant term; must equal `anchor_term + 1`.
    Grant(Term),
}

/// The first failed §26 rule. Any failure retires the incident (T9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityViolation {
    /// R1: `target_node_id != config.peer.id`.
    Target,
    /// R2: `observer_session_id` is not this process's session.
    ObserverSession,
    /// R3: no live episode, or a different loss generation.
    Episode,
    /// R4: the Witness epoch moved away from `anchor_term`.
    WitnessEpoch,
}

/// Stage 14 §24 G: why the fencing gate stopped an accepted attempt. Every
/// reason blocks the attempt before any LeaseRequest. The gate's only pass
/// outcome is a `FencingClearance` minted from the current durable, valid
/// `CONFIRMED` incident (Phase 14.10); `CONFIRMED` itself is a fencing
/// state, never promotion permission, and a clearance is not authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencingGateBlock {
    /// §26 R7: local state is not Standby / no phase / no authority / O=None
    /// / M=None, or shutdown was requested. Nothing was read or written.
    NotEligible,
    /// No observer session or no live loss episode: no incident can open.
    FencingUnavailable,
    /// A pre-commit store failure; nothing was committed by this gate.
    StoreUnavailable,
    /// T1 opened `UNKNOWN(not-attempted)` (`B = none`).
    FencingRequired,
    /// `UNKNOWN` / `FAILED` with `B = none`: attestation is the only path.
    FencingUnconfirmed,
    /// `REQUESTED` / `VERIFYING`, or a fence action ran in this frame.
    FencingInProgress,
}

/// Why the gate cannot mint a `FencingClearance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearanceRefusal {
    /// The incident is not `CONFIRMED` (§24 G: every other state blocks).
    NotConfirmed,
    /// A §26 continuity rule failed; the caller retires the incident.
    Continuity(ContinuityViolation),
}

impl FencingIncident {
    /// T1 (`B = none`) / T2 (`B = command`): the only constructor of a new
    /// incident. Called only by `NodeMutationStore::open_fencing_incident`,
    /// which allocates the sequence number and the identity and validates the
    /// whole Node v3 image before writing.
    pub(crate) fn open(
        incident_seq: u64,
        incident_id: IncidentId,
        opening: IncidentOpening,
    ) -> Self {
        let (attempt_token_high_water, state) = match opening.backend {
            FencingBackend::None => (0, FencingState::Unknown(UnknownReason::NotAttempted {})),
            FencingBackend::Command => (1, FencingState::Requested { attempt_token: 1 }),
        };
        Self {
            incident_seq,
            incident_id,
            target_node_id: opening.target_node_id,
            anchor_term: opening.anchor_term,
            observer_session_id: opening.observer_session_id,
            observer_loss_generation: opening.observer_loss_generation,
            attempt_token_high_water,
            state,
        }
    }

    pub fn incident_ref(&self) -> IncidentRef {
        IncidentRef {
            incident_seq: self.incident_seq,
            incident_id: self.incident_id.clone(),
        }
    }

    /// T3: `UNKNOWN`/`FAILED` → `REQUESTED(k+1)` for a new explicit operator
    /// action with `B = command`. The token high-water is checked, never
    /// wrapped.
    pub fn request_again(
        &self,
        backend: FencingBackend,
    ) -> Result<FencingTransition, FencingTransitionError> {
        if !matches!(
            self.state,
            FencingState::Unknown(_) | FencingState::Failed { .. }
        ) {
            return Err(self.illegal("request_again"));
        }
        if backend != FencingBackend::Command {
            return Err(FencingTransitionError::BackendNotCommand);
        }
        let token = self
            .attempt_token_high_water
            .checked_add(1)
            .ok_or(FencingTransitionError::AttemptTokenExhausted)?;
        Ok(self.transition(
            token,
            FencingState::Requested {
                attempt_token: token,
            },
        ))
    }

    /// T4: `REQUESTED(k)` → `VERIFYING(k, outcome)` after the fence action for
    /// token `k` returned or was killed. The outcome is provenance only.
    pub fn action_returned(
        &self,
        attempt_token: u64,
        action_outcome: ActionOutcome,
    ) -> Result<FencingTransition, FencingTransitionError> {
        match self.state {
            FencingState::Requested { attempt_token: k } if k == attempt_token => Ok(self
                .transition(
                    self.attempt_token_high_water,
                    FencingState::Verifying {
                        attempt_token: k,
                        action_outcome,
                    },
                )),
            FencingState::Requested { .. } => Err(FencingTransitionError::AttemptTokenMismatch),
            _ => Err(self.illegal("action_returned")),
        }
    }

    /// T5, `CONFIRMED` mint site 1 (§15): `VERIFYING(k)` → `CONFIRMED(backend
    /// k)` on one verify poll that returned exactly `isolated`. A later poll
    /// result against `CONFIRMED` is an idempotent no-op.
    pub fn confirm_by_verification(
        &self,
        attempt_token: u64,
    ) -> Result<FencingEventOutcome, FencingTransitionError> {
        match self.state {
            FencingState::Verifying {
                attempt_token: k, ..
            } if k == attempt_token => Ok(FencingEventOutcome::Transition(self.transition(
                self.attempt_token_high_water,
                FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: k }),
            ))),
            FencingState::Verifying { .. } => Err(FencingTransitionError::AttemptTokenMismatch),
            FencingState::Confirmed(_) => Ok(FencingEventOutcome::NoOp),
            _ => Err(self.illegal("confirm_by_verification")),
        }
    }

    /// T6: `VERIFYING(k)` → `FAILED(k)` on one verify poll that returned
    /// exactly `not-isolated`. `FAILED` never auto-retries.
    pub fn verification_not_isolated(
        &self,
        attempt_token: u64,
    ) -> Result<FencingEventOutcome, FencingTransitionError> {
        match self.state {
            FencingState::Verifying {
                attempt_token: k, ..
            } if k == attempt_token => Ok(FencingEventOutcome::Transition(self.transition(
                self.attempt_token_high_water,
                FencingState::Failed { attempt_token: k },
            ))),
            FencingState::Verifying { .. } => Err(FencingTransitionError::AttemptTokenMismatch),
            FencingState::Confirmed(_) => Ok(FencingEventOutcome::NoOp),
            _ => Err(self.illegal("verification_not_isolated")),
        }
    }

    /// T7: an inconclusive verify poll. With poll budget remaining the state
    /// stays `VERIFYING(k)` with no durable write; the last permitted poll
    /// gives `UNKNOWN(verify-inconclusive(kind))`.
    pub fn verification_inconclusive(
        &self,
        attempt_token: u64,
        kind: InconclusiveKind,
        poll_budget_exhausted: bool,
    ) -> Result<FencingEventOutcome, FencingTransitionError> {
        match self.state {
            FencingState::Verifying {
                attempt_token: k, ..
            } if k == attempt_token => {
                if !poll_budget_exhausted {
                    return Ok(FencingEventOutcome::NoOp);
                }
                Ok(FencingEventOutcome::Transition(self.transition(
                    self.attempt_token_high_water,
                    FencingState::Unknown(UnknownReason::VerifyInconclusive { kind }),
                )))
            }
            FencingState::Verifying { .. } => Err(FencingTransitionError::AttemptTokenMismatch),
            FencingState::Confirmed(_) => Ok(FencingEventOutcome::NoOp),
            _ => Err(self.illegal("verification_inconclusive")),
        }
    }

    /// T8, `CONFIRMED` mint site 2 (§15): a fully validated operator intent
    /// (§18.5) moves `UNKNOWN`, `REQUESTED`, `VERIFYING`, or `FAILED` to
    /// `CONFIRMED(operator)`. A repeated attestation against `CONFIRMED` is an
    /// idempotent no-op.
    pub fn confirm_by_attestation(
        &self,
        attestation_id: AttestationId,
    ) -> Result<FencingEventOutcome, FencingTransitionError> {
        match self.state {
            FencingState::Confirmed(_) => Ok(FencingEventOutcome::NoOp),
            _ => Ok(FencingEventOutcome::Transition(self.transition(
                self.attempt_token_high_water,
                FencingState::Confirmed(ConfirmedBy::Operator { attestation_id }),
            ))),
        }
    }

    /// §26 R1-R4. The first failed rule is returned; any failure retires the
    /// incident (T9) at the checkpoint that found it. R5-R8 are checked by
    /// the identity comparisons, the transitions, and the call sites.
    pub fn check_continuity(
        &self,
        context: &ContinuityContext<'_>,
        epoch: WitnessEpoch,
    ) -> Result<(), ContinuityViolation> {
        if &self.target_node_id != context.configured_peer {
            return Err(ContinuityViolation::Target);
        }
        if &self.observer_session_id != context.current_session {
            return Err(ContinuityViolation::ObserverSession);
        }
        if context
            .live_episode
            .is_none_or(|episode| episode.generation() != self.observer_loss_generation)
        {
            return Err(ContinuityViolation::Episode);
        }
        let epoch_holds = match epoch {
            WitnessEpoch::GateView(term) => term == self.anchor_term,
            WitnessEpoch::LatestObserved(term) => term.is_none_or(|term| term == self.anchor_term),
            WitnessEpoch::Grant(term) => self
                .anchor_term
                .0
                .checked_add(1)
                .is_some_and(|next| term.0 == next),
        };
        if !epoch_holds {
            return Err(ContinuityViolation::WitnessEpoch);
        }
        Ok(())
    }

    fn transition(&self, attempt_token_high_water: u64, state: FencingState) -> FencingTransition {
        let mut to = self.clone();
        to.attempt_token_high_water = attempt_token_high_water;
        to.state = state;
        FencingTransition {
            from: self.clone(),
            to,
        }
    }

    fn illegal(&self, event: &'static str) -> FencingTransitionError {
        FencingTransitionError::Illegal {
            state: self.state.name(),
            event,
        }
    }
}

impl FencingState {
    /// The §13.1 / §28 operator-visible name of the state (`fencing.state`).
    /// Presentation only: it is never parsed, compared for a decision, or
    /// persisted, and it carries no identifier.
    pub const fn operator_name(&self) -> &'static str {
        match self {
            Self::Unknown(_) => "UNKNOWN",
            Self::Requested { .. } => "REQUESTED",
            Self::Verifying { .. } => "VERIFYING",
            Self::Confirmed(_) => "CONFIRMED",
            Self::Failed { .. } => "FAILED",
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Unknown(_) => "unknown",
            Self::Requested { .. } => "requested",
            Self::Verifying { .. } => "verifying",
            Self::Confirmed(_) => "confirmed",
            Self::Failed { .. } => "failed",
        }
    }
}

/// §24 G: the gate's permission for the current accepted attempt to continue
/// past the fencing gate, minted only from the **current durable** `CONFIRMED`
/// incident whose §26 continuity holds against the fresh `Authorized` view. It
/// is not authority: it cannot acquire a lease, ARM, or promote, and every
/// later step (I, K, ARM) rechecks the incident against it. Not
/// `Clone`/`Copy`/serializable; this is its only construction site.
///
/// F-01: the input is a `DurableIncident`, which only
/// `NodeMutationStore::mint_fencing_clearance` can construct from its own
/// validated load. A `FencingIncident` value (deserialized, copied, or built
/// from its public fields) is durable schema, not proof, and cannot mint.
#[derive(Debug)]
pub struct FencingClearance {
    incident: IncidentRef,
    target_node_id: NodeId,
    anchor_term: Term,
    observer_session_id: SessionId,
    observer_loss_generation: u64,
    /// G-2 contract R4.1 G-A2: how the incident became `CONFIRMED` (T5 backend verification or T8
    /// operator attestation), copied from the durable incident at mint time. The success ARM
    /// clears the incident before the resources are touched, so this is the only place the route
    /// handoff can learn it from. Provenance only: it grants nothing.
    confirmed_by: ConfirmedBy,
}

impl FencingClearance {
    pub(crate) fn mint(
        durable: &DurableIncident<'_>,
        context: &ContinuityContext<'_>,
        view_term: Term,
    ) -> Result<Self, ClearanceRefusal> {
        let incident = durable.incident();
        incident
            .check_continuity(context, WitnessEpoch::GateView(view_term))
            .map_err(ClearanceRefusal::Continuity)?;
        let FencingState::Confirmed(confirmed_by) = &incident.state else {
            return Err(ClearanceRefusal::NotConfirmed);
        };
        Ok(Self {
            incident: incident.incident_ref(),
            target_node_id: incident.target_node_id.clone(),
            anchor_term: incident.anchor_term,
            observer_session_id: incident.observer_session_id.clone(),
            observer_loss_generation: incident.observer_loss_generation,
            confirmed_by: confirmed_by.clone(),
        })
    }

    pub fn incident(&self) -> &IncidentRef {
        &self.incident
    }

    pub fn target_node_id(&self) -> &NodeId {
        &self.target_node_id
    }

    pub fn anchor_term(&self) -> Term {
        self.anchor_term
    }

    /// G-2 G-A2: the mint-time provenance of the `CONFIRMED` state.
    pub fn confirmed_by(&self) -> &ConfirmedBy {
        &self.confirmed_by
    }

    /// G-2 G-A2: the verify attempt token when the incident was confirmed by the backend (T5);
    /// `None` for an operator attestation (T8).
    pub fn backend_attempt_token(&self) -> Option<u64> {
        // A read of the copied provenance, not a construction (guard 017 counts constructions).
        if let ConfirmedBy::Backend { attempt_token } = &self.confirmed_by {
            Some(*attempt_token)
        } else {
            None
        }
    }

    pub fn observer_session_id(&self) -> &SessionId {
        &self.observer_session_id
    }

    pub fn observer_loss_generation(&self) -> u64 {
        self.observer_loss_generation
    }

    /// §25.1: the durable binding this clearance was minted from, for the
    /// post-grant abort-cleanup transaction.
    pub fn binding(&self) -> IncidentBinding {
        IncidentBinding {
            incident: self.incident.clone(),
            observer_session_id: self.observer_session_id.clone(),
            observer_loss_generation: self.observer_loss_generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure_assessment::PeerFailureDetector;
    use crate::protocol::Sequence;
    use std::time::{Duration, Instant};

    const INCIDENT_UUID: &str = "11111111-2222-4333-8444-555555555555";
    const ATTESTATION_UUID: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";

    fn session() -> SessionId {
        SessionId::new("0123456789abcdef")
    }

    fn peer() -> NodeId {
        NodeId::new("node-b")
    }

    fn incident(high_water: u64, state: FencingState) -> FencingIncident {
        FencingIncident {
            incident_seq: 7,
            incident_id: IncidentId::new(INCIDENT_UUID),
            target_node_id: peer(),
            anchor_term: Term(41),
            observer_session_id: session(),
            observer_loss_generation: 1,
            attempt_token_high_water: high_water,
            state,
        }
    }

    fn confirmed_operator() -> FencingState {
        FencingState::Confirmed(ConfirmedBy::Operator {
            attestation_id: AttestationId::new(ATTESTATION_UUID),
        })
    }

    /// Every stored state (§13.1), with a consistent token high-water.
    fn every_state() -> Vec<(&'static str, FencingIncident)> {
        vec![
            (
                "unknown(not-attempted)",
                incident(0, FencingState::Unknown(UnknownReason::NotAttempted {})),
            ),
            (
                "unknown(verify-inconclusive)",
                incident(
                    1,
                    FencingState::Unknown(UnknownReason::VerifyInconclusive {
                        kind: InconclusiveKind::Timeout,
                    }),
                ),
            ),
            (
                "requested(1)",
                incident(1, FencingState::Requested { attempt_token: 1 }),
            ),
            (
                "verifying(1)",
                incident(
                    1,
                    FencingState::Verifying {
                        attempt_token: 1,
                        action_outcome: ActionOutcome::ReportedSuccess,
                    },
                ),
            ),
            (
                "confirmed(backend)",
                incident(
                    1,
                    FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 1 }),
                ),
            ),
            ("confirmed(operator)", incident(1, confirmed_operator())),
            (
                "failed(1)",
                incident(1, FencingState::Failed { attempt_token: 1 }),
            ),
        ]
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Expect {
        To(u64, FencingState),
        NoOp,
        Rejected,
    }

    fn classify(
        result: Result<FencingEventOutcome, FencingTransitionError>,
        from: &FencingIncident,
    ) -> Expect {
        match result {
            Ok(FencingEventOutcome::Transition(transition)) => {
                assert_eq!(transition.from(), from);
                let to = transition.to();
                // Only the state and the token high-water ever change.
                let mut identity = to.clone();
                identity.state = from.state.clone();
                identity.attempt_token_high_water = from.attempt_token_high_water;
                assert_eq!(&identity, from);
                Expect::To(to.attempt_token_high_water, to.state.clone())
            }
            Ok(FencingEventOutcome::NoOp) => Expect::NoOp,
            Err(_) => Expect::Rejected,
        }
    }

    fn apply_event(event: usize, incident: &FencingIncident) -> Expect {
        let wrap = |result: Result<FencingTransition, FencingTransitionError>| {
            result.map(FencingEventOutcome::Transition)
        };
        let result = match event {
            0 => wrap(incident.request_again(FencingBackend::Command)),
            1 => wrap(incident.request_again(FencingBackend::None)),
            2 => wrap(incident.action_returned(1, ActionOutcome::ReportedSuccess)),
            3 => wrap(incident.action_returned(2, ActionOutcome::ReportedSuccess)),
            4 => incident.confirm_by_verification(1),
            5 => incident.confirm_by_verification(2),
            6 => incident.verification_not_isolated(1),
            7 => incident.verification_inconclusive(1, InconclusiveKind::Signal, false),
            8 => incident.verification_inconclusive(1, InconclusiveKind::Signal, true),
            9 => incident.confirm_by_attestation(AttestationId::new(ATTESTATION_UUID)),
            _ => unreachable!(),
        };
        classify(result, incident)
    }

    const EVENTS: [&str; 10] = [
        "request_again(command)",
        "request_again(none)",
        "action_returned(1)",
        "action_returned(2)",
        "confirm_by_verification(1)",
        "confirm_by_verification(2)",
        "verification_not_isolated(1)",
        "verification_inconclusive(1, budget left)",
        "verification_inconclusive(1, final)",
        "confirm_by_attestation",
    ];

    /// §34.1: the exhaustive (state × event) matrix. Exactly the §13.2
    /// transitions T3-T8 apply; `CONFIRMED` absorbs later results as no-ops;
    /// every other pair is rejected, and nothing is ever mutated in place.
    #[test]
    fn stage14_4_exhaustive_state_event_matrix() {
        use Expect::{NoOp, Rejected, To};
        let requested = |k| FencingState::Requested { attempt_token: k };
        let confirmed_backend = FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 1 });
        let failed = FencingState::Failed { attempt_token: 1 };
        let verifying = FencingState::Verifying {
            attempt_token: 1,
            action_outcome: ActionOutcome::ReportedSuccess,
        };
        let inconclusive = FencingState::Unknown(UnknownReason::VerifyInconclusive {
            kind: InconclusiveKind::Signal,
        });
        let attested = || To(0, confirmed_operator());
        let attested_hw1 = || To(1, confirmed_operator());
        let rejected_except = |legal: Vec<(usize, Expect)>| {
            let mut row: Vec<Expect> = (0..EVENTS.len()).map(|_| Rejected).collect();
            for (event, expect) in legal {
                row[event] = expect;
            }
            row
        };
        let expected: Vec<Vec<Expect>> = vec![
            // unknown(not-attempted): T3, T8
            rejected_except(vec![(0, To(1, requested(1))), (9, attested())]),
            // unknown(verify-inconclusive): T3, T8
            rejected_except(vec![(0, To(2, requested(2))), (9, attested_hw1())]),
            // requested(1): T4, T8
            rejected_except(vec![(2, To(1, verifying.clone())), (9, attested_hw1())]),
            // verifying(1): T5, T6, budget-left no-op, T7, T8
            rejected_except(vec![
                (4, To(1, confirmed_backend.clone())),
                (6, To(1, failed.clone())),
                (7, NoOp),
                (8, To(1, inconclusive.clone())),
                (9, attested_hw1()),
            ]),
            // confirmed(backend): every later result is an idempotent no-op
            rejected_except((4..10).map(|event| (event, NoOp)).collect()),
            // confirmed(operator): same
            rejected_except((4..10).map(|event| (event, NoOp)).collect()),
            // failed(1): T3, T8 (never an automatic retry)
            rejected_except(vec![(0, To(2, requested(2))), (9, attested_hw1())]),
        ];
        for ((name, incident), expected_row) in every_state().into_iter().zip(expected) {
            let before = incident.clone();
            for (event, expect) in expected_row.into_iter().enumerate() {
                assert_eq!(
                    apply_event(event, &incident),
                    expect,
                    "{name} × {}",
                    EVENTS[event]
                );
                assert_eq!(incident, before, "{name} × {} mutated", EVENTS[event]);
            }
        }
    }

    /// T1 / T2: the backend selects the initial state and token high-water.
    #[test]
    fn stage14_4_open_selects_the_initial_state_by_backend() {
        let opening = |backend| IncidentOpening {
            target_node_id: peer(),
            anchor_term: Term(41),
            observer_session_id: session(),
            observer_loss_generation: 1,
            backend,
        };
        let none = FencingIncident::open(
            3,
            IncidentId::new(INCIDENT_UUID),
            opening(FencingBackend::None),
        );
        assert_eq!(
            none.state,
            FencingState::Unknown(UnknownReason::NotAttempted {})
        );
        assert_eq!(none.attempt_token_high_water, 0);
        let command = FencingIncident::open(
            3,
            IncidentId::new(INCIDENT_UUID),
            opening(FencingBackend::Command),
        );
        assert_eq!(command.state, FencingState::Requested { attempt_token: 1 });
        assert_eq!(command.attempt_token_high_water, 1);
        for opened in [none, command] {
            assert_eq!(opened.incident_seq, 3);
            assert_eq!(opened.target_node_id, peer());
            assert_eq!(opened.anchor_term, Term(41));
            assert_eq!(opened.observer_session_id, session());
            assert_eq!(opened.observer_loss_generation, 1);
        }
    }

    /// §13.2 / §15 E3, MF-5: an action result (including exit 0) only ever
    /// reaches `VERIFYING`; `UNKNOWN → VERIFYING` does not exist.
    #[test]
    fn stage14_4_action_outcomes_never_confirm() {
        let requested = incident(1, FencingState::Requested { attempt_token: 1 });
        for outcome in [
            ActionOutcome::ReportedSuccess,
            ActionOutcome::ReportedFailure,
            ActionOutcome::TimedOut,
            ActionOutcome::SpawnFailed,
            ActionOutcome::Signal,
        ] {
            let transition = requested.action_returned(1, outcome).unwrap();
            assert_eq!(
                transition.to().state,
                FencingState::Verifying {
                    attempt_token: 1,
                    action_outcome: outcome
                }
            );
        }
        let unknown = incident(0, FencingState::Unknown(UnknownReason::NotAttempted {}));
        assert!(
            unknown
                .action_returned(0, ActionOutcome::ReportedSuccess)
                .is_err()
        );
    }

    /// MF-8: every token-bound event requires the current attempt token.
    #[test]
    fn stage14_4_attempt_token_binding_and_exhaustion() {
        let verifying = incident(
            3,
            FencingState::Verifying {
                attempt_token: 3,
                action_outcome: ActionOutcome::TimedOut,
            },
        );
        for stale in [1, 2, 4] {
            assert_eq!(
                verifying.confirm_by_verification(stale).unwrap_err(),
                FencingTransitionError::AttemptTokenMismatch
            );
            assert_eq!(
                verifying.verification_not_isolated(stale).unwrap_err(),
                FencingTransitionError::AttemptTokenMismatch
            );
            assert_eq!(
                verifying
                    .verification_inconclusive(stale, InconclusiveKind::Timeout, true)
                    .unwrap_err(),
                FencingTransitionError::AttemptTokenMismatch
            );
        }
        let requested = incident(3, FencingState::Requested { attempt_token: 3 });
        assert_eq!(
            requested
                .action_returned(2, ActionOutcome::ReportedSuccess)
                .unwrap_err(),
            FencingTransitionError::AttemptTokenMismatch
        );
        let exhausted = incident(
            u64::MAX,
            FencingState::Failed {
                attempt_token: u64::MAX,
            },
        );
        assert_eq!(
            exhausted
                .request_again(FencingBackend::Command)
                .unwrap_err(),
            FencingTransitionError::AttemptTokenExhausted
        );
        assert_eq!(
            incident(1, FencingState::Failed { attempt_token: 1 })
                .request_again(FencingBackend::None)
                .unwrap_err(),
            FencingTransitionError::BackendNotCommand
        );
    }

    /// A detector in a confirmed legacy loss episode (generation 1).
    fn lost_detector() -> (PeerFailureDetector, SessionId, Instant) {
        let mut detector = PeerFailureDetector::new(Duration::from_secs(5)).unwrap();
        let peer_session = SessionId::new("peer-session-1");
        let t0 = Instant::now();
        detector
            .observe_session_established(peer_session.clone(), t0)
            .unwrap();
        assert!(
            detector
                .observe_trusted_heartbeat(&peer_session, Sequence(1), t0)
                .unwrap()
        );
        detector.observe_transport_failure(t0).unwrap();
        let lost_at = t0 + Duration::from_secs(5);
        detector.tick(lost_at).unwrap();
        assert_eq!(detector.loss_evidence().unwrap().generation(), 1);
        (detector, peer_session, lost_at)
    }

    fn check(
        incident: &FencingIncident,
        detector: &PeerFailureDetector,
        epoch: WitnessEpoch,
    ) -> Result<(), ContinuityViolation> {
        let evidence = detector.loss_evidence();
        let peer = peer();
        let session = session();
        incident.check_continuity(
            &ContinuityContext {
                configured_peer: &peer,
                current_session: &session,
                live_episode: evidence.as_ref(),
            },
            epoch,
        )
    }

    /// §26 R1-R4 and §34.2 against real detector provenance: target, observer
    /// session, episode (authenticated session, heartbeat recovery, clock
    /// regression, a new episode), and each Witness epoch checkpoint.
    #[test]
    fn stage14_4_continuity_rules_fail_closed_on_stale_provenance() {
        let confirmed = incident(
            1,
            FencingState::Confirmed(ConfirmedBy::Backend { attempt_token: 1 }),
        );
        let (detector, peer_session, lost_at) = lost_detector();
        assert_eq!(
            check(&confirmed, &detector, WitnessEpoch::GateView(Term(41))),
            Ok(())
        );

        // R1 / R2.
        let evidence = detector.loss_evidence();
        let wrong_peer = NodeId::new("node-c");
        let current = session();
        let restarted = SessionId::new("fedcba9876543210");
        let context = |configured_peer, current_session| ContinuityContext {
            configured_peer,
            current_session,
            live_episode: evidence.as_ref(),
        };
        assert_eq!(
            confirmed.check_continuity(
                &context(&wrong_peer, &current),
                WitnessEpoch::GateView(Term(41))
            ),
            Err(ContinuityViolation::Target)
        );
        assert_eq!(
            confirmed.check_continuity(
                &context(&peer(), &restarted),
                WitnessEpoch::GateView(Term(41))
            ),
            Err(ContinuityViolation::ObserverSession)
        );

        // R3: every episode end.
        let mut authenticated = detector.clone();
        authenticated
            .observe_session_established(peer_session.clone(), lost_at + Duration::from_secs(1))
            .unwrap();
        let mut recovered = detector.clone();
        recovered
            .observe_trusted_heartbeat(&peer_session, Sequence(2), lost_at + Duration::from_secs(1))
            .unwrap();
        let mut regressed = detector.clone();
        assert!(regressed.tick(lost_at - Duration::from_millis(1)).is_err());
        let mut relost = recovered.clone();
        relost
            .observe_transport_failure(lost_at + Duration::from_secs(2))
            .unwrap();
        relost.tick(lost_at + Duration::from_secs(7)).unwrap();
        assert_eq!(relost.loss_evidence().unwrap().generation(), 2);
        for (name, ended) in [
            ("authenticated session", &authenticated),
            ("heartbeat recovery", &recovered),
            ("clock regression", &regressed),
            ("new episode", &relost),
        ] {
            assert_eq!(
                check(&confirmed, ended, WitnessEpoch::GateView(Term(41))),
                Err(ContinuityViolation::Episode),
                "{name}"
            );
        }

        // R4 at each checkpoint.
        for (epoch, holds) in [
            (WitnessEpoch::GateView(Term(40)), false),
            (WitnessEpoch::GateView(Term(42)), false),
            (WitnessEpoch::LatestObserved(None), true),
            (WitnessEpoch::LatestObserved(Some(Term(41))), true),
            (WitnessEpoch::LatestObserved(Some(Term(42))), false),
            (WitnessEpoch::Grant(Term(42)), true),
            (WitnessEpoch::Grant(Term(41)), false),
            (WitnessEpoch::Grant(Term(43)), false),
        ] {
            assert_eq!(
                check(&confirmed, &detector, epoch).is_ok(),
                holds,
                "{epoch:?}"
            );
            if !holds {
                assert_eq!(
                    check(&confirmed, &detector, epoch),
                    Err(ContinuityViolation::WitnessEpoch)
                );
            }
        }
        let mut max_anchor = confirmed.clone();
        max_anchor.anchor_term = Term(u64::MAX);
        assert_eq!(
            check(&max_anchor, &detector, WitnessEpoch::Grant(Term(u64::MAX))),
            Err(ContinuityViolation::WitnessEpoch)
        );
    }
}
