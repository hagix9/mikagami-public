//! Caller-driven GET_TERM diagnostics and local Unavailable evidence.
//! Nested under evidence_fusion to keep token construction private.

use super::{
    EvidenceFusion, EvidenceFusionError, EvidenceFusionSnapshot, ObservationData, WitnessHolder,
    WitnessObservation, WitnessStatus,
};
use crate::failure_assessment::PeerFailureAssessment;
use crate::protocol::{RequestId, TermStatusPayload};
use crate::tcp::TcpError;
use crate::transport::TransportError;
use crate::witness_runtime::{
    WitnessPoll, WitnessResponseObservation, WitnessRuntimeError, WitnessSession,
};
use std::{
    fmt, io,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub request_id: RequestId,
    pub request_generation: u64,
    pub started_at: Instant,
    pub deadline: Instant,
    connection_provenance: Arc<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableCause {
    Timeout,
    Transport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// Validated remote data; the authority-view classification — not this
    /// raw payload — is the authorization-relevant fact.
    TermStatus(TermStatusPayload),
    Unavailable(UnavailableCause),
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ObservationProgress {
    AwaitingWitnessTerm,
    Ready(WitnessAuthorityViewEvidence),
    Unavailable(UnavailableCause),
}

/// The local authority context a TermStatus holder classification is
/// evaluated against, captured per observation request. This is an
/// *input* — never evidence — and carries no authority itself.
///
/// `expected_term` / `self_lease_id` describe the locally installed
/// lease authority, when one exists: a Witness view from a different
/// term, or a `Self` holder claim with a different lease identity, is
/// inconsistent with this node's authority context and must fail
/// closed. When no local authority is installed they are `None`: a
/// `Self` holder claim remains a quorum fact only (never executable
/// authority) and the reported term is accepted as current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorityViewExpectation {
    pub(crate) local_node_id: crate::protocol::NodeId,
    pub(crate) expected_term: Option<crate::protocol::Term>,
    pub(crate) self_lease_id: Option<crate::protocol::LeaseId>,
}

impl AuthorityViewExpectation {
    pub(crate) const fn new(
        local_node_id: crate::protocol::NodeId,
        expected_term: Option<crate::protocol::Term>,
        self_lease_id: Option<crate::protocol::LeaseId>,
    ) -> Self {
        Self {
            local_node_id,
            expected_term,
            self_lease_id,
        }
    }
}

/// Semantic holder classification of an authenticated, correlated
/// `TermStatus` response (Stage 13.3). Deliberately not a boolean:
/// each fail-closed class stays observable and testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityViewCompatibility {
    /// The Witness records no holder for the current term. Proves only
    /// that — not peer death, resource shutdown, fencing, or release.
    CompatibleNoHolder,
    /// The Witness records this node as holder with `remaining > 0`
    /// and matching term/lease identity. A quorum fact only — never
    /// `RuntimeLeaseAuthority` and never a Stage 13.2 shortcut.
    CompatibleSelfUnexpired,
    /// The Witness records a foreign holder with `remaining > 0`.
    ConflictingHolder,
    /// `Some(holder)` with `remaining = 0` or no remaining data:
    /// expired-but-unprocessed; GET_TERM performs no client-side
    /// expiry and this is never compatible.
    ExpiredButUnprocessed,
    /// The view is inconsistent with the local authority context:
    /// wrong term, a `Self` claim with missing or mismatched lease
    /// identity, or other unverifiable identity.
    InconsistentAuthorityView,
}

impl AuthorityViewCompatibility {
    /// Whether this classification is authority-view compatible for
    /// Stage 13.3 fusion. Every other class is incompatible.
    pub(crate) const fn is_compatible(self) -> bool {
        matches!(
            self,
            Self::CompatibleNoHolder | Self::CompatibleSelfUnexpired
        )
    }
}

/// Classify an authenticated, correlated `TermStatus` against the
/// local authority context captured at request begin.
///
/// Term consistency is checked for every holder class: evidence from
/// one term must never authorize another context. A `Self` claim
/// additionally requires `remaining > 0` and a present lease identity
/// that — when a local authority context exists — matches the
/// installed term/lease identity exactly; anything else fails closed.
fn classify_authority_view(
    payload: &crate::protocol::TermStatusPayload,
    expectation: &AuthorityViewExpectation,
) -> AuthorityViewCompatibility {
    if expectation
        .expected_term
        .is_some_and(|expected| expected != payload.current_term)
    {
        return AuthorityViewCompatibility::InconsistentAuthorityView;
    }
    let remaining = payload
        .lease_remaining_ms
        .map(|remaining| remaining.0)
        .unwrap_or(0);
    match &payload.current_holder {
        None => AuthorityViewCompatibility::CompatibleNoHolder,
        Some(_) if remaining == 0 => AuthorityViewCompatibility::ExpiredButUnprocessed,
        Some(holder) if holder != &expectation.local_node_id => {
            AuthorityViewCompatibility::ConflictingHolder
        }
        Some(_) => {
            match (&payload.current_lease_id, &expectation.self_lease_id) {
                // Local authority context installed: exact lease
                // identity match required.
                (Some(lease_id), Some(expected)) if lease_id == expected => {
                    AuthorityViewCompatibility::CompatibleSelfUnexpired
                }
                (Some(_), Some(_)) => AuthorityViewCompatibility::InconsistentAuthorityView,
                // No local authority to compare against: the Self claim
                // is a quorum fact only. It is compatible but can never
                // mint or skip executable authority.
                (Some(_), None) => AuthorityViewCompatibility::CompatibleSelfUnexpired,
                // A holder claim with no lease identity is malformed.
                (None, _) => AuthorityViewCompatibility::InconsistentAuthorityView,
            }
        }
    }
}

/// Ephemeral current-attempt authority-view evidence (Stage 13.3):
/// the term and holder classification obtained from the current
/// authenticated, correlated GET_TERM completion, never from the
/// historical/stored `EvidenceFusionSnapshot::witness_term`.
///
/// The fields are private, there is no public/general constructor, and
/// no `From`/`Into` conversion from `EvidenceFusionSnapshot` exists.
/// Only the observation lifecycle in this module can mint a value, and
/// only from a correlated completion for the current request
/// generation. It is deliberately not `Clone`/`Copy`, not
/// serializable, and not persistable. It carries no authority, no
/// lease handle, and no mutation capability — a compatible
/// classification is only a fact input to fusion/policy.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WitnessAuthorityViewEvidence {
    term: crate::protocol::Term,
    compatibility: AuthorityViewCompatibility,
    lease_remaining_ms: Option<crate::protocol::DurationMs>,
    observed_at: Instant,
    request_generation: u64,
    observation_generation: u64,
}

#[allow(dead_code)]
impl WitnessAuthorityViewEvidence {
    /// The current correlated authority term. Read-only.
    pub(crate) const fn term(&self) -> crate::protocol::Term {
        self.term
    }

    /// The semantic holder classification of this view. Read-only.
    pub(crate) const fn compatibility(&self) -> AuthorityViewCompatibility {
        self.compatibility
    }

    /// The Witness-reported remaining lease time, if any. Read-only.
    pub(crate) const fn lease_remaining_ms(&self) -> Option<crate::protocol::DurationMs> {
        self.lease_remaining_ms
    }

    /// The completion acceptance time (the fixed freshness epoch). Read-only.
    pub(crate) const fn observed_at(&self) -> Instant {
        self.observed_at
    }

    /// The request generation that produced this view. Read-only.
    pub(crate) const fn request_generation(&self) -> u64 {
        self.request_generation
    }

    /// The observation generation at completion time. Read-only.
    pub(crate) const fn observation_generation(&self) -> u64 {
        self.observation_generation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterSnapshot {
    pub pending: Option<PendingRequest>,
    pub request_generation: u64,
    pub observation_generation: u64,
    pub last_completion: Option<Completion>,
    pub delivery_pending: bool,
    pub failed: bool,
    pub fusion: EvidenceFusionSnapshot,
}

#[derive(Debug)]
pub enum AdapterError {
    InvalidTimeout,
    Random(getrandom::Error),
    TimeWentBackwards,
    DeadlineOverflow,
    GenerationExhausted,
    Busy,
    Failed,
    NoPendingRequest,
    ConnectionProvenanceMismatch,
    ExpiredRequest,
    Runtime(WitnessRuntimeError),
    Fusion(EvidenceFusionError),
}
impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Witness evidence adapter: {self:?}")
    }
}
impl std::error::Error for AdapterError {}

/// Observation-state-only Witness evidence adapter.
///
/// It deliberately owns NO transport/session state: the one physical
/// `WitnessConnection`, `ProcessSession`, `MessageAuthenticator`, and the
/// single `WitnessRequestOutstanding` live in the neutral `WitnessSession`,
/// which is borrowed for the duration of each transport-touching call. This
/// keeps observation (what was observed) separate from authority mutation and
/// guarantees a single outstanding request slot for the logical session.
pub struct WitnessEvidenceAdapter {
    fusion: EvidenceFusion,
    // Fresh random namespace per adapter; never caller-selected request IDs.
    request_namespace: String,
    request_generation: u64,
    observation_generation: u64,
    request_timeout: Duration,
    pending: Option<PendingRequest>,
    delivery: Option<WitnessObservation>,
    last_completion: Option<Completion>,
    last_completion_request_generation: Option<u64>,
    last_completion_at: Option<Instant>,
    /// The local authority context captured at `begin_observation_at`
    /// for the in-flight request. Cleared with the pending request.
    expectation: Option<AuthorityViewExpectation>,
    /// The holder classification computed at TermStatus acceptance;
    /// consumed by the one-shot `Ready` exposure.
    last_authority_view: Option<(
        AuthorityViewCompatibility,
        Option<crate::protocol::DurationMs>,
    )>,
    // One-shot consumption marker: the request generation whose completion was
    // already exposed as a current-term observation.
    progressed_generation: Option<u64>,
    /// Phase 14.12 F7: the settled-generation watermark. The highest request
    /// generation of THIS adapter whose response is settled: accepted as the
    /// current response, or already discarded as a late response (A2). It
    /// starts at 0 (generations start at 1), only ever rises (`settle`), and
    /// never exceeds `request_generation`.
    ///
    /// Invariant (F7 contract amendment): every generation `h` with
    /// `settled_generation < h < request_generation` was issued by this
    /// adapter and completed as `Unavailable(Timeout)`. Proof: a generation is
    /// issued only by `start_at`, which needs no pending request, so the
    /// previous generation ended before the next was issued — by acceptance
    /// (raises the watermark to it), by timeout, or by a transport / send
    /// failure, which sets `failed` and so forbids any later `start_at`. A
    /// late response is therefore discardable exactly when its generation lies
    /// strictly between the watermark and the current generation. One counter
    /// replaces the former set of the last 8 expired generations: nothing is
    /// forgotten, so neither a stale frame becomes acceptable nor does a
    /// legitimate late frame become fatal, and the state is 8 bytes. Late
    /// answers come in generation order (one Witness, one stream, one
    /// outstanding request); an answer at or below the watermark fails closed.
    settled_generation: u64,
    /// Number of late responses discarded (diagnostics / loop control only).
    stale_discarded: u64,
    last_time: Option<Instant>,
    failed: bool,
}

/// At most this many frames are read (and so at most this many late frames
/// are discarded) per `poll_at` call; the attempt-bound wait polls again every
/// slice. Unchanged from the former `MAX_EXPIRED_GENERATIONS + 1` reads.
const MAX_STALE_FRAMES_PER_POLL: usize = 9;

/// Phase 14.12 E3b: the longest single wait between two polls of an
/// attempt-bound observation (and therefore between two shutdown checks).
/// Never a reason to wait past the request's deadline.
pub(crate) const ATTEMPT_OBSERVATION_WAIT_SLICE: Duration = Duration::from_millis(10);

/// How one attempt's observation step ended (Phase 14.12 E3b).
#[allow(dead_code)] // production use is Linux-only; tests exercise it everywhere
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptObservationWait {
    /// The step issued its own GET_TERM and it is no longer pending: the
    /// response was accepted, or the request ended as a terminal
    /// `Unavailable` (timeout or transport). The attempt's single
    /// `poll_observation_at` then decides; only an accepted response can
    /// become `Ready`.
    Resolved,
    /// No GET_TERM was issued; the attempt fails closed.
    NotIssued(&'static str),
    /// A shutdown was seen while waiting; the attempt fails closed.
    Interrupted,
    /// A poll or expiry failed (authentication, session, sequence,
    /// protocol, correlation or clock error, or a disconnect); the attempt
    /// fails closed without reading another frame.
    Failed,
}

impl AttemptObservationWait {
    /// `Ok` only when the step resolved its own request; everything else is
    /// the reason the attempt is blocked before mutation.
    #[allow(dead_code)] // production use is Linux-only
    pub(crate) const fn into_result(self) -> Result<(), &'static str> {
        match self {
            Self::Resolved => Ok(()),
            Self::NotIssued(reason) => Err(reason),
            Self::Interrupted => Err("shutdown requested while waiting for the Witness"),
            Self::Failed => Err("Witness observation failed"),
        }
    }
}

impl WitnessEvidenceAdapter {
    /// Pass config.lease.request_timeout_sec as a Duration; no new timeout default.
    pub fn new(request_timeout: Duration) -> Result<Self, AdapterError> {
        if request_timeout.is_zero() {
            return Err(AdapterError::InvalidTimeout);
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(AdapterError::Random)?;
        let request_namespace = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            fusion: EvidenceFusion::with_default_timeout(),
            request_namespace,
            request_generation: 0,
            observation_generation: 0,
            request_timeout,
            pending: None,
            delivery: None,
            last_completion: None,
            last_completion_request_generation: None,
            last_completion_at: None,
            expectation: None,
            last_authority_view: None,
            progressed_generation: None,
            settled_generation: 0,
            stale_discarded: 0,
            last_time: None,
            failed: false,
        })
    }

    /// Whether the Witness session is lost for good as far as this adapter can
    /// tell: a sticky adapter failure, or the last observation completed as
    /// `Unavailable(Transport)` (the stream is closed or reset). A timeout
    /// alone is not a lost session. Diagnostic/liveness only.
    pub(crate) fn session_lost(&self) -> bool {
        self.failed
            || matches!(
                self.last_completion,
                Some(Completion::Unavailable(UnavailableCause::Transport))
            )
    }

    pub fn snapshot(&self) -> AdapterSnapshot {
        AdapterSnapshot {
            pending: self.pending.clone(),
            request_generation: self.request_generation,
            observation_generation: self.observation_generation,
            last_completion: self.last_completion.clone(),
            delivery_pending: self.delivery.is_some(),
            failed: self.failed,
            fusion: self.fusion.snapshot(),
        }
    }

    fn check_time(&self, now: Instant) -> Result<(), AdapterError> {
        if self.last_time.is_some_and(|last| now < last) {
            return Err(AdapterError::TimeWentBackwards);
        }
        Ok(())
    }

    pub(crate) fn start_at(
        &mut self,
        session: &mut WitnessSession,
        expectation: AuthorityViewExpectation,
        now: Instant,
    ) -> Result<RequestId, AdapterError> {
        self.check_time(now)?;
        if self.failed {
            return Err(AdapterError::Failed);
        }
        // A1: a pending request whose deadline has passed (`now >= deadline`,
        // the same boundary as `poll_at` / `tick_at`) is completed through the
        // existing expiry path (`tick_at` -> `complete_unavailable(Timeout)`,
        // which also resets the shared outstanding slot) and its queued
        // Unavailable token is drained exactly as `poll_observation_at` does.
        // Any failure returns here: no new request is issued from an
        // ambiguous state. A pending request still inside its deadline is
        // never replaced.
        self.expire_pending_at(session, now)?;
        if self.pending.is_some() || self.delivery.is_some() {
            return Err(AdapterError::Busy);
        }
        let generation = self
            .request_generation
            .checked_add(1)
            .ok_or(AdapterError::GenerationExhausted)?;
        let deadline = now
            .checked_add(self.request_timeout)
            .ok_or(AdapterError::DeadlineOverflow)?;
        let id = RequestId::new(format!("{}-{generation}", self.request_namespace));
        self.request_generation = generation;
        self.last_completion = None;
        self.last_completion_request_generation = None;
        self.last_completion_at = None;
        self.last_authority_view = None;
        self.progressed_generation = None;
        self.last_time = Some(now);
        self.expectation = Some(expectation);
        self.pending = Some(PendingRequest {
            request_id: id.clone(),
            request_generation: generation,
            started_at: now,
            deadline,
            connection_provenance: session.provenance(),
        });
        if let Err(error) = session.send_get_term(id.clone()) {
            // A partial send is never retried on this stream.
            self.failed = true;
            if terminal(&error) {
                self.complete_unavailable(session, UnavailableCause::Transport, now)?;
            } else {
                self.pending = None;
                self.expectation = None;
                session.reset_outstanding();
            }
            return Err(AdapterError::Runtime(error));
        }
        Ok(id)
    }

    /// Complete a pending request whose deadline has passed (`now >=
    /// deadline`) through the existing expiry path, and drain the queued
    /// Unavailable token. Returns whether anything expired. A request still
    /// inside its deadline is never touched. Issues no request and polls no
    /// socket: it exposes no evidence.
    pub(crate) fn expire_pending_at(
        &mut self,
        session: &mut WitnessSession,
        now: Instant,
    ) -> Result<bool, AdapterError> {
        if !self
            .pending
            .as_ref()
            .is_some_and(|pending| now >= pending.deadline)
        {
            return Ok(false);
        }
        self.tick_at(session, now)?;
        self.drain_observation_token(now)?;
        Ok(true)
    }

    /// Time advances only here or through explicit caller events; no automatic request send.
    pub(crate) fn tick_at(
        &mut self,
        session: &mut WitnessSession,
        now: Instant,
    ) -> Result<(), AdapterError> {
        self.check_time(now)?;
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| now >= pending.deadline)
        {
            self.complete_unavailable(session, UnavailableCause::Timeout, now)?;
        }
        self.fusion.tick(now).map_err(AdapterError::Fusion)?;
        self.last_time = Some(now);
        Ok(())
    }

    /// At most one framed response per call; partial data stays in TcpConnection.
    pub(crate) fn poll_at(
        &mut self,
        session: &mut WitnessSession,
        now: Instant,
    ) -> Result<(), AdapterError> {
        self.check_time(now)?;
        if self.failed {
            return Err(AdapterError::Failed);
        }
        if self.pending.as_ref().is_some_and(|p| now >= p.deadline) {
            self.tick_at(session, now)?;
            return Err(AdapterError::ExpiredRequest);
        }
        // A2: late responses of already timed-out generations are discarded
        // (no evidence); the poll then continues to the next frame so a
        // legitimate current response queued behind them is still found.
        // Bounded by `MAX_STALE_FRAMES_PER_POLL`; the wait polls again.
        for _ in 0..MAX_STALE_FRAMES_PER_POLL {
            let discarded_before = self.stale_discarded;
            let result = session.poll_pending();
            self.accept_poll(session, result, now)?;
            if self.stale_discarded == discarded_before {
                break;
            }
        }
        Ok(())
    }

    /// Phase 14.12 E3b: the attempt-bound observation step of one manual
    /// promotion attempt. It issues this attempt's OWN GET_TERM and waits for
    /// that one request, never longer than its deadline (`begin + request
    /// timeout`), in slices of `ATTEMPT_OBSERVATION_WAIT_SLICE` so a shutdown
    /// is seen between slices.
    ///
    /// The step only begins and accepts (`poll_at`); it never exposes `Ready`
    /// (the attempt's one `poll_observation_at` does) and never repeats: a
    /// timeout, failure or interruption ends the step, and a new request is
    /// issued only by a later attempt. A request that was already pending
    /// when the step started is never adopted — it is completed if its
    /// deadline has passed (the F2 expiry path), otherwise the shared slot is
    /// busy and nothing is issued. `shutdown_requested` is read before the
    /// request is issued and before every poll.
    ///
    /// `clock` and `pause` are injected so the step is deterministic under a
    /// virtual clock; production passes `Instant::now` and `thread::sleep`.
    #[allow(dead_code)] // production use is Linux-only; tests exercise it everywhere
    pub(crate) fn complete_attempt_observation(
        &mut self,
        session: &mut WitnessSession,
        expectation: AuthorityViewExpectation,
        shutdown_requested: &dyn Fn() -> bool,
        clock: &mut dyn FnMut() -> Instant,
        pause: &mut dyn FnMut(Duration),
    ) -> AttemptObservationWait {
        if shutdown_requested() {
            return AttemptObservationWait::NotIssued("shutdown requested");
        }
        let now = clock();
        if self.expire_pending_at(session, now).is_err() {
            return AttemptObservationWait::Failed;
        }
        if self.pending.is_some() || self.delivery.is_some() || session.request_in_flight() {
            return AttemptObservationWait::NotIssued("Witness session is busy");
        }
        if self.start_at(session, expectation, now).is_err() {
            return AttemptObservationWait::NotIssued("GET_TERM could not be issued");
        }
        let Some(deadline) = self.pending.as_ref().map(|pending| pending.deadline) else {
            return AttemptObservationWait::Failed;
        };
        loop {
            if shutdown_requested() {
                return AttemptObservationWait::Interrupted;
            }
            let now = clock();
            if now >= deadline {
                // The request timed out: the existing expiry path completes it
                // as `Unavailable(Timeout)`, drains its token and frees the slot.
                return match self.expire_pending_at(session, now) {
                    Ok(_) => AttemptObservationWait::Resolved,
                    Err(_) => AttemptObservationWait::Failed,
                };
            }
            if self.poll_at(session, now).is_err() {
                // A classified terminal transport failure has already
                // completed the request as `Unavailable` (as in
                // `poll_observation_at`); the attempt's one evaluate then
                // reports it. Every other error leaves no completion.
                return if self.completed_unavailable().is_some() {
                    AttemptObservationWait::Resolved
                } else {
                    AttemptObservationWait::Failed
                };
            }
            if self.pending.is_none() {
                // A shutdown that arrived with the answer still wins: the
                // attempt is not evaluated (the accepted completion is only
                // ever exposed by an evaluate, which a blocked attempt skips).
                return if shutdown_requested() {
                    AttemptObservationWait::Interrupted
                } else {
                    AttemptObservationWait::Resolved
                };
            }
            pause(ATTEMPT_OBSERVATION_WAIT_SLICE.min(deadline - now));
        }
    }

    /// Raise the settled-generation watermark (never lowers it).
    fn settle(&mut self, generation: u64) {
        self.settled_generation = self.settled_generation.max(generation);
    }

    /// The generation number of a request id this adapter issued
    /// (`<namespace>-<generation>`), if the id is EXACTLY such an id: the
    /// canonical decimal form only, so an alias that merely parses to an owed
    /// generation (`+1`, `01`) is not this adapter's id and is never
    /// discarded as a late answer.
    fn own_generation(&self, id: &RequestId) -> Option<u64> {
        let generation: u64 = id
            .as_str()
            .strip_prefix(self.request_namespace.as_str())?
            .strip_prefix('-')?
            .parse()
            .ok()?;
        (id.as_str() == format!("{}-{generation}", self.request_namespace)).then_some(generation)
    }

    fn accept_poll(
        &mut self,
        session: &mut WitnessSession,
        result: Result<WitnessPoll, WitnessRuntimeError>,
        now: Instant,
    ) -> Result<(), AdapterError> {
        self.check_time(now)?;
        match result {
            Ok(WitnessPoll::NoFrame) => {
                self.last_time = Some(now);
                Ok(())
            }
            Ok(WitnessPoll::Pending(pending, provenance)) => {
                // A2 (checked first): the frame has already been
                // authenticated and validated for cluster, identity, session
                // and sequence by `poll_pending`. It is discarded ONLY if it
                // is a TermStatus response, from this session's provenance,
                // for a request id of this adapter whose generation is above the
                // settled watermark and below the current one (hence completed
                // as a timeout and not yet answered), on an adapter that has not
                // failed. Everything else falls through to the unchanged
                // fail-closed paths.
                if Arc::ptr_eq(&session.provenance(), &provenance)
                    && matches!(
                        pending.message().unsigned().message,
                        crate::protocol::ProtocolMessage::TermStatus(_)
                    )
                    && let Some(generation) = pending
                        .message()
                        .unsigned()
                        .common
                        .request_id
                        .as_ref()
                        .and_then(|id| self.own_generation(id))
                    && !self.failed
                    && generation < self.request_generation
                    && self.settled_generation < generation
                {
                    session
                        .discard_stale_response(&pending)
                        .map_err(AdapterError::Runtime)?;
                    self.settle(generation);
                    self.stale_discarded += 1;
                    self.last_time = Some(now);
                    return Ok(());
                }
                let current = self
                    .pending
                    .as_ref()
                    .ok_or(AdapterError::NoPendingRequest)?;
                if !Arc::ptr_eq(&current.connection_provenance, &provenance)
                    || !Arc::ptr_eq(&session.provenance(), &provenance)
                {
                    return Err(AdapterError::ConnectionProvenanceMismatch);
                }
                if now >= current.deadline {
                    return Err(AdapterError::ExpiredRequest);
                }
                let request_generation = current.request_generation;
                let response = session
                    .handle_pending_response(&pending)
                    .map_err(AdapterError::Runtime)?;
                let WitnessResponseObservation::TermStatus(payload) = response else {
                    unreachable!("GET_TERM response matrix");
                };
                self.pending = None;
                self.settle(request_generation);
                // Stage 13.3: classify the authenticated, correlated
                // TermStatus against the local authority context captured
                // at request begin, then immediately deliver the semantic
                // observation token to fusion — compatible or not.
                let expectation = self.expectation.take().unwrap_or_else(|| {
                    // Defensive: an observation begun without an
                    // expectation cannot verify Self claims — every
                    // holder classifies as foreign (fail closed).
                    AuthorityViewExpectation::new(crate::protocol::NodeId::new(""), None, None)
                });
                let compatibility = classify_authority_view(&payload, &expectation);
                self.deliver_authority_view(&payload, compatibility, now)?;
                self.last_authority_view = Some((compatibility, payload.lease_remaining_ms));
                self.last_completion = Some(Completion::TermStatus(payload));
                self.last_completion_request_generation = Some(request_generation);
                self.last_completion_at = Some(now);
                self.last_time = Some(now);
                Ok(())
            }
            Ok(WitnessPoll::Eof) => {
                self.failed = true;
                self.complete_unavailable(session, UnavailableCause::Transport, now)
            }
            Err(error) if transient(&error) => {
                self.last_time = Some(now);
                Ok(())
            }
            Err(error) => {
                if terminal(&error) {
                    self.failed = true;
                    if self.pending.is_some() {
                        self.complete_unavailable(session, UnavailableCause::Transport, now)?;
                    }
                }
                Err(AdapterError::Runtime(error))
            }
        }
    }

    /// Mint and deliver the fusion observation token for an accepted
    /// TermStatus completion. Compatible classifications become
    /// `WitnessStatus::AuthorityViewCompatible`; every other class
    /// becomes `AuthorityViewIncompatible` — the Witness answered, but
    /// its view cannot support authorization.
    fn deliver_authority_view(
        &mut self,
        payload: &crate::protocol::TermStatusPayload,
        compatibility: AuthorityViewCompatibility,
        now: Instant,
    ) -> Result<(), AdapterError> {
        let status = if compatibility.is_compatible() {
            WitnessStatus::AuthorityViewCompatible
        } else {
            WitnessStatus::AuthorityViewIncompatible
        };
        let holder = match &payload.current_holder {
            None => WitnessHolder::None,
            Some(_) => match compatibility {
                AuthorityViewCompatibility::CompatibleSelfUnexpired => WitnessHolder::Local,
                _ => WitnessHolder::Peer,
            },
        };
        let Some(generation) = self.observation_generation.checked_add(1) else {
            self.failed = true;
            return Err(AdapterError::GenerationExhausted);
        };
        self.observation_generation = generation;
        let token = WitnessObservation {
            origin: Arc::clone(&self.fusion.observation_origin),
            generation,
            observed_at: now,
            data: ObservationData {
                status,
                boot_id: None,
                term: Some(payload.current_term.0),
                holder,
            },
        };
        self.fusion
            .observe_witness(token, now)
            .map_err(AdapterError::Fusion)
    }

    /// Begin one caller-driven authority observation.  The response is
    /// completed only by a later `poll_observation_at` call.
    ///
    /// `expectation` is the local authority context captured for this
    /// request: the TermStatus holder classification is evaluated
    /// against it at acceptance. It is observation input only, never
    /// evidence and never authority.
    #[allow(dead_code)]
    pub(crate) fn begin_observation_at(
        &mut self,
        session: &mut WitnessSession,
        expectation: AuthorityViewExpectation,
        now: Instant,
    ) -> Result<RequestId, AdapterError> {
        self.start_at(session, expectation, now)
    }

    /// Poll the current observation and expose only a completion produced by
    /// this request generation.  Stored historical completions cannot make a
    /// new observation ready.
    ///
    /// A single request generation yields at most one `Ready` current-term
    /// observation.  Once exposed it is consumed; obtaining another current
    /// term requires a new `begin_observation_at` and a new correlated
    /// GET_TERM completion.  The freshness epoch is the completion acceptance
    /// time, never the poll time.
    #[allow(dead_code)]
    pub(crate) fn poll_observation_at(
        &mut self,
        session: &mut WitnessSession,
        now: Instant,
    ) -> Result<ObservationProgress, AdapterError> {
        self.check_time(now)?;

        // Evidence freshness follows the observation poll time: witness
        // evidence that expired between request begin and response acceptance
        // is stale at the observation epoch and must already be recomputed out.
        self.fusion.tick(now).map_err(AdapterError::Fusion)?;

        // A terminal local Unavailable is already decided: finish it without
        // polling the socket again, so a later late frame cannot wedge the
        // token or surface an unrelated correlation error.
        if self.completed_unavailable().is_some() {
            return self.finish_unavailable(now);
        }

        // poll_at reports an expired request as an error after issuing the
        // one-time local Unavailable completion. A classified terminal
        // transport failure likewise completes the pending request and issues
        // the local Unavailable token. Normalize those two cases so the
        // observation lifecycle reports a finished `Unavailable` observation
        // and drains its token in the same call. Authentication, semantic,
        // protocol, and provenance errors leave the request pending (or the
        // completion non-Unavailable) and therefore stay fail-closed.
        if let Err(error) = self.poll_at(session, now) {
            let normalized = matches!(error, AdapterError::ExpiredRequest)
                || self.completed_unavailable().is_some();
            if normalized {
                return self.finish_unavailable(now);
            }
            return Err(error);
        }

        if self.pending.is_some() {
            let expired = self
                .pending
                .as_ref()
                .is_some_and(|pending| now >= pending.deadline);
            if expired {
                // Defensive: route the timeout through the normal lifecycle
                // mutation so any Unavailable is backed by an evidence token
                // and an incremented observation generation.
                self.tick_at(session, now)?;
                return self.finish_unavailable(now);
            }
            return Ok(ObservationProgress::AwaitingWitnessTerm);
        }

        let progressed = self.progressed_generation == Some(self.request_generation);
        if !progressed
            && let (
                Some(Completion::TermStatus(payload)),
                Some(generation),
                Some(accepted_at),
                Some((compatibility, lease_remaining_ms)),
            ) = (
                &self.last_completion,
                self.last_completion_request_generation,
                self.last_completion_at,
                self.last_authority_view,
            )
            && generation == self.request_generation
        {
            let evidence = WitnessAuthorityViewEvidence {
                term: payload.current_term,
                compatibility,
                lease_remaining_ms,
                observed_at: accepted_at,
                request_generation: generation,
                observation_generation: self.observation_generation,
            };
            self.progressed_generation = Some(generation);
            return Ok(ObservationProgress::Ready(evidence));
        }

        if self.completed_unavailable().is_some() {
            return self.finish_unavailable(now);
        }

        Ok(ObservationProgress::AwaitingWitnessTerm)
    }

    /// The terminal local Unavailable cause for the current request, if any.
    /// `pending` must be cleared: a still-pending request is not a completed
    /// observation.
    fn completed_unavailable(&self) -> Option<UnavailableCause> {
        if self.pending.is_some() {
            return None;
        }
        match &self.last_completion {
            Some(Completion::Unavailable(cause)) => Some(*cause),
            _ => None,
        }
    }

    /// Finish a completed local Unavailable observation: drain exactly one
    /// queued fusion token (preserving its source completion time) and report
    /// the classification. Idempotent; absence of a token is a no-op.
    fn finish_unavailable(&mut self, now: Instant) -> Result<ObservationProgress, AdapterError> {
        let Some(cause) = self.completed_unavailable() else {
            return Ok(ObservationProgress::AwaitingWitnessTerm);
        };
        self.drain_observation_token(now)?;
        Ok(ObservationProgress::Unavailable(cause))
    }

    /// Idempotently drain the queued fusion token for a terminal Unavailable
    /// observation.  Delivery preserves the source completion time; absence of
    /// a token is a no-op.
    fn drain_observation_token(&mut self, now: Instant) -> Result<(), AdapterError> {
        if self.delivery.is_some() {
            self.deliver_at(now)?;
        }
        Ok(())
    }

    fn complete_unavailable(
        &mut self,
        session: &mut WitnessSession,
        cause: UnavailableCause,
        now: Instant,
    ) -> Result<(), AdapterError> {
        if self.pending.take().is_none() {
            return Err(AdapterError::NoPendingRequest);
        }
        self.expectation = None;
        session.reset_outstanding();
        self.last_time = Some(now);
        let Some(generation) = self.observation_generation.checked_add(1) else {
            self.failed = true;
            return Err(AdapterError::GenerationExhausted);
        };
        self.observation_generation = generation;
        self.last_completion = Some(Completion::Unavailable(cause));
        self.delivery = Some(WitnessObservation {
            origin: Arc::clone(&self.fusion.observation_origin),
            generation,
            observed_at: now,
            data: ObservationData {
                status: WitnessStatus::Unavailable,
                boot_id: None,
                term: None,
                holder: WitnessHolder::Unknown,
            },
        });
        Ok(())
    }

    /// Consume the queued token even on rejection. Never remint a rejected completion.
    pub fn deliver_at(&mut self, now: Instant) -> Result<bool, AdapterError> {
        self.check_time(now)?;
        let Some(token) = self.delivery.take() else {
            return Ok(false);
        };
        self.last_time = Some(now);
        self.fusion
            .observe_witness(token, now)
            .map_err(AdapterError::Fusion)?;
        Ok(true)
    }

    /// Feed the current peer assessment plus the fresh local loss
    /// evidence minted by the sole detector owner for this observation
    /// transaction. `local_loss` is `Some` only while the assessment is
    /// `CommunicationLost` with a live epoch; recovery or invalidation
    /// passes `None`, clearing any stored evidence.
    pub fn observe_peer_at(
        &mut self,
        peer: PeerFailureAssessment,
        local_loss: Option<crate::failure_assessment::LocalLossEvidence>,
        now: Instant,
    ) -> Result<(), AdapterError> {
        self.check_time(now)?;
        self.fusion
            .observe_peer(peer, local_loss, now)
            .map_err(AdapterError::Fusion)?;
        self.last_time = Some(now);
        Ok(())
    }
}

fn io_error(error: &WitnessRuntimeError) -> Option<&io::Error> {
    match error {
        WitnessRuntimeError::Tcp(TcpError::Io(e) | TcpError::Transport(TransportError::Io(e))) => {
            Some(e)
        }
        _ => None,
    }
}
fn transient(error: &WitnessRuntimeError) -> bool {
    io_error(error).is_some_and(|e| {
        matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
        )
    })
}
fn terminal(error: &WitnessRuntimeError) -> bool {
    io_error(error).is_some_and(|e| {
        matches!(
            e.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
        )
    }) || matches!(
        error,
        WitnessRuntimeError::Tcp(TcpError::Transport(
            TransportError::TruncatedPrefix | TransportError::TruncatedPayload
        ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        CborSerializer, ClusterId, CommonFields, NodeId, PROTOCOL_VERSION, ProtocolMessage,
        Sequence, SessionId, Term, UnsignedEnvelope,
    };
    use crate::security::MessageAuthenticator;
    use crate::security::Psk;
    use crate::session::ProcessSession;
    use crate::tcp::TcpConnection;
    use crate::witness_runtime::{
        PendingWitnessMessage, WitnessConnection, WitnessRequestOutstanding,
    };
    use std::net::{TcpListener, TcpStream};
    use std::ops::{Deref, DerefMut};

    fn auth() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]))
    }

    /// Default authority-view expectation for request lifecycle tests:
    /// local node `a`, no installed lease authority.
    fn expectation() -> AuthorityViewExpectation {
        AuthorityViewExpectation::new(NodeId::new("a"), None, None)
    }

    /// Fresh local-loss evidence epoch for `CommunicationLost` inputs.
    fn fresh_loss(at: Instant) -> Option<crate::failure_assessment::LocalLossEvidence> {
        Some(crate::failure_assessment::LocalLossEvidence::new_for_test(
            1, at,
        ))
    }

    /// Test harness: pairs the observation-only adapter with its neutral
    /// session, mirroring the production composition shape (session + observer).
    struct Harness {
        adapter: WitnessEvidenceAdapter,
        session: WitnessSession,
        /// Phase 14.12 RW-1: a duplicate handle on the SAME client socket the
        /// session reads (set by `e3b_fixture_with`), used only to ask the
        /// kernel how many bytes are waiting to be read. It never reads.
        probe: Option<TcpStream>,
        /// Phase 14.12 RW-2: the scripted Witness's socket descriptor (NOT a
        /// duplicate: a duplicate would keep the connection open after a test
        /// drops the Witness). Used only while the Witness's `TcpConnection`
        /// is alive, to ask the kernel whether everything it wrote has been
        /// acknowledged by the adapter's socket.
        server_fd: Option<std::os::fd::RawFd>,
    }

    impl Deref for Harness {
        type Target = WitnessEvidenceAdapter;
        fn deref(&self) -> &Self::Target {
            &self.adapter
        }
    }
    impl DerefMut for Harness {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.adapter
        }
    }
    impl Harness {
        fn new(connection: WitnessConnection, process: ProcessSession, timeout: Duration) -> Self {
            let mut session = WitnessSession::new(connection, process, auth());
            session.reset_outstanding();
            let adapter = WitnessEvidenceAdapter::new(timeout).unwrap();
            Self {
                adapter,
                session,
                probe: None,
                server_fd: None,
            }
        }
        /// Phase 14.12 RW-2: the adapter's socket descriptor (through the
        /// duplicate handle `probe`, which shares the socket).
        fn client_fd(&self) -> std::os::fd::RawFd {
            std::os::fd::AsRawFd::as_raw_fd(
                self.probe.as_ref().expect("fixture has a probe handle"),
            )
        }
        fn start_at(&mut self, now: Instant) -> Result<RequestId, AdapterError> {
            self.adapter.start_at(&mut self.session, expectation(), now)
        }
        fn tick_at(&mut self, now: Instant) -> Result<(), AdapterError> {
            self.adapter.tick_at(&mut self.session, now)
        }
        fn poll_at(&mut self, now: Instant) -> Result<(), AdapterError> {
            self.adapter.poll_at(&mut self.session, now)
        }
        fn begin_observation_at(&mut self, now: Instant) -> Result<RequestId, AdapterError> {
            self.adapter
                .begin_observation_at(&mut self.session, expectation(), now)
        }
        fn poll_observation_at(
            &mut self,
            now: Instant,
        ) -> Result<ObservationProgress, AdapterError> {
            self.adapter.poll_observation_at(&mut self.session, now)
        }
        fn accept_poll(
            &mut self,
            result: Result<WitnessPoll, WitnessRuntimeError>,
            now: Instant,
        ) -> Result<(), AdapterError> {
            self.adapter.accept_poll(&mut self.session, result, now)
        }
        fn provenance(&self) -> Arc<()> {
            self.session.provenance()
        }
        fn highest_sequence(&self) -> Sequence {
            self.session.highest_sequence_for_test()
        }
        fn receive_pending(&mut self) -> Result<PendingWitnessMessage, WitnessRuntimeError> {
            self.session.receive_pending_for_test()
        }
        fn wait_for_readable_for_test(&mut self) {
            self.session.wait_for_readable_for_test().unwrap();
        }
    }

    fn fixture() -> (Harness, TcpConnection, Instant) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let probe = client.try_clone().unwrap();
        let (server, _) = listener.accept().unwrap();
        let server_fd = std::os::fd::AsRawFd::as_raw_fd(&server);
        let connection = WitnessConnection::new(
            NodeId::new("a"),
            NodeId::new("w"),
            ClusterId::new("cluster"),
            SessionId::new("w-session"),
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let mut harness = Harness::new(
            connection,
            ProcessSession::from_session_id(SessionId::new("a-session")),
            Duration::from_secs(2),
        );
        harness.probe = Some(probe);
        harness.server_fd = Some(server_fd);
        (
            harness,
            TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
            Instant::now(),
        )
    }
    fn response(id: RequestId, seq: u64) -> UnsignedEnvelope {
        UnsignedEnvelope {
            common: CommonFields {
                protocol_version: PROTOCOL_VERSION,
                cluster_id: ClusterId::new("cluster"),
                sender_node_id: NodeId::new("w"),
                receiver_node_id: NodeId::new("a"),
                session_id: SessionId::new("w-session"),
                sequence: Sequence(seq),
                term: Term(7),
                lease_id: None,
                request_id: Some(id),
                operation_id: None,
            },
            message: ProtocolMessage::TermStatus(TermStatusPayload {
                current_term: Term(7),
                current_holder: Some(NodeId::new("a")),
                current_lease_id: None,
                lease_remaining_ms: None,
            }),
        }
    }
    // Real framed TCP + existing HMAC, semantic, identity and correlation paths.
    // Blocking test receive follows a completed send; adapter clock is synthetic.
    fn receive(a: &mut Harness, now: Instant) -> Result<(), AdapterError> {
        let provenance = a.provenance();
        let result = a
            .receive_pending()
            .map(Box::new)
            .map(|pending| WitnessPoll::Pending(pending, provenance));
        a.accept_poll(result, now)
    }

    #[test]
    fn authenticated_term_status_delivers_authority_view_and_duplicate_has_no_effect() {
        let (mut a, mut server, t) = fixture();
        a.observe_peer_at(PeerFailureAssessment::CommunicationLost, fresh_loss(t), t)
            .unwrap();
        let id = a.start_at(t).unwrap();
        let wire = response(id, 1);
        server
            .send_message(wire.clone(), &CborSerializer, &auth())
            .unwrap();
        receive(&mut a, t).unwrap();
        let expected = match wire.message.clone() {
            ProtocolMessage::TermStatus(p) => p,
            _ => unreachable!(),
        };
        let before = a.snapshot();
        assert_eq!(
            before.last_completion,
            Some(Completion::TermStatus(expected))
        );
        assert!(before.pending.is_none());
        assert!(!before.delivery_pending);
        // The accepted TermStatus minted exactly one authority-view token.
        // The scripted holder is Self with no remaining lease data, which
        // classifies as ExpiredButUnprocessed -> AuthorityViewIncompatible.
        assert_eq!(before.observation_generation, 1);
        assert_eq!(before.fusion.witness_boot_id, None);
        assert_eq!(
            before.fusion.witness_status,
            WitnessStatus::AuthorityViewIncompatible
        );
        assert_eq!(before.fusion.witness_term, Some(7));
        assert_eq!(before.fusion.witness_holder, WitnessHolder::Peer);
        assert_eq!(
            before.fusion.state,
            super::super::EvidenceFusionState::AmbiguousPartition
        );
        server.send_message(wire, &CborSerializer, &auth()).unwrap();
        assert!(receive(&mut a, t).is_err());
        assert_eq!(a.snapshot(), before);
    }

    #[cfg(unix)]
    #[test]
    fn begin_observation_is_pending_until_correlated_completion() {
        let (mut adapter, mut server, started_at) = fixture();
        adapter.begin_observation_at(started_at).unwrap();
        assert!(matches!(
            adapter.poll_observation_at(started_at).unwrap(),
            ObservationProgress::AwaitingWitnessTerm
        ));

        let accepted_at = started_at + Duration::from_secs(1);
        let request_id = adapter.snapshot().pending.unwrap().request_id;
        server
            .send_message(response(request_id, 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        assert!(matches!(
            adapter.poll_observation_at(accepted_at).unwrap(),
            ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                term: Term(7),
                observed_at,
                ..
            }) if observed_at == accepted_at
        ));
    }

    #[cfg(unix)]
    #[test]
    fn current_term_observation_is_one_shot_with_acceptance_time_freshness() {
        let (mut adapter, mut server, started_at) = fixture();
        let request_id = adapter.begin_observation_at(started_at).unwrap();
        let accepted_at = started_at + Duration::from_millis(500);
        let poll_at = started_at + Duration::from_secs(1);
        server
            .send_message(response(request_id, 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();

        // First poll: Ready with the completion acceptance time, not the poll time.
        assert!(matches!(
            adapter.poll_observation_at(accepted_at).unwrap(),
            ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                term: Term(7),
                observed_at,
                ..
            }) if observed_at == accepted_at
        ));

        // A later poll of the same generation must not remint Ready or freshness.
        assert!(matches!(
            adapter.poll_observation_at(poll_at).unwrap(),
            ObservationProgress::AwaitingWitnessTerm
        ));
    }

    #[cfg(unix)]
    #[test]
    fn previous_completion_cannot_make_a_new_observation_ready() {
        let (mut adapter, mut server, started_at) = fixture();
        let first = adapter.begin_observation_at(started_at).unwrap();
        server
            .send_message(response(first, 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        assert!(matches!(
            adapter.poll_observation_at(started_at).unwrap(),
            ObservationProgress::Ready(_)
        ));

        let next_at = started_at + Duration::from_secs(1);
        adapter.begin_observation_at(next_at).unwrap();
        assert!(matches!(
            adapter.poll_observation_at(next_at).unwrap(),
            ObservationProgress::AwaitingWitnessTerm
        ));
    }

    #[test]
    fn deadline_poll_reports_unavailable_timeout_and_delivers_evidence_once() {
        let (mut adapter, _server, started_at) = fixture();
        adapter
            .observe_peer_at(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(started_at),
                started_at,
            )
            .unwrap();
        adapter.begin_observation_at(started_at).unwrap();

        let deadline = started_at + Duration::from_secs(2);
        assert_eq!(
            adapter.poll_observation_at(deadline).unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Timeout)
        );
        assert!(adapter.snapshot().pending.is_none());
        assert_eq!(adapter.snapshot().observation_generation, 1);
        // The queued local Unavailable token is drained, not left pending.
        assert!(!adapter.snapshot().delivery_pending);
        // The drained token actually reached fusion, once, with the source
        // completion time (not a later poll time).
        let fusion = adapter.snapshot().fusion;
        assert_eq!(fusion.witness_status, WitnessStatus::Unavailable);
        assert_eq!(fusion.witness_observed_at, Some(deadline));
        assert_eq!(
            fusion.state,
            super::super::EvidenceFusionState::AmbiguousPartition
        );

        // Re-poll is idempotent: still Unavailable, no second token/generation,
        // and no additional fusion mutation.
        assert_eq!(
            adapter.poll_observation_at(deadline).unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Timeout)
        );
        assert_eq!(adapter.snapshot().observation_generation, 1);
        assert!(!adapter.snapshot().delivery_pending);
        assert_eq!(adapter.snapshot().fusion, fusion);

        // A subsequent observation is not permanently wedged as Busy.
        let next = adapter.begin_observation_at(deadline).unwrap();
        assert_eq!(adapter.snapshot().pending.unwrap().request_id, next);
    }

    #[test]
    fn classified_terminal_error_is_surfaced_and_drained_in_first_observation_poll() {
        let (mut adapter, _server, started_at) = fixture();
        adapter
            .observe_peer_at(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(started_at),
                started_at,
            )
            .unwrap();
        adapter.begin_observation_at(started_at).unwrap();

        // Terminal read/reset classified at the documented poll boundary: the
        // request completes and one Unavailable token is queued, while the
        // lower-level accept_poll still reports the transport error.
        assert!(
            adapter
                .accept_poll(
                    Err(WitnessRuntimeError::Tcp(TcpError::Io(io::Error::from(
                        io::ErrorKind::ConnectionReset
                    )))),
                    started_at,
                )
                .is_err()
        );
        assert_eq!(adapter.snapshot().observation_generation, 1);

        // The observation lifecycle must expose that completion as
        // Unavailable(Transport) and drain it in the same call.
        assert_eq!(
            adapter.poll_observation_at(started_at).unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Transport)
        );
        assert!(!adapter.snapshot().delivery_pending);
        assert_eq!(
            adapter.snapshot().fusion.witness_status,
            WitnessStatus::Unavailable
        );
    }

    #[cfg(unix)]
    #[test]
    fn auth_semantic_error_is_not_normalized_to_transport_unavailable() {
        let (mut adapter, mut server, started_at) = fixture();
        adapter.begin_observation_at(started_at).unwrap();
        let request_id = adapter.snapshot().pending.unwrap().request_id;
        let bad_auth = MessageAuthenticator::new(Psk::from_test_bytes([0x66; 32]));
        server
            .send_message(response(request_id, 1), &CborSerializer, &bad_auth)
            .unwrap();
        adapter.wait_for_readable_for_test();

        // An authentication rejection is not a terminal transport failure: it
        // stays fail-closed and must not become Unavailable or Ready.
        assert!(matches!(
            adapter.poll_observation_at(started_at),
            Err(AdapterError::Runtime(_))
        ));
        assert!(adapter.snapshot().pending.is_some());
        assert_eq!(adapter.snapshot().observation_generation, 0);
        assert_eq!(
            adapter.snapshot().fusion.witness_status,
            WitnessStatus::Unknown
        );
    }

    #[cfg(unix)]
    #[test]
    fn new_begin_and_completion_yield_a_second_ready_observation() {
        let (mut adapter, mut server, started_at) = fixture();
        let first = adapter.begin_observation_at(started_at).unwrap();
        server
            .send_message(response(first.clone(), 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        let first_ready = adapter.poll_observation_at(started_at).unwrap();
        assert!(matches!(
            first_ready,
            ObservationProgress::Ready(WitnessAuthorityViewEvidence { term: Term(7), .. })
        ));
        // Consumed: same generation cannot yield Ready again.
        assert!(matches!(
            adapter.poll_observation_at(started_at).unwrap(),
            ObservationProgress::AwaitingWitnessTerm
        ));

        let next_at = started_at + Duration::from_secs(1);
        let second = adapter.begin_observation_at(next_at).unwrap();
        assert_ne!(first, second);
        assert!(matches!(
            adapter.poll_observation_at(next_at).unwrap(),
            ObservationProgress::AwaitingWitnessTerm
        ));
        server
            .send_message(response(second, 2), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        assert!(matches!(
            adapter.poll_observation_at(next_at).unwrap(),
            ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                term: Term(7),
                observed_at,
                ..
            }) if observed_at == next_at
        ));
    }

    #[test]
    fn forced_request_id_collision_from_old_connection_is_rejected() {
        let (mut old, mut old_server, t) = fixture();
        let old_id = old.start_at(t).unwrap();
        old_server
            .send_message(response(old_id.clone(), 1), &CborSerializer, &auth())
            .unwrap();
        let old_pending = old.receive_pending().unwrap();
        let old_provenance = old.provenance();
        let old_namespace = old.request_namespace.clone();

        let (mut current, _current_server, current_time) = fixture();
        current.request_namespace = old_namespace;
        let current_id = current.start_at(current_time).unwrap();
        assert_eq!(current_id, old_id);
        let before = current.snapshot();
        let result = current.accept_poll(
            Ok(WitnessPoll::Pending(Box::new(old_pending), old_provenance)),
            current_time,
        );
        assert!(matches!(
            result,
            Err(AdapterError::ConnectionProvenanceMismatch)
        ));
        assert_eq!(current.snapshot(), before);
        assert_eq!(current.observation_generation, 0);
        assert!(current.delivery.is_none());
    }

    #[test]
    fn same_connection_provenance_is_required_alongside_request_id() {
        let (mut current, mut server, t) = fixture();
        let id = current.start_at(t).unwrap();
        let mut pending = response(id, 1);
        pending.common.request_id = Some(RequestId::new("wrong-request"));
        server
            .send_message(pending, &CborSerializer, &auth())
            .unwrap();
        let before = current.snapshot();
        assert!(matches!(
            receive(&mut current, t),
            Err(AdapterError::Runtime(
                WitnessRuntimeError::RequestIdMismatch { .. }
            ))
        ));
        assert_eq!(current.snapshot(), before);
        assert_eq!(current.observation_generation, 0);
    }

    #[test]
    fn auth_wrong_identity_and_wrong_correlation_do_not_complete_or_issue() {
        let (mut a, mut server, t) = fixture();
        let id = a.start_at(t).unwrap();
        let before = a.snapshot();
        let bad_auth = MessageAuthenticator::new(Psk::from_test_bytes([0x66; 32]));
        server
            .send_message(response(id.clone(), 1), &CborSerializer, &bad_auth)
            .unwrap();
        assert!(receive(&mut a, t).is_err());
        assert_eq!(a.snapshot(), before);
        for field in 0..5 {
            let mut wire = response(id.clone(), 2);
            match field {
                0 => wire.common.cluster_id = ClusterId::new("wrong"),
                1 => wire.common.sender_node_id = NodeId::new("wrong"),
                2 => wire.common.receiver_node_id = NodeId::new("wrong"),
                3 => wire.common.session_id = SessionId::new("wrong"),
                _ => wire.common.request_id = Some(RequestId::new("wrong")),
            }
            server.send_message(wire, &CborSerializer, &auth()).unwrap();
            assert!(receive(&mut a, t).is_err());
            assert_eq!(a.snapshot(), before);
            assert_eq!(a.highest_sequence(), Sequence(0));
        }
        server.send_payload(&[0xff]).unwrap();
        assert!(receive(&mut a, t).is_err());
        assert_eq!(a.snapshot(), before);
        // Authenticated but semantically invalid: sign bypasses send_message validation.
        let mut wire = response(id, 3);
        wire.common.request_id = None;
        use crate::protocol::CanonicalSerializer;
        let signed = auth().sign(wire, &CborSerializer).unwrap();
        server
            .send_payload(&CborSerializer.serialize_wire(&signed).unwrap())
            .unwrap();
        assert!(receive(&mut a, t).is_err());
        assert_eq!(a.snapshot(), before);
    }

    #[test]
    fn timeout_once_then_late_a_cannot_change_current_b() {
        let (mut a, mut server, t) = fixture();
        let id = a.start_at(t).unwrap();
        a.tick_at(t + Duration::from_secs(2) - Duration::from_nanos(1))
            .unwrap();
        assert_eq!(a.snapshot().observation_generation, 0);
        a.tick_at(t + Duration::from_secs(2)).unwrap();
        assert!(a.snapshot().pending.is_none());
        assert_eq!(a.snapshot().observation_generation, 1);
        assert_eq!(
            a.delivery.as_ref().unwrap().observed_at,
            t + Duration::from_secs(2)
        );
        a.tick_at(t + Duration::from_secs(2)).unwrap();
        assert_eq!(a.snapshot().observation_generation, 1);
        assert!(a.deliver_at(t + Duration::from_secs(2)).unwrap());
        assert!(!a.deliver_at(t + Duration::from_secs(2)).unwrap());
        let b = a.start_at(t + Duration::from_secs(2)).unwrap();
        assert_ne!(b, id);
        let before = a.snapshot();
        server
            .send_message(response(id, 1), &CborSerializer, &auth())
            .unwrap();
        // F1/A2: the late response of the generation that really timed out is
        // discarded without any effect on the current request (it is NOT an
        // error any more, and it still cannot change current B).
        receive(&mut a, t + Duration::from_secs(2)).unwrap();
        assert_eq!(a.snapshot(), before);
        a.tick_at(t + Duration::from_secs(4)).unwrap();
        assert_eq!(a.snapshot().observation_generation, 2);
    }

    #[test]
    fn expired_and_unsolicited_success_do_not_replace_timeout() {
        let (mut a, mut server, t) = fixture();
        server
            .send_message(
                response(RequestId::new("unsolicited"), 1),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
        assert!(matches!(
            receive(&mut a, t),
            Err(AdapterError::NoPendingRequest)
        ));
        let id = a.start_at(t).unwrap();
        let before = a.snapshot();
        server
            .send_message(response(id.clone(), 2), &CborSerializer, &auth())
            .unwrap();
        assert!(matches!(
            receive(&mut a, t + Duration::from_secs(2)),
            Err(AdapterError::ExpiredRequest)
        ));
        assert_eq!(a.snapshot(), before);
        a.tick_at(t + Duration::from_secs(2)).unwrap();
        let before = a.snapshot();
        server
            .send_message(response(id, 3), &CborSerializer, &auth())
            .unwrap();
        assert!(matches!(
            receive(&mut a, t + Duration::from_secs(2)),
            Err(AdapterError::NoPendingRequest)
        ));
        assert_eq!(a.snapshot(), before);
    }

    #[test]
    fn eof_issues_one_terminal_unavailable_and_no_retry() {
        let (mut a, _server, t) = fixture();
        a.start_at(t).unwrap();
        // Deterministic test-only fault at the same result boundary used by poll_at.
        assert!(!a.session_lost(), "a fresh adapter has a live session");
        a.accept_poll(Ok(WitnessPoll::Eof), t).unwrap();
        assert!(a.snapshot().failed);
        assert!(a.session_lost(), "EOF is a lost session (ADD-7)");
        assert!(a.snapshot().pending.is_none());
        assert_eq!(a.snapshot().observation_generation, 1);
        assert_eq!(
            a.snapshot().last_completion,
            Some(Completion::Unavailable(UnavailableCause::Transport))
        );
        assert!(matches!(a.poll_at(t), Err(AdapterError::Failed)));
        assert_eq!(a.snapshot().observation_generation, 1);
    }

    #[test]
    fn transient_no_frame_keeps_request_and_emits_nothing() {
        let (mut a, _server, t) = fixture();
        a.start_at(t).unwrap();
        let before = a.snapshot();
        a.poll_at(t).unwrap();
        assert_eq!(a.snapshot(), before);
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::TimedOut,
        ] {
            a.accept_poll(
                Err(WitnessRuntimeError::Tcp(TcpError::Io(io::Error::from(
                    kind,
                )))),
                t,
            )
            .unwrap();
            assert_eq!(a.snapshot(), before);
        }
    }

    #[test]
    fn delivery_preserves_completion_time_at_four_and_six_seconds() {
        for delay in [4, 6] {
            let (mut a, _server, t) = fixture();
            a.observe_peer_at(PeerFailureAssessment::CommunicationLost, fresh_loss(t), t)
                .unwrap();
            a.start_at(t).unwrap();
            let completed = t + Duration::from_secs(2);
            a.tick_at(completed).unwrap();
            assert!(
                a.deliver_at(completed + Duration::from_secs(delay))
                    .unwrap()
            );
            let s = a.snapshot();
            assert_eq!(s.fusion.witness_observed_at, Some(completed));
            assert_eq!(s.observation_generation, 1);
            assert_eq!(
                s.fusion.state,
                if delay == 4 {
                    super::super::EvidenceFusionState::AmbiguousPartition
                } else {
                    super::super::EvidenceFusionState::Unproven
                }
            );
        }
    }

    #[test]
    fn fusion_rejection_consumes_token_without_reissuing() {
        for error in 0..3 {
            let (mut a, _server, t) = fixture();
            a.start_at(t).unwrap();
            let t = t + Duration::from_secs(2);
            a.tick_at(t).unwrap();
            match error {
                0 => a.fusion.observation_high_water = 1,
                1 => a.fusion.tick(t + Duration::from_secs(1)).unwrap(),
                _ => a.fusion = EvidenceFusion::with_default_timeout(),
            }
            assert!(matches!(a.deliver_at(t), Err(AdapterError::Fusion(_))));
            assert!(!a.deliver_at(t).unwrap());
            assert_eq!(a.snapshot().observation_generation, 1);
            a.tick_at(t + Duration::from_secs(2)).unwrap();
            assert!(!a.snapshot().delivery_pending);
        }
    }

    #[test]
    fn generation_overflow_clears_request_and_fails_closed() {
        let (mut a, _server, t) = fixture();
        a.start_at(t).unwrap();
        a.observation_generation = u64::MAX;
        assert!(matches!(
            a.tick_at(t + Duration::from_secs(2)),
            Err(AdapterError::GenerationExhausted)
        ));
        let s = a.snapshot();
        assert!(s.failed);
        assert!(s.pending.is_none());
        assert!(!s.delivery_pending);
        assert_eq!(s.observation_generation, u64::MAX);
        assert!(matches!(
            a.start_at(t + Duration::from_secs(2)),
            Err(AdapterError::Failed)
        ));
    }

    #[test]
    fn restart_has_new_request_namespace_and_rejects_old_response_and_token() {
        let (mut a, _server, t) = fixture();
        a.start_at(t).unwrap();
        a.tick_at(t + Duration::from_secs(2)).unwrap();
        let old_token = a.delivery.take().unwrap();
        let old_id = a.start_at(t + Duration::from_secs(2)).unwrap();
        assert_eq!(a.snapshot().pending.as_ref().unwrap().request_id, old_id);
        drop(a);
        let (mut b, mut server, t) = fixture();
        assert!(b.snapshot().pending.is_none());
        assert_eq!(b.snapshot().observation_generation, 0);
        server
            .send_message(response(old_id.clone(), 1), &CborSerializer, &auth())
            .unwrap();
        assert!(matches!(
            receive(&mut b, t),
            Err(AdapterError::NoPendingRequest)
        ));
        let new_id = b.start_at(t).unwrap();
        assert_ne!(new_id, old_id);
        server
            .send_message(response(old_id, 2), &CborSerializer, &auth())
            .unwrap();
        assert!(receive(&mut b, t).is_err());
        assert!(matches!(
            b.fusion
                .observe_witness(old_token, t + Duration::from_secs(10)),
            Err(EvidenceFusionError::InvalidObservation)
        ));
    }

    #[test]
    fn status_is_pure_and_backwards_clock_cannot_change_state() {
        let (mut a, _server, t) = fixture();
        a.start_at(t).unwrap();
        let before = a.snapshot();
        assert_eq!(a.snapshot(), before);
        assert!(a.delivery.is_none());
        let earlier = t - Duration::from_nanos(1);
        assert!(matches!(
            a.tick_at(earlier),
            Err(AdapterError::TimeWentBackwards)
        ));
        assert!(matches!(
            a.poll_at(earlier),
            Err(AdapterError::TimeWentBackwards)
        ));
        assert!(matches!(
            a.start_at(earlier),
            Err(AdapterError::TimeWentBackwards)
        ));
        assert!(matches!(
            a.deliver_at(earlier),
            Err(AdapterError::TimeWentBackwards)
        ));
        assert_eq!(a.snapshot(), before);
    }

    #[test]
    fn query_then_timeout_delivers_only_local_unavailable() {
        let (mut a, mut server, t) = fixture();
        a.observe_peer_at(PeerFailureAssessment::CommunicationLost, fresh_loss(t), t)
            .unwrap();
        let id = a.start_at(t).unwrap();
        server
            .send_message(response(id, 1), &CborSerializer, &auth())
            .unwrap();
        receive(&mut a, t).unwrap();
        assert!(!a.deliver_at(t).unwrap());
        a.start_at(t).unwrap();
        a.tick_at(t + Duration::from_secs(2)).unwrap();
        a.deliver_at(t + Duration::from_secs(2)).unwrap();
        assert_eq!(
            a.snapshot().fusion.state,
            super::super::EvidenceFusionState::AmbiguousPartition
        );
        assert_eq!(a.snapshot().observation_generation, 2);
        // Adapter owns only query transport + pure fusion: no HA resource or lease owner.
    }

    #[cfg(unix)]
    #[test]
    fn real_tcp_poll_reuses_authentication_and_correlation_pipeline() {
        let (mut a, mut server, t) = fixture();
        let id = a.start_at(t).unwrap();
        let request = server.receive_message(&CborSerializer, &auth()).unwrap();
        let crate::tcp::ReceiveMessageResult::Message(request) = request else {
            panic!("expected request")
        };
        assert_eq!(request.unsigned().common.request_id, Some(id.clone()));
        assert_eq!(request.unsigned().common.operation_id, None);
        assert_eq!(request.unsigned().message, ProtocolMessage::GetTerm);
        server
            .send_message(response(id, 1), &CborSerializer, &auth())
            .unwrap();
        a.wait_for_readable_for_test();
        a.poll_at(t).unwrap();
        assert!(a.snapshot().pending.is_none());
        assert!(matches!(
            a.snapshot().last_completion,
            Some(Completion::TermStatus(_))
        ));
        assert_eq!(a.highest_sequence(), Sequence(1));
        assert_eq!(a.snapshot().observation_generation, 1);
        assert!(!a.snapshot().delivery_pending);
    }

    #[test]
    fn terminal_transport_error_emits_once_but_auth_error_does_not() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::UnexpectedEof,
        ] {
            let (mut a, _server, t) = fixture();
            a.start_at(t).unwrap();
            assert!(
                a.accept_poll(
                    Err(WitnessRuntimeError::Tcp(TcpError::Io(io::Error::from(
                        kind
                    )))),
                    t
                )
                .is_err()
            );
            assert!(a.snapshot().pending.is_none());
            assert_eq!(a.snapshot().observation_generation, 1);
            assert!(a.snapshot().delivery_pending);
            assert!(a.poll_at(t).is_err());
            assert_eq!(a.snapshot().observation_generation, 1);
        }
    }

    #[test]
    fn one_request_one_delivery_slot_and_finite_deadline() {
        let (mut a, _server, t) = fixture();
        a.start_at(t).unwrap();
        let before = a.snapshot();
        assert!(matches!(a.start_at(t), Err(AdapterError::Busy)));
        assert_eq!(a.snapshot(), before);
        a.tick_at(t + Duration::from_secs(2)).unwrap();
        let before = a.snapshot();
        assert!(matches!(
            a.start_at(t + Duration::from_secs(2)),
            Err(AdapterError::Busy)
        ));
        assert_eq!(a.snapshot(), before);
        a.deliver_at(t + Duration::from_secs(2)).unwrap();
        a.request_generation = u64::MAX;
        assert!(matches!(
            a.start_at(t + Duration::from_secs(2)),
            Err(AdapterError::GenerationExhausted)
        ));
        assert_eq!(a.snapshot().request_generation, u64::MAX);
        a.request_generation = 1;
        a.request_timeout = Duration::MAX;
        assert!(matches!(
            a.start_at(t + Duration::from_secs(2)),
            Err(AdapterError::DeadlineOverflow)
        ));
        assert!(a.snapshot().pending.is_none());
    }

    // --- Phase 14.12 F1 (Option A: A1 expiry on begin, A2 late-response discard) ---

    /// Write one response and (Phase 14.12 RW-2) wait until it has reached
    /// the adapter's socket, so a later frame can never overtake the
    /// readability the test then waits for.
    fn f1_send(a: &Harness, server: &mut TcpConnection, id: RequestId, seq: u64) {
        server
            .send_message(response(id, seq), &CborSerializer, &auth())
            .unwrap();
        await_peer_received(
            a.server_fd.expect("fixture has the Witness descriptor"),
            a.client_fd(),
            "a response written by the scripted Witness",
        );
    }

    fn f1_ns(a: &Harness) -> String {
        a.adapter.request_namespace.clone()
    }

    /// T-F1-1 + deadline boundary: a pending request is never replaced inside
    /// its deadline (`now < deadline`), and at `now >= deadline` the expiry
    /// path completes it so the next begin succeeds.
    #[test]
    fn f1_a1_expired_pending_is_completed_by_begin_and_deadline_is_inclusive() {
        let (mut a, mut server, t) = fixture();
        let id1 = a.start_at(t).unwrap();
        f1_send(&a, &mut server, id1, 1); // the response arrives but is never polled
        let before = a.snapshot();
        assert!(matches!(
            a.start_at(t + Duration::from_secs(2) - Duration::from_nanos(1)),
            Err(AdapterError::Busy)
        ));
        assert_eq!(a.snapshot(), before, "inside the deadline nothing changes");
        let id2 = a.start_at(t + Duration::from_secs(2)).unwrap();
        let after = a.snapshot();
        assert_eq!(after.pending.as_ref().unwrap().request_id, id2);
        assert_eq!(after.pending.as_ref().unwrap().request_generation, 2);
        assert_eq!(after.observation_generation, 1, "one timeout completion");
        assert!(!after.delivery_pending, "its Unavailable token was drained");
        assert_eq!(a.stale_discarded, 0);
        assert_eq!(a.settled_generation, 0, "generation 1 is still owed");

        // One nanosecond past the deadline behaves the same way.
        let (mut b, _server_b, t) = fixture();
        b.start_at(t).unwrap();
        b.start_at(t + Duration::from_secs(2) + Duration::from_nanos(1))
            .unwrap();
        assert_eq!(b.snapshot().pending.unwrap().request_generation, 2);
    }

    /// T-F1-1 (single outstanding): begin after expiry never leaves two
    /// requests in flight; a failure to complete leaves no new request.
    #[test]
    fn f1_a1_begin_after_expiry_keeps_a_single_outstanding_request() {
        let (mut a, _server, t) = fixture();
        a.start_at(t).unwrap();
        assert!(a.session.request_in_flight());
        a.start_at(t + Duration::from_secs(3)).unwrap();
        assert!(a.session.request_in_flight());
        assert_eq!(a.snapshot().pending.unwrap().request_generation, 2);
        // A clock regression is refused before anything is touched.
        let before = a.snapshot();
        assert!(matches!(
            a.start_at(t),
            Err(AdapterError::TimeWentBackwards)
        ));
        assert_eq!(a.snapshot(), before);
    }

    /// T-F1-2: the legitimate late response of the timed-out generation is
    /// discarded (no evidence, sequence committed) and the current
    /// generation's response behind it becomes the only Ready observation.
    #[cfg(unix)]
    #[test]
    fn f1_a2_late_response_of_timed_out_generation_is_discarded_and_current_is_ready() {
        let (mut a, mut server, t) = fixture();
        let id1 = a.start_at(t).unwrap();
        f1_send(&a, &mut server, id1, 1);
        let t2 = t + Duration::from_secs(2);
        let id2 = a.start_at(t2).unwrap();
        f1_send(&a, &mut server, id2, 2);
        a.wait_for_readable_for_test();
        let ready = a
            .poll_observation_at(t2 + Duration::from_millis(100))
            .unwrap();
        assert!(matches!(
            ready,
            ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                request_generation: 2,
                ..
            })
        ));
        assert_eq!(a.stale_discarded, 1);
        assert_eq!(
            a.settled_generation, 2,
            "generation 1 discarded, generation 2 accepted"
        );
        assert_eq!(a.highest_sequence(), Sequence(2));
        // One-shot: nothing further is Ready.
        assert!(matches!(
            a.poll_observation_at(t2 + Duration::from_millis(200))
                .unwrap(),
            ObservationProgress::AwaitingWitnessTerm
        ));
    }

    /// A late response that arrives alone (current response not yet there)
    /// is discarded without producing evidence; the request stays pending.
    #[cfg(unix)]
    #[test]
    fn f1_a2_discard_alone_exposes_nothing_and_keeps_the_current_request_pending() {
        let (mut a, mut server, t) = fixture();
        let id1 = a.start_at(t).unwrap();
        f1_send(&a, &mut server, id1, 1);
        let t2 = t + Duration::from_secs(2);
        a.start_at(t2).unwrap();
        a.wait_for_readable_for_test();
        let progress = a
            .poll_observation_at(t2 + Duration::from_millis(50))
            .unwrap();
        assert!(matches!(progress, ObservationProgress::AwaitingWitnessTerm));
        assert_eq!(a.stale_discarded, 1);
        let snapshot = a.snapshot();
        assert_eq!(snapshot.pending.unwrap().request_generation, 2);
        assert_eq!(snapshot.last_completion, None);
    }

    /// T-F1-3: every other uncorrelated response stays a fail-closed error
    /// and is never discarded as "late".
    #[cfg(unix)]
    #[test]
    fn f1_a2_everything_else_still_fails_closed() {
        enum Bad {
            OtherNamespace,
            FutureGeneration,
            CompletedGenerationNotExpired,
            WrongType,
            ReplayedSequence,
            WrongSession,
            BadMac,
            DiscardedTwice,
        }
        for bad in [
            Bad::OtherNamespace,
            Bad::FutureGeneration,
            Bad::CompletedGenerationNotExpired,
            Bad::WrongType,
            Bad::ReplayedSequence,
            Bad::WrongSession,
            Bad::BadMac,
            Bad::DiscardedTwice,
        ] {
            let (mut a, mut server, t) = fixture();
            let ns = f1_ns(&a);
            let t2 = t + Duration::from_secs(2);
            let mut now = t2;
            let wrong: UnsignedEnvelope;
            let mut key_override: Option<MessageAuthenticator> = None;
            match bad {
                Bad::CompletedGenerationNotExpired => {
                    // Generation 1 completes with a normal TermStatus; generation 2
                    // is then pending. A second response for generation 1 is not a
                    // "late response of a timed-out generation".
                    let id1 = a.start_at(t).unwrap();
                    f1_send(&a, &mut server, id1.clone(), 1);
                    a.wait_for_readable_for_test();
                    a.poll_at(t).unwrap();
                    assert!(a.snapshot().pending.is_none());
                    a.deliver_at(t).unwrap();
                    a.start_at(t).unwrap();
                    wrong = response(id1, 2);
                    now = t;
                }
                Bad::ReplayedSequence => {
                    let id1 = a.start_at(t).unwrap();
                    f1_send(&a, &mut server, id1.clone(), 1);
                    a.wait_for_readable_for_test();
                    a.poll_at(t).unwrap();
                    a.deliver_at(t).unwrap();
                    let id2 = a.start_at(t).unwrap();
                    // Generation 2 times out, generation 3 is pending; the late
                    // response for 2 repeats sequence 1 (already committed).
                    a.start_at(t2).unwrap();
                    wrong = response(id2, 1);
                }
                Bad::DiscardedTwice => {
                    let id1 = a.start_at(t).unwrap();
                    f1_send(&a, &mut server, id1.clone(), 1);
                    a.start_at(t2).unwrap();
                    a.wait_for_readable_for_test();
                    a.poll_at(t2).unwrap(); // first (legitimate) discard
                    assert_eq!(a.stale_discarded, 1);
                    wrong = response(id1, 2); // the same generation again
                }
                _ => {
                    let id1 = a.start_at(t).unwrap();
                    a.start_at(t2).unwrap();
                    let mut w = response(
                        match bad {
                            Bad::OtherNamespace => RequestId::new("other-namespace-1"),
                            Bad::FutureGeneration => RequestId::new(format!("{ns}-9")),
                            _ => id1,
                        },
                        1,
                    );
                    match bad {
                        Bad::WrongType => {
                            w.message =
                                ProtocolMessage::LeaseGrant(crate::protocol::LeaseGrantPayload {
                                    term: Term(1),
                                    lease_id: crate::protocol::LeaseId::new("l"),
                                    holder_node_id: NodeId::new("w"),
                                    lease_ttl_ms: crate::protocol::DurationMs(1),
                                    renew_after_ms: crate::protocol::DurationMs(1),
                                    lease_remaining_ms: crate::protocol::DurationMs(1),
                                });
                        }
                        Bad::WrongSession => w.common.session_id = SessionId::new("other"),
                        Bad::BadMac => {
                            key_override =
                                Some(MessageAuthenticator::new(Psk::from_test_bytes([0x66; 32])));
                        }
                        _ => {}
                    }
                    wrong = w;
                }
            }
            let generation_before = a.snapshot().pending.as_ref().map(|p| p.request_generation);
            let discarded_before = a.stale_discarded;
            let key = key_override.unwrap_or_else(auth);
            server.send_message(wrong, &CborSerializer, &key).unwrap();
            a.wait_for_readable_for_test();
            let result = a.poll_at(now);
            assert!(result.is_err(), "must fail closed");
            assert_eq!(
                a.stale_discarded, discarded_before,
                "nothing may be discarded as late"
            );
            assert_eq!(
                a.snapshot().pending.as_ref().map(|p| p.request_generation),
                generation_before,
                "the current request is untouched"
            );
        }
    }

    /// F1T (independent audit, LOW / test coverage): the `generation <
    /// request_generation` condition of the A2 discard must be pinned by a test.
    ///
    /// Generation A times out. The next generation has NOT begun yet, so A is
    /// still the CURRENT generation (`A == request_generation`) even though it
    /// is recorded as expired. A's response now arrives. It must NOT be
    /// discarded as a "late response of a past generation": with no pending
    /// request it is an uncorrelated frame and fails closed with
    /// `NoPendingRequest`. Nothing may change: no discard, no committed
    /// sequence, no new outstanding request, no evidence, an unchanged
    /// snapshot, and A stays recorded as expired. Only after the next
    /// generation begins is the same kind of frame a legitimate late response.
    #[cfg(unix)]
    #[test]
    fn f1t_response_of_the_current_timed_out_generation_before_the_next_begin_is_not_discarded() {
        let (mut a, mut server, t) = fixture();
        let id_a = a.start_at(t).unwrap();
        let t2 = t + Duration::from_secs(2);
        a.tick_at(t2).unwrap(); // generation A completes as Unavailable(Timeout)
        a.deliver_at(t2).unwrap(); // its token is drained, nothing left queued
        assert_eq!(a.settled_generation, 0, "generation 1 is still owed");
        assert_eq!(a.snapshot().request_generation, 1);
        assert!(a.snapshot().pending.is_none());
        assert!(!a.session.request_in_flight());

        let before = a.snapshot();
        let sequence_before = a.highest_sequence();
        for (sequence, through_poll_at) in [(1u64, false), (2u64, true)] {
            f1_send(&a, &mut server, id_a.clone(), sequence);
            a.wait_for_readable_for_test();
            let result = if through_poll_at {
                a.poll_at(t2)
            } else {
                receive(&mut a, t2)
            };
            assert!(
                matches!(result, Err(AdapterError::NoPendingRequest)),
                "a response of the current (timed-out) generation with no pending request \
                 must fail closed, got {result:?}"
            );
            assert_eq!(a.stale_discarded, 0, "nothing may be discarded as late");
            assert_eq!(a.settled_generation, 0, "generation A is still owed");
            assert_eq!(
                a.highest_sequence(),
                sequence_before,
                "no sequence is committed for the rejected frame"
            );
            assert!(
                !a.session.request_in_flight(),
                "no outstanding request is created"
            );
            assert_eq!(a.snapshot(), before, "no state or evidence change");
            assert!(!a.snapshot().delivery_pending, "no evidence token queued");
        }

        // Once the next generation has begun, A's frame IS a legitimate late
        // response of a past generation: discarded, sequence committed, still
        // no evidence and the new request stays pending.
        a.start_at(t2).unwrap();
        f1_send(&a, &mut server, id_a, 3);
        a.wait_for_readable_for_test();
        a.poll_at(t2).unwrap();
        assert_eq!(a.stale_discarded, 1);
        assert_eq!(
            a.settled_generation, 1,
            "generation 1's late answer is settled"
        );
        assert_eq!(a.highest_sequence(), Sequence(3));
        let after = a.snapshot();
        assert_eq!(after.pending.unwrap().request_generation, 2);
        assert_eq!(after.last_completion, None);
        assert!(!after.delivery_pending);
    }

    /// Section 7 boundaries, deterministic (synthetic clock; timeout 2 s):
    /// deadline - 1 ns, deadline, deadline + 1 ns, before / after the next
    /// begin, before / after the new response arrives.
    #[cfg(unix)]
    #[test]
    fn f1_boundaries_around_the_deadline_the_next_begin_and_response_arrival() {
        let two = Duration::from_secs(2);

        // Just before the deadline: the arrived response is Ready.
        let (mut a, mut server, t) = fixture();
        let id = a.begin_observation_at(t).unwrap();
        f1_send(&a, &mut server, id, 1);
        a.wait_for_readable_for_test();
        assert!(matches!(
            a.poll_observation_at(t + two - Duration::from_nanos(1))
                .unwrap(),
            ObservationProgress::Ready(_)
        ));

        // At the deadline and just after it: Unavailable(Timeout), the arrived
        // response is NOT used, and a re-poll is idempotent.
        for offset in [Duration::ZERO, Duration::from_nanos(1)] {
            let (mut a, mut server, t) = fixture();
            let id = a.begin_observation_at(t).unwrap();
            f1_send(&a, &mut server, id, 1);
            a.wait_for_readable_for_test();
            let at = t + two + offset;
            assert_eq!(
                a.poll_observation_at(at).unwrap(),
                ObservationProgress::Unavailable(UnavailableCause::Timeout)
            );
            let generation = a.snapshot().observation_generation;
            assert_eq!(
                a.poll_observation_at(at).unwrap(),
                ObservationProgress::Unavailable(UnavailableCause::Timeout)
            );
            assert_eq!(a.snapshot().observation_generation, generation);

            // Next begin right after the expiry (the "next prime"): the old
            // response is still queued; before the new response arrives the
            // observation is Awaiting and the old frame is discarded.
            let id2 = a.begin_observation_at(at).unwrap();
            assert_eq!(a.snapshot().pending.unwrap().request_generation, 2);
            assert!(matches!(
                a.poll_observation_at(at + Duration::from_millis(10))
                    .unwrap(),
                ObservationProgress::AwaitingWitnessTerm
            ));
            assert_eq!(a.stale_discarded, 1);
            // After the new response arrives: Ready, from generation 2 only.
            f1_send(&a, &mut server, id2, 2);
            a.wait_for_readable_for_test();
            assert!(matches!(
                a.poll_observation_at(at + Duration::from_millis(20))
                    .unwrap(),
                ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                    request_generation: 2,
                    ..
                })
            ));
        }

        // A signal between the expiry and the next begin sees no observation
        // (fail closed): this is the residual window of Option A.
        let (mut a, mut server, t) = fixture();
        let id = a.begin_observation_at(t).unwrap();
        f1_send(&a, &mut server, id, 1);
        a.wait_for_readable_for_test();
        assert_eq!(
            a.poll_observation_at(t + two + Duration::from_millis(500))
                .unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Timeout)
        );
        assert!(a.snapshot().pending.is_none());
    }

    // --- Architecture Guard v1 (inline behavior guards) ---
    //
    // The guards below pin the Stage 12.7 observation lifecycle so a future
    // change cannot silently let stale evidence, repeated polling, or a failure
    // class become promotion-relevant authority.

    /// MKM-ARCH-002: current term and freshness provenance.
    ///
    /// A stored `EvidenceFusion` term must never make a new observation Ready;
    /// the current term must come only from the current correlated GET_TERM
    /// completion, and the freshness epoch must be that completion's acceptance
    /// time, never a later poll time.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_002_current_term_requires_current_completion_and_source_time() {
        let (mut adapter, mut server, started_at) = fixture();
        // Plant a stored historical term; it is not a current-term proof.
        adapter.fusion.witness_term = Some(99);

        let request_id = adapter.begin_observation_at(started_at).unwrap();
        // No completion yet: the stored term alone must not produce Ready.
        assert!(
            matches!(
                adapter.poll_observation_at(started_at).unwrap(),
                ObservationProgress::AwaitingWitnessTerm
            ),
            "MKM-ARCH-002 violated: stored fusion term produced Ready without a current completion"
        );

        let accepted_at = started_at + Duration::from_millis(250);
        server
            .send_message(response(request_id, 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        // Current term comes from the completion (7, not the stored 99), and
        // freshness is the completion acceptance time (250ms, not the earlier
        // poll or request-start time).
        assert!(
            matches!(
                adapter.poll_observation_at(accepted_at).unwrap(),
                ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                    term: Term(7),
                    observed_at,
                    ..
                }) if observed_at == accepted_at
            ),
            "MKM-ARCH-002 violated: Ready term/freshness not sourced from the current completion"
        );

        // A later poll cannot re-mint freshness.
        let later = started_at + Duration::from_secs(1);
        assert!(
            matches!(
                adapter.poll_observation_at(later).unwrap(),
                ObservationProgress::AwaitingWitnessTerm
            ),
            "MKM-ARCH-002 violated: later poll re-minted freshness for a consumed completion"
        );
    }

    /// MKM-ARCH-003: failure classes never become Ready.
    ///
    /// Only a valid authenticated, correlated, current GET_TERM TermStatus may
    /// produce Ready. Timeout, terminal transport, auth, semantic/protocol,
    /// wrong/stale correlation, wrong connection provenance, and duplicate
    /// completions must never do so.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_003_failure_classes_never_produce_ready() {
        fn assert_not_ready(name: &str, result: Result<ObservationProgress, AdapterError>) {
            assert!(
                !matches!(result, Ok(ObservationProgress::Ready(_))),
                "MKM-ARCH-003 violated: {name} produced Ready authority evidence"
            );
        }

        // timeout
        {
            let (mut adapter, _server, t) = fixture();
            adapter.begin_observation_at(t).unwrap();
            assert_not_ready(
                "timeout",
                adapter.poll_observation_at(t + Duration::from_secs(2)),
            );
        }

        // terminal transport failure
        {
            let (mut adapter, _server, t) = fixture();
            adapter.begin_observation_at(t).unwrap();
            let _ = adapter.accept_poll(
                Err(WitnessRuntimeError::Tcp(TcpError::Io(io::Error::from(
                    io::ErrorKind::ConnectionReset,
                )))),
                t,
            );
            assert_not_ready("terminal transport", adapter.poll_observation_at(t));
        }

        // authentication failure
        {
            let (mut adapter, mut server, t) = fixture();
            adapter.begin_observation_at(t).unwrap();
            let id = adapter.snapshot().pending.unwrap().request_id;
            let bad_auth = MessageAuthenticator::new(Psk::from_test_bytes([0x66; 32]));
            server
                .send_message(response(id, 1), &CborSerializer, &bad_auth)
                .unwrap();
            adapter.wait_for_readable_for_test();
            assert_not_ready("auth", adapter.poll_observation_at(t));
        }

        // semantic/protocol failure (authenticated but structurally invalid)
        {
            use crate::protocol::CanonicalSerializer;
            let (mut adapter, mut server, t) = fixture();
            adapter.begin_observation_at(t).unwrap();
            let id = adapter.snapshot().pending.unwrap().request_id;
            let mut wire = response(id, 1);
            wire.common.request_id = None;
            let signed = auth().sign(wire, &CborSerializer).unwrap();
            server
                .send_payload(&CborSerializer.serialize_wire(&signed).unwrap())
                .unwrap();
            adapter.wait_for_readable_for_test();
            assert_not_ready("semantic/protocol", adapter.poll_observation_at(t));
        }

        // wrong/stale correlation
        {
            let (mut adapter, mut server, t) = fixture();
            adapter.begin_observation_at(t).unwrap();
            server
                .send_message(
                    response(RequestId::new("wrong-request"), 1),
                    &CborSerializer,
                    &auth(),
                )
                .unwrap();
            adapter.wait_for_readable_for_test();
            assert_not_ready("wrong correlation", adapter.poll_observation_at(t));
        }

        // wrong connection provenance
        {
            let (mut old, mut old_server, t) = fixture();
            let old_id = old.start_at(t).unwrap();
            old_server
                .send_message(response(old_id, 1), &CborSerializer, &auth())
                .unwrap();
            let old_pending = old.receive_pending().unwrap();
            let old_provenance = old.provenance();
            let namespace = old.request_namespace.clone();

            let (mut current, _current_server, current_time) = fixture();
            current.request_namespace = namespace;
            current.start_at(current_time).unwrap();
            // A completion bound to an obsolete connection provenance is
            // rejected; it must not complete the current request.
            assert!(
                current
                    .accept_poll(
                        Ok(WitnessPoll::Pending(Box::new(old_pending), old_provenance)),
                        current_time,
                    )
                    .is_err(),
                "MKM-ARCH-003 violated: wrong connection provenance was accepted"
            );
            assert_not_ready(
                "wrong provenance",
                current.poll_observation_at(current_time),
            );
        }

        // duplicate completion after a consumed Ready
        {
            let (mut adapter, mut server, t) = fixture();
            let id = adapter.begin_observation_at(t).unwrap();
            server
                .send_message(response(id.clone(), 1), &CborSerializer, &auth())
                .unwrap();
            adapter.wait_for_readable_for_test();
            assert!(matches!(
                adapter.poll_observation_at(t).unwrap(),
                ObservationProgress::Ready(_)
            ));
            server
                .send_message(response(id, 1), &CborSerializer, &auth())
                .unwrap();
            adapter.wait_for_readable_for_test();
            assert_not_ready("duplicate completion", adapter.poll_observation_at(t));
        }

        // Positive control: a valid authenticated correlated current completion
        // DOES produce Ready, proving this guard is not vacuous.
        {
            let (mut adapter, mut server, t) = fixture();
            let id = adapter.begin_observation_at(t).unwrap();
            server
                .send_message(response(id, 1), &CborSerializer, &auth())
                .unwrap();
            adapter.wait_for_readable_for_test();
            assert!(matches!(
                adapter.poll_observation_at(t).unwrap(),
                ObservationProgress::Ready(_)
            ));
        }
    }

    /// MKM-ARCH-004: one request generation yields at most one Ready.
    ///
    /// Repeated polling of generation N cannot produce another Ready; generation
    /// N+1 requires a new begin and a new correlated completion, after which it
    /// can produce its own Ready.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_004_one_generation_yields_at_most_one_ready() {
        let (mut adapter, mut server, t) = fixture();
        let gen1 = adapter.begin_observation_at(t).unwrap();
        server
            .send_message(response(gen1.clone(), 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();

        let mut ready_count = 0;
        for step in 0..3u64 {
            let now = t + Duration::from_millis(step * 100);
            if matches!(
                adapter.poll_observation_at(now).unwrap(),
                ObservationProgress::Ready(_)
            ) {
                ready_count += 1;
            }
        }
        assert_eq!(
            ready_count, 1,
            "MKM-ARCH-004 violated: one request generation produced Ready more than once"
        );

        // Generation N+1 requires a fresh begin and a fresh correlated completion.
        let next = t + Duration::from_secs(1);
        let gen2 = adapter.begin_observation_at(next).unwrap();
        assert_ne!(gen1, gen2);
        assert!(matches!(
            adapter.poll_observation_at(next).unwrap(),
            ObservationProgress::AwaitingWitnessTerm
        ));
        server
            .send_message(response(gen2, 2), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        assert!(
            matches!(
                adapter.poll_observation_at(next).unwrap(),
                ObservationProgress::Ready(_)
            ),
            "MKM-ARCH-004 violated: a new generation with a new completion could not produce Ready"
        );
    }

    /// MKM-ARCH-005: Unavailable evidence exactly-once delivery.
    ///
    /// A completed Unavailable observation reaches EvidenceFusion exactly once
    /// with its original source time; it cannot be dropped, duplicated,
    /// overwritten by beginning another observation, or refreshed by repeated
    /// poll/drain.
    #[test]
    fn mkm_arch_005_unavailable_delivered_exactly_once_with_source_time() {
        let (mut adapter, _server, t) = fixture();
        adapter
            .observe_peer_at(PeerFailureAssessment::CommunicationLost, fresh_loss(t), t)
            .unwrap();
        adapter.begin_observation_at(t).unwrap();

        let completion_time = t + Duration::from_secs(2);
        assert_eq!(
            adapter.poll_observation_at(completion_time).unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Timeout)
        );
        let after_first = adapter.snapshot().fusion;
        assert_eq!(after_first.witness_status, WitnessStatus::Unavailable);
        assert_eq!(
            after_first.witness_observed_at,
            Some(completion_time),
            "MKM-ARCH-005 violated: Unavailable source time was not preserved"
        );

        // Repeated poll/drain must not refresh or duplicate the delivered evidence.
        assert_eq!(
            adapter
                .poll_observation_at(completion_time + Duration::from_secs(1))
                .unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Timeout)
        );
        assert_eq!(
            adapter.snapshot().fusion,
            after_first,
            "MKM-ARCH-005 violated: repeated poll/drain mutated delivered Unavailable evidence"
        );
        assert!(!adapter.snapshot().delivery_pending);

        // Beginning another observation must not overwrite the delivered evidence.
        adapter
            .begin_observation_at(completion_time + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            adapter.snapshot().fusion,
            after_first,
            "MKM-ARCH-005 violated: beginning a new observation overwrote delivered evidence"
        );

        // A later completion is a new, distinct Unavailable observation (newer
        // source time), not a silent drop or reuse of the old one.
        let second_deadline = completion_time + Duration::from_secs(3);
        assert_eq!(
            adapter.poll_observation_at(second_deadline).unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Timeout)
        );
        let after_second = adapter.snapshot().fusion;
        assert_eq!(after_second.witness_status, WitnessStatus::Unavailable);
        assert_eq!(after_second.witness_observed_at, Some(second_deadline));
        assert_ne!(
            after_second.witness_observed_at, after_first.witness_observed_at,
            "MKM-ARCH-005 violated: a new Unavailable reused the previous source time"
        );
    }

    // --- Stage 12.8a: current-term / stored-evidence type hardening ---

    /// Stage 12.8a-A/B: a valid current correlated GET_TERM completion creates
    /// a `WitnessAuthorityViewEvidence` with the expected term, and its `observed_at` is
    /// the original completion acceptance time (exposed only via accessors).
    #[cfg(unix)]
    #[test]
    fn current_witness_term_is_minted_from_correlated_completion() {
        let (mut adapter, mut server, started_at) = fixture();
        let request_id = adapter.begin_observation_at(started_at).unwrap();
        let accepted_at = started_at + Duration::from_millis(750);
        server
            .send_message(response(request_id, 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();

        let ObservationProgress::Ready(current) = adapter.poll_observation_at(accepted_at).unwrap()
        else {
            panic!("expected a current correlated term observation");
        };
        assert_eq!(current.term(), Term(7));
        assert_eq!(current.observed_at(), accepted_at);
        assert_eq!(
            current.request_generation(),
            adapter.snapshot().request_generation
        );
    }

    /// Stage 12.8a-C: a stored `EvidenceFusionSnapshot::witness_term` cannot by
    /// itself produce a `WitnessAuthorityViewEvidence` or a Ready current-attempt
    /// observation. No `From`/`Into` from the snapshot to the current term
    /// exists; only a correlated completion can yield Ready.
    #[cfg(unix)]
    #[test]
    fn stored_witness_term_cannot_mint_current_witness_term_or_ready() {
        let (mut adapter, mut server, started_at) = fixture();
        // Plant a historical term in the fusion snapshot.
        adapter.fusion.witness_term = Some(42);

        let _pending = adapter.begin_observation_at(started_at).unwrap();
        // Without a completion, the stored term must not produce Ready.
        assert!(
            matches!(
                adapter.poll_observation_at(started_at).unwrap(),
                ObservationProgress::AwaitingWitnessTerm
            ),
            "Stage 12.8a-C violated: stored witness_term produced Ready without a completion"
        );

        // A fresh correlated completion yields the completion's own term (7),
        // not the stored 42.
        let accepted_at = started_at + Duration::from_millis(200);
        server
            .send_message(
                response(adapter.snapshot().pending.unwrap().request_id, 1),
                &CborSerializer,
                &auth(),
            )
            .unwrap();
        adapter.wait_for_readable_for_test();
        let ObservationProgress::Ready(current) = adapter.poll_observation_at(accepted_at).unwrap()
        else {
            panic!("expected a current correlated term observation");
        };
        assert_eq!(
            current.term(),
            Term(7),
            "Stage 12.8a-C violated: current term did not come from the correlated completion"
        );
        assert_ne!(current.term(), Term(42));
    }

    /// Stage 12.8e SEQ-3: a late completion from a superseded request
    /// generation cannot become current authority for the newer generation.
    #[cfg(unix)]
    #[test]
    fn stage_12_8e_seq_3_superseded_generation_cannot_authorize() {
        let (mut adapter, mut server, t) = fixture();
        let gen1 = adapter.begin_observation_at(t).unwrap();
        server
            .send_message(response(gen1.clone(), 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        // Generation 1 becomes Ready and is consumed.
        assert!(matches!(
            adapter.poll_observation_at(t).unwrap(),
            ObservationProgress::Ready(_)
        ));

        // Generation 2 supersedes it.
        let t2 = t + Duration::from_secs(1);
        let gen2 = adapter.begin_observation_at(t2).unwrap();
        assert_ne!(gen1, gen2);
        assert!(matches!(
            adapter.poll_observation_at(t2).unwrap(),
            ObservationProgress::AwaitingWitnessTerm
        ));

        // A late generation-1 completion arrives: it must be rejected by
        // correlation and must not produce a current Ready term.
        server
            .send_message(response(gen1, 2), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        let result = adapter.poll_observation_at(t2);
        assert!(
            !matches!(result, Ok(ObservationProgress::Ready(_))),
            "SEQ-3 violated: superseded generation completion became current authority"
        );
    }

    /// Stage 12.8e SEQ-4: an Unavailable observation is delivered exactly once,
    /// then a later fresh generation independently becomes Ready; the old
    /// Unavailable state is not reused as current authority.
    #[test]
    fn stage_12_8e_seq_4_unavailable_then_fresh_ready_is_independent() {
        let (mut adapter, mut server, t) = fixture();
        adapter
            .observe_peer_at(PeerFailureAssessment::CommunicationLost, fresh_loss(t), t)
            .unwrap();

        // First observation times out -> exactly-once Unavailable evidence.
        adapter.begin_observation_at(t).unwrap();
        let deadline = t + Duration::from_secs(2);
        assert_eq!(
            adapter.poll_observation_at(deadline).unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Timeout)
        );
        let after_unavailable = adapter.snapshot().fusion;
        assert_eq!(after_unavailable.witness_status, WitnessStatus::Unavailable);
        assert!(!adapter.snapshot().delivery_pending);

        // A later, independent generation reaches a correlated completion.
        let t2 = deadline + Duration::from_secs(1);
        let gen2 = adapter.begin_observation_at(t2).unwrap();
        server
            .send_message(response(gen2, 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        let ObservationProgress::Ready(current) = adapter.poll_observation_at(t2).unwrap() else {
            panic!("SEQ-4: fresh generation did not become Ready");
        };
        // The fresh current term comes from the fresh completion, and the old
        // Unavailable evidence was not reused or duplicated. The accepted
        // TermStatus replaces witness_status with its own real
        // classification — Self with no remaining data is
        // ExpiredButUnprocessed, so the fused state stays fail-closed.
        assert_eq!(current.term(), Term(7));
        let fusion = &adapter.snapshot().fusion;
        assert_eq!(
            fusion.witness_status,
            WitnessStatus::AuthorityViewIncompatible,
            "SEQ-4: accepted TermStatus must update witness_status to its real classification"
        );
        assert_eq!(
            fusion.state,
            super::super::EvidenceFusionState::AmbiguousPartition,
            "SEQ-4: expired-but-unprocessed holder must not become failover-ready"
        );
    }

    // --- MKM-ARCH-012-PRE: one neutral session owner / one outstanding slot ---
    //
    // Ownership is enforced structurally: `WitnessEvidenceAdapter::new(timeout)`
    // takes no `WitnessConnection`, `ProcessSession`, or `MessageAuthenticator`,
    // and the adapter stores none of them nor a `WitnessRequestOutstanding`.
    // Transport state lives in the neutral `WitnessSession`. The behavioral
    // tests below prove the single-outstanding invariant and that real GET_TERM
    // still succeeds through the borrowed session (positive control).

    /// Positive control: a real observation request flows through the borrowed
    /// neutral session and correlates to a Ready term.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_012_pre_get_term_succeeds_through_borrowed_session() {
        let (mut adapter, mut server, t) = fixture();
        let request_id = adapter.begin_observation_at(t).unwrap();
        server
            .send_message(response(request_id, 1), &CborSerializer, &auth())
            .unwrap();
        adapter.wait_for_readable_for_test();
        assert!(matches!(
            adapter.poll_observation_at(t).unwrap(),
            ObservationProgress::Ready(WitnessAuthorityViewEvidence { term: Term(7), .. })
        ));
    }

    /// The session's single outstanding slot cannot be bypassed by a second
    /// observation request while one is in flight.
    #[cfg(unix)]
    #[test]
    fn mkm_arch_012_pre_second_request_cannot_bypass_shared_outstanding() {
        let (mut adapter, _server, t) = fixture();
        adapter.begin_observation_at(t).unwrap();
        // The shared slot is already awaiting a response.
        assert!(matches!(
            adapter.session.outstanding(),
            WitnessRequestOutstanding::AwaitingResponse(_)
        ));
        // Attempting to send a second GET_TERM through the same session fails.
        let second = adapter
            .session
            .send_get_term(RequestId::new("second-request"));
        assert!(
            matches!(second, Err(WitnessRuntimeError::RequestAlreadyOutstanding)),
            "MKM-ARCH-012-PRE violated: a second Witness request bypassed the shared outstanding slot"
        );
    }

    // --- Phase 14.12 E3b: the attempt-bound observation step ---
    //
    // Deterministic: a virtual clock advanced only by the step's own `pause`,
    // a real adapter, a real `WitnessSession` and real loopback TCP. The
    // Witness stand-in writes its scripted frames from inside `pause` when
    // the virtual time reaches them (the production timeout, 5 s).

    const E3B_TIMEOUT: Duration = Duration::from_secs(5);

    fn e3b_fixture() -> (Harness, Option<TcpConnection>, Instant) {
        e3b_fixture_with(E3B_TIMEOUT)
    }

    fn e3b_fixture_with(timeout: Duration) -> (Harness, Option<TcpConnection>, Instant) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let probe = client.try_clone().unwrap();
        let (server, _) = listener.accept().unwrap();
        let server_fd = std::os::fd::AsRawFd::as_raw_fd(&server);
        let connection = WitnessConnection::new(
            NodeId::new("a"),
            NodeId::new("w"),
            ClusterId::new("cluster"),
            SessionId::new("w-session"),
            TcpConnection::from_stream(client, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        );
        let mut harness = Harness::new(
            connection,
            ProcessSession::from_session_id(SessionId::new("a-session")),
            timeout,
        );
        harness.probe = Some(probe);
        harness.server_fd = Some(server_fd);
        (
            harness,
            Some(
                TcpConnection::from_stream(server, Duration::from_secs(2), Duration::from_secs(2))
                    .unwrap(),
            ),
            Instant::now(),
        )
    }

    /// `FIONREAD`: the platform's request number for "bytes waiting to be read".
    #[cfg(target_os = "linux")]
    const FIONREAD: u64 = 0x541B;
    #[cfg(target_os = "macos")]
    const FIONREAD: u64 = 0x4004_667F;

    /// `TIOCOUTQ`: "bytes in the send queue" (unsent plus not yet acknowledged).
    #[cfg(target_os = "linux")]
    const TIOCOUTQ: u64 = 0x5411;
    /// macOS spells the same query `getsockopt(SOL_SOCKET, SO_NWRITE)`.
    #[cfg(target_os = "macos")]
    const SOL_SOCKET: i32 = 0xffff;
    #[cfg(target_os = "macos")]
    const SO_NWRITE: i32 = 0x1024;

    /// Linux only: `setsockopt(IPPROTO_TCP, TCP_QUICKACK, 1)` makes the
    /// receiving socket send an acknowledgement it was holding back.
    #[cfg(target_os = "linux")]
    const IPPROTO_TCP: i32 = 6;
    #[cfg(target_os = "linux")]
    const TCP_QUICKACK: i32 = 12;

    unsafe extern "C" {
        fn ioctl(fd: i32, request: u64, ...) -> i32;
        #[cfg(target_os = "macos")]
        fn getsockopt(fd: i32, level: i32, name: i32, value: *mut i32, len: *mut u32) -> i32;
        #[cfg(target_os = "linux")]
        fn setsockopt(fd: i32, level: i32, name: i32, value: *const i32, len: u32) -> i32;
    }

    /// Phase 14.12 RW-2: the most real time a test waits for the kernel to
    /// deliver bytes the scripted Witness (or the adapter) already wrote. A
    /// healthy loopback does it in microseconds and a 30 ms injected delay in
    /// well under a second, so reaching this limit means the bytes were lost,
    /// the peer is gone or the socket is wedged — never "a bit slow".
    const DELIVERY_SYNC_LIMIT: Duration = Duration::from_secs(10);

    /// Bytes written to the socket `fd` that the peer's kernel has not yet
    /// acknowledged (the send queue: unsent + unacknowledged).
    fn undelivered_bytes(fd: std::os::fd::RawFd) -> usize {
        let mut queued: i32 = 0;
        #[cfg(target_os = "linux")]
        // SAFETY: TIOCOUTQ writes one c_int through the pointer; the caller
        // passes the descriptor of a socket it keeps open for the call.
        let status = unsafe { ioctl(fd, TIOCOUTQ, &mut queued as *mut i32) };
        #[cfg(target_os = "macos")]
        let status = {
            let mut len: u32 = 4;
            // SAFETY: SO_NWRITE writes one c_int and its length; both
            // pointers outlive the call and the caller keeps the socket open.
            unsafe {
                getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_NWRITE,
                    &mut queued as *mut i32,
                    &mut len as *mut u32,
                )
            }
        };
        assert_eq!(status, 0, "send-queue query failed");
        usize::try_from(queued).unwrap()
    }

    /// Ask the receiving socket `fd` to acknowledge now what it already holds.
    /// Without it a receiver that has nothing to send back may hold its
    /// acknowledgement for up to 40 ms (delayed ACK), which would make every
    /// wait below 40 ms slower for no reason. It changes timing only, never
    /// what is delivered; best effort (no effect off Linux).
    fn acknowledge_now(fd: std::os::fd::RawFd) {
        #[cfg(target_os = "linux")]
        {
            let one: i32 = 1;
            // SAFETY: a plain integer option on a socket the caller keeps open.
            let _ = unsafe { setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one as *const i32, 4) };
        }
        #[cfg(not(target_os = "linux"))]
        let _ = fd;
    }

    /// Phase 14.12 RW-2: wait for the event itself — every byte written to
    /// the socket `sender` has been acknowledged by the socket `receiver`,
    /// which on TCP means it sits in the receiver's queue — instead of
    /// sleeping and hoping. Independent of frame length and frame count
    /// (nothing to compute, nothing to desynchronize), and immediate when
    /// nothing is in flight. `what` names the wait in the failure message.
    fn await_peer_received(sender: std::os::fd::RawFd, receiver: std::os::fd::RawFd, what: &str) {
        let started = std::time::Instant::now();
        loop {
            let queued = undelivered_bytes(sender);
            if queued == 0 {
                return;
            }
            acknowledge_now(receiver);
            assert!(
                started.elapsed() < DELIVERY_SYNC_LIMIT,
                "{what}: {queued} byte(s) written to the socket were not acknowledged by the \
                 peer within {DELIVERY_SYNC_LIMIT:?} (test synchronization limit)"
            );
            std::thread::sleep(Duration::from_micros(200));
        }
    }

    /// Phase 14.12 RW-1: bytes the kernel holds for `stream`'s socket that
    /// nobody has read yet (`FIONREAD`).
    fn unread_bytes(stream: &TcpStream) -> usize {
        use std::os::fd::AsRawFd;
        let mut available: i32 = 0;
        // SAFETY: FIONREAD writes one c_int through the pointer; the fd is a
        // live socket owned by `stream` for the whole call.
        let status = unsafe { ioctl(stream.as_raw_fd(), FIONREAD, &mut available as *mut i32) };
        assert_eq!(status, 0, "FIONREAD failed");
        usize::try_from(available).unwrap()
    }

    /// The id this adapter will give its next request.
    fn e3b_next_id(a: &Harness) -> RequestId {
        RequestId::new(format!(
            "{}-{}",
            a.adapter.request_namespace,
            a.adapter.request_generation + 1
        ))
    }

    /// Phase 14.12 RW-2: wait until the end-of-stream the scripted Witness
    /// caused by closing its socket has reached `client` (a duplicate handle
    /// on the adapter's socket, `Harness::probe`). `peek` blocks until the
    /// socket is readable or its read timeout lapses; it consumes nothing. If
    /// bytes are queued the end-of-stream cannot be seen behind them and the
    /// wait ends (the adapter reads those first anyway).
    fn await_peer_closed(client: &TcpStream, what: &str) {
        let started = std::time::Instant::now();
        let mut byte = [0_u8; 1];
        loop {
            match client.peek(&mut byte) {
                Ok(_) => return,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    assert!(
                        started.elapsed() < DELIVERY_SYNC_LIMIT,
                        "{what}: the end of the stream did not reach the adapter's socket \
                         within {DELIVERY_SYNC_LIMIT:?} (test synchronization limit)"
                    );
                }
                // A reset is also "the peer is gone".
                Err(_) => return,
            }
        }
    }

    /// Frames the Witness side has received so far (each is one GET_TERM).
    /// Phase 14.12 RW-2: first waits until the adapter's socket holds nothing
    /// unacknowledged — every request the adapter wrote is then in the
    /// Witness's receive queue, so the count is exact (no fixed sleep).
    fn e3b_requests_seen(a: &Harness, server: &mut Option<TcpConnection>) -> usize {
        await_peer_received(
            a.client_fd(),
            a.server_fd.expect("fixture has the Witness descriptor"),
            "requests written by the adapter",
        );
        let server = server.as_mut().unwrap();
        let mut seen = 0;
        while let Ok(crate::tcp::PollFrameResult::Frame(_)) = server.poll_payload() {
            seen += 1;
        }
        seen
    }

    struct E3bStep {
        wait: AttemptObservationWait,
        /// Virtual time at which the step returned.
        end: Duration,
        pauses: Vec<Duration>,
    }

    /// Run the step at virtual time `start` (relative to `t0`). `shutdown_at`
    /// raises the live shutdown query once the virtual time reaches it.
    /// `on_pause(elapsed_since_start, server)` returns whether it wrote
    /// something. Phase 14.12 RW-2: the step then waits until the kernel has
    /// delivered everything the Witness wrote (`await_peer_received`) before
    /// the next slice polls, so a write can never land "after" the virtual
    /// time it belongs to. When the closure closed the Witness's socket the
    /// step waits for the end-of-stream to arrive instead. (With no `server`
    /// the closure stands for a writer thread streaming on its own; there is
    /// no discrete write to wait for and the step only yields briefly.)
    fn e3b_step(
        a: &mut Harness,
        server: &mut Option<TcpConnection>,
        t0: Instant,
        start: Duration,
        shutdown_at: Option<Duration>,
        mut on_pause: impl FnMut(Duration, &mut Option<TcpConnection>) -> bool,
    ) -> E3bStep {
        let offset = std::cell::Cell::new(start);
        let pauses = std::cell::RefCell::new(Vec::new());
        let (server_fd, client_fd) = (a.server_fd, a.client_fd());
        let shutdown = || shutdown_at.is_some_and(|at| offset.get() >= at);
        let wait = a.adapter.complete_attempt_observation(
            &mut a.session,
            expectation(),
            &shutdown,
            &mut || t0 + offset.get(),
            &mut |d| {
                pauses.borrow_mut().push(d);
                offset.set(offset.get() + d);
                let had_server = server.is_some();
                if on_pause(offset.get() - start, server) {
                    match (had_server, server.is_some()) {
                        (true, true) => await_peer_received(
                            server_fd.expect("fixture has the Witness descriptor"),
                            client_fd,
                            "frames written by the scripted Witness",
                        ),
                        (true, false) => await_peer_closed(
                            a.probe.as_ref().expect("fixture has a probe handle"),
                            "the Witness closed its socket",
                        ),
                        (false, _) => std::thread::sleep(Duration::from_millis(3)),
                    }
                }
            },
        );
        E3bStep {
            wait,
            end: offset.get(),
            pauses: pauses.into_inner(),
        }
    }

    /// A Witness that answers the step's own request `delay` after it began.
    fn e3b_answer_after(
        delay: Duration,
        id: RequestId,
        seq: u64,
    ) -> impl FnMut(Duration, &mut Option<TcpConnection>) -> bool {
        let mut sent = false;
        move |elapsed, server| {
            if sent || elapsed < delay {
                return false;
            }
            sent = true;
            server
                .as_mut()
                .unwrap()
                .send_message(response(id.clone(), seq), &CborSerializer, &auth())
                .unwrap();
            true
        }
    }

    fn e3b_silent(_: Duration, _: &mut Option<TcpConnection>) -> bool {
        false
    }

    /// Delays up to the deadline are accepted — 3 s, 4 s, 4.9 s are not
    /// discarded for "taking long" — and the step never waits past the
    /// answer by more than one slice. One request per step.
    #[test]
    fn e3b_step_accepts_responses_up_to_the_deadline() {
        for millis in [10_u64, 1_000, 2_999, 3_000, 3_001, 4_000, 4_900, 4_990] {
            let (mut a, mut server, t0) = e3b_fixture();
            let delay = Duration::from_millis(millis);
            let id = e3b_next_id(&a);
            let step = e3b_step(
                &mut a,
                &mut server,
                t0,
                Duration::ZERO,
                None,
                e3b_answer_after(delay, id, 1),
            );
            assert_eq!(step.wait, AttemptObservationWait::Resolved, "{millis} ms");
            assert!(
                step.end >= delay && step.end <= delay + ATTEMPT_OBSERVATION_WAIT_SLICE,
                "{millis} ms: waited until {:?}",
                step.end
            );
            assert!(
                step.pauses
                    .iter()
                    .all(|pause| *pause <= ATTEMPT_OBSERVATION_WAIT_SLICE)
            );
            assert_eq!(e3b_requests_seen(&a, &mut server), 1, "one GET_TERM");
            let ready = a.poll_observation_at(t0 + step.end).unwrap();
            assert!(
                matches!(
                    ready,
                    ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                        request_generation: 1,
                        ..
                    })
                ),
                "{millis} ms: {ready:?}"
            );
            assert!(a.snapshot().pending.is_none());
            assert!(!a.session.request_in_flight());
        }
    }

    /// The 5 s boundary: an answer that reaches the socket exactly at the
    /// deadline (or after) is not evidence. The wait ends exactly at the
    /// deadline — never one slice past it — completes the request as
    /// `Unavailable(Timeout)`, issues no second request, and the late frame
    /// is discarded by the next attempt's own poll (A2) without evidence.
    #[test]
    fn e3b_step_times_out_exactly_at_the_deadline_and_never_retries() {
        for millis in [5_000_u64, 5_200] {
            let (mut a, mut server, t0) = e3b_fixture();
            let id = e3b_next_id(&a);
            let step = e3b_step(
                &mut a,
                &mut server,
                t0,
                Duration::ZERO,
                None,
                e3b_answer_after(Duration::from_millis(millis), id, 1),
            );
            assert_eq!(step.wait, AttemptObservationWait::Resolved);
            assert_eq!(step.end, E3B_TIMEOUT, "the wait ends at the deadline");
            assert_eq!(step.pauses.iter().sum::<Duration>(), E3B_TIMEOUT);
            assert_eq!(e3b_requests_seen(&a, &mut server), 1, "no retry");
            assert_eq!(
                a.poll_observation_at(t0 + step.end).unwrap(),
                ObservationProgress::Unavailable(UnavailableCause::Timeout)
            );
            assert_eq!(a.adapter.settled_generation, 0);
            assert!(!a.session.request_in_flight());

            // The next attempt (a new SIGUSR1) issues its own request; the
            // late frame of generation 1 is discarded, the answer to
            // generation 2 is the evidence.
            if millis == 5_000 {
                let id2 = e3b_next_id(&a);
                let start = step.end + Duration::from_secs(1);
                let again = e3b_step(
                    &mut a,
                    &mut server,
                    t0,
                    start,
                    None,
                    e3b_answer_after(Duration::from_millis(10), id2, 2),
                );
                assert_eq!(again.wait, AttemptObservationWait::Resolved);
                assert_eq!(a.adapter.stale_discarded, 1);
                assert!(matches!(
                    a.poll_observation_at(t0 + again.end).unwrap(),
                    ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                        request_generation: 2,
                        ..
                    })
                ));
            }
        }
    }

    /// A silent Witness: one request, a wait of exactly the deadline, a
    /// terminal Timeout, no Ready — and a Witness that never answers cannot
    /// make a second request happen inside the same step.
    #[test]
    fn e3b_step_with_a_silent_witness_waits_the_deadline_once() {
        let (mut a, mut server, t0) = e3b_fixture();
        let step = e3b_step(&mut a, &mut server, t0, Duration::ZERO, None, e3b_silent);
        assert_eq!(step.wait, AttemptObservationWait::Resolved);
        assert_eq!(step.end, E3B_TIMEOUT);
        // The step itself completed the request and drained its Unavailable
        // token (the wait is bounded by its own deadline check, not by an
        // error out of the poll).
        assert!(!a.snapshot().delivery_pending);
        assert_eq!(e3b_requests_seen(&a, &mut server), 1);
        assert_eq!(
            a.poll_observation_at(t0 + step.end).unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Timeout)
        );
        assert_eq!(a.adapter.request_generation, 1);
    }

    /// The last slice is cut to the deadline: with a timeout that is not a
    /// multiple of the slice the wait still ends exactly at the deadline.
    #[test]
    fn e3b_step_never_waits_past_the_deadline_when_the_timeout_is_not_slice_aligned() {
        let timeout = Duration::from_millis(5_004);
        let (mut a, mut server, t0) = e3b_fixture_with(timeout);
        let step = e3b_step(&mut a, &mut server, t0, Duration::ZERO, None, e3b_silent);
        assert_eq!(step.wait, AttemptObservationWait::Resolved);
        assert_eq!(step.end, timeout);
        assert_eq!(step.pauses.iter().sum::<Duration>(), timeout);
        assert_eq!(step.pauses.last(), Some(&Duration::from_millis(4)));
    }

    /// F6 / R1: after a long idle there is no background request at all, so
    /// nothing was left behind. A single attempt after 45 s, 100 s and 600 s
    /// issues exactly one request and is evaluated.
    #[test]
    fn e3b_step_after_a_long_idle_issues_one_request_and_is_ready() {
        for idle in [45_u64, 100, 600] {
            let (mut a, mut server, t0) = e3b_fixture();
            // The adapter is never touched during the idle: no loop request.
            assert_eq!(a.adapter.request_generation, 0);
            assert_eq!(e3b_requests_seen(&a, &mut server), 0);
            let start = Duration::from_secs(idle);
            let id = e3b_next_id(&a);
            let step = e3b_step(
                &mut a,
                &mut server,
                t0,
                start,
                None,
                e3b_answer_after(Duration::from_millis(20), id, 1),
            );
            assert_eq!(step.wait, AttemptObservationWait::Resolved);
            assert_eq!(e3b_requests_seen(&a, &mut server), 1);
            assert_eq!(a.adapter.settled_generation, 1);
            assert!(matches!(
                a.poll_observation_at(t0 + step.end).unwrap(),
                ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                    request_generation: 1,
                    ..
                })
            ));
        }
    }

    /// Time out `count` attempts in a row (a stalled Witness), then flush
    /// every withheld answer at once while no attempt is running. Returns the
    /// virtual time of the next attempt.
    fn e3b_stall_then_flush(
        a: &mut Harness,
        server: &mut Option<TcpConnection>,
        t0: Instant,
        count: u64,
    ) -> Duration {
        let mut now = Duration::ZERO;
        for _ in 0..count {
            let step = e3b_step(a, server, t0, now, None, e3b_silent);
            assert_eq!(step.wait, AttemptObservationWait::Resolved);
            a.poll_observation_at(t0 + step.end).unwrap();
            now = step.end + Duration::from_secs(1);
        }
        for generation in 1..=count {
            let id = RequestId::new(format!("{}-{generation}", a.adapter.request_namespace));
            server
                .as_mut()
                .unwrap()
                .send_message(response(id, generation), &CborSerializer, &auth())
                .unwrap();
        }
        await_peer_received(
            a.server_fd.expect("fixture has the Witness descriptor"),
            a.client_fd(),
            "the flushed answers of the stalled Witness",
        );
        now
    }

    /// F6: the late answers of eight timed-out generations are discarded by the next
    /// attempt's own wait (A2) and the attempt is evaluated on its own
    /// answer — a stalled Witness that recovers does not disturb it.
    #[test]
    fn e3b_late_answers_of_eight_timed_out_generations_are_discarded() {
        let (mut a, mut server, t0) = e3b_fixture();
        let now = e3b_stall_then_flush(&mut a, &mut server, t0, 8);
        assert_eq!(
            a.adapter.settled_generation, 0,
            "eight owed generations, one counter"
        );
        let id = e3b_next_id(&a);
        let step = e3b_step(
            &mut a,
            &mut server,
            t0,
            now,
            None,
            e3b_answer_after(Duration::from_millis(10), id, 100),
        );
        assert_eq!(step.wait, AttemptObservationWait::Resolved);
        assert_eq!(a.adapter.stale_discarded, 8);
        assert!(matches!(
            a.poll_observation_at(t0 + step.end).unwrap(),
            ObservationProgress::Ready(WitnessAuthorityViewEvidence {
                request_generation: 9,
                ..
            })
        ));
    }

    /// Shutdown before the request: nothing is issued. Shutdown while
    /// waiting: the wait ends within a slice, nothing more is issued, no
    /// Ready exists; the unanswered request is never adopted by a later step
    /// (busy until its deadline, then completed and replaced).
    #[test]
    fn e3b_step_shutdown_before_and_during_the_wait() {
        let (mut a, mut server, t0) = e3b_fixture();
        let before = e3b_step(
            &mut a,
            &mut server,
            t0,
            Duration::ZERO,
            Some(Duration::ZERO),
            e3b_silent,
        );
        assert_eq!(
            before.wait,
            AttemptObservationWait::NotIssued("shutdown requested")
        );
        assert!(before.pauses.is_empty());
        assert_eq!(a.adapter.request_generation, 0);
        assert_eq!(e3b_requests_seen(&a, &mut server), 0);

        let during = e3b_step(
            &mut a,
            &mut server,
            t0,
            Duration::ZERO,
            Some(Duration::from_secs(1)),
            e3b_silent,
        );
        assert_eq!(during.wait, AttemptObservationWait::Interrupted);
        assert_eq!(during.end, Duration::from_secs(1));
        assert_eq!(e3b_requests_seen(&a, &mut server), 1);
        assert_eq!(a.adapter.request_generation, 1);
        assert!(a.adapter.last_completion.is_none());
        assert!(a.snapshot().pending.is_some());

        // Not adopted: the leftover is busy inside its deadline ...
        let busy = e3b_step(
            &mut a,
            &mut server,
            t0,
            Duration::from_secs(2),
            None,
            e3b_silent,
        );
        assert_eq!(
            busy.wait,
            AttemptObservationWait::NotIssued("Witness session is busy")
        );
        assert_eq!(e3b_requests_seen(&a, &mut server), 0);
        assert_eq!(a.adapter.request_generation, 1);
        // ... and completed, then replaced by the step's own request, after it.
        let after = e3b_step(
            &mut a,
            &mut server,
            t0,
            Duration::from_secs(5),
            None,
            e3b_silent,
        );
        assert_eq!(after.wait, AttemptObservationWait::Resolved);
        assert_eq!(a.adapter.request_generation, 2);
        assert_eq!(a.adapter.settled_generation, 0);
    }

    /// Shutdown observed at the instant the answer is on the socket and
    /// before the next poll: the answer is not accepted and no Ready exists.
    #[test]
    fn e3b_step_shutdown_just_before_the_answer_is_read_accepts_nothing() {
        let (mut a, mut server, t0) = e3b_fixture();
        let id = e3b_next_id(&a);
        let step = e3b_step(
            &mut a,
            &mut server,
            t0,
            Duration::ZERO,
            Some(Duration::from_secs(1)),
            e3b_answer_after(Duration::from_secs(1), id, 1),
        );
        assert_eq!(step.wait, AttemptObservationWait::Interrupted);
        assert!(a.adapter.last_completion.is_none());
        assert!(a.snapshot().pending.is_some());
    }

    /// Timeout and shutdown at the same instant: the shutdown is read first,
    /// so the step reports the interruption; either way no evidence exists
    /// and the attempt is blocked.
    #[test]
    fn e3b_step_timeout_and_shutdown_at_the_same_instant_fail_closed() {
        let (mut a, mut server, t0) = e3b_fixture();
        let step = e3b_step(
            &mut a,
            &mut server,
            t0,
            Duration::ZERO,
            Some(E3B_TIMEOUT),
            e3b_silent,
        );
        assert_eq!(step.wait, AttemptObservationWait::Interrupted);
        assert_eq!(step.end, E3B_TIMEOUT);
        assert!(a.adapter.last_completion.is_none());
        assert_eq!(e3b_requests_seen(&a, &mut server), 1, "no second request");
        assert!(step.wait.into_result().is_err());
    }

    /// Shutdown arriving together with the answer: the answer is accepted
    /// but the step reports `Interrupted`, so the attempt is not evaluated.
    #[test]
    fn e3b_step_shutdown_with_the_answer_interrupts_instead_of_resolving() {
        let (mut a, mut server, t0) = e3b_fixture();
        // Write the answer to the socket from inside the first `pause`, then
        // raise the shutdown on the check that follows the accepting poll.
        let own = e3b_next_id(&a);
        let calls = std::cell::Cell::new(0_u32);
        let answered = std::cell::Cell::new(false);
        let shutdown = || {
            calls.set(calls.get() + 1);
            // 1: before the request, 2: top of loop 1, 3: top of loop 2,
            // 4: after the poll that accepted the answer.
            calls.get() >= 4
        };
        let (server_fd, client_fd) = (a.server_fd, a.client_fd());
        let mut pause = |_: Duration| {
            if !answered.replace(true) {
                server
                    .as_mut()
                    .unwrap()
                    .send_message(response(own.clone(), 1), &CborSerializer, &auth())
                    .unwrap();
                await_peer_received(
                    server_fd.expect("fixture has the Witness descriptor"),
                    client_fd,
                    "the answer written by the scripted Witness",
                );
            }
        };
        let wait = a.adapter.complete_attempt_observation(
            &mut a.session,
            expectation(),
            &shutdown,
            &mut || t0,
            &mut pause,
        );
        assert_eq!(wait, AttemptObservationWait::Interrupted);
        assert!(a.snapshot().pending.is_none(), "the answer was accepted");
        assert_eq!(a.adapter.progressed_generation, None, "but never exposed");
    }

    /// A shared slot held by another operation: nothing is issued, the other
    /// operation's outstanding request is untouched.
    #[test]
    fn e3b_step_never_issues_over_a_foreign_outstanding_request() {
        let (mut a, mut server, t0) = e3b_fixture();
        a.session
            .send_get_term(RequestId::new("foreign-request"))
            .unwrap();
        let before = a.session.outstanding().clone();
        let step = e3b_step(&mut a, &mut server, t0, Duration::ZERO, None, e3b_silent);
        assert_eq!(
            step.wait,
            AttemptObservationWait::NotIssued("Witness session is busy")
        );
        assert!(step.pauses.is_empty());
        assert_eq!(a.adapter.request_generation, 0);
        assert!(!a.adapter.failed);
        assert_eq!(a.session.outstanding(), &before);
        assert_eq!(
            e3b_requests_seen(&a, &mut server),
            1,
            "only the foreign one"
        );
    }

    /// A disconnect while waiting ends the request as a terminal transport
    /// `Unavailable`; the adapter is failed for good (no reconnect exists) so
    /// a later step issues nothing.
    #[test]
    fn e3b_step_witness_disconnect_is_terminal_and_fail_closed() {
        let (mut a, mut server, t0) = e3b_fixture();
        let step = e3b_step(
            &mut a,
            &mut server,
            t0,
            Duration::ZERO,
            None,
            |elapsed, server| {
                if elapsed >= Duration::from_secs(1) && server.is_some() {
                    *server = None;
                    return true;
                }
                false
            },
        );
        assert_eq!(step.wait, AttemptObservationWait::Resolved);
        assert_eq!(
            a.poll_observation_at(t0 + step.end).unwrap(),
            ObservationProgress::Unavailable(UnavailableCause::Transport)
        );
        assert!(a.adapter.failed);
        let later = e3b_step(
            &mut a,
            &mut server,
            t0,
            step.end + Duration::from_secs(1),
            None,
            e3b_silent,
        );
        assert!(matches!(later.wait, AttemptObservationWait::NotIssued(_)));
        assert_eq!(a.adapter.request_generation, 1);
    }

    /// Authentication failure (wrong key), replay, a foreign namespace and a
    /// future generation each fail the attempt closed with no evidence.
    #[test]
    fn e3b_step_authentication_sequence_and_correlation_failures_fail_closed() {
        #[derive(Clone, Copy)]
        enum Bad {
            WrongKey,
            Replay,
            ForeignNamespace,
            FutureGeneration,
        }
        for bad in [
            Bad::WrongKey,
            Bad::Replay,
            Bad::ForeignNamespace,
            Bad::FutureGeneration,
        ] {
            let (mut a, mut server, t0) = e3b_fixture();
            let mut start = Duration::ZERO;
            if matches!(bad, Bad::Replay) {
                // A first, honest attempt consumes sequence 1.
                let id = e3b_next_id(&a);
                let first = e3b_step(
                    &mut a,
                    &mut server,
                    t0,
                    start,
                    None,
                    e3b_answer_after(Duration::from_millis(10), id, 1),
                );
                assert_eq!(first.wait, AttemptObservationWait::Resolved);
                a.poll_observation_at(t0 + first.end).unwrap();
                start = first.end + Duration::from_secs(1);
            }
            let own = e3b_next_id(&a);
            let generation = a.adapter.request_generation + 1;
            let namespace = a.adapter.request_namespace.clone();
            let step = e3b_step(&mut a, &mut server, t0, start, None, {
                let mut sent = false;
                move |elapsed, server| {
                    if sent || elapsed < Duration::from_millis(100) {
                        return false;
                    }
                    sent = true;
                    let server = server.as_mut().unwrap();
                    match bad {
                        Bad::WrongKey => server
                            .send_message(
                                response(own.clone(), 1),
                                &CborSerializer,
                                &MessageAuthenticator::new(Psk::from_test_bytes([0x66; 32])),
                            )
                            .unwrap(),
                        Bad::Replay => server
                            .send_message(response(own.clone(), 1), &CborSerializer, &auth())
                            .unwrap(),
                        Bad::ForeignNamespace => server
                            .send_message(
                                response(RequestId::new(format!("foreign-{generation}")), 2),
                                &CborSerializer,
                                &auth(),
                            )
                            .unwrap(),
                        Bad::FutureGeneration => server
                            .send_message(
                                response(
                                    RequestId::new(format!("{namespace}-{}", generation + 1)),
                                    2,
                                ),
                                &CborSerializer,
                                &auth(),
                            )
                            .unwrap(),
                    }
                    true
                }
            });
            assert_eq!(step.wait, AttemptObservationWait::Failed);
            assert!(a.adapter.last_completion.is_none());
            // Nothing was exposed for the failed attempt's own generation.
            assert_eq!(a.adapter.progressed_generation, None);
        }
    }

    /// A clock that went backwards is rejected; nothing is issued.
    #[test]
    fn e3b_step_clock_regression_issues_nothing() {
        let (mut a, mut server, t0) = e3b_fixture();
        let id = e3b_next_id(&a);
        let first = e3b_step(
            &mut a,
            &mut server,
            t0,
            Duration::from_secs(10),
            None,
            e3b_answer_after(Duration::from_millis(10), id, 1),
        );
        assert_eq!(first.wait, AttemptObservationWait::Resolved);
        a.poll_observation_at(t0 + first.end).unwrap();
        let before = e3b_requests_seen(&a, &mut server);
        assert_eq!(before, 1);
        let back = e3b_step(
            &mut a,
            &mut server,
            t0,
            Duration::from_secs(5),
            None,
            e3b_silent,
        );
        assert!(matches!(back.wait, AttemptObservationWait::NotIssued(_)));
        assert_eq!(e3b_requests_seen(&a, &mut server), 0);
        assert_eq!(a.adapter.request_generation, 1);
    }

    // ======================================================================
    // Phase 14.12 F7: the settled-generation watermark.
    //
    // A real adapter, a real `WitnessSession` and real loopback TCP; the
    // clock is virtual (advanced only by the step's own `pause`). A scripted
    // Witness writes frames in Witness order. N-cases are the F7 negative
    // tests, R-cases the recovery tests, W-cases check the invariants that
    // make the watermark sound (see the F7 contract amendment).
    // ======================================================================

    struct F7 {
        a: Harness,
        server: Option<TcpConnection>,
        t0: Instant,
        now: Duration,
        seq: u64,
    }

    impl F7 {
        fn new() -> Self {
            let (a, server, t0) = e3b_fixture();
            Self {
                a,
                server,
                t0,
                now: Duration::ZERO,
                seq: 0,
            }
        }
        /// The generation the next attempt will issue.
        fn next_gen(&self) -> u64 {
            self.a.adapter.request_generation + 1
        }
        fn id(&self, generation: u64) -> RequestId {
            RequestId::new(format!("{}-{generation}", self.a.adapter.request_namespace))
        }
        fn frame(&mut self, id: RequestId) -> UnsignedEnvelope {
            self.seq += 1;
            response(id, self.seq)
        }
        /// Answers for the given generations, in the given order.
        fn answers(&mut self, generations: &[u64]) -> Vec<UnsignedEnvelope> {
            generations
                .iter()
                .map(|generation| {
                    let id = self.id(*generation);
                    self.frame(id)
                })
                .collect()
        }
        /// Send one frame exactly as `TcpConnection::send_message` does
        /// (validate, sign, serialize, frame) and return its bytes on the wire.
        fn send_counted(&mut self, frame: UnsignedEnvelope, key: u8) -> usize {
            use crate::protocol::CanonicalSerializer;
            frame.validate().unwrap();
            let wire = MessageAuthenticator::new(Psk::from_test_bytes([key; 32]))
                .sign(frame, &CborSerializer)
                .unwrap();
            let payload = CborSerializer.serialize_wire(&wire).unwrap();
            self.server
                .as_mut()
                .unwrap()
                .send_payload(&payload)
                .unwrap();
            crate::framing::encode_frame(&payload).unwrap().len()
        }
        /// Phase 14.12 RW-1: the explicit receive synchronization. The kernel
        /// is asked, not slept on: nothing reads the client socket between the
        /// snapshot taken before a write and the end of this wait (the step
        /// that reads starts only after it returns), so the socket holds
        /// exactly `before + sent` unread bytes once every frame of the round
        /// has been delivered. Under load a loopback segment can be delayed
        /// far beyond any fixed sleep; this waits for the event itself and
        /// fails loudly (never silently desynchronizes the model) if the
        /// bytes do not arrive within 10 s.
        fn await_delivery(&self, target: usize) {
            let probe = self.a.probe.as_ref().expect("fixture has a probe handle");
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while unread_bytes(probe) < target {
                assert!(
                    std::time::Instant::now() < deadline,
                    "frames written by the scripted Witness were not delivered within 10 s"
                );
                std::thread::sleep(Duration::from_micros(200));
            }
        }
        /// Write frames now (small counts only) and wait until every one is
        /// readable on the client socket.
        fn write(&mut self, frames: &[UnsignedEnvelope]) {
            let before = unread_bytes(self.a.probe.as_ref().expect("probe"));
            let mut sent = 0;
            for frame in frames {
                sent += self.send_counted(frame.clone(), 0x55);
            }
            self.await_delivery(before + sent);
        }
        fn write_with_key(&mut self, frame: UnsignedEnvelope, key: u8) {
            let before = unread_bytes(self.a.probe.as_ref().expect("probe"));
            let sent = self.send_counted(frame, key);
            self.await_delivery(before + sent);
        }
        /// One step with no new frames; the stalled Witness's kernel still
        /// takes the requests in, so its receive buffer is drained.
        fn silent_step(&mut self) -> AttemptObservationWait {
            let step = e3b_step(
                &mut self.a,
                &mut self.server,
                self.t0,
                self.now,
                None,
                |_, srv| {
                    if let Some(srv) = srv.as_mut() {
                        while let Ok(crate::tcp::PollFrameResult::Frame(_)) = srv.poll_payload() {}
                    }
                    false
                },
            );
            self.now = step.end + Duration::from_secs(1);
            if step.wait == AttemptObservationWait::Resolved {
                self.a.poll_observation_at(self.t0 + step.end).unwrap();
            }
            step.wait
        }
        /// One attempt that gets no answer and times out.
        fn timeout(&mut self) {
            assert_eq!(self.silent_step(), AttemptObservationWait::Resolved);
        }
        /// One attempt with `before` written ahead of its own answer (when
        /// `answer`). A writer thread lets large backlogs stream while the
        /// step reads. Returns the step's result and whether it was Ready.
        fn attempt_with(
            &mut self,
            before: &[UnsignedEnvelope],
            answer: bool,
        ) -> (AttemptObservationWait, bool) {
            let own = self.next_gen();
            let mut frames = before.to_vec();
            if answer {
                let id = self.id(own);
                frames.push(self.frame(id));
            }
            let mut server = self.server.take().unwrap();
            let writer = std::thread::spawn(move || {
                for frame in &frames {
                    // A Witness whose peer stops reading gives up (the write
                    // times out); the scenario then records the outcome.
                    if server
                        .send_message(frame.clone(), &CborSerializer, &auth())
                        .is_err()
                    {
                        break;
                    }
                }
                server
            });
            let mut dummy = None;
            let step = e3b_step(&mut self.a, &mut dummy, self.t0, self.now, None, |_, _| {
                true
            });
            self.server = Some(writer.join().unwrap());
            self.now = step.end + Duration::from_secs(1);
            let ready = step.wait == AttemptObservationWait::Resolved
                && matches!(
                    self.a.poll_observation_at(self.t0 + step.end),
                    Ok(ObservationProgress::Ready(_))
                );
            (step.wait, ready)
        }
        /// Let a failed attempt's request reach its deadline and complete.
        fn settle(&mut self) {
            self.now += Duration::from_secs(6);
            let _ = self
                .a
                .adapter
                .expire_pending_at(&mut self.a.session, self.t0 + self.now);
            let _ = self.a.adapter.deliver_at(self.t0 + self.now);
        }
        /// Everything an attempt must leave alone when it fails closed.
        fn state(&self) -> (u64, u64, u64, Sequence, bool, bool) {
            (
                self.a.adapter.request_generation,
                self.a.adapter.settled_generation,
                self.a.adapter.stale_discarded,
                self.a.highest_sequence(),
                self.a.adapter.last_completion.is_some(),
                self.a.adapter.progressed_generation.is_some(),
            )
        }
        /// Run one attempt whose first frame is `bad`: it must fail closed,
        /// expose no evidence, commit no sequence, and leave its own request
        /// outstanding (to expire) without discarding anything.
        fn must_fail_closed(&mut self, bad: Vec<UnsignedEnvelope>, what: &str) {
            let before = self.state();
            let (wait, ready) = self.attempt_with(&bad, false);
            assert_eq!(wait, AttemptObservationWait::Failed, "{what}");
            assert!(!ready, "{what}");
            let after = self.state();
            assert_eq!(after.1, before.1, "{what}: watermark moved");
            assert_eq!(after.2, before.2, "{what}: something was discarded");
            assert_eq!(after.3, before.3, "{what}: a sequence was committed");
            assert!(!after.4 && !after.5, "{what}: evidence appeared");
            assert!(self.a.snapshot().pending.is_some(), "{what}");
            assert!(self.a.session.request_in_flight(), "{what}");
        }
    }

    fn f7_label(result: (AttemptObservationWait, bool)) -> String {
        match result {
            (AttemptObservationWait::Resolved, true) => "Ready".into(),
            (other, _) => format!("{other:?}"),
        }
    }

    /// F7-N01 .. N05 and R7-01 .. R7-06 (adapter level): `n` consecutive
    /// timeouts, then the Witness recovers and flushes every late answer
    /// ahead of the answer to the next request. The first attempt after the
    /// recovery discards them all and is evaluated on its own answer; later
    /// healthy attempts follow. The watermark is one counter for any `n`.
    #[test]
    fn f7_n01_to_n05_and_r7_backlogs_of_any_size_are_drained_and_recovered() {
        for n in [1_u64, 8, 9, 10, 30, 100, 1_000] {
            let mut f = F7::new();
            for _ in 0..n {
                f.timeout();
            }
            assert_eq!(
                f.a.adapter.settled_generation, 0,
                "n={n}: nothing settled yet"
            );
            assert_eq!(f.a.adapter.request_generation, n);
            let stale: Vec<u64> = (1..=n).collect();
            let before = f.answers(&stale);
            let result = f.attempt_with(&before, true);
            assert_eq!(f7_label(result), "Ready", "n={n}");
            assert_eq!(
                f.a.adapter.stale_discarded, n,
                "n={n}: every late answer discarded"
            );
            assert_eq!(f.a.adapter.settled_generation, n + 1, "n={n}");
            assert_eq!(f.a.adapter.request_generation, n + 1);
            assert!(f.a.snapshot().pending.is_none());
            assert!(!f.a.session.request_in_flight());
            assert_eq!(f.a.highest_sequence(), Sequence(n + 1));
            // Later attempts are ordinary.
            for round in 0..3 {
                let r = f.attempt_with(&[], true);
                assert_eq!(f7_label(r), "Ready", "n={n} round {round}");
            }
            assert_eq!(f.a.adapter.stale_discarded, n);
        }
    }

    /// F7-N06: timeouts mixed with accepted generations (in Witness order),
    /// then a repeat of an ACCEPTED generation's answer. Only the timed-out
    /// generations' answers are discarded; the repeat fails closed.
    #[test]
    fn f7_n06_timeouts_mixed_with_accepted_generations() {
        let mut f = F7::new();
        f.timeout(); // 1
        let late1 = f.answers(&[1]);
        assert_eq!(f7_label(f.attempt_with(&late1, true)), "Ready"); // 2
        f.timeout(); // 3
        let late3 = f.answers(&[3]);
        assert_eq!(f7_label(f.attempt_with(&late3, true)), "Ready"); // 4
        f.timeout(); // 5
        assert_eq!(f.a.adapter.settled_generation, 4);
        let repeat2 = f.answers(&[2]);
        let late5 = f.answers(&[5]);
        let before = f.state();
        let r6 = f.attempt_with(&[repeat2, late5].concat(), true); // 6
        assert_eq!(
            r6.0,
            AttemptObservationWait::Failed,
            "the repeat of accepted generation 2"
        );
        assert_eq!(
            f.a.adapter.settled_generation, 4,
            "nothing was settled by the repeat"
        );
        assert_eq!(f.a.adapter.stale_discarded, before.2);
        f.settle();
        assert_eq!(f7_label(f.attempt_with(&[], true)), "Ready"); // 7: late5, ans6 (late), ans7
        assert_eq!(f.a.adapter.settled_generation, 7);
    }

    /// F7-N07 / N09: generations that were never issued, or are ahead of the
    /// current one, are not late answers: they fail the attempt closed.
    #[test]
    fn f7_n07_n09_unissued_and_future_generations_are_not_discarded() {
        // (name, offset from the generation the attempt issues; None = absolute)
        let cases: [(&str, Option<u64>, u64); 5] = [
            ("N07 generation 0", None, 0),
            ("N07 far beyond anything issued", None, u64::MAX),
            ("N07 current + 1000", Some(1000), 0),
            ("N09 the next generation (+1)", Some(1), 0),
            ("N09 two ahead (+2)", Some(2), 0),
        ];
        for (name, offset, absolute) in cases {
            let mut f = F7::new();
            f.timeout();
            f.timeout();
            let current = f.next_gen();
            let g = offset.map_or(absolute, |o| current + o);
            let frames = f.answers(&[g]);
            f.must_fail_closed(frames, name);
            // The owed generations are still owed and later recoverable.
            f.settle();
            let late = f.answers(&[1, 2]);
            assert_eq!(f7_label(f.attempt_with(&late, true)), "Ready", "{name}");
        }
    }

    /// F7-N08: the current generation's answer is never discarded. While its
    /// request is pending it is accepted; after its own timeout and before
    /// the next begin it is not discarded either (F1T), and the next begin
    /// then makes it an ordinary late answer.
    #[test]
    fn f7_n08_the_current_generation_is_never_discarded() {
        let mut f = F7::new();
        f.timeout(); // generation 1 timed out, nothing pending
        let current = f.a.adapter.request_generation;
        let frame = f.answers(&[current]);
        f.write(&frame);
        f.a.wait_for_readable_for_test();
        let before = f.a.snapshot();
        let seq_before = f.a.highest_sequence();
        let r = f.a.poll_at(f.t0 + f.now);
        assert!(matches!(r, Err(AdapterError::NoPendingRequest)), "{r:?}");
        assert_eq!(f.a.adapter.stale_discarded, 0);
        assert_eq!(f.a.adapter.settled_generation, 0);
        assert_eq!(f.a.snapshot(), before);
        assert_eq!(f.a.highest_sequence(), seq_before);
        // (The rejected frame was read and dropped without committing anything.)
        // Next begin: a repeat of generation 1's answer is now a late answer
        // and is discarded.
        let again = f.answers(&[current]);
        let r = f.attempt_with(&again, true);
        assert_eq!(f7_label(r), "Ready");
        assert_eq!(f.a.adapter.stale_discarded, 1);
        // A pending current generation's answer is accepted, not discarded.
        let mut g = F7::new();
        assert_eq!(f7_label(g.attempt_with(&[], true)), "Ready");
        assert_eq!(g.a.adapter.stale_discarded, 0);
        assert_eq!(g.a.adapter.settled_generation, 1);
    }

    /// F7-N10: another namespace — a made-up one, a near miss of this one,
    /// and the namespace of another adapter instance.
    #[test]
    fn f7_n10_other_namespaces_are_not_discarded() {
        let other = WitnessEvidenceAdapter::new(E3B_TIMEOUT).unwrap();
        for kind in 0..3 {
            let mut f = F7::new();
            f.timeout();
            let id = match kind {
                0 => "foreign-namespace-1".to_string(),
                1 => format!("{}x-1", f.a.adapter.request_namespace),
                _ => format!("{}-1", other.request_namespace),
            };
            let frame = f.frame(RequestId::new(id.clone()));
            f.must_fail_closed(vec![frame], &id);
        }
    }

    /// F7-N11: another session — a different session id inside the envelope
    /// (rejected by the session layer), and a frame whose connection
    /// provenance is not this session's (rejected before any discard).
    #[test]
    fn f7_n11_other_sessions_are_not_discarded() {
        let mut f = F7::new();
        f.timeout();
        let mut frame = f.answers(&[1]);
        frame[0].common.session_id = SessionId::new("other-session");
        f.must_fail_closed(frame, "other session id");

        let mut g = F7::new();
        g.timeout();
        let frame = g.answers(&[1]);
        g.write(&frame);
        g.a.wait_for_readable_for_test();
        let provenance = g.a.provenance();
        let pending = g.a.receive_pending().unwrap();
        // Same frame, but presented with a provenance of another connection.
        let foreign = Arc::new(());
        assert!(!Arc::ptr_eq(&foreign, &provenance));
        // A pending current request exists, so a discard is the only way out.
        g.a.start_at(g.t0 + g.now).unwrap();
        let r = g.a.accept_poll(
            Ok(WitnessPoll::Pending(Box::new(pending), foreign)),
            g.t0 + g.now,
        );
        assert!(
            matches!(r, Err(AdapterError::ConnectionProvenanceMismatch)),
            "{r:?}"
        );
        assert_eq!(g.a.adapter.stale_discarded, 0);
        assert_eq!(g.a.adapter.settled_generation, 0);
    }

    /// F7-N12: replay — the same frame again (same sequence), and the same
    /// generation again under a new sequence.
    #[test]
    fn f7_n12_replays_are_not_discarded() {
        for same_sequence in [true, false] {
            let mut f = F7::new();
            f.timeout();
            let first = f.answers(&[1]);
            assert_eq!(f7_label(f.attempt_with(&first, true)), "Ready"); // gen 2
            let repeat = if same_sequence {
                first.clone()
            } else {
                f.answers(&[1])
            };
            f.timeout();
            let before = f.state();
            let (wait, ready) = f.attempt_with(&repeat, true);
            assert_eq!(
                wait,
                AttemptObservationWait::Failed,
                "same_sequence={same_sequence}"
            );
            assert!(!ready);
            assert_eq!(f.a.adapter.stale_discarded, before.2);
            assert_eq!(f.a.highest_sequence(), before.3);
        }
    }

    /// F7-N13: sequence reversal and repetition — only the in-order frame is
    /// discarded; a later frame whose sequence is lower than (3) or equal to
    /// (10) the committed one fails the attempt closed without committing a
    /// sequence, although its generation is owed and above the watermark.
    #[test]
    fn f7_n13_sequence_reversal_and_repetition_are_not_discarded() {
        for second in [3_u64, 10] {
            let mut f = F7::new();
            f.timeout();
            f.timeout();
            let mut frames = f.answers(&[1, 2]);
            frames[0].common.sequence = Sequence(10);
            frames[1].common.sequence = Sequence(second);
            let r = f.attempt_with(&frames, true);
            assert_eq!(
                r.0,
                AttemptObservationWait::Failed,
                "second sequence {second}"
            );
            assert_eq!(f.a.adapter.stale_discarded, 1, "only the in-order frame");
            assert_eq!(f.a.adapter.settled_generation, 1);
            assert_eq!(f.a.highest_sequence(), Sequence(10));
            assert!(f.a.adapter.last_completion.is_none());
        }
    }

    /// F7-N14: authentication failure — a stale frame signed with another key.
    #[test]
    fn f7_n14_authentication_failure_is_not_discarded() {
        let mut f = F7::new();
        f.timeout();
        let frame = f.answers(&[1]).remove(0);
        f.write_with_key(frame, 0x66);
        let before = f.state();
        let (wait, ready) = f.attempt_with(&[], false);
        assert_eq!(wait, AttemptObservationWait::Failed);
        assert!(!ready);
        let after = f.state();
        assert_eq!((after.1, after.2, after.3), (before.1, before.2, before.3));
        assert!(!after.4 && !after.5);
    }

    /// F7-N15: request ids that are not exactly an id this adapter issued:
    /// unparsable, empty number, signed, padded, zero-padded and overflowing
    /// numbers. The zero-padded alias of an owed generation is NOT discarded.
    #[test]
    fn f7_n15_request_ids_must_be_exactly_those_issued() {
        let ns = F7::new().a.adapter.request_namespace.clone();
        for suffix in [
            "",
            "abc",
            "+1",
            "-1",
            " 1",
            "1 ",
            "01",
            "001",
            "1.0",
            "18446744073709551616",
        ] {
            let mut f = F7::new();
            assert_ne!(f.a.adapter.request_namespace, ns);
            f.timeout();
            let id = RequestId::new(format!("{}-{suffix}", f.a.adapter.request_namespace));
            let frame = f.frame(id);
            f.must_fail_closed(vec![frame], &format!("suffix {suffix:?}"));
        }
    }

    /// F7-N16: wrong message kind — a non-TermStatus answer, and a request
    /// kind, that carry an owed generation's id are not discarded.
    #[test]
    fn f7_n16_wrong_message_kinds_are_not_discarded() {
        for kind in 0..2 {
            let mut f = F7::new();
            f.timeout();
            let mut frame = f.answers(&[1]);
            frame[0].message = if kind == 0 {
                ProtocolMessage::LeaseReject(crate::protocol::LeaseRejectPayload {
                    code: crate::protocol::WitnessMutationOutcomeCode::PolicyReject,
                    reason: "not a TermStatus".into(),
                })
            } else {
                ProtocolMessage::GetTerm
            };
            f.must_fail_closed(frame, &format!("kind {kind}"));
        }
    }

    /// F7-N17: session reset. Clearing the shared outstanding slot does not
    /// touch the watermark or make an owed generation undiscardable; an
    /// adapter restart (new namespace, watermark 0) cannot discard a frame of
    /// the previous adapter and starts clean at generation 1.
    #[test]
    fn f7_n17_session_reset_and_adapter_restart() {
        let mut f = F7::new();
        f.timeout();
        f.a.session.reset_outstanding();
        assert_eq!(f.a.adapter.settled_generation, 0);
        let late = f.answers(&[1]);
        assert_eq!(f7_label(f.attempt_with(&late, true)), "Ready");
        assert_eq!(f.a.adapter.settled_generation, 2);

        // Restart: a new adapter on the same stream.
        let old_namespace = f.a.adapter.request_namespace.clone();
        f.a.adapter = WitnessEvidenceAdapter::new(E3B_TIMEOUT).unwrap();
        assert_eq!(f.a.adapter.settled_generation, 0);
        assert_ne!(f.a.adapter.request_namespace, old_namespace);
        let old = RequestId::new(format!("{old_namespace}-1"));
        let frame = f.frame(old);
        // The new adapter has issued nothing yet: the old id is foreign.
        let before = f.state();
        let (wait, _) = f.attempt_with(&[frame], false);
        assert_eq!(wait, AttemptObservationWait::Failed);
        assert_eq!(f.a.adapter.stale_discarded, before.2);
        assert_eq!(f.a.adapter.settled_generation, 0);
    }

    /// F7-N18: generation overflow / wraparound boundary. The watermark only
    /// compares; it never adds. Near `u64::MAX` the discard works, the next
    /// begin after the last generation is refused (`GenerationExhausted`,
    /// adapter failed), nothing wraps, and the watermark never exceeds the
    /// current generation.
    #[test]
    fn f7_n18_generation_overflow_boundary() {
        let (mut a, mut server, t0) = e3b_fixture();
        a.adapter.request_generation = u64::MAX - 3;
        a.adapter.settled_generation = u64::MAX - 3;
        // MAX-2 times out, MAX-1 times out, MAX is pending.
        let mut now = Duration::ZERO;
        for _ in 0..2 {
            let step = e3b_step(&mut a, &mut server, t0, now, None, e3b_silent);
            assert_eq!(step.wait, AttemptObservationWait::Resolved);
            a.poll_observation_at(t0 + step.end).unwrap();
            now = step.end + Duration::from_secs(1);
        }
        assert_eq!(a.adapter.request_generation, u64::MAX - 1);
        // The last generation.
        let own = RequestId::new(format!("{}-{}", a.adapter.request_namespace, u64::MAX));
        let late = RequestId::new(format!("{}-{}", a.adapter.request_namespace, u64::MAX - 2));
        let step = e3b_step(&mut a, &mut server, t0, now, None, {
            let mut sent = false;
            move |elapsed, srv| {
                if sent || elapsed < Duration::from_millis(10) {
                    return false;
                }
                sent = true;
                let s = srv.as_mut().unwrap();
                s.send_message(response(late.clone(), 1), &CborSerializer, &auth())
                    .unwrap();
                s.send_message(response(own.clone(), 2), &CborSerializer, &auth())
                    .unwrap();
                true
            }
        });
        assert_eq!(step.wait, AttemptObservationWait::Resolved);
        assert!(matches!(
            a.poll_observation_at(t0 + step.end).unwrap(),
            ObservationProgress::Ready(_)
        ));
        assert_eq!(a.adapter.request_generation, u64::MAX);
        assert_eq!(a.adapter.settled_generation, u64::MAX);
        assert_eq!(
            a.adapter.stale_discarded, 1,
            "MAX-2 discarded, MAX accepted"
        );
        // No generation is left to issue: fail closed, nothing wraps.
        now = step.end + Duration::from_secs(1);
        let again = e3b_step(&mut a, &mut server, t0, now, None, e3b_silent);
        assert!(matches!(again.wait, AttemptObservationWait::NotIssued(_)));
        assert_eq!(a.adapter.request_generation, u64::MAX);
        // An id one past u64::MAX does not parse, and MAX itself is never "late".
        let mut f = F7::new();
        f.timeout();
        let ns = f.a.adapter.request_namespace.clone();
        let frame = f.frame(RequestId::new(format!("{ns}-18446744073709551616")));
        f.must_fail_closed(vec![frame], "one past u64::MAX");
        let frame = f.frame(RequestId::new(format!("{ns}-{}", u64::MAX)));
        f.settle();
        f.must_fail_closed(vec![frame], "u64::MAX is far ahead");
    }

    /// F7-N19: timeout and shutdown race while a backlog waits — the step is
    /// interrupted (nothing accepted past the interruption), the state stays
    /// consistent, and the next attempt discards the rest and recovers.
    #[test]
    fn f7_n19_timeout_and_shutdown_race_with_a_backlog() {
        let mut f = F7::new();
        for _ in 0..200 {
            f.timeout();
        }
        let stale: Vec<u64> = (1..=200).collect();
        let mut frames = f.answers(&stale);
        let own = f.next_gen();
        let id = f.id(own);
        frames.push(f.frame(id));
        let mut server = f.server.take().unwrap();
        let writer = std::thread::spawn(move || {
            for frame in &frames {
                if server
                    .send_message(frame.clone(), &CborSerializer, &auth())
                    .is_err()
                {
                    break;
                }
            }
            server
        });
        let mut dummy = None;
        // Shutdown 30 ms (virtual) into the wait.
        let step = e3b_step(
            &mut f.a,
            &mut dummy,
            f.t0,
            f.now,
            Some(f.now + Duration::from_millis(30)),
            |_, _| true,
        );
        f.server = Some(writer.join().unwrap());
        f.now = step.end + Duration::from_secs(1);
        assert_eq!(step.wait, AttemptObservationWait::Interrupted);
        assert!(f.a.adapter.last_completion.is_none());
        assert!(f.a.adapter.settled_generation < own);
        f.settle();
        assert_eq!(f7_label(f.attempt_with(&[], true)), "Ready");
        assert_eq!(
            f.a.adapter.stale_discarded, 201,
            "200 stale + the interrupted request's"
        );
    }

    /// F7-N20: more late answers than one poll reads stay on the socket. One
    /// `poll_at` reads at most `MAX_STALE_FRAMES_PER_POLL` (9) frames; the rest
    /// wait for the next poll, in order, none is lost and none is accepted
    /// early.
    #[test]
    fn f7_n20_more_than_nine_late_answers_stay_on_the_socket() {
        let mut f = F7::new();
        for _ in 0..25 {
            f.timeout();
        }
        let stale: Vec<u64> = (1..=25).collect();
        let frames = f.answers(&stale);
        f.write(&frames);
        // Begin generation 26 by hand and poll it directly.
        let t = f.t0 + f.now;
        f.a.start_at(t).unwrap();
        f.a.wait_for_readable_for_test();
        let before = f.a.snapshot();
        let mut discarded = Vec::new();
        for _ in 0..4 {
            f.a.poll_at(t).unwrap();
            discarded.push(f.a.adapter.stale_discarded);
        }
        assert_eq!(
            discarded,
            vec![9, 18, 25, 25],
            "9 per poll, then nothing left"
        );
        assert_eq!(f.a.adapter.settled_generation, 25);
        assert!(
            f.a.snapshot().pending.is_some(),
            "the current request is still pending"
        );
        assert!(f.a.adapter.last_completion.is_none());
        // W15: discarding late answers creates and changes no evidence at all.
        assert_eq!(f.a.snapshot(), before);
    }

    /// W-invariant (F7 contract amendment, W3 / W4 / W10 / W11): a random walk
    /// of real attempts — accepted, timed out and unanswered, timed out and
    /// answered late, failed on a forged frame, with a backlog queued ahead —
    /// against an independent model of the socket. After every attempt: the
    /// watermark equals the model's, is monotone and ≤ the current generation;
    /// EVERY generation strictly between the watermark and the current one
    /// timed out; the discard count equals the model's; nothing is left
    /// outstanding.
    #[test]
    fn f7_w_invariant_random_walk() {
        #[derive(Clone)]
        enum Q {
            Ans(u64),
            Forged,
        }
        let (mut accepted, mut failed, mut timed_out) = (0_u64, 0_u64, 0_u64);
        for seed in 0..30_u64 {
            let mut state = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut rnd = move |n: u64| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) % n
            };
            let mut f = F7::new();
            // kind[g]: 'A' accepted, 'T' timed out (after expiry).
            let mut kind: std::collections::BTreeMap<u64, char> = Default::default();
            let mut socket: std::collections::VecDeque<Q> = Default::default();
            let mut late_owed: Vec<u64> = Vec::new();
            let mut previous_floor = 0_u64;
            let mut model_discards = 0_u64;
            for _ in 0..40 {
                let own = f.next_gen();
                let answer = rnd(10) >= 5;
                let mut frames: Vec<UnsignedEnvelope> = Vec::new();
                if answer {
                    for g in std::mem::take(&mut late_owed) {
                        frames.extend(f.answers(&[g]));
                        socket.push_back(Q::Ans(g));
                    }
                    if rnd(10) == 0 {
                        let frame = f.frame(RequestId::new("foreign-namespace-7"));
                        frames.push(frame);
                        socket.push_back(Q::Forged);
                    }
                    frames.extend(f.answers(&[own]));
                    socket.push_back(Q::Ans(own));
                }
                f.write(&frames);
                let wait = f.silent_step();
                // The model reads the socket in order.
                let mut model_settled = previous_floor;
                let mut outcome = "Timeout";
                while let Some(item) = socket.pop_front() {
                    match item {
                        Q::Ans(g) if g == own => {
                            model_settled = model_settled.max(own);
                            outcome = "Accepted";
                            break;
                        }
                        Q::Ans(g) if model_settled < g && g < own => {
                            model_settled = g;
                            model_discards += 1;
                        }
                        _ => {
                            outcome = "Failed";
                            break;
                        }
                    }
                }
                let expect_wait = if outcome == "Failed" {
                    AttemptObservationWait::Failed
                } else {
                    AttemptObservationWait::Resolved
                };
                assert_eq!(
                    wait, expect_wait,
                    "seed {seed} generation {own} ({outcome})"
                );
                match outcome {
                    "Accepted" => {
                        kind.insert(own, 'A');
                        accepted += 1;
                    }
                    "Failed" => {
                        f.settle();
                        kind.insert(own, 'T');
                        failed += 1;
                    }
                    _ => {
                        kind.insert(own, 'T');
                        timed_out += 1;
                        if rnd(2) == 0 {
                            late_owed.push(own);
                        }
                    }
                }
                let floor = f.a.adapter.settled_generation;
                let current = f.a.adapter.request_generation;
                assert_eq!(floor, model_settled, "seed {seed}: watermark != model");
                assert!(floor >= previous_floor, "seed {seed}: watermark went down");
                assert!(
                    floor <= current,
                    "seed {seed}: watermark above the current generation"
                );
                for h in (floor + 1)..current {
                    assert_eq!(
                        kind.get(&h),
                        Some(&'T'),
                        "seed {seed}: generation {h} is above the watermark but did not time out"
                    );
                }
                assert_eq!(f.a.adapter.stale_discarded, model_discards, "seed {seed}");
                assert!(f.a.snapshot().pending.is_none(), "seed {seed}");
                assert!(!f.a.session.request_in_flight(), "seed {seed}");
                previous_floor = floor;
            }
        }
        assert!(
            accepted > 100 && failed > 0 && timed_out > 100,
            "{accepted} {failed} {timed_out}"
        );
    }

    /// W2: a generation can be consumed without a request on the wire — when
    /// the send itself fails after the counter moved. The adapter is failed
    /// for good by that, so no later generation is ever issued and the
    /// watermark's meaning (every generation between it and the current one
    /// timed out) cannot be broken by the gap.
    #[test]
    fn f7_w2_a_send_failure_consumes_a_generation_and_fails_the_adapter() {
        let (mut a, _server, t0) = e3b_fixture();
        // Occupy the shared slot behind the adapter's back so the send fails.
        a.session.send_get_term(RequestId::new("foreign")).unwrap();
        let r = a.start_at(t0);
        assert!(r.is_err(), "{r:?}");
        assert_eq!(
            a.adapter.request_generation, 1,
            "the generation was consumed"
        );
        assert!(a.adapter.failed, "and the adapter is failed for good");
        assert!(a.snapshot().pending.is_none());
        assert_eq!(a.adapter.settled_generation, 0);
        a.session.reset_outstanding();
        let again = a.start_at(t0 + Duration::from_secs(1));
        assert!(
            matches!(again, Err(AdapterError::Failed)),
            "no generation is issued after the gap: {again:?}"
        );
        assert_eq!(a.adapter.request_generation, 1);
    }

    /// W14: a failed adapter (disconnect, send failure, exhausted counters)
    /// discards nothing: the watermark does not describe a stream that is gone.
    #[test]
    fn f7_w14_a_failed_adapter_discards_nothing() {
        let mut f = F7::new();
        f.timeout();
        f.timeout();
        let frame = f.answers(&[1]);
        f.write(&frame);
        f.a.wait_for_readable_for_test();
        let provenance = f.a.provenance();
        let pending = f.a.receive_pending().unwrap();
        f.a.adapter.failed = true;
        f.a.adapter.pending = None;
        let r = f.a.accept_poll(
            Ok(WitnessPoll::Pending(Box::new(pending), provenance)),
            f.t0 + f.now,
        );
        assert!(r.is_err(), "{r:?}");
        assert_eq!(f.a.adapter.stale_discarded, 0);
        assert_eq!(f.a.adapter.settled_generation, 0);
    }
}
