//! Runtime-only peer communication failure assessment.
//!
//! This module classifies loss of authenticated communication evidence. It
//! never asserts peer death and has no path to promotion, demotion, leases,
//! fencing, or resource operations.

use crate::protocol::{Sequence, SessionId};
use std::fmt;
use std::time::{Duration, Instant};

pub const FAILURE_CONFIRMATION_WINDOW: Duration = Duration::from_secs(5);

/// Stage 13.3 (R-01): the maximum age of confirmed local
/// communication-loss evidence that may participate in
/// `FailoverEvidenceReady` / `Authorized`. A confirmed loss older than
/// this bound is a stale episode — Protocol v1 carries no peer
/// incarnation identity, so an old loss cannot prove the peer is still
/// unreachable now.
///
/// The bound is deliberately much larger than
/// `FAILURE_CONFIRMATION_WINDOW` (5s): loss must persist for the full
/// confirmation window before evidence even exists, then remains usable
/// for several observation cycles; it is still short enough that a
/// silently-recovered or restarted peer cannot ride an ancient loss
/// episode into authorization.
pub const LOCAL_LOSS_EVIDENCE_MAX_AGE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerFailureAssessment {
    Unobserved,
    Healthy,
    Suspect,
    CommunicationLost,
}

/// Fresh local communication-loss evidence (Stage 13.3).
///
/// Minted only by `PeerFailureDetector::loss_evidence` while the
/// detector is in `CommunicationLost` and carries the monotonic epoch
/// at which that assessment was confirmed plus the detector's loss
/// generation. Fields are private: callers can inspect freshness and
/// provenance but cannot fabricate or relabel an episode. The value is
/// ephemeral — not `Clone`, not `Copy`, not serializable, not
/// persistent — and a new value is minted from detector state on each
/// query, so an old value can never be rejuvenated.
///
/// Generation is provenance, not rejuvenation: it only ever increases
/// when the detector *transitions into* `CommunicationLost` again after
/// invalidation; it cannot make an old `lost_at` fresh.
#[derive(Debug)]
pub struct LocalLossEvidence {
    generation: u64,
    lost_at: Instant,
    /// Stage 14 §10.2 freshness reference: `last_failed_contact_at` when a
    /// permitted observation refreshed or formed the episode, otherwise
    /// `lost_at` (an unrefreshed legacy episode).
    freshness_reference: Instant,
}

impl LocalLossEvidence {
    /// The detector loss generation this evidence was minted from.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The monotonic time at which `CommunicationLost` was confirmed.
    pub const fn lost_at(&self) -> Instant {
        self.lost_at
    }

    /// Stage 14 §10.2: the instant freshness is measured from.
    pub const fn freshness_reference(&self) -> Instant {
        self.freshness_reference
    }

    /// Whether this evidence is still inside
    /// `LOCAL_LOSS_EVIDENCE_MAX_AGE` of its freshness reference at `now`
    /// (inclusive bound; a backwards clock is not fresh).
    pub fn is_fresh_at(&self, now: Instant) -> bool {
        now.checked_duration_since(self.freshness_reference)
            .is_some_and(|age| age <= LOCAL_LOSS_EVIDENCE_MAX_AGE)
    }

    /// Test-only issuer for downstream fusion/policy tests. Production
    /// evidence is minted exclusively by `PeerFailureDetector`.
    #[cfg(test)]
    pub(crate) fn new_for_test(generation: u64, lost_at: Instant) -> Self {
        Self {
            generation,
            lost_at,
            freshness_reference: lost_at,
        }
    }
}

/// A completed Appendix R verified-listen window `[w_start, w_end]`.
///
/// Minted only by the Inbound verified-listen instrumentation in
/// `DaemonPeerRuntime::tick_at` after every Appendix R.3 condition held, and
/// consumed exactly once by `PeerFailureDetector::observe_verified_listen_window`.
/// Not `Clone`, not `Copy`, not serializable; the fields are private.
#[derive(Debug)]
pub struct VerifiedListenWindow {
    w_start: Instant,
    w_end: Instant,
    listener_generation: u64,
}

impl VerifiedListenWindow {
    pub(crate) const fn new(w_start: Instant, w_end: Instant, listener_generation: u64) -> Self {
        Self {
            w_start,
            w_end,
            listener_generation,
        }
    }

    /// The conservative instant from which non-contact was observed.
    pub const fn w_start(&self) -> Instant {
        self.w_start
    }

    /// The completing sample instant (never a freshness source).
    pub const fn w_end(&self) -> Instant {
        self.w_end
    }

    pub const fn listener_generation(&self) -> u64 {
        self.listener_generation
    }
}

/// Stage 14 Design Revision 4 §10.8: why the detector is in `Suspect`.
///
/// Runtime-only provenance owned by `PeerFailureDetector`. It is never
/// persisted, never serialized, and never an input to authority: it only
/// decides whether elapsed time may complete `Suspect → CommunicationLost`.
/// A new process starts with a new detector and no provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspectOrigin {
    /// Existing Stage 13.3 entry from `Healthy` (heartbeat staleness,
    /// transport failure, session loss or replacement). The legacy
    /// elapsed-time confirmation applies.
    Healthy,
    /// Conservative-mode restart formation (§11). Completes only on a second
    /// qualifying observation, never by elapsed time.
    RestartFormation,
    /// Re-formation after a non-authenticated invalidation (§10.5). Completes
    /// only on a second qualifying observation, never by elapsed time.
    UncertaintyFormation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    HeartbeatStale,
    TransportUnavailable,
    SessionLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerFailureSnapshot {
    pub assessment: PeerFailureAssessment,
    pub reason: Option<FailureReason>,
    pub suspect_since: Option<Instant>,
    /// Stage 14 §10.8 provenance of the current `Suspect`; `None` unless the
    /// assessment is `Suspect`.
    pub suspect_origin: Option<SuspectOrigin>,
    /// Monotonic epoch of the current confirmed `CommunicationLost`
    /// episode, if one is currently evidence-valid.
    pub lost_at: Option<Instant>,
    /// Provenance generation of the current loss episode. Increments on
    /// each `CommunicationLost` transition; never decrements.
    pub loss_generation: u64,
    /// Stage 14 §10.2: start of the latest qualifying permitted observation
    /// (`t_start` / `w_start`), the evidence freshness reference.
    pub last_failed_contact_at: Option<Instant>,
    /// Stage 14 §10.2 / §11: qualifying observations in the current
    /// formation sequence.
    pub formation_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAssessmentError {
    TimeWentBackwards,
    ZeroConfirmationWindow,
}

impl fmt::Display for FailureAssessmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimeWentBackwards => write!(f, "failure assessment time moved backwards"),
            Self::ZeroConfirmationWindow => {
                write!(f, "failure confirmation window must be greater than zero")
            }
        }
    }
}

impl std::error::Error for FailureAssessmentError {}

#[derive(Debug, Clone)]
pub struct PeerFailureDetector {
    confirmation_window: Duration,
    assessment: PeerFailureAssessment,
    reason: Option<FailureReason>,
    suspect_since: Option<Instant>,
    /// Stage 14 §10.8: `Some` exactly while the assessment is `Suspect`.
    suspect_origin: Option<SuspectOrigin>,
    current_session: Option<SessionId>,
    accepted_sequence: Option<Sequence>,
    last_observed_at: Option<Instant>,
    /// Monotonic epoch of the current confirmed loss episode. `None`
    /// means the current assessment (if `CommunicationLost`) has no
    /// usable evidence — it was invalidated by recovery or session
    /// re-establishment and is awaiting re-confirmation.
    lost_at: Option<Instant>,
    /// Provenance generation: incremented on every transition into
    /// `CommunicationLost` (including re-confirmation after
    /// invalidation). Never used to refresh an existing epoch, and never
    /// reused: once exhausted, no new episode can form (fail closed).
    loss_generation: u64,
    /// Stage 14 §10.2: evidence reference, the start of the latest
    /// qualifying permitted observation. Set only by
    /// `record_permitted_observation`; cleared on every invalidation.
    last_failed_contact_at: Option<Instant>,
    /// Stage 14 §10.2 / §11: qualifying observations in the current
    /// formation sequence.
    formation_count: u8,
    /// Stage 14 §11.1 condition 1: restart/uncertainty formation exists only
    /// in conservative mode.
    restart_formation_enabled: bool,
    /// Stage 14 §11.1 condition 2: authenticated peer traffic was accepted in
    /// this process session, so the restart formation path does not apply.
    authenticated_contact_seen: bool,
    /// Stage 14 §10.5 / §11.1 (Revision 5): observations counted toward
    /// formation must start strictly after the latest sequence reset.
    formation_floor: Option<Instant>,
}

impl PeerFailureDetector {
    pub fn new(confirmation_window: Duration) -> Result<Self, FailureAssessmentError> {
        if confirmation_window.is_zero() {
            return Err(FailureAssessmentError::ZeroConfirmationWindow);
        }
        Ok(Self {
            confirmation_window,
            assessment: PeerFailureAssessment::Unobserved,
            reason: None,
            suspect_since: None,
            suspect_origin: None,
            current_session: None,
            accepted_sequence: None,
            last_observed_at: None,
            lost_at: None,
            loss_generation: 0,
            last_failed_contact_at: None,
            formation_count: 0,
            restart_formation_enabled: false,
            authenticated_contact_seen: false,
            formation_floor: None,
        })
    }

    /// Stage 14 §11.1 condition 1: enable the conservative-mode formation
    /// path. Configuration is immutable per process; the daemon sets this
    /// once at construction from `cluster.mode`.
    pub fn with_restart_formation(mut self, conservative_mode: bool) -> Self {
        self.restart_formation_enabled = conservative_mode;
        self
    }

    pub fn with_default_window() -> Self {
        Self::new(FAILURE_CONFIRMATION_WINDOW).expect("non-zero default window")
    }

    pub const fn confirmation_window(&self) -> Duration {
        self.confirmation_window
    }

    pub const fn assessment(&self) -> PeerFailureAssessment {
        self.assessment
    }

    pub const fn snapshot(&self) -> PeerFailureSnapshot {
        PeerFailureSnapshot {
            assessment: self.assessment,
            reason: self.reason,
            suspect_since: self.suspect_since,
            suspect_origin: self.suspect_origin,
            lost_at: self.lost_at,
            loss_generation: self.loss_generation,
            last_failed_contact_at: self.last_failed_contact_at,
            formation_count: self.formation_count,
        }
    }

    /// Fresh local communication-loss evidence for the current
    /// confirmed episode, if one exists. A new value is minted from
    /// detector state on each call; `None` means there is no usable
    /// evidence (not lost, or the epoch was invalidated and is awaiting
    /// re-confirmation).
    pub fn loss_evidence(&self) -> Option<LocalLossEvidence> {
        if self.assessment != PeerFailureAssessment::CommunicationLost {
            return None;
        }
        // §10.2: freshness is measured from `last_failed_contact_at` when a
        // permitted observation refreshed or formed the episode, otherwise
        // from `lost_at`.
        self.lost_at.map(|lost_at| LocalLossEvidence {
            generation: self.loss_generation,
            lost_at,
            freshness_reference: self.last_failed_contact_at.unwrap_or(lost_at),
        })
    }

    pub fn observe_session_established(
        &mut self,
        session_id: SessionId,
        now: Instant,
    ) -> Result<(), FailureAssessmentError> {
        // Revision 5 §10.8: a session other than the current one (including
        // the first session of this process) is a new observation context.
        let new_session = self.current_session.as_ref() != Some(&session_id);
        self.observe_time(now)?;
        // §10.5 / §11: an authenticated session is authenticated peer
        // contact. It cancels any formation sequence (RestartFormation →
        // Unobserved; UncertaintyFormation keeps its origin with count 0) and
        // ends the restart-formation path for this process session. It never
        // makes the detector Healthy; only a trusted heartbeat does.
        self.authenticated_contact_seen = true;
        self.cancel_formation_sequence(now);
        if new_session {
            self.current_session = Some(session_id);
            self.accepted_sequence = None;
            if self.assessment == PeerFailureAssessment::Healthy {
                self.assessment = PeerFailureAssessment::Suspect;
                self.reason = Some(FailureReason::SessionLost);
                self.suspect_since = Some(now);
                self.suspect_origin = Some(SuspectOrigin::Healthy);
            }
        }
        if self.assessment == PeerFailureAssessment::CommunicationLost {
            // Session establishment or re-establishment (Revision 5 §10.5,
            // §10.8) resets the observation context: the old loss epoch is
            // invalidated (no fresh evidence) and a full re-confirmation
            // window must elapse under the session before a new epoch can
            // form. The assessment itself stays CommunicationLost — the peer
            // is not proven reachable until a trusted heartbeat arrives.
            self.lost_at = None;
            self.last_failed_contact_at = None;
            self.suspect_since = Some(now);
        }
        Ok(())
    }

    /// Records only a heartbeat accepted by the authenticated current-session
    /// observer. `false` means stale, replayed, or wrong-session input.
    pub fn observe_trusted_heartbeat(
        &mut self,
        session_id: &SessionId,
        sequence: Sequence,
        now: Instant,
    ) -> Result<bool, FailureAssessmentError> {
        self.observe_time(now)?;
        if self.current_session.as_ref() != Some(session_id)
            || self
                .accepted_sequence
                .is_some_and(|accepted| sequence.0 <= accepted.0)
        {
            return Ok(false);
        }
        self.accepted_sequence = Some(sequence);
        self.assessment = PeerFailureAssessment::Healthy;
        self.reason = None;
        self.suspect_since = None;
        // §10.8 reset table: authenticated peer return clears provenance.
        self.suspect_origin = None;
        self.formation_count = 0;
        self.formation_floor = None;
        self.authenticated_contact_seen = true;
        // Recovery invalidates the loss epoch: the old evidence can
        // never be relabeled fresh. A later loss forms a new episode
        // with a new generation and a new monotonic epoch.
        self.lost_at = None;
        self.last_failed_contact_at = None;
        Ok(true)
    }

    pub fn observe_heartbeat_stale(&mut self, now: Instant) -> Result<(), FailureAssessmentError> {
        self.enter_suspect(FailureReason::HeartbeatStale, now)
    }

    pub fn observe_transport_failure(
        &mut self,
        now: Instant,
    ) -> Result<(), FailureAssessmentError> {
        self.enter_suspect(FailureReason::TransportUnavailable, now)
    }

    pub fn observe_session_lost(&mut self, now: Instant) -> Result<(), FailureAssessmentError> {
        self.enter_suspect(FailureReason::SessionLost, now)
    }

    pub fn tick(&mut self, now: Instant) -> Result<(), FailureAssessmentError> {
        self.observe_time(now)?;
        // §10.8 normative restriction: elapsed time completes only a
        // Healthy-origin Suspect. Formation origins complete only on a
        // qualifying observation; one observation plus a timer never forms
        // CommunicationLost.
        if self.assessment == PeerFailureAssessment::Suspect
            && self.suspect_origin == Some(SuspectOrigin::Healthy)
            && let Some(since) = self.suspect_since
        {
            let elapsed = now
                .checked_duration_since(since)
                .ok_or(FailureAssessmentError::TimeWentBackwards)?;
            if elapsed >= self.confirmation_window
                && let Some(generation) = self.next_loss_generation()
            {
                self.assessment = PeerFailureAssessment::CommunicationLost;
                self.lost_at = Some(now);
                self.loss_generation = generation;
                // §10.8 reset table: a new loss episode clears provenance.
                self.suspect_origin = None;
            }
        } else if self.assessment == PeerFailureAssessment::CommunicationLost
            && self.lost_at.is_none()
            && let Some(since) = self.suspect_since
        {
            // Re-confirmation after invalidation (e.g. session
            // re-establishment): a new epoch forms only after a full
            // confirmation window under the new context, with a new
            // generation. The invalidated epoch is never reused.
            let elapsed = now
                .checked_duration_since(since)
                .ok_or(FailureAssessmentError::TimeWentBackwards)?;
            if elapsed >= self.confirmation_window
                && let Some(generation) = self.next_loss_generation()
            {
                self.lost_at = Some(now);
                self.loss_generation = generation;
            }
        }
        Ok(())
    }

    /// Stage 14 §10.3.1 (Outbound): a real, foreground-initiated contact
    /// attempt to the configured peer that was started at `t_start` and
    /// failed. The only callers are the §10.3.1 sites in
    /// `DaemonPeerRuntime`.
    pub fn observe_initiated_contact_failure(
        &mut self,
        t_start: Instant,
        now: Instant,
    ) -> Result<(), FailureAssessmentError> {
        self.record_permitted_observation(t_start, now)
    }

    /// Stage 14 §10.3.2 (Inbound): a completed Appendix R verified-listen
    /// window. The single caller is the Inbound verified-listen completion
    /// point in `DaemonPeerRuntime::tick_at`. The completing sample `w_end`
    /// is that iteration's `now`; `w_start` is the evidence reference.
    pub fn observe_verified_listen_window(
        &mut self,
        window: VerifiedListenWindow,
    ) -> Result<(), FailureAssessmentError> {
        self.record_permitted_observation(window.w_start, window.w_end)
    }

    /// Stage 14 §10.5: identity or authentication uncertainty on a
    /// connection attributed to the configured peer (including an accepted
    /// Inbound connection that does not authenticate). A non-authenticated
    /// invalidation: it never re-confirms by elapsed time.
    pub fn observe_identity_uncertainty(
        &mut self,
        now: Instant,
    ) -> Result<(), FailureAssessmentError> {
        self.observe_time(now)?;
        self.invalidate_for_uncertainty(now);
        Ok(())
    }

    /// Appendix R.5 / §10.8: a listener-generation change (Inbound) voids the
    /// open window (runtime) and resets restart formation. A live episode is
    /// unaffected (window-only invalidation).
    pub fn observe_listener_generation_change(&mut self) {
        if self.assessment != PeerFailureAssessment::Suspect {
            return;
        }
        match self.suspect_origin {
            Some(SuspectOrigin::RestartFormation) => {
                self.assessment = PeerFailureAssessment::Unobserved;
                self.suspect_origin = None;
                self.suspect_since = None;
                self.formation_count = 0;
            }
            Some(SuspectOrigin::UncertaintyFormation) => {
                self.suspect_since = None;
                self.formation_count = 0;
            }
            _ => {}
        }
    }

    /// The single writer of `last_failed_contact_at` and of the §11
    /// formation state (§10.2, §10.3, §11.1). Refreshes a live episode
    /// forward-only, or counts toward conservative-mode formation; every
    /// other state ignores the observation.
    fn record_permitted_observation(
        &mut self,
        start: Instant,
        now: Instant,
    ) -> Result<(), FailureAssessmentError> {
        self.observe_time(now)?;
        if start > now {
            return Ok(());
        }
        match (self.assessment, self.suspect_origin) {
            (PeerFailureAssessment::CommunicationLost, _) => {
                // §10.3 refresh: only the same live episode, and the
                // reference only moves forward (an observation that started
                // before the current reference never refreshes it).
                if let Some(lost_at) = self.lost_at {
                    let reference = self.last_failed_contact_at.unwrap_or(lost_at);
                    if start >= reference {
                        self.last_failed_contact_at = Some(start);
                    }
                }
            }
            (PeerFailureAssessment::Unobserved, _)
                if self.formation_permitted(start) && !self.authenticated_contact_seen =>
            {
                // §11.1: the first counted observation.
                self.assessment = PeerFailureAssessment::Suspect;
                self.suspect_origin = Some(SuspectOrigin::RestartFormation);
                self.reason = None;
                self.suspect_since = Some(start);
                self.formation_count = 1;
            }
            (
                PeerFailureAssessment::Suspect,
                Some(SuspectOrigin::RestartFormation | SuspectOrigin::UncertaintyFormation),
            ) if self.formation_permitted(start) => match self.suspect_since {
                Some(first) if self.formation_count >= 1 => {
                    // §11.1 condition 4: the span between the start instants
                    // of the first and the confirming observation is at least
                    // FAILURE_CONFIRMATION_WINDOW; distinct attempts only.
                    let confirms = start
                        .checked_duration_since(first)
                        .is_some_and(|span| !span.is_zero() && span >= self.confirmation_window);
                    if confirms && let Some(generation) = self.next_loss_generation() {
                        self.assessment = PeerFailureAssessment::CommunicationLost;
                        self.loss_generation = generation;
                        self.lost_at = Some(now);
                        self.last_failed_contact_at = Some(start);
                        // §10.8 reset table: a new loss episode.
                        self.suspect_origin = None;
                        self.formation_count = 0;
                        self.formation_floor = None;
                    }
                }
                _ => {
                    self.suspect_since = Some(start);
                    self.formation_count = 1;
                }
            },
            _ => {}
        }
        Ok(())
    }

    /// §11.1 conditions 1 and 5: conservative mode, and the observation
    /// started strictly after the latest sequence reset (Revision 5: an
    /// observation starting at the reset instant is not proven new).
    fn formation_permitted(&self, start: Instant) -> bool {
        self.restart_formation_enabled && self.formation_floor.is_none_or(|floor| start > floor)
    }

    /// §10.5 / §10.8: a non-authenticated invalidation. Clears the episode,
    /// the evidence reference, and any formation sequence. An episode, a
    /// Healthy detector, or a Healthy/Uncertainty-origin Suspect becomes
    /// Suspect(UncertaintyFormation); Unobserved or RestartFormation becomes
    /// Unobserved. Elapsed time never completes the result.
    fn invalidate_for_uncertainty(&mut self, at: Instant) {
        let to_uncertainty = !matches!(
            (self.assessment, self.suspect_origin),
            (PeerFailureAssessment::Unobserved, _)
                | (
                    PeerFailureAssessment::Suspect,
                    Some(SuspectOrigin::RestartFormation)
                )
        );
        self.lost_at = None;
        self.last_failed_contact_at = None;
        self.suspect_since = None;
        self.reason = None;
        self.formation_count = 0;
        self.formation_floor = Some(at);
        if to_uncertainty {
            self.assessment = PeerFailureAssessment::Suspect;
            self.suspect_origin = Some(SuspectOrigin::UncertaintyFormation);
        } else {
            self.assessment = PeerFailureAssessment::Unobserved;
            self.suspect_origin = None;
        }
    }

    /// §11 "an authenticated peer contact at any point cancels formation".
    fn cancel_formation_sequence(&mut self, at: Instant) {
        if self.assessment != PeerFailureAssessment::Suspect {
            return;
        }
        match self.suspect_origin {
            Some(SuspectOrigin::RestartFormation) => {
                self.assessment = PeerFailureAssessment::Unobserved;
                self.suspect_origin = None;
                self.suspect_since = None;
                self.formation_count = 0;
                self.formation_floor = Some(at);
            }
            Some(SuspectOrigin::UncertaintyFormation) => {
                self.suspect_since = None;
                self.formation_count = 0;
                self.formation_floor = Some(at);
            }
            _ => {}
        }
    }

    /// The generation of the next loss episode. `None` once the generation
    /// space is exhausted: a new episode must have a new generation
    /// (Stage 14 §10.5, §10.8, §12.3), so an exhausted detector forms no
    /// further evidence epoch rather than reusing an old generation.
    fn next_loss_generation(&self) -> Option<u64> {
        self.loss_generation.checked_add(1)
    }

    fn enter_suspect(
        &mut self,
        reason: FailureReason,
        now: Instant,
    ) -> Result<(), FailureAssessmentError> {
        self.observe_time(now)?;
        if self.assessment == PeerFailureAssessment::Healthy {
            self.assessment = PeerFailureAssessment::Suspect;
            self.suspect_since = Some(now);
            self.reason = Some(reason);
            self.suspect_origin = Some(SuspectOrigin::Healthy);
        }
        Ok(())
    }

    /// Test-only: place the detector in `Suspect` with a formation origin.
    /// The production entries for `RestartFormation` / `UncertaintyFormation`
    /// (a first qualifying observation, a non-authenticated invalidation)
    /// belong to the Stage 14 evidence unit; this seam lets the §10.8 timer
    /// restriction and reset rows be tested now.
    #[cfg(test)]
    pub(crate) fn enter_suspect_for_test(&mut self, origin: SuspectOrigin, since: Instant) {
        self.assessment = PeerFailureAssessment::Suspect;
        self.reason = None;
        self.suspect_since = Some(since);
        self.suspect_origin = Some(origin);
        self.lost_at = None;
        self.last_observed_at = Some(since);
    }

    /// Test-only: position the generation counter near exhaustion.
    #[cfg(test)]
    pub(crate) fn set_loss_generation_for_test(&mut self, generation: u64) {
        self.loss_generation = generation;
    }

    /// Test-only: the formation floor (Revision 5 §10.8 session table).
    #[cfg(test)]
    pub(crate) const fn formation_floor_for_test(&self) -> Option<Instant> {
        self.formation_floor
    }

    /// Test-only: the current authenticated peer session.
    #[cfg(test)]
    pub(crate) const fn current_session_for_test(&self) -> Option<&SessionId> {
        self.current_session.as_ref()
    }

    fn observe_time(&mut self, now: Instant) -> Result<(), FailureAssessmentError> {
        if let Some(last) = self.last_observed_at
            && now < last
        {
            // Stage 14 §10.5: monotonic clock regression invalidates (a
            // non-authenticated invalidation) and fails closed for this
            // evaluation. The time high-water is kept, so observations must
            // start strictly after it to count again.
            self.invalidate_for_uncertainty(last);
            return Err(FailureAssessmentError::TimeWentBackwards);
        }
        self.last_observed_at = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn detector() -> PeerFailureDetector {
        PeerFailureDetector::new(Duration::from_secs(5)).unwrap()
    }

    fn session() -> SessionId {
        SessionId::new("session-1")
    }

    fn established_healthy() -> (PeerFailureDetector, Instant) {
        let mut detector = detector();
        let t0 = Instant::now();
        detector.observe_session_established(session(), t0).unwrap();
        detector
            .observe_trusted_heartbeat(&session(), Sequence(1), t0)
            .unwrap();
        (detector, t0)
    }

    #[test]
    fn startup_begins_unobserved() {
        assert_eq!(detector().assessment(), PeerFailureAssessment::Unobserved);
    }

    #[test]
    fn tcp_connected_only_remains_unobserved() {
        let mut detector = detector();
        detector
            .observe_session_established(session(), Instant::now())
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Unobserved);
    }

    #[test]
    fn established_without_heartbeat_remains_unobserved() {
        let mut detector = detector();
        let now = Instant::now();
        detector
            .observe_session_established(session(), now)
            .unwrap();
        detector.tick(now + Duration::from_secs(30)).unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Unobserved);
    }

    #[test]
    fn first_valid_heartbeat_is_healthy() {
        let (detector, _) = established_healthy();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Healthy);
    }

    #[test]
    fn stale_heartbeat_enters_suspect() {
        let (mut detector, now) = established_healthy();
        detector
            .observe_heartbeat_stale(now + Duration::from_secs(3))
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
    }

    #[test]
    fn transport_failure_enters_suspect() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
    }

    #[test]
    fn session_loss_enters_suspect() {
        let (mut detector, now) = established_healthy();
        detector.observe_session_lost(now).unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
    }

    #[test]
    fn suspect_records_caller_time() {
        let (mut detector, now) = established_healthy();
        let failure_at = now + Duration::from_secs(17);
        detector.observe_transport_failure(failure_at).unwrap();
        assert_eq!(detector.snapshot().suspect_since, Some(failure_at));
    }

    #[test]
    fn before_deadline_remains_suspect_and_at_deadline_is_lost() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector
            .tick(now + Duration::from_secs(5) - Duration::from_nanos(1))
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
        detector.tick(now + Duration::from_secs(5)).unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
    }

    #[test]
    fn synthetic_future_time_is_deterministic() {
        let (mut detector, now) = established_healthy();
        let future = now + Duration::from_secs(5);
        detector.observe_transport_failure(now).unwrap();
        detector.tick(future).unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
    }

    #[test]
    fn reconnect_and_established_alone_do_not_recover() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector
            .observe_session_established(SessionId::new("session-2"), now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
        detector.tick(now + Duration::from_secs(6)).unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
    }

    #[test]
    fn valid_new_session_heartbeat_recovers() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        let new_session = SessionId::new("session-2");
        detector
            .observe_session_established(new_session.clone(), now + Duration::from_secs(1))
            .unwrap();
        assert!(
            detector
                .observe_trusted_heartbeat(&new_session, Sequence(1), now + Duration::from_secs(2))
                .unwrap()
        );
        assert_eq!(detector.assessment(), PeerFailureAssessment::Healthy);
    }

    #[test]
    fn communication_lost_reconnect_only_stays_lost() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector.tick(now + Duration::from_secs(5)).unwrap();
        detector
            .observe_session_established(SessionId::new("session-2"), now + Duration::from_secs(6))
            .unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
    }

    #[test]
    fn communication_lost_new_heartbeat_recovers() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector.tick(now + Duration::from_secs(5)).unwrap();
        let new_session = SessionId::new("session-2");
        detector
            .observe_session_established(new_session.clone(), now + Duration::from_secs(6))
            .unwrap();
        detector
            .observe_trusted_heartbeat(&new_session, Sequence(1), now + Duration::from_secs(7))
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Healthy);
    }

    #[test]
    fn old_session_heartbeat_cannot_recover() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector
            .observe_session_established(SessionId::new("session-2"), now + Duration::from_secs(1))
            .unwrap();
        assert!(
            !detector
                .observe_trusted_heartbeat(&session(), Sequence(2), now + Duration::from_secs(2))
                .unwrap()
        );
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
    }

    #[test]
    fn replayed_sequence_cannot_recover() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        assert!(
            !detector
                .observe_trusted_heartbeat(&session(), Sequence(1), now + Duration::from_secs(1))
                .unwrap()
        );
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
    }

    #[test]
    fn invalid_identity_cannot_recover() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        assert!(
            !detector
                .observe_trusted_heartbeat(&SessionId::new("wrong-session"), Sequence(2), now)
                .unwrap()
        );
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
    }

    #[test]
    fn flap_starts_a_new_episode() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        let first = detector.snapshot().suspect_since.unwrap();
        detector
            .observe_trusted_heartbeat(&session(), Sequence(2), now + Duration::from_secs(1))
            .unwrap();
        detector
            .observe_heartbeat_stale(now + Duration::from_secs(2))
            .unwrap();
        assert!(detector.snapshot().suspect_since.unwrap() > first);
    }

    #[test]
    fn old_episode_deadline_does_not_end_new_episode() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector
            .observe_trusted_heartbeat(&session(), Sequence(2), now + Duration::from_secs(1))
            .unwrap();
        detector
            .observe_transport_failure(now + Duration::from_secs(2))
            .unwrap();
        detector.tick(now + Duration::from_secs(5)).unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
        detector.tick(now + Duration::from_secs(7)).unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
    }

    #[test]
    fn never_fresh_transport_failures_remain_unobserved() {
        let mut detector = detector();
        let now = Instant::now();
        detector.observe_transport_failure(now).unwrap();
        detector.tick(now + Duration::from_secs(30)).unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Unobserved);
    }

    #[test]
    fn never_fresh_repeated_failures_remain_unobserved() {
        let mut detector = detector();
        let now = Instant::now();
        for offset in [0, 1, 2, 10] {
            detector
                .observe_transport_failure(now + Duration::from_secs(offset))
                .unwrap();
        }
        assert_eq!(detector.assessment(), PeerFailureAssessment::Unobserved);
    }

    #[test]
    fn only_tick_advances_assessment() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        assert_eq!(
            detector.snapshot().assessment,
            PeerFailureAssessment::Suspect
        );
        detector.tick(now + Duration::from_secs(5)).unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
    }

    #[test]
    fn restart_starts_unobserved() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector.tick(now + Duration::from_secs(5)).unwrap();
        let restarted = PeerFailureDetector::new(detector.confirmation_window()).unwrap();
        assert_eq!(restarted.assessment(), PeerFailureAssessment::Unobserved);
        assert_eq!(restarted.snapshot().suspect_since, None);
    }

    #[test]
    fn rejects_zero_window_and_backwards_time() {
        assert!(matches!(
            PeerFailureDetector::new(Duration::ZERO),
            Err(FailureAssessmentError::ZeroConfirmationWindow)
        ));
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        assert_eq!(
            detector.tick(now - Duration::from_secs(1)),
            Err(FailureAssessmentError::TimeWentBackwards)
        );
    }

    #[test]
    fn healthy_session_replacement_becomes_suspect_until_new_heartbeat() {
        let (mut detector, now) = established_healthy();
        let replacement_at = now + Duration::from_secs(2);
        detector
            .observe_session_established(SessionId::new("session-2"), replacement_at)
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
        assert_eq!(detector.snapshot().suspect_since, Some(replacement_at));
        let replacement = SessionId::new("session-2");
        assert!(
            detector
                .observe_trusted_heartbeat(&replacement, Sequence(1), replacement_at)
                .unwrap()
        );
        assert_eq!(detector.assessment(), PeerFailureAssessment::Healthy);
    }

    #[test]
    fn duplicate_current_session_established_does_not_invalidate_healthy() {
        let (mut detector, now) = established_healthy();
        let sequence = detector.accepted_sequence;
        detector
            .observe_session_established(session(), now)
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Healthy);
        assert_eq!(detector.snapshot().suspect_since, None);
        assert_eq!(detector.accepted_sequence, sequence);
    }

    #[test]
    fn communication_lost_plus_new_session_stays_lost_until_heartbeat() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector.tick(now + Duration::from_secs(5)).unwrap();
        let replacement = SessionId::new("session-2");
        detector
            .observe_session_established(replacement.clone(), now + Duration::from_secs(6))
            .unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        detector
            .observe_trusted_heartbeat(&replacement, Sequence(1), now + Duration::from_secs(7))
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Healthy);
    }

    #[test]
    fn unobserved_plus_established_stays_unobserved_until_heartbeat() {
        let mut detector = detector();
        let now = Instant::now();
        detector
            .observe_session_established(session(), now)
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Unobserved);
        detector
            .observe_trusted_heartbeat(&session(), Sequence(1), now)
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Healthy);
    }

    #[test]
    /// Clock regression is rejected without accepting the event, without
    /// touching the session/sequence gate, and without lowering the time
    /// high-water. Stage 14 Design Revision 4 §10.5 intentionally amends the
    /// former "no assessment mutation" expectation: a regression also
    /// invalidates as a non-authenticated invalidation (fail closed).
    fn backwards_events_do_not_mutate_time_or_session_state_and_invalidate() {
        let (mut detector, now) = established_healthy();
        let later = now + Duration::from_secs(3);
        detector.observe_transport_failure(later).unwrap();
        let before = detector.clone();
        assert_eq!(
            detector.observe_trusted_heartbeat(&session(), Sequence(2), now),
            Err(FailureAssessmentError::TimeWentBackwards)
        );
        assert_eq!(detector.current_session, before.current_session);
        assert_eq!(detector.accepted_sequence, before.accepted_sequence);
        assert_eq!(detector.last_observed_at, before.last_observed_at);
        let invalidated = detector.snapshot();
        assert_eq!(invalidated.assessment, PeerFailureAssessment::Suspect);
        assert_eq!(
            invalidated.suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        assert_eq!(invalidated.suspect_since, None);
        assert_eq!(invalidated.lost_at, None);
        assert_eq!(
            invalidated.loss_generation,
            before.snapshot().loss_generation
        );
        assert_eq!(
            detector.observe_session_established(SessionId::new("session-2"), now),
            Err(FailureAssessmentError::TimeWentBackwards)
        );
        assert_eq!(detector.current_session, before.current_session);
        assert_eq!(detector.last_observed_at, before.last_observed_at);
        assert_eq!(
            detector.tick(now + Duration::from_secs(2)),
            Err(FailureAssessmentError::TimeWentBackwards)
        );
        assert_eq!(detector.snapshot(), invalidated);
        assert_eq!(detector.last_observed_at, before.last_observed_at);
    }

    #[test]
    fn equal_timestamp_is_accepted_and_restart_resets_time_high_water() {
        let (mut detector, now) = established_healthy();
        detector
            .observe_session_established(session(), now)
            .unwrap();
        detector
            .observe_trusted_heartbeat(&session(), Sequence(2), now)
            .unwrap();
        assert_eq!(detector.last_observed_at, Some(now));
        let restarted = PeerFailureDetector::new(detector.confirmation_window()).unwrap();
        assert_eq!(restarted.last_observed_at, None);
        assert_eq!(restarted.assessment(), PeerFailureAssessment::Unobserved);
    }

    // -----------------------------------------------------------------
    // Stage 14 Phase 14.2: loss generation and Suspect provenance
    // (Design Revision 4 §8, §10.5, §10.8, §12.3, §34.15).
    // -----------------------------------------------------------------

    const FORMATION_ORIGINS: [SuspectOrigin; 2] = [
        SuspectOrigin::RestartFormation,
        SuspectOrigin::UncertaintyFormation,
    ];

    fn assert_provenance_invariant(detector: &PeerFailureDetector) {
        let snapshot = detector.snapshot();
        assert_eq!(
            snapshot.suspect_origin.is_some(),
            snapshot.assessment == PeerFailureAssessment::Suspect,
            "suspect_origin must be Some exactly while Suspect: {snapshot:?}"
        );
    }

    #[test]
    fn stage14_every_existing_suspect_entry_is_healthy_origin() {
        type Entry = fn(&mut PeerFailureDetector, Instant);
        let entries: [(Entry, FailureReason); 4] = [
            (
                |d, at| d.observe_heartbeat_stale(at).unwrap(),
                FailureReason::HeartbeatStale,
            ),
            (
                |d, at| d.observe_transport_failure(at).unwrap(),
                FailureReason::TransportUnavailable,
            ),
            (
                |d, at| d.observe_session_lost(at).unwrap(),
                FailureReason::SessionLost,
            ),
            (
                |d, at| {
                    d.observe_session_established(SessionId::new("session-2"), at)
                        .unwrap()
                },
                FailureReason::SessionLost,
            ),
        ];
        for (enter, reason) in entries {
            let (mut detector, now) = established_healthy();
            assert_eq!(detector.snapshot().suspect_origin, None);
            let at = now + Duration::from_secs(1);
            enter(&mut detector, at);
            let snapshot = detector.snapshot();
            assert_eq!(snapshot.assessment, PeerFailureAssessment::Suspect);
            assert_eq!(snapshot.suspect_origin, Some(SuspectOrigin::Healthy));
            assert_eq!(snapshot.reason, Some(reason));
            assert_eq!(snapshot.suspect_since, Some(at));
            assert_provenance_invariant(&detector);
        }
    }

    #[test]
    fn stage14_healthy_origin_timer_confirmation_is_unchanged() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector
            .tick(now + Duration::from_secs(5) - Duration::from_nanos(1))
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
        detector.tick(now + Duration::from_secs(5)).unwrap();
        let snapshot = detector.snapshot();
        assert_eq!(
            snapshot.assessment,
            PeerFailureAssessment::CommunicationLost
        );
        assert_eq!(snapshot.suspect_origin, None);
        assert_eq!(snapshot.loss_generation, 1);
        assert_eq!(snapshot.lost_at, Some(now + Duration::from_secs(5)));
        assert_provenance_invariant(&detector);
    }

    /// §10.8 / §34.15: one formation-origin Suspect plus a 60 s timer is
    /// still Suspect. Kills MF-41 (a timer that ignores SuspectOrigin).
    #[test]
    fn stage14_formation_origin_suspect_never_completes_by_elapsed_time() {
        for origin in FORMATION_ORIGINS {
            let (mut detector, now) = established_healthy();
            detector.enter_suspect_for_test(origin, now);
            for seconds in [5, 6, 30, 60, 3600] {
                detector.tick(now + Duration::from_secs(seconds)).unwrap();
                let snapshot = detector.snapshot();
                assert_eq!(snapshot.assessment, PeerFailureAssessment::Suspect);
                assert_eq!(snapshot.suspect_origin, Some(origin));
                assert_eq!(snapshot.suspect_since, Some(now));
                assert_eq!(snapshot.loss_generation, 0);
                assert_eq!(snapshot.lost_at, None);
                assert!(detector.loss_evidence().is_none());
            }
        }
    }

    #[test]
    fn stage14_authenticated_peer_return_clears_provenance() {
        let origins = [
            SuspectOrigin::Healthy,
            SuspectOrigin::RestartFormation,
            SuspectOrigin::UncertaintyFormation,
        ];
        for origin in origins {
            let (mut detector, now) = established_healthy();
            detector.enter_suspect_for_test(origin, now + Duration::from_secs(1));
            assert!(
                detector
                    .observe_trusted_heartbeat(
                        &session(),
                        Sequence(2),
                        now + Duration::from_secs(2)
                    )
                    .unwrap()
            );
            let snapshot = detector.snapshot();
            assert_eq!(snapshot.assessment, PeerFailureAssessment::Healthy);
            assert_eq!(snapshot.suspect_origin, None);
            assert_eq!(snapshot.suspect_since, None);
            assert_eq!(snapshot.lost_at, None);
            assert_provenance_invariant(&detector);
        }
    }

    #[test]
    fn stage14_observer_restart_has_no_provenance_and_no_generation() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector.tick(now + Duration::from_secs(5)).unwrap();
        detector
            .observe_transport_failure(now + Duration::from_secs(6))
            .unwrap();
        assert_eq!(detector.snapshot().loss_generation, 1);
        let restarted = PeerFailureDetector::new(detector.confirmation_window()).unwrap();
        let snapshot = restarted.snapshot();
        assert_eq!(snapshot.assessment, PeerFailureAssessment::Unobserved);
        assert_eq!(snapshot.suspect_origin, None);
        assert_eq!(snapshot.loss_generation, 0);
        assert_eq!(snapshot.lost_at, None);
        assert!(restarted.loss_evidence().is_none());
    }

    /// Attack B: repeated failure notifications within one episode change
    /// neither the provenance nor the generation.
    #[test]
    fn stage14_repeated_failures_in_one_episode_do_not_inflate_or_relabel() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        let first = detector.snapshot();
        for offset in 1..=4 {
            let at = now + Duration::from_millis(offset * 100);
            detector.observe_transport_failure(at).unwrap();
            detector.observe_heartbeat_stale(at).unwrap();
            detector.observe_session_lost(at).unwrap();
            detector.tick(at).unwrap();
            let snapshot = detector.snapshot();
            assert_eq!(snapshot.suspect_origin, first.suspect_origin);
            assert_eq!(snapshot.suspect_since, first.suspect_since);
            assert_eq!(snapshot.reason, first.reason);
            assert_eq!(snapshot.loss_generation, 0);
        }
        detector.tick(now + Duration::from_secs(5)).unwrap();
        let lost = detector.snapshot();
        assert_eq!(lost.loss_generation, 1);
        for offset in 6..=20 {
            let at = now + Duration::from_secs(offset);
            detector.observe_transport_failure(at).unwrap();
            detector.observe_heartbeat_stale(at).unwrap();
            detector.observe_session_lost(at).unwrap();
            detector.tick(at).unwrap();
            assert_eq!(detector.snapshot(), lost);
        }
        let evidence = detector.loss_evidence().unwrap();
        assert_eq!(evidence.generation(), 1);
        assert_eq!(evidence.lost_at(), lost.lost_at.unwrap());
    }

    /// Attack C: loss A, recovery, later loss B are never provenance
    /// equivalent; evidence already handed out keeps its own generation.
    #[test]
    fn stage14_later_loss_is_a_new_generation_and_old_evidence_stays_distinct() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        detector.tick(now + Duration::from_secs(5)).unwrap();
        let episode_a = detector.loss_evidence().unwrap();
        assert_eq!(episode_a.generation(), 1);

        assert!(
            detector
                .observe_trusted_heartbeat(&session(), Sequence(2), now + Duration::from_secs(6))
                .unwrap()
        );
        assert!(detector.loss_evidence().is_none());
        assert_eq!(detector.snapshot().loss_generation, 1);

        detector
            .observe_transport_failure(now + Duration::from_secs(7))
            .unwrap();
        detector.tick(now + Duration::from_secs(12)).unwrap();
        let episode_b = detector.loss_evidence().unwrap();
        assert_eq!(episode_b.generation(), 2);
        assert_ne!(episode_a.generation(), episode_b.generation());
        assert!(episode_b.lost_at() > episode_a.lost_at());
        // The episode A value is unchanged and cannot be relabeled.
        assert_eq!(episode_a.generation(), 1);
    }

    /// Attack A: Suspect under peer session A, reconnect to peer session B,
    /// then a late session-A result. The late result is rejected and leaves
    /// the current provenance untouched.
    #[test]
    fn stage14_late_previous_session_result_cannot_touch_current_provenance() {
        let (mut detector, now) = established_healthy();
        detector.observe_transport_failure(now).unwrap();
        let session_b = SessionId::new("session-2");
        detector
            .observe_session_established(session_b.clone(), now + Duration::from_secs(1))
            .unwrap();
        let before = detector.snapshot();
        assert_eq!(before.suspect_origin, Some(SuspectOrigin::Healthy));
        for sequence in [1, 2, 99] {
            assert!(
                !detector
                    .observe_trusted_heartbeat(
                        &session(),
                        Sequence(sequence),
                        now + Duration::from_secs(2)
                    )
                    .unwrap()
            );
            assert_eq!(detector.snapshot(), before);
        }

        // Same attack after the loss was confirmed and the epoch was
        // invalidated by the reconnect: the late result neither restores the
        // old epoch nor clears the pending re-confirmation.
        detector.tick(now + Duration::from_secs(6)).unwrap();
        let lost = detector.loss_evidence().unwrap();
        assert_eq!(lost.generation(), 1);
        let session_c = SessionId::new("session-3");
        detector
            .observe_session_established(session_c, now + Duration::from_secs(7))
            .unwrap();
        assert!(detector.loss_evidence().is_none());
        let pending = detector.snapshot();
        assert!(
            !detector
                .observe_trusted_heartbeat(&session_b, Sequence(5), now + Duration::from_secs(8))
                .unwrap()
        );
        assert_eq!(detector.snapshot(), pending);
        detector.tick(now + Duration::from_secs(12)).unwrap();
        let reconfirmed = detector.loss_evidence().unwrap();
        assert_eq!(reconfirmed.generation(), 2);
        assert_ne!(reconfirmed.generation(), lost.generation());
    }

    /// Attack E: the generation never wraps or repeats. At exhaustion no new
    /// episode forms, so no evidence can carry a reused generation.
    #[test]
    fn stage14_generation_exhaustion_fails_closed_without_reuse() {
        let (mut detector, now) = established_healthy();
        detector.set_loss_generation_for_test(u64::MAX - 1);
        detector.observe_transport_failure(now).unwrap();
        detector.tick(now + Duration::from_secs(5)).unwrap();
        assert_eq!(detector.loss_evidence().unwrap().generation(), u64::MAX);

        // Recovery, then a new loss: no generation is left for it.
        assert!(
            detector
                .observe_trusted_heartbeat(&session(), Sequence(2), now + Duration::from_secs(6))
                .unwrap()
        );
        detector
            .observe_transport_failure(now + Duration::from_secs(7))
            .unwrap();
        detector.tick(now + Duration::from_secs(60)).unwrap();
        let snapshot = detector.snapshot();
        assert_eq!(snapshot.assessment, PeerFailureAssessment::Suspect);
        assert_eq!(snapshot.suspect_origin, Some(SuspectOrigin::Healthy));
        assert_eq!(snapshot.loss_generation, u64::MAX);
        assert_eq!(snapshot.lost_at, None);
        assert!(detector.loss_evidence().is_none());

        // The re-confirmation path is exhausted the same way.
        let (mut lost, t0) = established_healthy();
        lost.set_loss_generation_for_test(u64::MAX - 1);
        lost.observe_transport_failure(t0).unwrap();
        lost.tick(t0 + Duration::from_secs(5)).unwrap();
        lost.observe_session_established(SessionId::new("session-2"), t0 + Duration::from_secs(6))
            .unwrap();
        lost.tick(t0 + Duration::from_secs(60)).unwrap();
        assert_eq!(lost.assessment(), PeerFailureAssessment::CommunicationLost);
        assert_eq!(lost.snapshot().loss_generation, u64::MAX);
        assert!(lost.loss_evidence().is_none());
    }

    /// Suspect of any origin is not evidence: no loss evidence is minted, so
    /// Suspect alone cannot reach `FailoverEvidenceReady` or authority.
    #[test]
    fn stage14_suspect_of_any_origin_mints_no_loss_evidence() {
        let (mut healthy, now) = established_healthy();
        healthy.observe_transport_failure(now).unwrap();
        assert!(healthy.loss_evidence().is_none());
        for origin in FORMATION_ORIGINS {
            let (mut detector, now) = established_healthy();
            detector.enter_suspect_for_test(origin, now);
            detector.tick(now + Duration::from_secs(120)).unwrap();
            assert!(detector.loss_evidence().is_none());
            assert_ne!(
                detector.assessment(),
                PeerFailureAssessment::CommunicationLost
            );
        }
    }

    #[test]
    fn stage14_provenance_invariant_holds_across_the_lifecycle() {
        let (mut detector, now) = established_healthy();
        assert_provenance_invariant(&detector);
        let session_b = SessionId::new("session-2");
        let steps: Vec<Box<dyn Fn(&mut PeerFailureDetector)>> = vec![
            Box::new(move |d| d.observe_transport_failure(now).unwrap()),
            Box::new(move |d| d.tick(now + Duration::from_secs(5)).unwrap()),
            Box::new({
                let session_b = session_b.clone();
                move |d| {
                    d.observe_session_established(session_b.clone(), now + Duration::from_secs(6))
                        .unwrap()
                }
            }),
            Box::new(move |d| d.tick(now + Duration::from_secs(11)).unwrap()),
            Box::new({
                let session_b = session_b.clone();
                move |d| {
                    d.observe_trusted_heartbeat(
                        &session_b,
                        Sequence(1),
                        now + Duration::from_secs(12),
                    )
                    .unwrap();
                }
            }),
            Box::new(move |d| {
                d.observe_heartbeat_stale(now + Duration::from_secs(13))
                    .unwrap()
            }),
            Box::new(move |d| d.tick(now + Duration::from_secs(18)).unwrap()),
        ];
        for step in steps {
            step(&mut detector);
            assert_provenance_invariant(&detector);
        }
        assert_eq!(detector.snapshot().loss_generation, 3);
    }

    // -----------------------------------------------------------------
    // Stage 14 Phase 14.3: permitted observations, freshness reference,
    // formation, and non-authenticated invalidation (Design Revision 4
    // §10.2, §10.3, §10.5, §10.8, §11, §34.3, §34.4, §34.15, §34.16).
    // -----------------------------------------------------------------

    fn conservative() -> PeerFailureDetector {
        detector().with_restart_formation(true)
    }

    /// Healthy → transport failure → confirmed legacy episode at `lost_at`.
    fn legacy_lost(detector: &mut PeerFailureDetector) -> (Instant, Instant) {
        let t0 = Instant::now();
        detector.observe_session_established(session(), t0).unwrap();
        detector
            .observe_trusted_heartbeat(&session(), Sequence(1), t0)
            .unwrap();
        detector.observe_transport_failure(t0).unwrap();
        let lost_at = t0 + Duration::from_secs(5);
        detector.tick(lost_at).unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        (t0, lost_at)
    }

    /// Two production observations forming a restart episode (§11.1).
    fn restart_formed(detector: &mut PeerFailureDetector, t0: Instant) -> Instant {
        detector.observe_initiated_contact_failure(t0, t0).unwrap();
        let second = t0 + Duration::from_secs(5);
        detector
            .observe_initiated_contact_failure(second, second + Duration::from_millis(300))
            .unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        second
    }

    #[test]
    fn stage14_3_outbound_failed_contact_refreshes_live_episode_forward_only() {
        let mut detector = detector();
        let (_, lost_at) = legacy_lost(&mut detector);
        let before = detector.loss_evidence().unwrap();
        assert_eq!(before.freshness_reference(), lost_at);

        // An attempt that started before the episode never refreshes it.
        detector
            .observe_initiated_contact_failure(lost_at - Duration::from_millis(1), lost_at)
            .unwrap();
        assert_eq!(detector.snapshot().last_failed_contact_at, None);

        let t_start = lost_at + Duration::from_secs(20);
        let completed = t_start + Duration::from_secs(3);
        detector
            .observe_initiated_contact_failure(t_start, completed)
            .unwrap();
        let refreshed = detector.loss_evidence().unwrap();
        assert_eq!(refreshed.freshness_reference(), t_start);
        assert_eq!(refreshed.lost_at(), lost_at);
        assert_eq!(refreshed.generation(), before.generation());
        // The completion instant is never the reference (§10.2).
        assert!(refreshed.is_fresh_at(t_start + Duration::from_secs(30)));
        assert!(
            !refreshed.is_fresh_at(t_start + Duration::from_secs(30) + Duration::from_nanos(1))
        );

        // Duplicate or reordered (older) observations never move it back.
        detector
            .observe_initiated_contact_failure(t_start, completed)
            .unwrap();
        detector
            .observe_initiated_contact_failure(t_start - Duration::from_secs(1), completed)
            .unwrap();
        assert_eq!(detector.snapshot().last_failed_contact_at, Some(t_start));
    }

    /// §10.2 truth table and §34.16 boundaries.
    #[test]
    fn stage14_3_freshness_reference_truth_table() {
        // Unrefreshed legacy episode: reference = lost_at.
        let mut legacy = detector();
        let (_, lost_at) = legacy_lost(&mut legacy);
        let evidence = legacy.loss_evidence().unwrap();
        assert_eq!(evidence.freshness_reference(), lost_at);
        assert!(evidence.is_fresh_at(lost_at + Duration::from_millis(29_999)));
        assert!(evidence.is_fresh_at(lost_at + Duration::from_secs(30)));
        assert!(!evidence.is_fresh_at(lost_at + Duration::from_secs(30) + Duration::from_nanos(1)));
        assert!(!evidence.is_fresh_at(lost_at - Duration::from_nanos(1)));

        // Formation episode: reference = the confirming observation start;
        // lost_at is the later transition instant and is not a source.
        let mut formed = conservative();
        let t0 = Instant::now();
        let start2 = restart_formed(&mut formed, t0);
        let evidence = formed.loss_evidence().unwrap();
        let snapshot = formed.snapshot();
        assert_eq!(evidence.freshness_reference(), start2);
        assert_eq!(snapshot.lost_at, Some(start2 + Duration::from_millis(300)));
        assert!(evidence.is_fresh_at(start2 + Duration::from_secs(30)));
        assert!(!evidence.is_fresh_at(start2 + Duration::from_secs(30) + Duration::from_nanos(1)));

        // No episode: no evidence at all.
        assert!(detector().loss_evidence().is_none());
    }

    /// §11.1 / §34.4 / §34.15 / §34.16, attacks G and H.
    #[test]
    fn stage14_3_restart_formation_needs_two_observations_spanning_the_window() {
        let mut detector = conservative();
        let t1 = Instant::now();
        detector.observe_initiated_contact_failure(t1, t1).unwrap();
        let snapshot = detector.snapshot();
        assert_eq!(snapshot.assessment, PeerFailureAssessment::Suspect);
        assert_eq!(
            snapshot.suspect_origin,
            Some(SuspectOrigin::RestartFormation)
        );
        assert_eq!(snapshot.formation_count, 1);
        assert_eq!(snapshot.suspect_since, Some(t1));
        assert!(detector.loss_evidence().is_none());

        // Attack G: time alone never completes formation.
        detector.tick(t1 + Duration::from_secs(60)).unwrap();
        assert_eq!(
            detector.snapshot().assessment,
            PeerFailureAssessment::Suspect
        );
        assert!(detector.loss_evidence().is_none());

        // A second failure within < 5 s of the first start does not complete.
        let early = t1 + Duration::from_secs(3);
        detector
            .observe_initiated_contact_failure(early, t1 + Duration::from_secs(61))
            .unwrap();
        assert_eq!(detector.snapshot().formation_count, 1);
        assert_eq!(
            detector.snapshot().assessment,
            PeerFailureAssessment::Suspect
        );

        // Attack H: a distinct observation ≥ 5 s after the first completes.
        let t2 = t1 + Duration::from_secs(5);
        let transition = t1 + Duration::from_secs(62);
        detector
            .observe_initiated_contact_failure(t2, transition)
            .unwrap();
        let formed = detector.snapshot();
        assert_eq!(formed.assessment, PeerFailureAssessment::CommunicationLost);
        assert_eq!(formed.loss_generation, 1);
        assert_eq!(formed.suspect_origin, None);
        assert_eq!(formed.formation_count, 0);
        // §34.16: distinct t_start1, t_start2, and transition values.
        assert_eq!(formed.suspect_since, Some(t1));
        assert_eq!(formed.last_failed_contact_at, Some(t2));
        assert_eq!(formed.lost_at, Some(transition));
        assert_eq!(detector.loss_evidence().unwrap().freshness_reference(), t2);
    }

    #[test]
    fn stage14_3_availability_mode_never_forms_from_observations() {
        let mut detector = detector();
        let t1 = Instant::now();
        for offset in [0, 5, 10, 60] {
            let at = t1 + Duration::from_secs(offset);
            detector.observe_initiated_contact_failure(at, at).unwrap();
            detector.tick(at).unwrap();
        }
        assert_eq!(detector.assessment(), PeerFailureAssessment::Unobserved);
        assert_eq!(detector.snapshot().formation_count, 0);
        assert!(detector.loss_evidence().is_none());
    }

    /// §11.1 condition 2 and "an authenticated contact cancels formation".
    #[test]
    fn stage14_3_authenticated_contact_cancels_and_blocks_restart_formation() {
        let mut detector = conservative();
        let t1 = Instant::now();
        detector.observe_initiated_contact_failure(t1, t1).unwrap();
        assert_eq!(detector.snapshot().formation_count, 1);
        let contact = t1 + Duration::from_secs(1);
        detector
            .observe_session_established(session(), contact)
            .unwrap();
        let cancelled = detector.snapshot();
        assert_eq!(cancelled.assessment, PeerFailureAssessment::Unobserved);
        assert_eq!(cancelled.formation_count, 0);
        assert_eq!(cancelled.suspect_origin, None);
        // After authenticated traffic in this process session the restart
        // formation path no longer exists.
        for offset in [2, 7, 12] {
            let at = t1 + Duration::from_secs(offset);
            detector.observe_initiated_contact_failure(at, at).unwrap();
        }
        assert_eq!(detector.assessment(), PeerFailureAssessment::Unobserved);
        assert!(detector.loss_evidence().is_none());
    }

    /// §10.5 / §10.8 invalidation matrix (identity uncertainty).
    #[test]
    fn stage14_3_uncertainty_invalidation_state_matrix() {
        type Setup = fn() -> PeerFailureDetector;
        let cases: [(&str, Setup, PeerFailureAssessment, Option<SuspectOrigin>); 6] = [
            (
                "episode",
                || {
                    let mut d = conservative();
                    legacy_lost(&mut d);
                    d
                },
                PeerFailureAssessment::Suspect,
                Some(SuspectOrigin::UncertaintyFormation),
            ),
            (
                "healthy",
                || established_healthy().0.with_restart_formation(true),
                PeerFailureAssessment::Suspect,
                Some(SuspectOrigin::UncertaintyFormation),
            ),
            (
                "healthy-origin suspect",
                || {
                    let (mut d, now) = established_healthy();
                    d.observe_transport_failure(now).unwrap();
                    d
                },
                PeerFailureAssessment::Suspect,
                Some(SuspectOrigin::UncertaintyFormation),
            ),
            (
                "uncertainty-origin suspect",
                || {
                    let (mut d, now) = established_healthy();
                    d.observe_identity_uncertainty(now).unwrap();
                    d
                },
                PeerFailureAssessment::Suspect,
                Some(SuspectOrigin::UncertaintyFormation),
            ),
            (
                "unobserved",
                conservative,
                PeerFailureAssessment::Unobserved,
                None,
            ),
            (
                "restart formation",
                || {
                    let mut d = conservative();
                    let t = Instant::now();
                    d.observe_initiated_contact_failure(t, t).unwrap();
                    d
                },
                PeerFailureAssessment::Unobserved,
                None,
            ),
        ];
        for (name, setup, assessment, origin) in cases {
            let mut detector = setup();
            let generation = detector.snapshot().loss_generation;
            let at =
                detector.last_observed_at.unwrap_or_else(Instant::now) + Duration::from_secs(1);
            detector.observe_identity_uncertainty(at).unwrap();
            let snapshot = detector.snapshot();
            assert_eq!(snapshot.assessment, assessment, "{name}");
            assert_eq!(snapshot.suspect_origin, origin, "{name}");
            assert_eq!(snapshot.lost_at, None, "{name}");
            assert_eq!(snapshot.last_failed_contact_at, None, "{name}");
            assert_eq!(snapshot.suspect_since, None, "{name}");
            assert_eq!(snapshot.formation_count, 0, "{name}");
            assert_eq!(snapshot.loss_generation, generation, "{name}");
            assert!(detector.loss_evidence().is_none(), "{name}");
            // Attack I: elapsed time never re-confirms after uncertainty.
            detector.tick(at + Duration::from_secs(120)).unwrap();
            assert!(detector.loss_evidence().is_none(), "{name}");
            assert_ne!(
                detector.assessment(),
                PeerFailureAssessment::CommunicationLost,
                "{name}"
            );
        }
    }

    /// Attack J: UncertaintyFormation completes only on two new qualifying
    /// observations taken after the invalidating event (§10.5, §11.1).
    #[test]
    fn stage14_3_uncertainty_formation_completes_only_on_two_new_observations() {
        let mut detector = conservative();
        let (_, lost_at) = legacy_lost(&mut detector);
        let invalidated_at = lost_at + Duration::from_secs(1);
        detector
            .observe_identity_uncertainty(invalidated_at)
            .unwrap();

        // Observations that started before the invalidation never count.
        detector
            .observe_initiated_contact_failure(lost_at, invalidated_at)
            .unwrap();
        assert_eq!(detector.snapshot().formation_count, 0);

        let o1 = invalidated_at + Duration::from_secs(1);
        detector.observe_initiated_contact_failure(o1, o1).unwrap();
        assert_eq!(detector.snapshot().formation_count, 1);
        assert_eq!(
            detector.snapshot().suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        let o2 = o1 + Duration::from_secs(5);
        detector.observe_initiated_contact_failure(o2, o2).unwrap();
        let formed = detector.snapshot();
        assert_eq!(formed.assessment, PeerFailureAssessment::CommunicationLost);
        assert_eq!(formed.loss_generation, 2);
        assert_eq!(formed.last_failed_contact_at, Some(o2));

        // Availability mode: UncertaintyFormation stays Suspect until an
        // authenticated contact.
        let mut availability = detector_with_lost_then_uncertain();
        let at = availability.last_observed_at.unwrap() + Duration::from_secs(1);
        for offset in [0, 5, 10] {
            let start = at + Duration::from_secs(offset);
            availability
                .observe_initiated_contact_failure(start, start)
                .unwrap();
        }
        assert_eq!(availability.assessment(), PeerFailureAssessment::Suspect);
        assert!(availability.loss_evidence().is_none());
    }

    fn detector_with_lost_then_uncertain() -> PeerFailureDetector {
        let mut detector = detector();
        let (_, lost_at) = legacy_lost(&mut detector);
        detector
            .observe_identity_uncertainty(lost_at + Duration::from_secs(1))
            .unwrap();
        detector
    }

    /// Attack F and §34.3 "clock regression blocks and invalidates".
    #[test]
    fn stage14_3_clock_regression_invalidates_each_state() {
        // Fresh refreshed evidence → regression → no stale freshness survives.
        let mut refreshed = conservative();
        let (_, lost_at) = legacy_lost(&mut refreshed);
        let start = lost_at + Duration::from_secs(10);
        refreshed
            .observe_initiated_contact_failure(start, start)
            .unwrap();
        assert!(refreshed.loss_evidence().is_some());
        assert_eq!(
            refreshed.tick(start - Duration::from_secs(1)),
            Err(FailureAssessmentError::TimeWentBackwards)
        );
        assert!(refreshed.loss_evidence().is_none());
        assert_eq!(refreshed.snapshot().last_failed_contact_at, None);
        assert_eq!(
            refreshed.snapshot().suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        // Observations starting before the time high-water never count.
        refreshed
            .observe_initiated_contact_failure(start - Duration::from_secs(1), start)
            .unwrap();
        assert_eq!(refreshed.snapshot().formation_count, 0);

        let regress = |mut detector: PeerFailureDetector| {
            let last = detector.last_observed_at.unwrap();
            assert_eq!(
                detector.tick(last - Duration::from_millis(1)),
                Err(FailureAssessmentError::TimeWentBackwards)
            );
            assert!(detector.loss_evidence().is_none());
            detector.snapshot()
        };
        let healthy = regress(established_healthy().0);
        assert_eq!(
            healthy.suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        let suspect = regress({
            let (mut d, now) = established_healthy();
            d.observe_transport_failure(now + Duration::from_secs(1))
                .unwrap();
            d
        });
        assert_eq!(
            suspect.suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        let restart = regress({
            let mut d = conservative();
            let t = Instant::now();
            d.observe_initiated_contact_failure(t, t).unwrap();
            d
        });
        assert_eq!(restart.assessment, PeerFailureAssessment::Unobserved);
        let uncertain = regress(detector_with_lost_then_uncertain());
        assert_eq!(
            uncertain.suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        assert_eq!(uncertain.formation_count, 0);
    }

    /// Attack K: a partial formation never leaks across a reset boundary.
    #[test]
    fn stage14_3_partial_formation_never_leaks_across_a_reset() {
        for reset in ["uncertainty", "listener-generation"] {
            let mut detector = conservative();
            let t1 = Instant::now();
            detector.observe_initiated_contact_failure(t1, t1).unwrap();
            assert_eq!(detector.snapshot().formation_count, 1);
            let boundary = t1 + Duration::from_secs(1);
            match reset {
                "uncertainty" => detector.observe_identity_uncertainty(boundary).unwrap(),
                _ => detector.observe_listener_generation_change(),
            }
            assert_eq!(detector.snapshot().formation_count, 0, "{reset}");
            // An observation that would have completed the old sequence now
            // only starts a new one.
            let t2 = t1 + Duration::from_secs(6);
            detector.observe_initiated_contact_failure(t2, t2).unwrap();
            let snapshot = detector.snapshot();
            assert_eq!(
                snapshot.assessment,
                PeerFailureAssessment::Suspect,
                "{reset}"
            );
            assert_eq!(snapshot.formation_count, 1, "{reset}");
            assert_eq!(snapshot.suspect_since, Some(t2), "{reset}");
            assert!(detector.loss_evidence().is_none(), "{reset}");
        }
    }

    /// Appendix R.5 / §10.8: a listener-generation change resets formation
    /// but leaves a live episode untouched (window-only invalidation).
    #[test]
    fn stage14_3_listener_generation_change_resets_formation_only() {
        let mut formed = conservative();
        let t0 = Instant::now();
        restart_formed(&mut formed, t0);
        let before = formed.snapshot();
        formed.observe_listener_generation_change();
        assert_eq!(formed.snapshot(), before);
        assert!(formed.loss_evidence().is_some());

        let mut uncertain = detector_with_lost_then_uncertain().with_restart_formation(true);
        let at = uncertain.last_observed_at.unwrap() + Duration::from_secs(1);
        uncertain.observe_initiated_contact_failure(at, at).unwrap();
        assert_eq!(uncertain.snapshot().formation_count, 1);
        uncertain.observe_listener_generation_change();
        let snapshot = uncertain.snapshot();
        assert_eq!(
            snapshot.suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        assert_eq!(snapshot.formation_count, 0);
    }

    /// Observations never mint evidence until the exact CommunicationLost
    /// boundary (§11.1), and a refresh never changes the generation.
    #[test]
    fn stage14_3_observations_mint_no_evidence_before_the_loss_boundary() {
        let mut detector = conservative();
        let t1 = Instant::now();
        detector.observe_initiated_contact_failure(t1, t1).unwrap();
        assert!(detector.loss_evidence().is_none());
        detector
            .observe_identity_uncertainty(t1 + Duration::from_secs(1))
            .unwrap();
        assert!(detector.loss_evidence().is_none());
        detector.tick(t1 + Duration::from_secs(600)).unwrap();
        assert!(detector.loss_evidence().is_none());

        let mut formed = conservative();
        restart_formed(&mut formed, Instant::now());
        let generation = formed.snapshot().loss_generation;
        let next = formed.last_observed_at.unwrap() + Duration::from_secs(8);
        formed
            .observe_initiated_contact_failure(next, next)
            .unwrap();
        assert_eq!(formed.snapshot().loss_generation, generation);
        assert_eq!(formed.snapshot().last_failed_contact_at, Some(next));
    }

    /// Phase 14.2 contract preserved: formation never reuses a generation.
    #[test]
    fn stage14_3_formation_at_generation_exhaustion_fails_closed() {
        let mut detector = conservative();
        detector.set_loss_generation_for_test(u64::MAX);
        let t1 = Instant::now();
        detector.observe_initiated_contact_failure(t1, t1).unwrap();
        let t2 = t1 + Duration::from_secs(5);
        detector.observe_initiated_contact_failure(t2, t2).unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
        assert_eq!(detector.snapshot().loss_generation, u64::MAX);
        assert!(detector.loss_evidence().is_none());
    }

    #[test]
    fn stage14_3_verified_listen_window_refreshes_from_w_start_only() {
        let mut detector = detector();
        let (_, lost_at) = legacy_lost(&mut detector);
        let w_start = lost_at + Duration::from_secs(2);
        let w_end = w_start + Duration::from_secs(8);
        detector
            .observe_verified_listen_window(VerifiedListenWindow::new(w_start, w_end, 1))
            .unwrap();
        assert_eq!(detector.snapshot().last_failed_contact_at, Some(w_start));
        assert_eq!(
            detector.loss_evidence().unwrap().freshness_reference(),
            w_start
        );
        assert_eq!(detector.snapshot().loss_generation, 1);
    }

    // -----------------------------------------------------------------
    // Stage 14 Phase 14.3 remediation (Design Revision 5): F14.3-02 strict
    // formation floor and F14.3-DQ-01 stale formation provenance.
    // -----------------------------------------------------------------

    /// Asserts that the detector holds no formation progress and no evidence.
    fn assert_no_progress(detector: &PeerFailureDetector, generation: u64) {
        let snapshot = detector.snapshot();
        assert_eq!(snapshot.formation_count, 0);
        assert_eq!(snapshot.suspect_since, None);
        assert_eq!(snapshot.last_failed_contact_at, None);
        assert_eq!(snapshot.lost_at, None);
        assert_eq!(snapshot.loss_generation, generation);
        assert!(detector.loss_evidence().is_none());
    }

    /// Revision 5 §10.5 / §11.1 (F14.3-02): an observation that starts exactly
    /// at the uncertainty reset instant is not proven new. It is not counted,
    /// cannot help complete UncertaintyFormation, refreshes nothing, and
    /// mints no evidence; `<` is rejected and `>` is eligible.
    #[test]
    fn stage14_3r_floor_equality_rejected_after_uncertainty() {
        let mut detector = conservative();
        let (_, lost_at) = legacy_lost(&mut detector);
        let reset = lost_at + Duration::from_secs(1);
        detector.observe_identity_uncertainty(reset).unwrap();
        assert_eq!(detector.formation_floor, Some(reset));

        // `start == floor`: rejected.
        detector
            .observe_initiated_contact_failure(reset, reset + Duration::from_secs(1))
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Suspect);
        assert_eq!(
            detector.snapshot().suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );
        assert_no_progress(&detector, 1);

        // `start < floor`: rejected.
        detector
            .observe_initiated_contact_failure(
                reset - Duration::from_millis(1),
                reset + Duration::from_secs(2),
            )
            .unwrap();
        assert_no_progress(&detector, 1);

        // Had the equal-instant observation counted, this one (a full window
        // after it) would complete the episode. It is only the first.
        let first = reset + FAILURE_CONFIRMATION_WINDOW;
        detector
            .observe_initiated_contact_failure(first, first)
            .unwrap();
        let snapshot = detector.snapshot();
        assert_eq!(snapshot.assessment, PeerFailureAssessment::Suspect);
        assert_eq!(snapshot.formation_count, 1);
        assert_eq!(snapshot.suspect_since, Some(first));
        assert_eq!(snapshot.loss_generation, 1);
        assert_eq!(snapshot.last_failed_contact_at, None);
        assert!(detector.loss_evidence().is_none());

        // `start > floor` (by the smallest step used here): eligible.
        let mut eligible = conservative();
        let (_, lost_at) = legacy_lost(&mut eligible);
        let reset = lost_at + Duration::from_secs(1);
        eligible.observe_identity_uncertainty(reset).unwrap();
        let after = reset + Duration::from_millis(1);
        eligible
            .observe_initiated_contact_failure(after, after)
            .unwrap();
        assert_eq!(eligible.snapshot().formation_count, 1);
        assert_eq!(eligible.snapshot().suspect_since, Some(after));
    }

    /// Revision 5 (F14.3-02): the clock-regression floor is the retained time
    /// high-water, and it is strict too; an equal-instant observation neither
    /// starts nor completes RestartFormation.
    #[test]
    fn stage14_3r_floor_equality_rejected_after_clock_regression() {
        let mut detector = conservative();
        let high_water = Instant::now() + Duration::from_secs(10);
        detector.tick(high_water).unwrap();
        assert_eq!(
            detector.tick(high_water - Duration::from_millis(1)),
            Err(FailureAssessmentError::TimeWentBackwards)
        );
        assert_eq!(detector.formation_floor, Some(high_water));

        detector
            .observe_initiated_contact_failure(high_water, high_water + Duration::from_secs(1))
            .unwrap();
        assert_eq!(detector.assessment(), PeerFailureAssessment::Unobserved);
        assert_no_progress(&detector, 0);

        let first = high_water + FAILURE_CONFIRMATION_WINDOW;
        detector
            .observe_initiated_contact_failure(first, first)
            .unwrap();
        assert_eq!(
            detector.snapshot().suspect_origin,
            Some(SuspectOrigin::RestartFormation)
        );
        assert_eq!(detector.snapshot().formation_count, 1);
        assert_eq!(detector.snapshot().suspect_since, Some(first));
        assert!(detector.loss_evidence().is_none());

        let second = first + FAILURE_CONFIRMATION_WINDOW;
        detector
            .observe_initiated_contact_failure(second, second)
            .unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        assert_eq!(detector.snapshot().last_failed_contact_at, Some(second));
    }

    /// Revision 5 §10.8 (F14.3-DQ-01) stale-provenance attack: formation
    /// progress, observations started before an authenticated session, and an
    /// episode formed before the first authenticated session never survive
    /// that session as evidence.
    #[test]
    fn stage14_3r_authenticated_session_rejects_stale_formation_provenance() {
        // UncertaintyFormation with one counted observation.
        let mut detector = conservative();
        let (_, lost_at) = legacy_lost(&mut detector);
        let reset = lost_at + Duration::from_secs(1);
        detector.observe_identity_uncertainty(reset).unwrap();
        let o1 = reset + Duration::from_secs(1);
        detector.observe_initiated_contact_failure(o1, o1).unwrap();
        assert_eq!(detector.snapshot().formation_count, 1);

        let session_at = o1 + Duration::from_secs(6);
        let replacement = SessionId::new("session-2");
        detector
            .observe_session_established(replacement.clone(), session_at)
            .unwrap();
        assert_eq!(detector.formation_floor, Some(session_at));
        assert_eq!(detector.current_session, Some(replacement));
        assert_no_progress(&detector, 1);

        // An attempt that started before the session (and a full window after
        // o1) is reported late: it would have completed the old sequence.
        let late = o1 + FAILURE_CONFIRMATION_WINDOW;
        assert!(late < session_at);
        detector
            .observe_initiated_contact_failure(late, session_at + Duration::from_secs(1))
            .unwrap();
        assert_no_progress(&detector, 1);
        // An attempt starting at the session instant is not proven newer.
        detector
            .observe_initiated_contact_failure(session_at, session_at + Duration::from_secs(1))
            .unwrap();
        assert_no_progress(&detector, 1);
        assert_eq!(
            detector.snapshot().suspect_origin,
            Some(SuspectOrigin::UncertaintyFormation)
        );

        // Only a complete post-session sequence forms a new episode.
        let n1 = session_at + Duration::from_secs(1);
        detector.observe_initiated_contact_failure(n1, n1).unwrap();
        assert_eq!(detector.snapshot().formation_count, 1);
        let n2 = n1 + FAILURE_CONFIRMATION_WINDOW;
        detector.observe_initiated_contact_failure(n2, n2).unwrap();
        assert_eq!(
            detector.assessment(),
            PeerFailureAssessment::CommunicationLost
        );
        assert_eq!(detector.snapshot().loss_generation, 2);
        assert_eq!(detector.loss_evidence().unwrap().freshness_reference(), n2);

        // A restart-formed episode (no session yet) is invalidated by the
        // first authenticated session; a late pre-session failed contact can
        // neither refresh it nor revive it.
        let mut formed = conservative();
        let t0 = Instant::now();
        let second = restart_formed(&mut formed, t0);
        assert!(formed.loss_evidence().is_some());
        let session_at = second + Duration::from_secs(1);
        formed
            .observe_session_established(session(), session_at)
            .unwrap();
        let snapshot = formed.snapshot();
        assert_eq!(
            snapshot.assessment,
            PeerFailureAssessment::CommunicationLost
        );
        assert_eq!(snapshot.lost_at, None);
        assert_eq!(snapshot.last_failed_contact_at, None);
        assert_eq!(snapshot.suspect_since, Some(session_at));
        assert_eq!(snapshot.loss_generation, 1);
        assert!(formed.loss_evidence().is_none());
        formed
            .observe_initiated_contact_failure(
                second + Duration::from_millis(500),
                session_at + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(formed.snapshot().last_failed_contact_at, None);
        assert!(formed.loss_evidence().is_none());
        // Only the pre-existing re-confirmation (a full window under the new
        // session, a new generation, reference = the new lost_at) follows.
        let reconfirmed = session_at + FAILURE_CONFIRMATION_WINDOW;
        formed.tick(reconfirmed).unwrap();
        let evidence = formed.loss_evidence().unwrap();
        assert_eq!(evidence.generation(), 2);
        assert_eq!(evidence.freshness_reference(), reconfirmed);
    }
}
