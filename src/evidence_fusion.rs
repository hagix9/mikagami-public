//! Runtime-only fusion of peer failure and Witness reachability evidence.
//!
//! This module reports diagnostic evidence only. It does not authorize or
//! perform promotion, demotion, lease mutation, fencing, or resource work.

use crate::failure_assessment::PeerFailureAssessment;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "witness_evidence_adapter.rs"]
pub mod adapter;

pub const WITNESS_EVIDENCE_TIMEOUT: Duration = Duration::from_secs(5);

/// Semantic status of the freshest Witness authority-view observation.
///
/// `AuthorityViewCompatible` (Stage 13.3, replacing the old ambiguous
/// authorization-relevant `Reachable`) means only: an authenticated,
/// correlated `TermStatus` was classified by the evidence adapter as
/// carrying no conflicting authoritative holder. It does **not** mean
/// transport reachability, peer death, lease ownership, fencing, or
/// mutation permission. `AuthorityViewIncompatible` means a completed,
/// authenticated `TermStatus` was classified as conflicting, expired,
/// or inconsistent — the Witness answered, but its view cannot support
/// authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessStatus {
    Unknown,
    AuthorityViewCompatible,
    AuthorityViewIncompatible,
    Unavailable,
    NotReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessHolder {
    Local,
    Peer,
    None,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceFusionState {
    Unproven,
    PeerDegraded,
    /// Stage 13.3 (replacing `CorroboratedLoss`): fresh local
    /// communication-loss evidence plus a fresh `AuthorityViewCompatible`
    /// Witness view are both present. Means only "Stage 13.3 evidence
    /// requirements are satisfied" — never peer death, fencing, lease
    /// ownership, or promotion-safety.
    FailoverEvidenceReady,
    AmbiguousPartition,
}

/// Opaque runtime-local evidence. The child adapter is the production issuer
/// for local Unavailable completions and remote authority-view classifications.
/// Public callers cannot construct or refresh this token.
#[derive(Debug, Clone)]
pub struct WitnessObservation {
    origin: Arc<()>,
    generation: u64,
    observed_at: Instant,
    data: ObservationData,
}

#[derive(Debug, Clone)]
struct ObservationData {
    status: WitnessStatus,
    boot_id: Option<String>,
    term: Option<u64>,
    holder: WitnessHolder,
}

#[cfg(test)]
impl ObservationData {
    pub fn authority_view_compatible(
        boot_id: impl Into<String>,
        term: Option<u64>,
        holder: WitnessHolder,
    ) -> Self {
        Self {
            status: WitnessStatus::AuthorityViewCompatible,
            boot_id: Some(boot_id.into()),
            term,
            holder,
        }
    }

    pub const fn unavailable() -> Self {
        Self {
            status: WitnessStatus::Unavailable,
            boot_id: None,
            term: None,
            holder: WitnessHolder::Unknown,
        }
    }

    pub const fn unknown() -> Self {
        Self {
            status: WitnessStatus::Unknown,
            boot_id: None,
            term: None,
            holder: WitnessHolder::Unknown,
        }
    }

    pub const fn not_ready() -> Self {
        Self {
            status: WitnessStatus::NotReady,
            boot_id: None,
            term: None,
            holder: WitnessHolder::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceFusionSnapshot {
    pub state: EvidenceFusionState,
    pub peer_assessment: PeerFailureAssessment,
    pub witness_status: WitnessStatus,
    pub witness_observed_at: Option<Instant>,
    pub witness_boot_id: Option<String>,
    pub witness_term: Option<u64>,
    pub witness_holder: WitnessHolder,
}

impl EvidenceFusionSnapshot {
    pub fn witness_is_fresh(&self, now: Instant, timeout: Duration) -> bool {
        self.witness_observed_at
            .and_then(|observed| now.checked_duration_since(observed))
            .is_some_and(|elapsed| elapsed <= timeout)
    }
}

/// Term-free, holder-free projection of [`EvidenceFusionSnapshot`] suitable for
/// policy/status/current-attempt evaluation.
///
/// It intentionally excludes `witness_term` and `witness_holder`: those remain
/// historical/stored evidence on the snapshot for status/debug, and must never
/// be substitutable for the current correlated authority term. The current
/// authority term is represented separately by
/// `evidence_fusion::adapter::WitnessAuthorityViewEvidence`, which only the observation
/// adapter can construct from a current correlated GET_TERM completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessEvidenceView {
    pub state: EvidenceFusionState,
    pub peer_assessment: PeerFailureAssessment,
    pub witness_status: WitnessStatus,
    pub witness_observed_at: Option<Instant>,
    pub witness_boot_id: Option<String>,
}

impl WitnessEvidenceView {
    /// Derive the safe, term-free view. There is deliberately no `From`
    /// conversion and no constructor that accepts a term or holder.
    pub fn from_snapshot(snapshot: &EvidenceFusionSnapshot) -> Self {
        Self {
            state: snapshot.state,
            peer_assessment: snapshot.peer_assessment,
            witness_status: snapshot.witness_status,
            witness_observed_at: snapshot.witness_observed_at,
            witness_boot_id: snapshot.witness_boot_id.clone(),
        }
    }

    pub fn witness_is_fresh(&self, now: Instant, timeout: Duration) -> bool {
        self.witness_observed_at
            .and_then(|observed| now.checked_duration_since(observed))
            .is_some_and(|elapsed| elapsed <= timeout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceFusionError {
    TimeWentBackwards,
    ZeroEvidenceTimeout,
    InvalidObservation,
    ReplayedObservation,
}

impl fmt::Display for EvidenceFusionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimeWentBackwards => write!(f, "evidence fusion time moved backwards"),
            Self::InvalidObservation => write!(f, "invalid Witness observation provenance"),
            Self::ReplayedObservation => write!(f, "replayed or older Witness observation"),
            Self::ZeroEvidenceTimeout => {
                write!(f, "Witness evidence timeout must be greater than zero")
            }
        }
    }
}

impl std::error::Error for EvidenceFusionError {}

#[derive(Debug)]
pub struct EvidenceFusion {
    observation_origin: Arc<()>,
    observation_high_water: u64,
    observation_time_high_water: Option<Instant>,
    witness_timeout: Duration,
    state: EvidenceFusionState,
    peer_assessment: PeerFailureAssessment,
    /// Fresh local communication-loss evidence for the current
    /// `CommunicationLost` assessment, supplied by the sole detector
    /// owner each observation. `None` while not lost or while the epoch
    /// is invalidated — and always cleared on recovery.
    local_loss: Option<crate::failure_assessment::LocalLossEvidence>,
    /// Provenance high-water for local loss generations: evidence with
    /// a lower generation than already accepted is regression and is
    /// rejected; equal or newer generations are accepted (an equal
    /// generation is the same episode re-observed).
    local_loss_high_water: u64,
    witness_status: WitnessStatus,
    witness_observed_at: Option<Instant>,
    witness_boot_id: Option<String>,
    witness_term: Option<u64>,
    witness_holder: WitnessHolder,
    last_observed_at: Option<Instant>,
}

impl EvidenceFusion {
    pub fn new(witness_timeout: Duration) -> Result<Self, EvidenceFusionError> {
        if witness_timeout.is_zero() {
            return Err(EvidenceFusionError::ZeroEvidenceTimeout);
        }
        Ok(Self {
            observation_origin: Arc::new(()),
            observation_high_water: 0,
            observation_time_high_water: None,
            witness_timeout,
            state: EvidenceFusionState::Unproven,
            peer_assessment: PeerFailureAssessment::Unobserved,
            local_loss: None,
            local_loss_high_water: 0,
            witness_status: WitnessStatus::Unknown,
            witness_observed_at: None,
            witness_boot_id: None,
            witness_term: None,
            witness_holder: WitnessHolder::Unknown,
            last_observed_at: None,
        })
    }

    pub fn with_default_timeout() -> Self {
        Self::new(WITNESS_EVIDENCE_TIMEOUT).expect("non-zero default timeout")
    }

    pub const fn witness_timeout(&self) -> Duration {
        self.witness_timeout
    }

    pub fn snapshot(&self) -> EvidenceFusionSnapshot {
        EvidenceFusionSnapshot {
            state: self.state,
            peer_assessment: self.peer_assessment,
            witness_status: self.witness_status,
            witness_observed_at: self.witness_observed_at,
            witness_boot_id: self.witness_boot_id.clone(),
            witness_term: self.witness_term,
            witness_holder: self.witness_holder,
        }
    }

    /// Record the current peer assessment and — only when the
    /// assessment is `CommunicationLost` — the fresh local loss
    /// evidence minted by the detector for this episode.
    ///
    /// Recovery (`Healthy`/`Suspect`/`Unobserved`) always clears the
    /// stored evidence: a recovered peer can never leave stale loss
    /// evidence behind. A `CommunicationLost` assessment without
    /// evidence, or with an expired epoch, is not fresh and cannot
    /// combine with Witness evidence.
    ///
    /// Evidence with a generation lower than the highest already
    /// accepted is provenance regression and is rejected; an equal
    /// generation is the same episode re-observed.
    pub fn observe_peer(
        &mut self,
        assessment: PeerFailureAssessment,
        local_loss: Option<crate::failure_assessment::LocalLossEvidence>,
        now: Instant,
    ) -> Result<(), EvidenceFusionError> {
        self.observe_time(now)?;
        if let Some(evidence) = &local_loss
            && evidence.generation() < self.local_loss_high_water
        {
            return Err(EvidenceFusionError::ReplayedObservation);
        }
        self.peer_assessment = assessment;
        match local_loss {
            Some(evidence) if assessment == PeerFailureAssessment::CommunicationLost => {
                self.local_loss_high_water = evidence.generation();
                self.local_loss = Some(evidence);
            }
            Some(_) => {
                // Evidence minted for a non-lost assessment is
                // inconsistent input; fail closed by dropping it.
                self.local_loss = None;
            }
            None => self.local_loss = None,
        }
        self.recompute(now);
        Ok(())
    }

    pub fn observe_witness(
        &mut self,
        observation: WitnessObservation,
        now: Instant,
    ) -> Result<(), EvidenceFusionError> {
        if self.last_observed_at.is_some_and(|last| now < last) || observation.observed_at > now {
            return Err(EvidenceFusionError::TimeWentBackwards);
        }
        // An authority-view-compatible claim must carry the correlated
        // authority term it was classified from; a term-free "compatible"
        // token is not valid evidence.
        if !Arc::ptr_eq(&self.observation_origin, &observation.origin)
            || (observation.data.status == WitnessStatus::AuthorityViewCompatible
                && observation.data.term.is_none())
        {
            return Err(EvidenceFusionError::InvalidObservation);
        }
        if observation.generation <= self.observation_high_water {
            return Err(EvidenceFusionError::ReplayedObservation);
        }
        if self
            .observation_time_high_water
            .is_some_and(|last| observation.observed_at < last)
        {
            return Err(EvidenceFusionError::TimeWentBackwards);
        }
        self.observe_time(now)?;
        self.observation_high_water = observation.generation;
        self.observation_time_high_water = Some(observation.observed_at);
        let source_time = observation.observed_at;
        let observation = observation.data;
        if observation.status == WitnessStatus::AuthorityViewCompatible
            && self
                .witness_boot_id
                .as_ref()
                .zip(observation.boot_id.as_ref())
                .is_some_and(|(previous, current)| previous != current)
        {
            self.witness_status = WitnessStatus::NotReady;
            self.witness_observed_at = None;
            self.witness_boot_id = observation.boot_id;
            self.witness_term = None;
            self.witness_holder = WitnessHolder::Unknown;
        } else {
            self.witness_status = observation.status;
            self.witness_observed_at = Some(source_time);
            self.witness_boot_id = observation.boot_id.or_else(|| self.witness_boot_id.clone());
            self.witness_term = observation.term;
            self.witness_holder = observation.holder;
        }
        self.recompute(now);
        Ok(())
    }

    pub fn tick(&mut self, now: Instant) -> Result<(), EvidenceFusionError> {
        self.observe_time(now)?;
        self.recompute(now);
        Ok(())
    }

    fn recompute(&mut self, now: Instant) {
        self.state = match self.peer_assessment {
            PeerFailureAssessment::Healthy | PeerFailureAssessment::Unobserved => {
                EvidenceFusionState::Unproven
            }
            PeerFailureAssessment::Suspect => EvidenceFusionState::PeerDegraded,
            // Both axes must be fresh inside the same observation
            // transaction: fresh confirmed local loss AND a fresh
            // authority-view-compatible Witness view. Anything else is
            // unproven or ambiguous — never ready.
            PeerFailureAssessment::CommunicationLost => {
                if !self.local_loss_is_fresh(now) || !self.witness_observation_is_fresh(now) {
                    EvidenceFusionState::Unproven
                } else {
                    match self.witness_status {
                        WitnessStatus::AuthorityViewCompatible => {
                            EvidenceFusionState::FailoverEvidenceReady
                        }
                        WitnessStatus::AuthorityViewIncompatible
                        | WitnessStatus::Unavailable
                        | WitnessStatus::NotReady => EvidenceFusionState::AmbiguousPartition,
                        WitnessStatus::Unknown => EvidenceFusionState::Unproven,
                    }
                }
            }
        };
    }

    fn local_loss_is_fresh(&self, now: Instant) -> bool {
        self.local_loss
            .as_ref()
            .is_some_and(|evidence| evidence.is_fresh_at(now))
    }

    fn witness_observation_is_fresh(&self, now: Instant) -> bool {
        self.witness_observed_at
            .and_then(|observed| now.checked_duration_since(observed))
            .is_some_and(|elapsed| elapsed <= self.witness_timeout)
    }

    fn observe_time(&mut self, now: Instant) -> Result<(), EvidenceFusionError> {
        if self.last_observed_at.is_some_and(|last| now < last) {
            return Err(EvidenceFusionError::TimeWentBackwards);
        }
        self.last_observed_at = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Synthetic trusted completion issuer, deliberately absent from production.
    fn issued(
        fusion: &EvidenceFusion,
        generation: u64,
        data: ObservationData,
        at: Instant,
    ) -> WitnessObservation {
        WitnessObservation {
            origin: Arc::clone(&fusion.observation_origin),
            generation,
            observed_at: at,
            data,
        }
    }

    impl EvidenceFusion {
        fn observe_test_witness(
            &mut self,
            data: ObservationData,
            at: Instant,
        ) -> Result<(), EvidenceFusionError> {
            let token = issued(
                self,
                self.observation_high_water.checked_add(1).unwrap(),
                data,
                at,
            );
            self.observe_witness(token, at)
        }
    }

    #[test]
    fn all_statuses_exact_boundary_and_stale_replay_do_not_refresh() {
        for (data, expected) in [
            (
                ObservationData::authority_view_compatible("boot-1", Some(7), WitnessHolder::None),
                EvidenceFusionState::FailoverEvidenceReady,
            ),
            (
                ObservationData::unavailable(),
                EvidenceFusionState::AmbiguousPartition,
            ),
            (
                ObservationData::not_ready(),
                EvidenceFusionState::AmbiguousPartition,
            ),
            (ObservationData::unknown(), EvidenceFusionState::Unproven),
        ] {
            let mut f = fusion();
            let t = t0();
            f.observe_peer(PeerFailureAssessment::CommunicationLost, fresh_loss(t), t)
                .unwrap();
            let a = issued(&f, 1, data.clone(), t);
            f.observe_witness(a.clone(), t).unwrap();
            f.tick(t + Duration::from_secs(5)).unwrap();
            assert_eq!(f.snapshot().state, expected);
            f.tick(t + Duration::from_secs(5) + Duration::from_nanos(1))
                .unwrap();
            assert_eq!(f.snapshot().state, EvidenceFusionState::Unproven);
            let before = f.snapshot();
            let clock = f.last_observed_at;
            assert_eq!(
                f.observe_witness(a, t + Duration::from_secs(6)),
                Err(EvidenceFusionError::ReplayedObservation)
            );
            assert_eq!(f.snapshot(), before);
            assert_eq!(f.last_observed_at, clock);
            assert_eq!(f.observation_high_water, 1);
            let b = issued(&f, 2, data, t + Duration::from_secs(7));
            f.observe_witness(b, t + Duration::from_secs(7)).unwrap();
            assert_eq!(f.snapshot().state, expected);
        }
    }

    #[test]
    fn boot_change_requires_new_completion_not_replayed_token() {
        let (mut f, t) = lost_with_witness();
        let b = issued(
            &f,
            2,
            ObservationData::authority_view_compatible("boot-2", Some(8), WitnessHolder::Peer),
            t,
        );
        f.observe_witness(b.clone(), t).unwrap();
        assert_eq!(f.snapshot().witness_status, WitnessStatus::NotReady);
        let before = f.snapshot();
        assert_eq!(
            f.observe_witness(b, t),
            Err(EvidenceFusionError::ReplayedObservation)
        );
        assert_eq!(f.snapshot(), before);
        let c = issued(
            &f,
            3,
            ObservationData::authority_view_compatible("boot-2", Some(8), WitnessHolder::Peer),
            t,
        );
        f.observe_witness(c, t).unwrap();
        assert_eq!(
            f.snapshot().state,
            EvidenceFusionState::FailoverEvidenceReady
        );
    }

    #[test]
    fn invalid_boot_and_foreign_runtime_tokens_are_rejected_without_mutation() {
        let mut f = fusion();
        let t = t0();
        // A term-free `AuthorityViewCompatible` claim is not valid
        // evidence: compatibility is classified from a correlated
        // authority term, so the term is mandatory provenance.
        for term in [None] {
            let token = issued(
                &f,
                1,
                ObservationData {
                    status: WitnessStatus::AuthorityViewCompatible,
                    boot_id: None,
                    term,
                    holder: WitnessHolder::None,
                },
                t,
            );
            let before = f.snapshot();
            assert_eq!(
                f.observe_witness(token, t),
                Err(EvidenceFusionError::InvalidObservation)
            );
            assert_eq!(f.snapshot(), before);
            assert_eq!(f.observation_high_water, 0);
        }
        let token = issued(&f, 1, ObservationData::unavailable(), t);
        let mut restarted = fusion();
        assert_eq!(
            restarted.observe_witness(token, t),
            Err(EvidenceFusionError::InvalidObservation)
        );
        assert_eq!(restarted.snapshot().state, EvidenceFusionState::Unproven);
        assert_eq!(restarted.observation_high_water, 0);
    }

    #[test]
    fn adversarial_unavailable_recovery_timeline_retains_replay_watermark() {
        let mut f = fusion();
        let t = t0();
        f.observe_peer(PeerFailureAssessment::CommunicationLost, fresh_loss(t), t)
            .unwrap();
        let a = issued(&f, 1, ObservationData::unavailable(), t);
        f.observe_witness(a.clone(), t).unwrap();
        f.tick(t + Duration::from_secs(5)).unwrap();
        assert_eq!(f.snapshot().state, EvidenceFusionState::AmbiguousPartition);
        f.tick(t + Duration::from_secs(5) + Duration::from_nanos(1))
            .unwrap();
        assert_eq!(f.snapshot().state, EvidenceFusionState::Unproven);
        assert_eq!(
            f.observe_witness(a, t + Duration::from_secs(6)),
            Err(EvidenceFusionError::ReplayedObservation)
        );
        let b = issued(
            &f,
            2,
            ObservationData::unavailable(),
            t + Duration::from_secs(7),
        );
        f.observe_witness(b.clone(), t + Duration::from_secs(7))
            .unwrap();
        assert_eq!(f.snapshot().state, EvidenceFusionState::AmbiguousPartition);
        f.tick(t + Duration::from_secs(12)).unwrap();
        assert_eq!(f.snapshot().state, EvidenceFusionState::AmbiguousPartition);
        let c = issued(
            &f,
            3,
            ObservationData::authority_view_compatible("boot-1", Some(7), WitnessHolder::None),
            t + Duration::from_secs(13),
        );
        f.observe_witness(c.clone(), t + Duration::from_secs(13))
            .unwrap();
        assert_eq!(
            f.snapshot().state,
            EvidenceFusionState::FailoverEvidenceReady
        );
        f.observe_peer(
            PeerFailureAssessment::Healthy,
            None,
            t + Duration::from_secs(14),
        )
        .unwrap();
        assert_eq!(f.snapshot().state, EvidenceFusionState::Unproven);
        for token in [b, c] {
            assert_eq!(
                f.observe_witness(token, t + Duration::from_secs(15)),
                Err(EvidenceFusionError::ReplayedObservation)
            );
            assert_eq!(f.observation_high_water, 3);
            assert_eq!(
                f.snapshot().witness_observed_at,
                Some(t + Duration::from_secs(13))
            );
        }
        f.observe_peer(
            PeerFailureAssessment::CommunicationLost,
            fresh_loss(t + Duration::from_secs(19)),
            t + Duration::from_secs(19),
        )
        .unwrap();
        assert_eq!(f.snapshot().state, EvidenceFusionState::Unproven);
    }

    #[test]
    fn source_time_not_delivery_time_controls_freshness_and_rejects_reversal() {
        let mut f = fusion();
        let t = t0();
        f.observe_peer(PeerFailureAssessment::CommunicationLost, fresh_loss(t), t)
            .unwrap();
        let a = issued(&f, 1, ObservationData::unavailable(), t);
        f.observe_witness(a, t + Duration::from_secs(6)).unwrap();
        assert_eq!(f.snapshot().state, EvidenceFusionState::Unproven);
        assert_eq!(f.snapshot().witness_observed_at, Some(t));
        let before = f.snapshot();
        for at in [t - Duration::from_nanos(1), t + Duration::from_secs(8)] {
            let b = issued(&f, 2, ObservationData::unavailable(), at);
            assert_eq!(
                f.observe_witness(b, t + Duration::from_secs(7)),
                Err(EvidenceFusionError::TimeWentBackwards)
            );
            assert_eq!(f.snapshot(), before);
            assert_eq!(f.observation_high_water, 1);
        }
    }

    fn fusion() -> EvidenceFusion {
        EvidenceFusion::new(Duration::from_secs(5)).unwrap()
    }

    /// Fresh local loss evidence epoch for test observations: the same
    /// generation each call (same episode re-observed is legal).
    fn fresh_loss(at: Instant) -> Option<crate::failure_assessment::LocalLossEvidence> {
        Some(crate::failure_assessment::LocalLossEvidence::new_for_test(
            1, at,
        ))
    }

    fn t0() -> Instant {
        Instant::now()
    }

    fn lost_with_witness() -> (EvidenceFusion, Instant) {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(now),
                now,
            )
            .unwrap();
        fusion
            .observe_test_witness(
                ObservationData::authority_view_compatible("boot-1", Some(7), WitnessHolder::None),
                now,
            )
            .unwrap();
        (fusion, now)
    }

    #[test]
    fn startup_is_unproven_and_time_alone_does_not_corrobate() {
        let mut fusion = fusion();
        let now = t0();
        fusion.tick(now + Duration::from_secs(60)).unwrap();
        let snapshot = fusion.snapshot();
        assert_eq!(snapshot.state, EvidenceFusionState::Unproven);
        assert_eq!(snapshot.witness_status, WitnessStatus::Unknown);
    }

    #[test]
    fn healthy_peer_is_unproven_even_when_witness_is_unavailable() {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(PeerFailureAssessment::Healthy, None, now)
            .unwrap();
        fusion
            .observe_test_witness(ObservationData::unavailable(), now)
            .unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::Unproven);
    }

    // MKM-ARCH-006 (failure independence at the value boundary): a Witness
    // observation cannot fabricate healthy peer evidence, and a peer
    // assessment cannot fabricate corroborating Witness status.
    #[test]
    fn mkm_arch_006_peer_and_witness_evidence_are_independent() {
        let mut fusion = fusion();
        let now = t0();
        // An AuthorityViewCompatible Witness observation must not turn an
        // Unobserved peer into Healthy; fusion remains Unproven for a
        // non-lost peer.
        fusion
            .observe_test_witness(
                ObservationData::authority_view_compatible("boot-1", Some(7), WitnessHolder::None),
                now,
            )
            .unwrap();
        let snapshot = fusion.snapshot();
        assert_eq!(snapshot.peer_assessment, PeerFailureAssessment::Unobserved);
        assert_eq!(snapshot.state, EvidenceFusionState::Unproven);

        // A peer assessment update cannot change the Witness status/term that
        // was observed independently.
        let witness_status_before = snapshot.witness_status;
        let witness_term_before = snapshot.witness_term;
        fusion
            .observe_peer(PeerFailureAssessment::Suspect, None, now)
            .unwrap();
        let after = fusion.snapshot();
        assert_eq!(after.witness_status, witness_status_before);
        assert_eq!(after.witness_term, witness_term_before);
    }

    #[test]
    fn suspect_peer_is_only_degraded() {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(PeerFailureAssessment::Suspect, None, now)
            .unwrap();
        fusion
            .observe_test_witness(
                ObservationData::authority_view_compatible(
                    "boot-1",
                    Some(7),
                    WitnessHolder::Unknown,
                ),
                now,
            )
            .unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::PeerDegraded);
    }

    #[test]
    fn communication_lost_and_fresh_witness_is_corroborated_only() {
        let (fusion, now) = lost_with_witness();
        let snapshot = fusion.snapshot();
        assert_eq!(snapshot.state, EvidenceFusionState::FailoverEvidenceReady);
        assert!(snapshot.witness_is_fresh(now, fusion.witness_timeout()));
        assert_eq!(snapshot.witness_holder, WitnessHolder::None);
    }

    #[test]
    fn communication_lost_and_unavailable_witness_is_ambiguous() {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(now),
                now,
            )
            .unwrap();
        fusion
            .observe_test_witness(ObservationData::unavailable(), now)
            .unwrap();
        assert_eq!(
            fusion.snapshot().state,
            EvidenceFusionState::AmbiguousPartition
        );
    }

    #[test]
    fn unknown_witness_does_not_corrobate() {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(now),
                now,
            )
            .unwrap();
        fusion
            .observe_test_witness(ObservationData::unknown(), now)
            .unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::Unproven);
    }

    #[test]
    fn witness_reachability_expires_without_sticky_corroboration() {
        let (mut fusion, now) = lost_with_witness();
        fusion.tick(now + Duration::from_secs(6)).unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::Unproven);
        assert!(
            !fusion
                .snapshot()
                .witness_is_fresh(now + Duration::from_secs(6), fusion.witness_timeout())
        );
    }

    #[test]
    fn unavailable_witness_expires_from_ambiguous_to_unproven() {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(now),
                now,
            )
            .unwrap();
        fusion
            .observe_test_witness(ObservationData::unavailable(), now)
            .unwrap();
        assert_eq!(
            fusion.snapshot().state,
            EvidenceFusionState::AmbiguousPartition
        );
        fusion.tick(now + Duration::from_secs(6)).unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::Unproven);
        fusion.tick(now + Duration::from_secs(60)).unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::Unproven);
    }

    #[test]
    fn not_ready_witness_expires_from_ambiguous_to_unproven() {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(now),
                now,
            )
            .unwrap();
        fusion
            .observe_test_witness(ObservationData::not_ready(), now)
            .unwrap();
        assert_eq!(
            fusion.snapshot().state,
            EvidenceFusionState::AmbiguousPartition
        );
        fusion.tick(now + Duration::from_secs(6)).unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::Unproven);
        fusion.tick(now + Duration::from_secs(60)).unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::Unproven);
    }

    #[test]
    fn fresh_witness_observation_after_expiry_is_used_again() {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(now),
                now,
            )
            .unwrap();
        fusion
            .observe_test_witness(ObservationData::unavailable(), now)
            .unwrap();
        fusion.tick(now + Duration::from_secs(6)).unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::Unproven);
        fusion
            .observe_test_witness(
                ObservationData::authority_view_compatible("boot-1", Some(7), WitnessHolder::None),
                now + Duration::from_secs(7),
            )
            .unwrap();
        assert_eq!(
            fusion.snapshot().state,
            EvidenceFusionState::FailoverEvidenceReady
        );
    }

    #[test]
    fn witness_recovery_changes_only_evidence() {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(now),
                now,
            )
            .unwrap();
        fusion
            .observe_test_witness(ObservationData::unavailable(), now)
            .unwrap();
        fusion
            .observe_test_witness(
                ObservationData::authority_view_compatible("boot-1", Some(7), WitnessHolder::Peer),
                now,
            )
            .unwrap();
        assert_eq!(
            fusion.snapshot().state,
            EvidenceFusionState::FailoverEvidenceReady
        );
        assert_eq!(
            fusion.snapshot().peer_assessment,
            PeerFailureAssessment::CommunicationLost
        );
    }

    #[test]
    fn peer_recovery_clears_all_fusion_evidence() {
        let (mut fusion, now) = lost_with_witness();
        fusion
            .observe_peer(
                PeerFailureAssessment::Healthy,
                None,
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(fusion.snapshot().state, EvidenceFusionState::Unproven);
    }

    #[test]
    fn witness_boot_change_invalidates_prior_corroboration() {
        let (mut fusion, now) = lost_with_witness();
        fusion
            .observe_test_witness(
                ObservationData::authority_view_compatible("boot-2", Some(8), WitnessHolder::None),
                now + Duration::from_secs(1),
            )
            .unwrap();
        let snapshot = fusion.snapshot();
        assert_eq!(snapshot.state, EvidenceFusionState::Unproven);
        assert_eq!(snapshot.witness_status, WitnessStatus::NotReady);
        assert_eq!(snapshot.witness_boot_id.as_deref(), Some("boot-2"));
    }

    #[test]
    fn not_ready_witness_cannot_corrobate_until_fresh_reachable_observation() {
        let (mut fusion, now) = lost_with_witness();
        fusion
            .observe_test_witness(ObservationData::not_ready(), now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            fusion.snapshot().state,
            EvidenceFusionState::AmbiguousPartition
        );
        fusion
            .observe_test_witness(
                ObservationData::authority_view_compatible("boot-1", Some(7), WitnessHolder::None),
                now + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(
            fusion.snapshot().state,
            EvidenceFusionState::FailoverEvidenceReady
        );
    }

    #[test]
    fn backwards_events_are_rejected_without_mutation() {
        let (mut fusion, now) = lost_with_witness();
        let before = fusion.snapshot();
        assert_eq!(
            fusion
                .observe_test_witness(ObservationData::unavailable(), now - Duration::from_secs(1)),
            Err(EvidenceFusionError::TimeWentBackwards)
        );
        assert_eq!(fusion.snapshot(), before);
        assert_eq!(
            fusion.observe_peer(
                PeerFailureAssessment::Healthy,
                None,
                now - Duration::from_secs(1)
            ),
            Err(EvidenceFusionError::TimeWentBackwards)
        );
        assert_eq!(fusion.snapshot(), before);
        assert_eq!(
            fusion.tick(now - Duration::from_secs(1)),
            Err(EvidenceFusionError::TimeWentBackwards)
        );
        assert_eq!(fusion.snapshot(), before);
    }

    #[test]
    fn equal_timestamps_are_allowed_and_snapshot_is_pure() {
        let mut fusion = fusion();
        let now = t0();
        fusion
            .observe_peer(
                PeerFailureAssessment::CommunicationLost,
                fresh_loss(now),
                now,
            )
            .unwrap();
        fusion
            .observe_test_witness(
                ObservationData::authority_view_compatible("boot-1", Some(7), WitnessHolder::None),
                now,
            )
            .unwrap();
        let before = fusion.snapshot();
        assert_eq!(fusion.snapshot(), before);
        fusion.tick(now).unwrap();
        assert_eq!(fusion.snapshot(), before);
    }

    #[test]
    fn restart_starts_unproven_without_freshness_high_water() {
        let (fusion, _) = lost_with_witness();
        let restarted = EvidenceFusion::new(fusion.witness_timeout()).unwrap();
        let snapshot = restarted.snapshot();
        assert_eq!(snapshot.state, EvidenceFusionState::Unproven);
        assert_eq!(snapshot.witness_status, WitnessStatus::Unknown);
        assert_eq!(snapshot.witness_observed_at, None);
    }

    #[test]
    fn rejects_zero_timeout() {
        assert!(matches!(
            EvidenceFusion::new(Duration::ZERO),
            Err(EvidenceFusionError::ZeroEvidenceTimeout)
        ));
    }

    // Stage 12.8a: the term-free evidence view must not carry historical
    // term/holder, while the snapshot still retains them for status/debug.
    #[test]
    fn witness_evidence_view_excludes_historical_term_and_holder() {
        let (fusion, _) = lost_with_witness();
        let snapshot = fusion.snapshot();
        // The snapshot keeps historical term/holder for status.
        assert_eq!(snapshot.witness_term, Some(7));
        assert_eq!(snapshot.witness_holder, WitnessHolder::None);

        let view = WitnessEvidenceView::from_snapshot(&snapshot);
        // The view reflects allowed evidence fields...
        assert_eq!(view.state, snapshot.state);
        assert_eq!(view.peer_assessment, snapshot.peer_assessment);
        assert_eq!(view.witness_status, snapshot.witness_status);
        assert_eq!(view.witness_observed_at, snapshot.witness_observed_at);
        assert_eq!(view.witness_boot_id, snapshot.witness_boot_id);
        // ...and there is no field carrying witness_term or witness_holder.
        // This structural absence is guaranteed by the type definition, so no
        // source grep is needed.
    }
}
