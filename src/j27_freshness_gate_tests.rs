//! Phase 1-J27 TEST-ONLY: the Stage 14 fencing gate with local-loss evidence minted by the real
//! detector after a long fencing (OD-J26-6). The detector is driven only through its §10.3.2
//! entry (`observe_verified_listen_window`), with windows as the Appendix R instrumentation mints
//! them; nothing sets a detector field.
//!
//! Test-only: everything is inside `mod tests`, so the architecture guards (which read a module
//! up to its `mod tests`) treat this file as having no production code.

mod tests {
    use crate::failure_assessment::{LocalLossEvidence, PeerFailureDetector, VerifiedListenWindow};
    use crate::fencing::{
        ActionOutcome, ClearanceRefusal, ContinuityContext, ContinuityViolation, FencingBackend,
        FencingEventOutcome, FencingIncident, FencingState, IncidentOpening,
    };
    use crate::node_mutation::{NodeMutationError, NodeMutationStore};
    use crate::protocol::{ClusterId, NodeId, SessionId, Term};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    const OBSERVER: &str = "0123456789abcdef";
    const RESTARTED: &str = "fedcba9876543210";
    const ANCHOR: Term = Term(41);
    const WINDOW: Duration = Duration::from_secs(8);

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mikagami-j27-gate-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn store(path: &PathBuf) -> NodeMutationStore {
        let store = NodeMutationStore::new(path, ClusterId::new("j27-test"), NodeId::new("node-b"));
        store.initialize_new().unwrap();
        store
    }

    /// One completed verified-listen window `[start, start + 8 s]` of listener generation 1.
    fn window(detector: &mut PeerFailureDetector, start: Instant) {
        detector
            .observe_verified_listen_window(VerifiedListenWindow::new(start, start + WINDOW, 1))
            .unwrap();
    }

    /// A conservative-mode detector whose episode was formed by two windows (§11.1); the freshness
    /// reference is the second window's start.
    fn formed(t0: Instant) -> PeerFailureDetector {
        let mut detector = PeerFailureDetector::with_default_window().with_restart_formation(true);
        window(&mut detector, t0);
        window(&mut detector, t0 + Duration::from_secs(9));
        assert!(detector.loss_evidence().is_some());
        detector
    }

    fn context<'a>(
        peer: &'a NodeId,
        session: &'a SessionId,
        episode: Option<&'a LocalLossEvidence>,
    ) -> ContinuityContext<'a> {
        ContinuityContext {
            configured_peer: peer,
            current_session: session,
            live_episode: episode,
        }
    }

    /// An incident of `generation` for this observer, driven to CONFIRMED by its own verify.
    fn confirmed(store: &NodeMutationStore, generation: u64) -> FencingIncident {
        let requested = store
            .open_fencing_incident(IncidentOpening {
                target_node_id: NodeId::new("node-a"),
                anchor_term: ANCHOR,
                observer_session_id: SessionId::new(OBSERVER),
                observer_loss_generation: generation,
                backend: FencingBackend::Command,
            })
            .unwrap();
        let verifying = store
            .apply_fencing_transition(
                requested
                    .action_returned(1, ActionOutcome::ReportedSuccess)
                    .unwrap(),
            )
            .unwrap();
        let FencingEventOutcome::Transition(transition) =
            verifying.confirm_by_verification(1).unwrap()
        else {
            panic!("expected CONFIRMED");
        };
        let confirmed = store.apply_fencing_transition(transition).unwrap();
        assert!(matches!(confirmed.state, FencingState::Confirmed(_)));
        confirmed
    }

    /// FR-1 / FR-3 / FR-4 / FR-7: a CONFIRMED incident keeps its own (durable) evidence; the local loss
    /// is a separate, runtime-only input. After a fencing of 60 s the episode's evidence is stale -
    /// the clearance (fencing evidence) still exists, but the authorization's freshness input does not;
    /// only a new window after the fencing makes it fresh again, with the same generation, so the same
    /// incident still binds (R3) and `lost_at` is never rewritten.
    #[test]
    fn j27_gate_clearance_is_fencing_evidence_only_and_a_refresh_keeps_the_same_episode() {
        let file = path("refresh");
        let store = store(&file);
        let peer = NodeId::new("node-a");
        let session = SessionId::new(OBSERVER);
        let t0 = Instant::now();
        let mut detector = formed(t0);
        let before = detector.loss_evidence().unwrap();
        let generation = before.generation();
        let incident = confirmed(&store, generation);
        let fencing_end = t0 + Duration::from_secs(9 + 60);
        assert!(
            !before.is_fresh_at(fencing_end),
            "a 60 s fencing ages the evidence out"
        );
        // CONFIRMED is fencing evidence only: the clearance exists although the loss is stale (the
        // freshness is the evaluation's input, checked before the gate; Stage 14 R-01).
        store
            .mint_fencing_clearance(
                &incident.incident_ref(),
                &context(&peer, &session, Some(&before)),
                ANCHOR,
            )
            .unwrap();
        // A new window after the fencing: fresh again, same generation, same lost_at.
        window(&mut detector, fencing_end);
        let after = detector.loss_evidence().unwrap();
        assert_eq!(after.generation(), generation);
        assert_eq!(after.lost_at(), before.lost_at());
        assert_eq!(after.freshness_reference(), fencing_end);
        assert!(after.is_fresh_at(fencing_end + WINDOW));
        store
            .mint_fencing_clearance(
                &incident.incident_ref(),
                &context(&peer, &session, Some(&after)),
                ANCHOR,
            )
            .unwrap();
        let _ = std::fs::remove_file(&file);
    }

    /// FR-9 (J27 §7 cases 5-7): a new observer session or a new loss episode never uses the old
    /// CONFIRMED, even when the new evidence is fresh.
    #[test]
    fn j27_gate_a_new_session_or_generation_never_binds_the_old_confirmed() {
        let file = path("binding");
        let store = store(&file);
        let peer = NodeId::new("node-a");
        let t0 = Instant::now();
        let mut detector = formed(t0);
        let generation = detector.loss_evidence().unwrap().generation();
        let incident = confirmed(&store, generation);
        let refusal = |session: &str, episode: Option<&LocalLossEvidence>| {
            let session = SessionId::new(session);
            store
                .mint_fencing_clearance(
                    &incident.incident_ref(),
                    &context(&peer, &session, episode),
                    ANCHOR,
                )
                .err()
        };
        let fresh = detector.loss_evidence().unwrap();
        assert_eq!(
            refusal(RESTARTED, Some(&fresh)),
            Some(NodeMutationError::FencingClearanceRefused(
                ClearanceRefusal::Continuity(ContinuityViolation::ObserverSession)
            ))
        );
        // The episode ends (identity uncertainty) and re-forms from two new windows: generation + 1.
        let at = t0 + Duration::from_secs(40);
        detector.observe_identity_uncertainty(at).unwrap();
        assert!(detector.loss_evidence().is_none());
        assert_eq!(
            refusal(OBSERVER, None),
            Some(NodeMutationError::FencingClearanceRefused(
                ClearanceRefusal::Continuity(ContinuityViolation::Episode)
            ))
        );
        window(&mut detector, at + Duration::from_secs(1));
        window(&mut detector, at + Duration::from_secs(10));
        let renewed = detector.loss_evidence().unwrap();
        assert_eq!(renewed.generation(), generation + 1);
        assert!(renewed.is_fresh_at(at + Duration::from_secs(18)));
        assert_eq!(
            refusal(OBSERVER, Some(&renewed)),
            Some(NodeMutationError::FencingClearanceRefused(
                ClearanceRefusal::Continuity(ContinuityViolation::Episode)
            )),
            "fresh evidence of a new episode never binds the old incident"
        );
        let _ = std::fs::remove_file(&file);
    }
}
