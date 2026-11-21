//! Phase 1-J24 (J24-E): the fencing failure matrix of `FENCING_FAILURE_MATRIX.md`, tested against
//! the existing Stage 14 fencing incident model (`fencing`) and its durable store
//! (`NodeMutationStore`), with no fencing backend: every event below is what a backend run or an
//! operator would report. A pass here shows only that the model refuses or accepts the reported
//! facts as the matrix requires; it says nothing about whether a real backend isolates a real host.
//!
//! The gate's only pass outcome is a `FencingClearance`, minted from the current durable CONFIRMED
//! incident whose continuity (target, observer session, loss episode, Witness epoch) holds. So for
//! each row the test checks whether a clearance can be minted, and that the durable incident is
//! changed only by a legal transition.
//!
//! Test-only: everything is inside `mod tests`, so the architecture guards (which read a module up
//! to its `mod tests`) see no production code here.

#[cfg(test)]
mod tests {
    use crate::failure_assessment::LocalLossEvidence;
    use crate::fencing::{
        ActionOutcome, AttestationId, ClearanceRefusal, ContinuityContext, ContinuityViolation,
        FencingBackend, FencingEventOutcome, FencingIncident, FencingState, FencingTransition,
        FencingTransitionError, IncidentOpening, InconclusiveKind, UnknownReason, WitnessEpoch,
    };
    use crate::node_mutation::{NodeMutationError, NodeMutationStore};
    use crate::protocol::{ClusterId, NodeId, SessionId, Term};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    const OBSERVER: &str = "0123456789abcdef";
    const ANCHOR: Term = Term(41);
    const LOSS_GENERATION: u64 = 3;
    const ATTESTATION_UUID: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mikagami-j24-fencing-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn initialized(path: &Path) -> NodeMutationStore {
        let store = NodeMutationStore::new(path, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        store
    }

    fn opening(backend: FencingBackend) -> IncidentOpening {
        IncidentOpening {
            target_node_id: NodeId::new("node-b"),
            anchor_term: ANCHOR,
            observer_session_id: SessionId::new(OBSERVER),
            observer_loss_generation: LOSS_GENERATION,
            backend,
        }
    }

    fn applied(outcome: FencingEventOutcome) -> FencingTransition {
        match outcome {
            FencingEventOutcome::Transition(transition) => transition,
            FencingEventOutcome::NoOp => panic!("expected a transition"),
        }
    }

    /// The live facts of the promoting node: the configured peer, its own session and the current
    /// loss episode of the peer.
    struct Facts {
        peer: NodeId,
        session: SessionId,
        episode: Option<LocalLossEvidence>,
    }

    impl Facts {
        fn current() -> Self {
            Self {
                peer: NodeId::new("node-b"),
                session: SessionId::new(OBSERVER),
                episode: Some(LocalLossEvidence::new_for_test(
                    LOSS_GENERATION,
                    Instant::now(),
                )),
            }
        }

        fn context(&self) -> ContinuityContext<'_> {
            ContinuityContext {
                configured_peer: &self.peer,
                current_session: &self.session,
                live_episode: self.episode.as_ref(),
            }
        }
    }

    /// Mints a clearance against the Witness term `view` and returns the refusal, if any.
    fn clearance(
        store: &NodeMutationStore,
        incident: &FencingIncident,
        facts: &Facts,
        view: Term,
    ) -> Result<(), NodeMutationError> {
        store
            .mint_fencing_clearance(&incident.incident_ref(), &facts.context(), view)
            .map(|_| ())
    }

    fn not_confirmed() -> NodeMutationError {
        NodeMutationError::FencingClearanceRefused(ClearanceRefusal::NotConfirmed)
    }

    fn continuity(violation: ContinuityViolation) -> NodeMutationError {
        NodeMutationError::FencingClearanceRefused(ClearanceRefusal::Continuity(violation))
    }

    /// FM-1, FM-2, FM-3: a requested fence, a fence action that reported success, a timed-out or
    /// killed action and an inconclusive verification are never a fencing proof.
    #[test]
    fn j24_fm_request_action_success_timeout_and_inconclusive_verification_never_clear() {
        let file = path("progress");
        let store = initialized(&file);
        let facts = Facts::current();
        let requested = store
            .open_fencing_incident(opening(FencingBackend::Command))
            .unwrap();
        assert_eq!(
            requested.state,
            FencingState::Requested { attempt_token: 1 }
        );
        assert_eq!(
            clearance(&store, &requested, &facts, ANCHOR),
            Err(not_confirmed())
        );

        for outcome in [
            ActionOutcome::ReportedSuccess,
            ActionOutcome::TimedOut,
            ActionOutcome::Signal,
            ActionOutcome::SpawnFailed,
            ActionOutcome::ReportedFailure,
        ] {
            let verifying = applied_transition(&requested, |incident| {
                incident
                    .action_returned(1, outcome)
                    .map(FencingEventOutcome::Transition)
            });
            assert!(matches!(
                verifying.to().state,
                FencingState::Verifying { .. }
            ));
            // Not persisted: the matrix row is about the state, which is the same for each outcome.
            let _ = verifying;
        }
        let verifying = store
            .apply_fencing_transition(
                requested
                    .action_returned(1, ActionOutcome::ReportedSuccess)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            clearance(&store, &verifying, &facts, ANCHOR),
            Err(not_confirmed()),
            "a fence action that reported success is not a proof of isolation"
        );

        // An inconclusive poll with budget left changes nothing; the last one gives UNKNOWN.
        assert!(matches!(
            verifying
                .verification_inconclusive(1, InconclusiveKind::Timeout, false)
                .unwrap(),
            FencingEventOutcome::NoOp
        ));
        let unknown = store
            .apply_fencing_transition(applied(
                verifying
                    .verification_inconclusive(1, InconclusiveKind::Timeout, true)
                    .unwrap(),
            ))
            .unwrap();
        assert_eq!(
            unknown.state,
            FencingState::Unknown(UnknownReason::VerifyInconclusive {
                kind: InconclusiveKind::Timeout
            })
        );
        assert_eq!(
            clearance(&store, &unknown, &facts, ANCHOR),
            Err(not_confirmed())
        );
        let _ = fs::remove_file(file);
    }

    fn applied_transition(
        incident: &FencingIncident,
        event: impl FnOnce(&FencingIncident) -> Result<FencingEventOutcome, FencingTransitionError>,
    ) -> FencingTransition {
        applied(event(incident).unwrap())
    }

    /// FM-4: a verification that the target is NOT isolated is FAILED, never retried by itself, and
    /// never clears. Without a command backend only an operator attestation can confirm.
    #[test]
    fn j24_fm_failed_fencing_blocks_and_never_retries_by_itself() {
        let file = path("failed");
        let store = initialized(&file);
        let facts = Facts::current();
        let requested = store
            .open_fencing_incident(opening(FencingBackend::Command))
            .unwrap();
        let verifying = store
            .apply_fencing_transition(
                requested
                    .action_returned(1, ActionOutcome::ReportedSuccess)
                    .unwrap(),
            )
            .unwrap();
        let failed = store
            .apply_fencing_transition(applied(verifying.verification_not_isolated(1).unwrap()))
            .unwrap();
        assert_eq!(failed.state, FencingState::Failed { attempt_token: 1 });
        assert_eq!(
            clearance(&store, &failed, &facts, ANCHOR),
            Err(not_confirmed())
        );
        assert_eq!(
            failed.request_again(FencingBackend::None).unwrap_err(),
            FencingTransitionError::BackendNotCommand
        );

        // B = none: UNKNOWN(not-attempted) from the start; it never clears by itself.
        let other = path("failed-none");
        let none_store = initialized(&other);
        let unknown = none_store
            .open_fencing_incident(opening(FencingBackend::None))
            .unwrap();
        assert_eq!(
            unknown.state,
            FencingState::Unknown(UnknownReason::NotAttempted {})
        );
        assert_eq!(
            clearance(&none_store, &unknown, &facts, ANCHOR),
            Err(not_confirmed())
        );
        let _ = fs::remove_file(file);
        let _ = fs::remove_file(other);
    }

    /// FM-5 (J24 r2, audit E-2): a transition computed from an older incident value - an answer that
    /// arrives after the durable incident moved on - is refused by the store, and the store file is
    /// byte-for-byte unchanged. (The model's own token check is in the test below; this one goes
    /// through the store's write path.)
    #[test]
    fn j24_fm_a_stale_transition_is_refused_by_the_store_and_writes_nothing() {
        let file = path("stale-store");
        let store = initialized(&file);
        let requested = store
            .open_fencing_incident(opening(FencingBackend::Command))
            .unwrap();
        // Computed from REQUESTED(1) but not yet persisted ...
        let late = requested
            .action_returned(1, ActionOutcome::ReportedSuccess)
            .unwrap();
        // ... while another answer of the same attempt moved the durable incident on.
        let verifying = store
            .apply_fencing_transition(
                requested
                    .action_returned(1, ActionOutcome::TimedOut)
                    .unwrap(),
            )
            .unwrap();
        let before = fs::read(&file).unwrap();
        assert!(matches!(
            store.apply_fencing_transition(late),
            Err(NodeMutationError::FencingIncident(_))
        ));
        assert_eq!(fs::read(&file).unwrap(), before);
        assert_eq!(
            store.load_existing().unwrap().fencing_incident,
            Some(verifying)
        );
        let _ = fs::remove_file(file);
    }

    /// FM-4 (J24 r2, audit E-2): FAILED has no automatic way forward: no action result, verdict or
    /// inconclusive poll moves it, and only an explicit new request with a command backend (the
    /// operator's action) starts attempt k + 1; an attestation is the other explicit path.
    #[test]
    fn j24_fm_failed_moves_only_by_an_explicit_new_request_or_attestation() {
        let file = path("failed-explicit");
        let store = initialized(&file);
        let requested = store
            .open_fencing_incident(opening(FencingBackend::Command))
            .unwrap();
        let verifying = store
            .apply_fencing_transition(
                requested
                    .action_returned(1, ActionOutcome::ReportedSuccess)
                    .unwrap(),
            )
            .unwrap();
        let failed = store
            .apply_fencing_transition(applied(verifying.verification_not_isolated(1).unwrap()))
            .unwrap();
        for token in [1, 2] {
            assert!(matches!(
                failed.action_returned(token, ActionOutcome::ReportedSuccess),
                Err(FencingTransitionError::Illegal { .. })
            ));
            assert!(matches!(
                failed.confirm_by_verification(token),
                Err(FencingTransitionError::Illegal { .. })
            ));
            assert!(matches!(
                failed.verification_inconclusive(token, InconclusiveKind::Timeout, true),
                Err(FencingTransitionError::Illegal { .. })
            ));
        }
        let again = failed.request_again(FencingBackend::Command).unwrap();
        assert_eq!(
            again.to().state,
            FencingState::Requested { attempt_token: 2 }
        );
        assert!(matches!(
            failed
                .confirm_by_attestation(AttestationId::new(ATTESTATION_UUID))
                .unwrap(),
            FencingEventOutcome::Transition(_)
        ));
        let _ = fs::remove_file(file);
    }

    /// FM-5, FM-6: a stale answer (an older attempt token) is refused by the model; a duplicate
    /// confirmation is a no-op. (J24 r2, audit E-2: the model refuses before any store call, so "writes
    /// nothing" here is by construction; the store's own refusal is the test above.)
    #[test]
    fn j24_fm_stale_and_duplicate_fencing_answers_change_nothing() {
        let file = path("stale");
        let store = initialized(&file);
        let requested = store
            .open_fencing_incident(opening(FencingBackend::Command))
            .unwrap();
        let verifying = store
            .apply_fencing_transition(
                requested
                    .action_returned(1, ActionOutcome::TimedOut)
                    .unwrap(),
            )
            .unwrap();
        let unknown = store
            .apply_fencing_transition(applied(
                verifying
                    .verification_inconclusive(1, InconclusiveKind::Timeout, true)
                    .unwrap(),
            ))
            .unwrap();
        // The operator retries: attempt 2.
        let second = store
            .apply_fencing_transition(unknown.request_again(FencingBackend::Command).unwrap())
            .unwrap();
        assert_eq!(second.state, FencingState::Requested { attempt_token: 2 });
        let before = fs::read(&file).unwrap();
        // The late answer of attempt 1 arrives.
        assert_eq!(
            second
                .action_returned(1, ActionOutcome::ReportedSuccess)
                .unwrap_err(),
            FencingTransitionError::AttemptTokenMismatch
        );
        let verifying2 = store
            .apply_fencing_transition(
                second
                    .action_returned(2, ActionOutcome::ReportedSuccess)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            verifying2.confirm_by_verification(1).unwrap_err(),
            FencingTransitionError::AttemptTokenMismatch,
            "an isolated verdict of attempt 1 must not confirm attempt 2"
        );
        assert_ne!(
            fs::read(&file).unwrap(),
            before,
            "attempt 2's own transition was persisted"
        );
        let confirmed = store
            .apply_fencing_transition(applied(verifying2.confirm_by_verification(2).unwrap()))
            .unwrap();
        let persisted = fs::read(&file).unwrap();
        // Duplicate verdicts and attestations against CONFIRMED are no-ops (no write).
        assert!(matches!(
            confirmed.confirm_by_verification(2).unwrap(),
            FencingEventOutcome::NoOp
        ));
        assert!(matches!(
            confirmed.verification_not_isolated(2).unwrap(),
            FencingEventOutcome::NoOp
        ));
        assert!(matches!(
            confirmed
                .confirm_by_attestation(AttestationId::new(ATTESTATION_UUID))
                .unwrap(),
            FencingEventOutcome::NoOp
        ));
        assert_eq!(fs::read(&file).unwrap(), persisted);
        let _ = fs::remove_file(file);
    }

    /// FM-7 .. FM-11: a confirmed fencing clears only the attempt it was made for: the same target,
    /// the same promoting process, the same loss episode and the same Witness epoch. A restart of the
    /// promoting node, an ended episode, another target or a moved Witness term makes it stale; it is
    /// never carried over to another generation.
    #[test]
    fn j24_fm_confirmed_fencing_is_bound_to_target_session_episode_and_epoch() {
        let file = path("bound");
        let store = initialized(&file);
        let requested = store
            .open_fencing_incident(opening(FencingBackend::Command))
            .unwrap();
        let verifying = store
            .apply_fencing_transition(
                requested
                    .action_returned(1, ActionOutcome::ReportedSuccess)
                    .unwrap(),
            )
            .unwrap();
        let confirmed = store
            .apply_fencing_transition(applied(verifying.confirm_by_verification(1).unwrap()))
            .unwrap();
        let facts = Facts::current();
        let minted = store
            .mint_fencing_clearance(&confirmed.incident_ref(), &facts.context(), ANCHOR)
            .unwrap();
        assert_eq!(minted.target_node_id(), &NodeId::new("node-b"));
        assert_eq!(minted.anchor_term(), ANCHOR);
        assert_eq!(minted.observer_loss_generation(), LOSS_GENERATION);

        // The Witness term moved (another grant happened): the evidence is stale.
        assert_eq!(
            clearance(&store, &confirmed, &facts, Term(ANCHOR.0 + 1)),
            Err(continuity(ContinuityViolation::WitnessEpoch))
        );
        // The promoting node restarted (a new process session).
        let restarted = Facts {
            session: SessionId::new("fedcba9876543210"),
            ..Facts::current()
        };
        assert_eq!(
            clearance(&store, &confirmed, &restarted, ANCHOR),
            Err(continuity(ContinuityViolation::ObserverSession))
        );
        // The loss episode ended (the peer was heard again) or is another episode.
        let heard = Facts {
            episode: None,
            ..Facts::current()
        };
        assert_eq!(
            clearance(&store, &confirmed, &heard, ANCHOR),
            Err(continuity(ContinuityViolation::Episode))
        );
        let other_episode = Facts {
            episode: Some(LocalLossEvidence::new_for_test(
                LOSS_GENERATION + 1,
                Instant::now(),
            )),
            ..Facts::current()
        };
        assert_eq!(
            clearance(&store, &confirmed, &other_episode, ANCHOR),
            Err(continuity(ContinuityViolation::Episode))
        );
        // Another target than the configured peer.
        let other_peer = Facts {
            peer: NodeId::new("node-c"),
            ..Facts::current()
        };
        assert_eq!(
            clearance(&store, &confirmed, &other_peer, ANCHOR),
            Err(continuity(ContinuityViolation::Target))
        );
        // The grant that follows must be exactly the next term after the anchor.
        let context = facts.context();
        assert_eq!(
            confirmed.check_continuity(&context, WitnessEpoch::Grant(Term(ANCHOR.0 + 1))),
            Ok(())
        );
        for grant in [ANCHOR, Term(ANCHOR.0 + 2)] {
            assert_eq!(
                confirmed.check_continuity(&context, WitnessEpoch::Grant(grant)),
                Err(ContinuityViolation::WitnessEpoch)
            );
        }
        // A newer authenticated term seen after the incident opened also makes it stale.
        assert_eq!(
            confirmed.check_continuity(
                &context,
                WitnessEpoch::LatestObserved(Some(Term(ANCHOR.0 + 1)))
            ),
            Err(ContinuityViolation::WitnessEpoch)
        );
        let _ = fs::remove_file(file);
    }

    /// FM-12: a clearance needs the durable incident: a confirmed value that is not the store's
    /// current incident (for example after it was retired) cannot mint.
    #[test]
    fn j24_fm_a_retired_or_foreign_incident_cannot_clear() {
        let file = path("retired");
        let store = initialized(&file);
        let opened = store
            .open_fencing_incident(opening(FencingBackend::None))
            .unwrap();
        let confirmed = store
            .apply_fencing_transition(applied(
                opened
                    .confirm_by_attestation(AttestationId::new(ATTESTATION_UUID))
                    .unwrap(),
            ))
            .unwrap();
        store
            .retire_fencing_incident(&confirmed.incident_ref())
            .unwrap();
        let facts = Facts::current();
        assert!(matches!(
            clearance(&store, &confirmed, &facts, ANCHOR),
            Err(NodeMutationError::FencingIncident(_))
        ));
        let _ = fs::remove_file(file);
    }
}
