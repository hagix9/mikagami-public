//! Phase 1-J28 TEST-ONLY (Linux): the automatic trigger's facts of real durable incidents, built
//! only by the Stage 14 §13.2 transitions (T2, T4, T7, T3, T6), and the trigger driven by them
//! (H-1: `UNKNOWN` after attempt k and after attempt k+1 must differ, or the second fence action
//! is not counted against `max_fence_actions`).
//!
//! Test-only: everything is inside `mod tests`, so the architecture guards (which read a module
//! up to its `mod tests`) treat this file as having no production code.

mod tests {
    use crate::auto_failover::{
        AutoConfig, AutoDecision, AutoFailover, AutoInputs, FenceActivity, IncidentFacts,
        IncidentKind, LossEpisode,
    };
    use crate::failure_assessment::PeerFailureAssessment;
    use crate::fencing::{
        ActionOutcome, FencingBackend, FencingEventOutcome, FencingIncident, IncidentId,
        IncidentOpening, InconclusiveKind,
    };
    use crate::linux_node_runtime::auto_incident_facts_of;
    use crate::protocol::{NodeId, SessionId, Term};
    use crate::state_machine::NodeState;

    const SEC: u64 = 1_000;

    fn opened() -> FencingIncident {
        FencingIncident::open(
            1,
            IncidentId::new("00000000-0000-4000-8000-000000000028"),
            IncidentOpening {
                target_node_id: NodeId::new("node-a"),
                anchor_term: Term(7),
                observer_session_id: SessionId::new("0123456789abcdef"),
                observer_loss_generation: 1,
                backend: FencingBackend::Command,
            },
        )
    }

    fn to(outcome: FencingEventOutcome) -> FencingIncident {
        match outcome {
            FencingEventOutcome::Transition(transition) => transition.to().clone(),
            FencingEventOutcome::NoOp => panic!("expected a transition"),
        }
    }

    /// T4 then T7 (last permitted poll, inconclusive): `REQUESTED(k)` -> `UNKNOWN`.
    fn ends_unknown(requested: &FencingIncident, k: u64) -> FencingIncident {
        let verifying = requested
            .action_returned(k, ActionOutcome::ReportedSuccess)
            .unwrap()
            .to()
            .clone();
        to(verifying
            .verification_inconclusive(k, InconclusiveKind::Timeout, true)
            .unwrap())
    }

    fn facts(incident: &FencingIncident) -> IncidentFacts {
        auto_incident_facts_of(incident)
    }

    /// Every attempt that ends UNKNOWN is a distinct fact (the token high-water rises by T3);
    /// the other states keep their mapping.
    #[test]
    fn j28_unknown_facts_change_with_every_attempt() {
        let first = opened();
        assert_eq!(facts(&first).kind, IncidentKind::Requested);
        let unknown1 = ends_unknown(&first, 1);
        let requested2 = unknown1
            .request_again(FencingBackend::Command)
            .unwrap()
            .to()
            .clone();
        let unknown2 = ends_unknown(&requested2, 2);
        let (f1, f2) = (facts(&unknown1), facts(&unknown2));
        assert_eq!((f1.kind, f1.attempt_token), (IncidentKind::Unknown, 1));
        assert_eq!((f2.kind, f2.attempt_token), (IncidentKind::Unknown, 2));
        assert_ne!(
            f1, f2,
            "the second fence action must be visible to the trigger"
        );
        assert_eq!(f1.seq, f2.seq, "T3 keeps the same incident");
        let requested3 = unknown2
            .request_again(FencingBackend::Command)
            .unwrap()
            .to()
            .clone();
        let verifying3 = requested3
            .action_returned(3, ActionOutcome::ReportedSuccess)
            .unwrap()
            .to()
            .clone();
        let failed3 = to(verifying3.verification_not_isolated(3).unwrap());
        assert_eq!(
            (facts(&failed3).kind, facts(&failed3).attempt_token),
            (IncidentKind::Failed, 3)
        );
    }

    /// AR-1 end to end on the real facts: an episode whose every attempt ends UNKNOWN gets
    /// exactly `max_fence_actions` fence-bearing requests, then Exhausted, over a long partition.
    #[test]
    fn j28_trigger_on_real_unknown_facts_respects_max_fence_actions() {
        for max in 1..=3u32 {
            let mut machine = AutoFailover::new(AutoConfig {
                enabled: true,
                preferred: false,
                dwell_ms: 10 * SEC,
                bootstrap_dwell_ms: 20 * SEC,
                bootstrap_defer_ms: 15 * SEC,
                max_fence_actions: max,
                cycle_timeout_ms: 120 * SEC,
            });
            let mut durable: Option<FencingIncident> = None;
            let mut fence_actions = 0;
            let mut stop = None;
            for step in 0..900u64 {
                let inputs = AutoInputs {
                    now_ms: step * SEC,
                    uptime_ms: step * SEC + 60 * SEC,
                    running: true,
                    shutdown: false,
                    attempt_in_flight: false,
                    standby_safe: true,
                    node_state: NodeState::Standby,
                    backend_is_command: true,
                    assessment: PeerFailureAssessment::CommunicationLost,
                    loss: Some(LossEpisode {
                        observer_session: "0123456789abcdef".into(),
                        generation: 1,
                        fresh: true,
                    }),
                    peer_active_confirmed: true,
                    peer_node_state: None,
                    incident: durable.as_ref().map(facts),
                    // J29: the runtime's count of the fence actions it ran.
                    activity: FenceActivity {
                        actions_run: fence_actions as u64,
                        not_isolated_verdicts: 0,
                    },
                    bootstrap_session_open: false,
                    bootstrap_session_attested: false,
                };
                match machine.poll(&inputs) {
                    AutoDecision::Request { .. } => {
                        // The attempt runs one fence action (T2 or T3) that ends UNKNOWN.
                        let next = match durable.take() {
                            None => opened(),
                            Some(unknown) => unknown
                                .request_again(FencingBackend::Command)
                                .unwrap()
                                .to()
                                .clone(),
                        };
                        fence_actions += 1;
                        let k = next.attempt_token_high_water;
                        durable = Some(ends_unknown(&next, k));
                    }
                    AutoDecision::Exhausted(reason) => stop = Some(reason),
                    _ => {}
                }
            }
            assert_eq!(fence_actions, max, "max_fence_actions={max}");
            assert!(stop.unwrap().contains("fence action budget"));
        }
    }
}
