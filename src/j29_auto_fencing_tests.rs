//! Phase 1-J29 TEST-ONLY: the trigger's fence accounting (B1) and its `FAILED` hold (C1) over the
//! runtime's own `FenceActivity` counts. Every test here fails on a trigger that infers a fence
//! action from the incident facts, or takes the hold only from a `FAILED` incident it saw.

#[cfg(test)]
mod tests {
    use crate::auto_failover::{
        AutoConfig, AutoDecision, AutoFailover, AutoInputs, FenceActivity, IncidentFacts,
        IncidentKind, LossEpisode,
    };
    use crate::failure_assessment::PeerFailureAssessment;
    use crate::state_machine::NodeState;

    const SEC: u64 = 1_000;

    fn config(max_fence_actions: u32) -> AutoConfig {
        AutoConfig {
            enabled: true,
            preferred: false,
            dwell_ms: 10 * SEC,
            bootstrap_dwell_ms: 20 * SEC,
            bootstrap_defer_ms: 15 * SEC,
            max_fence_actions,
            cycle_timeout_ms: 120 * SEC,
        }
    }

    fn lost(now_ms: u64, generation: u64, activity: FenceActivity) -> AutoInputs {
        AutoInputs {
            now_ms,
            uptime_ms: now_ms + 60 * SEC,
            running: true,
            shutdown: false,
            attempt_in_flight: false,
            standby_safe: true,
            node_state: NodeState::Standby,
            backend_is_command: true,
            assessment: PeerFailureAssessment::CommunicationLost,
            loss: Some(LossEpisode {
                observer_session: "s1".into(),
                generation,
                fresh: true,
            }),
            peer_active_confirmed: true,
            peer_node_state: None,
            incident: None,
            activity,
            bootstrap_session_open: false,
            bootstrap_session_attested: false,
        }
    }

    /// A §10.5 non-authenticated invalidation (rogue arrival): `Suspect`, no episode.
    fn uncertain(now_ms: u64, activity: FenceActivity) -> AutoInputs {
        AutoInputs {
            assessment: PeerFailureAssessment::Suspect,
            loss: None,
            ..lost(now_ms, 0, activity)
        }
    }

    /// The peer's authenticated return (an Active peer: no bootstrap request).
    fn returned(now_ms: u64, activity: FenceActivity) -> AutoInputs {
        AutoInputs {
            assessment: PeerFailureAssessment::Healthy,
            loss: None,
            peer_node_state: Some(NodeState::Active),
            ..lost(now_ms, 0, activity)
        }
    }

    fn unknown(seq: u64, token: u64) -> Option<IncidentFacts> {
        Some(IncidentFacts {
            seq,
            attempt_token: token,
            kind: IncidentKind::Unknown,
        })
    }

    fn actions(n: u64) -> FenceActivity {
        FenceActivity {
            actions_run: n,
            not_isolated_verdicts: 0,
        }
    }

    /// B1: every attempt opens an incident and runs one fence action, and the incident is retired
    /// (R4, a moved Witness term) before the next poll, so every poll sees no incident. The runtime
    /// counted each action: the episode gets exactly `max_fence_actions` fence-bearing requests.
    #[test]
    fn j29_b1_a_retired_incident_does_not_hide_an_executed_fence() {
        for max in 1..=3u32 {
            let mut machine = AutoFailover::new(config(max));
            let mut ran = 0;
            let mut requests = 0;
            let mut stop = None;
            for step in 0..600u64 {
                match machine.poll(&lost(step * SEC, 1, actions(ran))) {
                    AutoDecision::Request { .. } => {
                        requests += 1;
                        ran += 1; // T2 + one fence action, then retired before the next poll
                    }
                    AutoDecision::Exhausted(reason) => {
                        assert!(stop.is_none());
                        stop = Some(reason);
                    }
                    _ => {}
                }
            }
            assert_eq!(requests, max, "max_fence_actions={max}");
            assert!(stop.unwrap().contains("fence action budget"));
        }
    }

    /// B1, the other direction: an attempt whose gate only retired a stale incident and opened
    /// nothing ran no fence action. The incident facts changed (UNKNOWN -> none) but the count did
    /// not: it is a reject, never a fence. With a budget of one fence action, one false count would
    /// end the cycle at once; the request budget stops it instead.
    #[test]
    fn j29_b1_a_retirement_without_a_fence_is_not_counted() {
        let mut machine = AutoFailover::new(AutoConfig {
            cycle_timeout_ms: 10_000 * SEC,
            ..config(1)
        });
        let mut requests = 0;
        let mut stop = None;
        for step in 0..900u64 {
            let mut inputs = lost(step * SEC, 1, actions(0));
            // Before the first request an UNKNOWN incident exists; the first attempt retires it.
            inputs.incident = if requests == 0 { unknown(1, 1) } else { None };
            match machine.poll(&inputs) {
                AutoDecision::Request { .. } => requests += 1,
                AutoDecision::Exhausted(reason) => {
                    stop = Some(reason);
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(requests, 8);
        assert!(stop.unwrap().contains("request budget"));
    }

    /// B1, no double count: an action that also changed the incident facts (UNKNOWN token k ->
    /// k+1) is one fence action, not two; UNKNOWN fence actions are counted.
    #[test]
    fn j29_b1_an_action_is_counted_once_and_unknown_actions_count() {
        let mut machine = AutoFailover::new(config(3));
        let mut ran = 0;
        let mut requests = 0;
        let mut stop = None;
        for step in 0..600u64 {
            let mut inputs = lost(step * SEC, 1, actions(ran));
            inputs.incident = if ran == 0 { None } else { unknown(1, ran) };
            match machine.poll(&inputs) {
                AutoDecision::Request { .. } => {
                    requests += 1;
                    ran += 1;
                }
                AutoDecision::Exhausted(reason) => {
                    stop = Some(reason);
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(requests, 3);
        assert!(stop.unwrap().contains("fence action budget"));
    }

    /// B1: a fence action that ended `FAILED` is counted, and the `FAILED` verdict holds.
    #[test]
    fn j29_b1_a_failed_action_is_counted_and_holds() {
        let mut machine = AutoFailover::new(config(2));
        let mut activity = actions(0);
        let mut requests = 0;
        let mut stops = Vec::new();
        for step in 0..900u64 {
            match machine.poll(&lost(step * SEC, 1 + step / 100, activity)) {
                AutoDecision::Request { .. } => {
                    requests += 1;
                    activity.actions_run += 1;
                    activity.not_isolated_verdicts += 1; // verified not isolated, then retired
                }
                AutoDecision::Exhausted(reason) => stops.push(reason),
                _ => {}
            }
        }
        assert_eq!(requests, 1);
        assert!(
            stops.iter().all(|reason| reason.contains("not isolated")),
            "{stops:?}"
        );
    }

    /// C1: the `FAILED` verdict is committed, no poll sees the `FAILED` incident (the observation
    /// failed on that tick), and the incident is retired when a rogue arrival ends the episode.
    /// The hold still forms from the runtime's count: the new episodes ask for nothing.
    #[test]
    fn j29_c1_a_failed_verdict_no_poll_saw_still_holds() {
        let mut machine = AutoFailover::new(config(2));
        let mut activity = actions(0);
        let mut now = 0;
        let mut requests = 0;
        while now <= 10 * SEC {
            if matches!(
                machine.poll(&lost(now, 1, activity)),
                AutoDecision::Request { .. }
            ) {
                requests += 1;
                activity.actions_run += 1;
            }
            now += SEC;
        }
        assert_eq!(requests, 1);
        // The verify wrote FAILED; this tick's poll did not run. A rogue arrival, then a new
        // episode formed by two windows (generations 2..): the FAILED incident is gone.
        activity.not_isolated_verdicts += 1;
        let mut stopped = Vec::new();
        for generation in 2..=6u64 {
            machine.poll(&uncertain(now, activity));
            now += 25 * SEC;
            for _ in 0..90 {
                match machine.poll(&lost(now, generation, activity)) {
                    AutoDecision::Request { .. } => requests += 1,
                    AutoDecision::Exhausted(reason) => stopped.push(reason),
                    _ => {}
                }
                now += SEC;
            }
        }
        assert_eq!(requests, 1, "no fence request after the FAILED verdict");
        assert_eq!(stopped.len(), 5);
        assert!(stopped.iter().all(|reason| reason.contains("not isolated")));
    }

    /// C1: the hold is not cleared by a new episode, a retired incident, a cycle timeout, an
    /// UNKNOWN incident or an unauthenticated arrival; only the authenticated return clears it, and
    /// the verdict already seen does not take it again afterwards.
    #[test]
    fn j29_c1_the_hold_ends_only_with_the_authenticated_return() {
        let mut machine = AutoFailover::new(config(2));
        let held = FenceActivity {
            actions_run: 1,
            not_isolated_verdicts: 1,
        };
        let mut now = 0;
        let mut requests = 0;
        let drive = |machine: &mut AutoFailover, inputs: AutoInputs| -> u32 {
            u32::from(matches!(
                machine.poll(&inputs),
                AutoDecision::Request { .. }
            ))
        };
        for generation in 1..=4u64 {
            for _ in 0..200 {
                let mut inputs = lost(now, generation, held);
                if generation == 3 {
                    inputs.incident = unknown(7, 3);
                }
                requests += drive(&mut machine, inputs);
                now += SEC;
            }
            requests += drive(&mut machine, uncertain(now, held));
            now += SEC;
        }
        assert_eq!(
            requests, 0,
            "held across new episodes, UNKNOWN, timeouts, rogue arrivals"
        );
        requests += drive(&mut machine, returned(now, held));
        now += SEC;
        // The dwell (10 s), then the first request of the new episode.
        for _ in 0..=10 {
            requests += drive(&mut machine, lost(now, 9, held));
            now += SEC;
        }
        assert_eq!(
            requests, 1,
            "after the authenticated return a new episode may fence"
        );
    }

    /// C1 / A-9: the hold is process memory. The old process holds after a `FAILED` verdict; a new
    /// process (a new machine, the runtime's counts starting at zero) starts without it.
    #[test]
    fn j29_c1_a_new_process_starts_without_the_hold() {
        let held = FenceActivity {
            actions_run: 1,
            not_isolated_verdicts: 1,
        };
        let asks = |machine: &mut AutoFailover, activity: FenceActivity| {
            (0..=10u64)
                .filter(|step| {
                    matches!(
                        machine.poll(&lost(step * SEC, 1, activity)),
                        AutoDecision::Request { .. }
                    )
                })
                .count()
        };
        let mut old = AutoFailover::new(config(2));
        assert_eq!(asks(&mut old, held), 0, "the old process holds");
        let mut new = AutoFailover::new(config(2));
        assert_eq!(
            asks(&mut new, actions(0)),
            1,
            "the new process starts without the hold"
        );
    }
}
