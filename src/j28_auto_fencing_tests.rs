//! Phase 1-J28 TEST-ONLY: the automatic fence path over long and repeated partitions (rate limit,
//! dwell, FAILED / UNKNOWN, incident regeneration, restart). The machine is driven only through
//! `AutoFailover::poll` with plain inputs, as the daemon builds them.
//!
//! Test-only: everything is inside `mod tests`, so the architecture guards (which read a module
//! up to its `mod tests`) treat this file as having no production code.

mod tests {
    use crate::auto_failover::{
        AutoConfig, AutoDecision, AutoFailover, AutoInputs, AutoOrigin, FenceActivity,
        IncidentFacts, IncidentKind, LossEpisode, MIN_UPTIME_MS,
    };
    use crate::failure_assessment::PeerFailureAssessment;
    use crate::state_machine::NodeState;

    const SEC: u64 = 1_000;

    /// The `[failover]` defaults (docs/configuration.md): dwell 10 s, 2 fence actions, 120 s.
    fn config() -> AutoConfig {
        AutoConfig {
            enabled: true,
            preferred: false,
            dwell_ms: 10 * SEC,
            bootstrap_dwell_ms: 20 * SEC,
            bootstrap_defer_ms: 15 * SEC,
            max_fence_actions: 2,
            cycle_timeout_ms: 120 * SEC,
        }
    }

    fn lost(now_ms: u64, generation: u64, incident: Option<IncidentFacts>) -> AutoInputs {
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
            incident,
            activity: FenceActivity::default(),
            bootstrap_session_open: false,
            bootstrap_session_attested: false,
        }
    }

    /// A §10.5 non-authenticated invalidation (rogue arrival): `Suspect`, no episode, no heartbeat.
    fn uncertain(now_ms: u64) -> AutoInputs {
        AutoInputs {
            assessment: PeerFailureAssessment::Suspect,
            loss: None,
            ..lost(now_ms, 0, None)
        }
    }

    /// The peer's authenticated return: an Active peer again (no bootstrap request).
    fn returned(now_ms: u64) -> AutoInputs {
        AutoInputs {
            assessment: PeerFailureAssessment::Healthy,
            loss: None,
            peer_node_state: Some(NodeState::Active),
            ..lost(now_ms, 0, None)
        }
    }

    fn facts(kind: IncidentKind, seq: u64, token: u64) -> Option<IncidentFacts> {
        Some(IncidentFacts {
            seq,
            attempt_token: token,
            kind,
        })
    }

    fn is_request(decision: AutoDecision) -> bool {
        matches!(decision, AutoDecision::Request { .. })
    }

    /// Drives one episode of `generation` from `start` for `seconds`, one poll a second, with the
    /// incident `outcome(n)` after the n-th request; returns (requests, the Exhausted reason).
    fn episode(
        machine: &mut AutoFailover,
        start: u64,
        seconds: u64,
        generation: u64,
        outcome: &dyn Fn(u32) -> Option<IncidentFacts>,
    ) -> (u32, Option<&'static str>) {
        let mut requests = 0;
        let mut stop = None;
        for step in 0..seconds {
            let incident = if requests == 0 {
                None
            } else {
                outcome(requests)
            };
            // J29: the runtime counts one fence action for every request whose attempt left an
            // incident (a fence ran); a request that opened nothing ran none.
            let mut inputs = lost(start + step * SEC, generation, incident);
            inputs.activity.actions_run =
                (1..=requests).filter(|n| outcome(*n).is_some()).count() as u64;
            match machine.poll(&inputs) {
                AutoDecision::Request { .. } => requests += 1,
                AutoDecision::Exhausted(reason) => {
                    assert!(stop.is_none(), "Exhausted is reported once per episode");
                    stop = Some(reason);
                }
                _ => {}
            }
        }
        (requests, stop)
    }

    /// AR-4 / H-2: FAILED stops the fence path, and a new episode formed by a non-authenticated
    /// invalidation (no peer return) does not restart it - in cf27 it did (`FenceTrack` reset).
    #[test]
    fn j28_failed_hold_survives_a_new_episode_without_the_peer_return() {
        let mut machine = AutoFailover::new(config());
        let failed = |_| facts(IncidentKind::Failed, 1, 1);
        let (requests, stop) = episode(&mut machine, 0, 60, 1, &failed);
        assert_eq!(requests, 1);
        assert!(stop.unwrap().contains("not isolated"));
        // A rogue connection ends the episode; the FAILED incident is retired (absent from now on)
        // and two new windows form generation 2, fresh, with the peer never heard from again.
        for step in 60..80 {
            assert_eq!(machine.poll(&uncertain(step * SEC)), AutoDecision::Idle);
        }
        let (requests, stop) = episode(&mut machine, 80 * SEC, 900, 2, &|_| None);
        assert_eq!(
            requests, 0,
            "no automatic fence of a peer verified as not isolated"
        );
        assert!(stop.unwrap().contains("not isolated"));
    }

    /// H-2: the hold is taken from any poll that sees FAILED, also while the loss is not fresh (a
    /// long verify) and before a cycle exists (an operator's FAILED).
    #[test]
    fn j28_failed_hold_is_taken_while_the_loss_is_stale_or_before_a_cycle() {
        for stale in [true, false] {
            let mut machine = AutoFailover::new(config());
            let mut seen = lost(0, 1, facts(IncidentKind::Failed, 1, 1));
            seen.loss.as_mut().unwrap().fresh = !stale;
            seen.peer_active_confirmed = !stale;
            assert!(!is_request(machine.poll(&seen)));
            machine.poll(&uncertain(SEC));
            let (requests, _) = episode(&mut machine, 2 * SEC, 600, 2, &|_| None);
            assert_eq!(requests, 0, "stale={stale}");
        }
    }

    /// H-2: only the peer's authenticated return (`Healthy`) - or a new process - ends the hold;
    /// then a later loss episode is handled as usual.
    #[test]
    fn j28_failed_hold_ends_only_with_the_authenticated_return() {
        let mut machine = AutoFailover::new(config());
        let failed = |_| facts(IncidentKind::Failed, 1, 1);
        episode(&mut machine, 0, 30, 1, &failed);
        for step in 30..40 {
            machine.poll(&uncertain(step * SEC));
        }
        assert_eq!(episode(&mut machine, 40 * SEC, 60, 2, &|_| None).0, 0);
        assert_eq!(machine.poll(&returned(100 * SEC)), AutoDecision::Idle);
        let (requests, _) = episode(&mut machine, 101 * SEC, 15, 3, &|_| None);
        assert_eq!(
            requests, 1,
            "a new episode after the return asks after the dwell"
        );
        let mut restarted = AutoFailover::new(config());
        assert_eq!(episode(&mut restarted, 0, 15, 2, &|_| None).0, 1);
    }

    /// AR-1 / H-1: UNKNOWN after every attempt, reported with the token high-water (1, 2, ...):
    /// exactly `max_fence_actions` fence-bearing requests in the episode, then Exhausted; the rest
    /// of a long partition asks for nothing.
    #[test]
    fn j28_repeated_unknown_is_capped_by_max_fence_actions() {
        for max in 1..=3u32 {
            let mut machine = AutoFailover::new(AutoConfig {
                max_fence_actions: max,
                ..config()
            });
            let unknown = |n: u32| facts(IncidentKind::Unknown, 1, u64::from(n));
            let (requests, stop) = episode(&mut machine, 0, 900, 1, &unknown);
            assert_eq!(requests, max, "max_fence_actions={max}");
            assert!(stop.unwrap().contains("fence action budget"));
        }
    }

    /// AR-7: episodes regenerated without a peer return (rogue arrivals, each a new generation) get
    /// a new per-episode budget, but the process window still allows 3 cycle starts per 600 s;
    /// the 4th and later episodes in the window are refused, and the window rolls.
    #[test]
    fn j28_regenerated_episodes_are_bounded_by_the_process_window() {
        let mut machine = AutoFailover::new(config());
        let mut cycles = Vec::new();
        let mut refused = 0;
        let mut now = 0;
        for generation in 1..=8u64 {
            let unknown = |n: u32| facts(IncidentKind::Unknown, generation, u64::from(n));
            let (requests, stop) = episode(&mut machine, now, 50, generation, &unknown);
            if requests > 0 {
                cycles.push(now);
            } else if stop.is_some_and(|reason| reason.contains("3 automatic cycles")) {
                refused += 1;
            }
            assert!(requests <= 2, "generation {generation}: {requests}");
            machine.poll(&uncertain(now + 50 * SEC));
            now += 60 * SEC;
        }
        // Cycle starts at 10 s, 70 s, 130 s; generations 4..8 (190..430 s) are inside the window.
        assert_eq!(cycles.len(), 3);
        assert_eq!(refused, 5);
        // 600 s after the first cycle start (at 10 s) a new one may start.
        let (requests, _) = episode(&mut machine, 600 * SEC, 15, 9, &|_| None);
        assert_eq!(requests, 1);
    }

    /// The window's boundary: a cycle start is refused while the oldest of three is younger than
    /// 600 s (599.999 s), allowed at exactly 600 s; a refused episode stays refused.
    #[test]
    fn j28_process_window_boundary() {
        for (age_ms, allowed) in [(599_999u64, false), (600_000, true)] {
            let mut machine = AutoFailover::new(config());
            for generation in 1..=3u64 {
                let base = (generation - 1) * 20 * SEC;
                machine.poll(&lost(base, generation, None));
                assert!(is_request(machine.poll(&lost(
                    base + 10 * SEC,
                    generation,
                    None
                ))));
            }
            // The oldest cycle started at 10 s.
            let at = 10 * SEC + age_ms;
            machine.poll(&lost(at - 10 * SEC, 4, None));
            let decision = machine.poll(&lost(at, 4, None));
            assert_eq!(
                is_request(decision),
                allowed,
                "age {age_ms} ms: {decision:?}"
            );
            if !allowed {
                assert!(
                    matches!(decision, AutoDecision::Exhausted(r) if r.contains("3 automatic"))
                );
                assert!(!is_request(machine.poll(&lost(at + 300 * SEC, 4, None))));
            }
        }
    }

    /// AR-2: the dwell, to the millisecond: no request before `dwell_ms` of continuous, fresh loss;
    /// a stale interval restarts it.
    #[test]
    fn j28_dwell_boundary_and_restart_on_stale() {
        let mut machine = AutoFailover::new(config());
        assert!(matches!(
            machine.poll(&lost(0, 1, None)),
            AutoDecision::Wait(_)
        ));
        assert!(!is_request(machine.poll(&lost(10 * SEC - 1, 1, None))));
        assert!(is_request(machine.poll(&lost(10 * SEC, 1, None))));

        let mut machine = AutoFailover::new(config());
        machine.poll(&lost(0, 1, None));
        let mut stale = lost(6 * SEC, 1, None);
        stale.loss.as_mut().unwrap().fresh = false;
        assert_eq!(machine.poll(&stale), AutoDecision::Idle);
        assert!(!is_request(machine.poll(&lost(7 * SEC, 1, None))));
        assert!(!is_request(machine.poll(&lost(16 * SEC, 1, None))));
        assert!(is_request(machine.poll(&lost(17 * SEC, 1, None))));
    }

    /// J27 interplay: after CONFIRMED the local loss is stale until a new observation (about 10 s).
    /// The cycle survives that gap - the next request belongs to the same cycle and uses no new
    /// process-window entry - and a CONFIRMED incident needs no fence budget.
    #[test]
    fn j28_cycle_survives_the_freshness_gap_after_confirmed() {
        let mut machine = AutoFailover::new(config());
        machine.poll(&lost(0, 1, None));
        assert!(is_request(machine.poll(&lost(10 * SEC, 1, None))));
        let confirmed = facts(IncidentKind::Confirmed, 1, 0);
        for step in 11..22 {
            let mut gap = lost(step * SEC, 1, confirmed);
            gap.loss.as_mut().unwrap().fresh = false;
            assert_eq!(machine.poll(&gap), AutoDecision::Idle);
        }
        assert_eq!(
            machine.poll(&lost(22 * SEC, 1, confirmed)),
            AutoDecision::Request {
                origin: AutoOrigin::Fence,
                first: false
            }
        );
        assert_eq!(machine.process_cycles.len(), 1);
    }

    /// AR-8 (Owner-approved A-9: no bound across restarts): a new process has an empty window, but
    /// it never fences a peer it has not itself seen Active twice (F-3), nor before 30 s of uptime,
    /// however long the partition lasts.
    #[test]
    fn j28_restart_resets_the_window_but_f3_and_uptime_block() {
        let mut machine = AutoFailover::new(config());
        for step in 0..3_600u64 {
            let mut inputs = lost(step * SEC, 1, None);
            inputs.peer_active_confirmed = false;
            assert!(!is_request(machine.poll(&inputs)), "{step}");
        }
        let mut machine = AutoFailover::new(config());
        for step in 0..30u64 {
            let mut inputs = lost(step * SEC, 1, None);
            inputs.uptime_ms = step * SEC;
            assert!(!is_request(machine.poll(&inputs)), "{step}");
        }
        assert_eq!(MIN_UPTIME_MS, 30 * SEC);
    }
}
