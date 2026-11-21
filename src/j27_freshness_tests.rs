//! Phase 1-J27 TEST-ONLY: local-loss freshness after a long fencing (OD-J26-6), at the peer
//! runtime (a child module of `daemon_peer_runtime`, so it can read the Appendix R
//! instrumentation). Every refresh asserted here comes from a real Stage 14 §10.3 observation
//! of the running runtime; nothing sets a detector field or a time directly.
//!
//! Test-only: everything is inside `mod tests`, so the architecture guards (which read a module
//! up to its `mod tests`) treat this file as having no production code.

mod tests {
    use super::super::*;
    use crate::failure_assessment::{
        LOCAL_LOSS_EVIDENCE_MAX_AGE as LOCAL_LOSS_MAX_AGE, PeerFailureAssessment, SuspectOrigin,
    };
    use crate::peer_observer::PeerObservationState;
    use crate::security::Psk;
    use std::io::Write;
    use std::net::TcpStream;
    use std::thread;

    fn auth() -> MessageAuthenticator {
        MessageAuthenticator::new(Psk::from_test_bytes([0x55; 32]))
    }

    /// A conservative-mode runtime (production: `cluster.mode` is always conservative).
    fn runtime(
        local: &str,
        peer: &str,
        local_priority: i32,
        peer_priority: i32,
    ) -> DaemonPeerRuntime {
        let mut runtime = DaemonPeerRuntime::new(
            ClusterId::new("cluster"),
            NodeId::new(local),
            NodeId::new(peer),
            local_priority,
            peer_priority,
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            auth(),
        )
        .unwrap();
        runtime.failure_assessment =
            PeerFailureDetector::with_default_window().with_restart_formation(true);
        runtime
    }

    /// node-a (canonical Outbound) dials node-b (canonical Inbound); both sessions established and
    /// both observers Fresh. Returns the listen address and the last instant used.
    fn established() -> (DaemonPeerRuntime, DaemonPeerRuntime, SocketAddr, Instant) {
        let mut inbound = runtime("node-b", "node-a", 90, 100);
        let address = inbound
            .bind("127.0.0.1:0".parse().unwrap(), Instant::now())
            .unwrap();
        let mut outbound = runtime("node-a", "node-b", 100, 90);
        outbound.peer_address = Some(address);
        outbound.connect_once(address).unwrap();
        let mut now = Instant::now();
        for _ in 0..4096 {
            now += Duration::from_millis(1);
            outbound.tick_at(now).unwrap();
            inbound.tick_at(now).unwrap();
            if outbound.snapshot(now).state == PeerObservationState::Fresh
                && inbound.snapshot(now).state == PeerObservationState::Fresh
            {
                return (outbound, inbound, address, now);
            }
            thread::yield_now();
        }
        panic!("the loopback pair did not reach Fresh");
    }

    /// Ticks only `observer` once a second, its peer staying silent with the socket open (a
    /// black-holed path: no frame, no FIN, no RST), until the observer's detector has a live
    /// episode. Returns the instant of that tick.
    fn tick_until_live_episode(observer: &mut DaemonPeerRuntime, now: &mut Instant) -> Instant {
        let held = observer.current_token.expect("a connection is held");
        for _ in 0..60 {
            *now += Duration::from_secs(1);
            observer.tick_at(*now).unwrap();
            if observer.loss_evidence().is_some() {
                return *now;
            }
            assert_eq!(
                observer.current_token,
                Some(held),
                "the connection is kept while there is no live episode ({:?})",
                observer.failure_assessment().assessment
            );
        }
        panic!("no live loss episode formed");
    }

    /// Ticks `runtime` once a second for `seconds`, voiding the verified-listen window after every
    /// tick as the daemon does before each blocking fencing step (a verify poll per iteration).
    fn fencing_polls(runtime: &mut DaemonPeerRuntime, now: &mut Instant, seconds: u64) {
        for _ in 0..seconds {
            *now += Duration::from_secs(1);
            runtime.tick_at(*now).unwrap();
            runtime.void_listen_window_for_fencing_step();
        }
    }

    /// Ticks `runtime` once a second (no fencing step) until its freshness reference moves past
    /// `after`; returns the new reference.
    fn tick_until_refreshed(
        runtime: &mut DaemonPeerRuntime,
        now: &mut Instant,
        after: Instant,
    ) -> Instant {
        for _ in 0..30 {
            *now += Duration::from_secs(1);
            runtime.tick_at(*now).unwrap();
            let reference = runtime
                .loss_evidence()
                .expect("the episode stays live")
                .freshness_reference();
            if reference > after {
                return reference;
            }
        }
        panic!("no refresh after {after:?}");
    }

    /// FR-2 / FR-7: the half-open connection is released exactly when the episode is live, and the
    /// release itself is not an observation: it moves no freshness, no generation, no `lost_at`, and
    /// raises no identity uncertainty (the session was authenticated).
    #[test]
    fn j27_fr_half_open_connection_is_released_only_on_a_live_episode() {
        let (_outbound, mut inbound, _address, mut now) = established();
        let formed = tick_until_live_episode(&mut inbound, &mut now);
        assert_eq!(
            inbound.current_token, None,
            "released in the tick that formed the episode"
        );
        let snapshot = inbound.failure_assessment();
        assert_eq!(
            snapshot.assessment,
            PeerFailureAssessment::CommunicationLost
        );
        assert_eq!(snapshot.lost_at, Some(formed));
        assert_eq!(
            snapshot.last_failed_contact_at, None,
            "the release is not an observation"
        );
        assert!(!inbound.pending_identity_uncertainty);
        let evidence = inbound.loss_evidence().unwrap();
        assert_eq!(evidence.freshness_reference(), formed);
        assert_eq!(evidence.generation(), snapshot.loss_generation);
        assert!(
            inbound.listen_window.is_none(),
            "no window in the release tick"
        );
    }

    /// FR-3: after the release, the only refresh is a completed verified-listen window (Appendix R)
    /// of the Inbound runtime itself, measured from its start; `lost_at` and the generation are
    /// unchanged, and the refreshed evidence ages out 30 s after the window start.
    #[test]
    fn j27_fr_refresh_after_the_release_comes_only_from_a_completed_window() {
        let (_outbound, mut inbound, _address, mut now) = established();
        let formed = tick_until_live_episode(&mut inbound, &mut now);
        let generation = inbound.failure_assessment().loss_generation;
        now += Duration::from_secs(1);
        inbound.tick_at(now).unwrap();
        let w_start = inbound
            .listen_window
            .as_ref()
            .expect("a window opens")
            .w_start;
        assert_eq!(
            w_start, now,
            "the first accept sample after the release opens it"
        );
        // Not complete before MAX_RETRY_DELAY + HANDSHAKE_TIMEOUT.
        for _ in 0..(VERIFIED_LISTEN_MIN_DURATION.as_secs() - 1) {
            now += Duration::from_secs(1);
            inbound.tick_at(now).unwrap();
            assert_eq!(inbound.failure_assessment().last_failed_contact_at, None);
        }
        now += Duration::from_secs(1);
        inbound.tick_at(now).unwrap();
        let snapshot = inbound.failure_assessment();
        assert_eq!(snapshot.last_failed_contact_at, Some(w_start));
        assert_eq!(snapshot.lost_at, Some(formed), "lost_at is never rewritten");
        assert_eq!(
            snapshot.loss_generation, generation,
            "a refresh is not a new episode"
        );
        let evidence = inbound.loss_evidence().unwrap();
        assert_eq!(evidence.freshness_reference(), w_start);
        assert_eq!(evidence.lost_at(), formed);
        assert!(evidence.is_fresh_at(w_start + LOCAL_LOSS_MAX_AGE));
        assert!(!evidence.is_fresh_at(w_start + LOCAL_LOSS_MAX_AGE + Duration::from_millis(1)));
    }

    /// FR-1 / FR-3 (J27 §7 cases 1-3): fencing of 31, 60 and 120 s. While a verify poll runs every
    /// iteration no window completes, so the fencing never refreshes the episode and it goes stale;
    /// the first window after the last step refreshes it from that window's start (after the
    /// fencing), with the same generation.
    #[test]
    fn j27_fr_fencing_of_31_60_120_s_never_refreshes_and_a_later_window_does() {
        for seconds in [31u64, 60, 120] {
            let (_outbound, mut inbound, _address, mut now) = established();
            let formed = tick_until_live_episode(&mut inbound, &mut now);
            let generation = inbound.failure_assessment().loss_generation;
            let fencing_start = now;
            fencing_polls(&mut inbound, &mut now, seconds);
            let fencing_end = now;
            let evidence = inbound.loss_evidence().expect("the episode stays live");
            assert_eq!(
                evidence.freshness_reference(),
                formed,
                "{seconds} s: no refresh"
            );
            assert!(
                !evidence.is_fresh_at(fencing_end),
                "{seconds} s: stale after the fencing"
            );
            assert!(fencing_end > fencing_start);
            let reference = tick_until_refreshed(&mut inbound, &mut now, formed);
            assert!(
                reference > fencing_end,
                "{seconds} s: observed after the last step"
            );
            let evidence = inbound.loss_evidence().unwrap();
            assert!(evidence.is_fresh_at(now));
            assert_eq!(evidence.generation(), generation, "{seconds} s");
            assert_eq!(evidence.lost_at(), formed, "{seconds} s");
            assert_eq!(
                now.duration_since(reference),
                VERIFIED_LISTEN_MIN_DURATION,
                "{seconds} s: one complete window"
            );
        }
    }

    /// FR-6 (J27 §7 cases 4, 10): the peer comes back after the release (the path heals): its own
    /// reconnect is accepted and authenticated, which ends the episode. No evidence is left, and the
    /// trusted heartbeat makes the detector Healthy.
    #[test]
    fn j27_fr_peer_return_after_the_release_ends_the_episode() {
        let (mut outbound, mut inbound, _address, mut now) = established();
        let old = inbound.current_token;
        tick_until_live_episode(&mut inbound, &mut now);
        let mut returned = false;
        for _ in 0..8000 {
            now += Duration::from_millis(5);
            let _ = outbound.tick_at(now);
            inbound.tick_at(now).unwrap();
            if inbound.current_token.is_some()
                && inbound.current_token != old
                && inbound.failure_assessment().assessment == PeerFailureAssessment::Healthy
            {
                returned = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(returned, "the peer did not return");
        assert!(inbound.loss_evidence().is_none());
        assert_eq!(inbound.failure_assessment().lost_at, None);
    }

    /// FR-5 (J27 §7 cases 8, 9): the new observation fails. A connection that arrives after the
    /// release and never authenticates (silent until the handshake deadline: a timeout; or garbage:
    /// an UNKNOWN frame) is identity uncertainty: the episode ends without a refresh, and a new one
    /// needs two new windows and a new generation.
    #[test]
    fn j27_fr_unauthenticated_arrival_after_the_release_ends_the_episode() {
        for garbage in [false, true] {
            let (_outbound, mut inbound, address, mut now) = established();
            tick_until_live_episode(&mut inbound, &mut now);
            let generation = inbound.failure_assessment().loss_generation;
            let mut rogue = TcpStream::connect(address).unwrap();
            if garbage {
                rogue.write_all(&[0xff; 64]).unwrap();
            }
            let mut accepted = false;
            for _ in 0..400 {
                now += Duration::from_millis(50);
                let _ = inbound.tick_at(now);
                // Garbage is accepted, read and disconnected within one tick: the unauthenticated
                // arrival count (§28.1) shows the acceptance then.
                accepted |= inbound.current_token.is_some()
                    || inbound.listener_interference_recent(now) > 0;
                if accepted && inbound.loss_evidence().is_none() {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            assert!(accepted, "garbage={garbage}: the arrival was accepted");
            let snapshot = inbound.failure_assessment();
            assert!(inbound.loss_evidence().is_none(), "garbage={garbage}");
            assert_eq!(snapshot.lost_at, None);
            assert_eq!(snapshot.last_failed_contact_at, None);
            assert_eq!(
                snapshot.suspect_origin,
                Some(SuspectOrigin::UncertaintyFormation),
                "garbage={garbage}"
            );
            drop(rogue);
            // Two new windows re-form a new episode with a new generation (never the old one).
            for _ in 0..40 {
                now += Duration::from_secs(1);
                let _ = inbound.tick_at(now);
                if inbound.loss_evidence().is_some() {
                    break;
                }
            }
            let evidence = inbound.loss_evidence().expect("re-formed from two windows");
            assert_eq!(evidence.generation(), generation + 1, "garbage={garbage}");
        }
    }

    /// The release needs both a live episode and an authenticated session: a healthy established
    /// pair keeps its connection, and an accepted connection that has not authenticated is left to
    /// the handshake deadline (Appendix R.6).
    #[test]
    fn j27_fr_healthy_or_unauthenticated_connections_are_not_released() {
        let (mut outbound, mut inbound, _address, mut now) = established();
        let held = inbound.current_token;
        for _ in 0..20 {
            now += Duration::from_secs(1);
            for step in 0..3 {
                let at = now + Duration::from_millis(step);
                outbound.tick_at(at).unwrap();
                inbound.tick_at(at).unwrap();
                thread::sleep(Duration::from_millis(2));
            }
            now += Duration::from_millis(3);
        }
        assert_eq!(inbound.current_token, held);
        assert_eq!(
            inbound.failure_assessment().assessment,
            PeerFailureAssessment::Healthy
        );
        // An accepted, unauthenticated connection while an episode is live is not released by the
        // J27 path (it would be uncertainty); the handshake deadline handles it.
        let (_outbound, mut inbound, address, mut now) = established();
        tick_until_live_episode(&mut inbound, &mut now);
        let _rogue = TcpStream::connect(address).unwrap();
        let mut token = None;
        for _ in 0..200 {
            now += Duration::from_millis(1);
            inbound.tick_at(now).unwrap();
            if inbound.current_token.is_some() {
                token = inbound.current_token;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(token.is_some(), "the arrival was accepted");
        assert!(!inbound.is_established());
        inbound.release_connection_of_live_loss_episode(now);
        assert_eq!(
            inbound.current_token, token,
            "not released before the handshake deadline"
        );
    }

    /// The Outbound role (the observer dials): after the release it reconnects, and an initiated
    /// contact that fails (here the silent peer never answers the HELLO within the handshake
    /// deadline) is the §10.3.1 observation that refreshes the episode from the attempt's start.
    #[test]
    fn j27_fr_outbound_release_then_a_failed_initiated_contact_refreshes() {
        let (mut outbound, _inbound, _address, mut now) = established();
        let formed = tick_until_live_episode(&mut outbound, &mut now);
        assert_eq!(outbound.current_token, None);
        let generation = outbound.failure_assessment().loss_generation;
        let mut attempt_start = None;
        for _ in 0..40 {
            now += Duration::from_secs(1);
            outbound.tick_at(now).unwrap();
            if attempt_start.is_none()
                && let Some((_, started)) = outbound.outbound_attempt
            {
                attempt_start = Some(started);
            }
            if outbound
                .failure_assessment()
                .last_failed_contact_at
                .is_some()
            {
                break;
            }
        }
        let started = attempt_start.expect("the runtime dialed again");
        let snapshot = outbound.failure_assessment();
        assert_eq!(snapshot.last_failed_contact_at, Some(started));
        assert!(started > formed);
        assert_eq!(snapshot.lost_at, Some(formed));
        assert_eq!(snapshot.loss_generation, generation);
    }

    /// Audit a01 NB-4: the Outbound role after the release, when the peer's port refuses (the
    /// peer's listener is gone): the refused `connect` is the §10.3.1 observation, from the
    /// attempt's start.
    #[test]
    fn j27_fr_outbound_release_then_a_refused_connect_refreshes() {
        let (mut outbound, inbound, _address, mut now) = established();
        let formed = tick_until_live_episode(&mut outbound, &mut now);
        assert_eq!(outbound.current_token, None);
        let generation = outbound.failure_assessment().loss_generation;
        drop(inbound);
        let mut refreshed = None;
        for _ in 0..40 {
            now += Duration::from_secs(1);
            outbound.tick_at(now).unwrap();
            if let Some(at) = outbound.failure_assessment().last_failed_contact_at {
                refreshed = Some((at, now));
                break;
            }
        }
        let (at, observed) = refreshed.expect("a refused connect refreshed the episode");
        assert_eq!(
            at, observed,
            "a refused connect starts and fails in the same iteration"
        );
        assert!(at > formed);
        let snapshot = outbound.failure_assessment();
        assert_eq!(snapshot.lost_at, Some(formed));
        assert_eq!(snapshot.loss_generation, generation);
        assert_eq!(outbound.current_token, None);
    }

    /// Audit a01 NB-1: the daemon reads one `now` per iteration, runs that iteration's blocking
    /// fencing step (which voids the window first), and only then ticks the peer with the same
    /// `now`. A window that tick opens starts before the step ended, so it would overlap the step
    /// (Appendix R.3(21)). `LinuxDaemonRuntime::peer_tick_at` therefore voids it again; the first
    /// window that counts is opened by a later iteration and starts after the last step.
    #[test]
    fn j27_fr_daemon_order_no_window_starts_before_the_last_fencing_step_ended() {
        const STEP: Duration = Duration::from_secs(2);
        let (_outbound, mut inbound, _address, mut now) = established();
        let formed = tick_until_live_episode(&mut inbound, &mut now);
        let mut step_end = now;
        for _ in 0..40 {
            // One daemon iteration with a verify poll: `now` is read, the step voids and blocks,
            // then the peer tick uses the iteration's `now`.
            now = step_end + Duration::from_secs(1);
            inbound.void_listen_window_for_fencing_step();
            step_end = now + STEP;
            inbound.tick_at(now).unwrap();
            let opened = inbound.listen_window.as_ref().map(|window| window.w_start);
            // The hazard the composition removes: this window would start before the step ended.
            assert_eq!(opened, Some(now));
            assert!(now < step_end);
            inbound.void_listen_window_for_fencing_step();
            assert!(inbound.listen_window.is_none());
        }
        assert_eq!(
            inbound.loss_evidence().unwrap().freshness_reference(),
            formed,
            "no refresh during the steps"
        );
        // The first iteration without a step (the fencing ended with the last poll).
        let resumed = step_end + Duration::from_secs(1);
        now = resumed;
        inbound.tick_at(now).unwrap();
        assert_eq!(inbound.listen_window.as_ref().unwrap().w_start, resumed);
        let reference = tick_until_refreshed(&mut inbound, &mut now, formed);
        assert_eq!(reference, resumed);
        assert!(
            reference > step_end,
            "the observation starts after the last step"
        );
    }
}
