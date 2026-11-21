//! Scenario and randomized tests of the two-node controllers (TWO_NODE_FAILURE_MATRIX.md).

use super::*;
use crate::two_node::controller::Event;
use crate::two_node::store::Basis;

const A: usize = 0;
const B: usize = 1;

fn two_seg_fenced() -> Layout {
    Layout {
        segments: 2,
        fencing: true,
        fence_path_shared: false,
        auto: true,
    }
}

fn one_seg_fenced_shared() -> Layout {
    Layout {
        segments: 1,
        fencing: true,
        fence_path_shared: true,
        auto: true,
    }
}

fn one_seg_fenced_separate() -> Layout {
    Layout {
        segments: 1,
        fencing: true,
        fence_path_shared: false,
        auto: true,
    }
}

fn one_seg_unfenced() -> Layout {
    Layout {
        segments: 1,
        fencing: false,
        fence_path_shared: false,
        auto: true,
    }
}

fn two_seg_unfenced() -> Layout {
    Layout {
        segments: 2,
        fencing: false,
        fence_path_shared: false,
        auto: true,
    }
}

/// Both nodes powered on together; returns the world once one node is Active.
fn started(layout: Layout) -> World {
    started_ordered(layout, false)
}

fn started_ordered(layout: Layout, controls_first: bool) -> World {
    let mut world = World::new(layout);
    world.controls_first = controls_first;
    world.power_on(A);
    world.power_on(B);
    assert!(
        world.run_until(30_000, |w| w.active().is_some()),
        "a cold start elects one Active: {:#?}",
        world.logs
    );
    // Let both sides observe the Active a few times (two consecutive announcements).
    world.run_for(3_000);
    world.assert_safe();
    world
}

fn basis_of(world: &World, i: usize) -> Option<Basis> {
    world
        .durable(i)
        .and_then(|d| d.intent)
        .map(|intent| intent.basis)
}

// ---- cold start -------------------------------------------------------------------------

#[test]
fn cold_start_elects_exactly_one_active_by_grant_in_every_layout() {
    for layout in [
        two_seg_fenced(),
        one_seg_fenced_shared(),
        one_seg_unfenced(),
        two_seg_unfenced(),
    ] {
        let world = started(layout);
        let active = world.active().unwrap();
        assert_eq!(active, A, "the preferred node asks first");
        assert_eq!(world.role(B), Some(Role::Standby));
        assert!(matches!(basis_of(&world, A), Some(Basis::Grant { .. })));
        assert_eq!(world.durable(A).unwrap().epoch, 1);
        assert_eq!(world.durable(B).unwrap().epoch, 1);
        assert_eq!(
            world.durable(B).unwrap().grant,
            None,
            "grant resolved once Active"
        );
    }
}

#[test]
fn cold_start_works_in_both_delivery_orders() {
    for controls_first in [false, true] {
        let world = started_ordered(two_seg_fenced(), controls_first);
        assert_eq!(world.active(), Some(A));
        assert_eq!(world.promotions.len(), 1, "no abandoned grant loop");
        assert!(!world.log_contains("a gate no longer holds"));
    }
}

#[test]
fn a_lone_node_never_promotes_automatically_wait_for_peer() {
    for layout in [two_seg_fenced(), one_seg_unfenced()] {
        let mut world = World::new(layout);
        world.power_on(A);
        world.run_for(180_000);
        assert_eq!(world.role(A), Some(Role::Standby));
        assert!(world.promotions.is_empty());
        world.assert_safe();
    }
}

#[test]
fn simultaneous_start_and_simultaneous_promotion_requests_elect_one() {
    let mut world = World::new(two_seg_fenced());
    world.power_on(A);
    world.power_on(B);
    world.run_for(1_500);
    world.send_event(A, Event::PromotionRequest);
    world.send_event(B, Event::PromotionRequest);
    world.run_for(20_000);
    world.assert_safe();
    assert!(world.active().is_some());
    assert_eq!(world.promotions.len(), 1, "{:?}", world.promotions);
}

#[test]
fn contention_without_preference_still_elects_one_by_node_id() {
    let mut world = World::new(one_seg_unfenced());
    world.tweak = Some(|cfg| {
        cfg.preferred = false;
        cfg.bootstrap_defer_ms = 0;
    });
    world.power_on(A);
    world.power_on(B);
    assert!(world.run_until(40_000, |w| w.active().is_some()));
    world.run_for(5_000);
    world.assert_safe();
    assert_eq!(world.promotions.len(), 1);
}

// ---- single-node failures ---------------------------------------------------------------

#[test]
fn active_power_loss_is_taken_over_only_after_a_confirmed_fence() {
    let mut world = started(two_seg_fenced());
    world.power_off(A);
    assert!(world.run_until(60_000, |w| w.active() == Some(B)));
    world.assert_safe();
    let basis = basis_of(&world, B).unwrap();
    assert!(matches!(basis, Basis::Fence { .. }), "{basis:?}");
    assert_eq!(world.durable(B).unwrap().epoch, 2);
    assert!(world.log_contains("verify observed the peer stopped"));
    assert!(world.log_contains("an acceptance report only"));
}

#[test]
fn standby_failure_changes_nothing_on_the_active() {
    let mut world = started(two_seg_fenced());
    world.power_off(B);
    world.run_for(120_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A));
    assert_eq!(world.promotions.len(), 1);
    assert!(
        !world.log_contains("fencing the peer"),
        "the Active never fences"
    );
}

// ---- segments ---------------------------------------------------------------------------

#[test]
fn one_of_two_segments_down_never_fences() {
    for segment in [0, 1] {
        let mut world = started(two_seg_fenced());
        world.set_link(segment, false, false);
        world.run_for(120_000);
        world.assert_safe();
        assert_eq!(world.active(), Some(A));
        assert!(world.log_contains("peer path degraded"));
        assert!(!world.log_contains("fencing the peer"));
    }
}

#[test]
fn both_segments_down_fences_then_promotes_the_standby() {
    let mut world = started(two_seg_fenced());
    world.set_all_links(false);
    assert!(world.run_until(90_000, |w| w.active() == Some(B)));
    world.assert_safe();
    assert!(
        !world.powered(A),
        "the old Active was stopped by the fence device"
    );
}

#[test]
fn single_segment_down_with_shared_fence_path_never_promotes() {
    let mut world = started(one_seg_fenced_shared());
    world.set_all_links(false);
    world.run_for(300_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A), "the Active keeps serving");
    assert_eq!(world.promotions.len(), 1);
    assert!(
        world.log_contains("fence cycle ended without a confirmed stop")
            || world.log_contains("timed out without a confirmed stop")
    );
}

#[test]
fn single_segment_down_with_separate_fence_path_takes_over_after_fence() {
    let mut world = started(one_seg_fenced_separate());
    world.set_all_links(false);
    assert!(world.run_until(90_000, |w| w.active() == Some(B)));
    world.assert_safe();
    assert!(!world.powered(A));
}

#[test]
fn without_fencing_a_peer_loss_is_never_taken_over_automatically() {
    for layout in [one_seg_unfenced(), two_seg_unfenced()] {
        let mut world = started(layout);
        world.power_off(A);
        world.run_for(300_000);
        world.assert_safe();
        assert_eq!(world.role(B), Some(Role::Standby));
        assert_eq!(world.promotions.len(), 1);
        assert!(!world.log_contains("fencing the peer"));
    }
}

#[test]
fn asymmetric_loss_takes_both_sides_down_and_stays_safe() {
    for (a_to_b, b_to_a) in [(false, true), (true, false)] {
        let mut world = started(two_seg_fenced());
        for segment in 0..2 {
            world.set_link(segment, a_to_b, b_to_a);
        }
        world.run_for(120_000);
        world.assert_safe();
        assert!(world.active().is_some());
        assert!(world.promotions.len() <= 2);
    }
}

// ---- fencing failures -------------------------------------------------------------------

#[test]
fn fence_failure_timeout_and_accept_without_stop_never_promote_and_are_bounded() {
    for mode in [
        FenceMode::Fails,
        FenceMode::TimesOut,
        FenceMode::AcceptsWithoutStop,
    ] {
        let mut world = started(two_seg_fenced());
        world.fence_mode = mode;
        world.set_all_links(false);
        world.run_for(15 * 60_000);
        world.assert_safe();
        assert_eq!(
            world.active(),
            Some(A),
            "{mode:?}: the old Active keeps serving"
        );
        assert_eq!(world.promotions.len(), 1, "{mode:?}");
        let attempts = world
            .logs
            .iter()
            .filter(|l| {
                l.contains("node-b")
                    && (l.contains("fencing the peer") || l.contains("fence attempt"))
            })
            .count();
        assert!(attempts >= 1, "{mode:?}");
        assert!(
            attempts <= CYCLE_LIMIT_TEST * 2,
            "{mode:?}: bounded retries, got {attempts}"
        );
        if mode == FenceMode::AcceptsWithoutStop {
            assert!(world.log_contains("NOT stopped"));
            assert_eq!(attempts, 1, "never fenced again after not-isolated");
        }
    }
}

const CYCLE_LIMIT_TEST: usize = crate::two_node::controller::CYCLE_LIMIT;

#[test]
fn slow_os_stop_beyond_the_verify_window_fails_safe_and_a_longer_window_succeeds() {
    let mut world = started(two_seg_fenced());
    world.tweak = None;
    world.fence_mode = FenceMode::SlowStop { delay_ms: 90_000 };
    world.set_all_links(false);
    // Default verify window: 10 polls x 2 s = 20 s < 90 s.
    world.run_for(100_000);
    world.assert_safe();
    assert_ne!(world.active(), Some(B));

    let mut world = World::new(two_seg_fenced());
    world.tweak = Some(|cfg| {
        cfg.verify_polls = 60;
        cfg.cycle_timeout_ms = 180_000;
    });
    world.power_on(A);
    world.power_on(B);
    assert!(world.run_until(30_000, |w| w.active() == Some(A)));
    world.run_for(3_000);
    world.fence_mode = FenceMode::SlowStop { delay_ms: 90_000 };
    world.set_all_links(false);
    assert!(world.run_until(200_000, |w| w.active() == Some(B)));
    world.assert_safe();
}

#[test]
fn restart_right_after_the_fence_comes_back_standby_and_never_resumes() {
    let mut world = started(two_seg_fenced());
    world.set_all_links(false);
    assert!(world.run_until(60_000, |w| !w.powered(A)));
    // An external actor powers the fenced node back on at once, links healed.
    world.power_on(A);
    world.set_all_links(true);
    world.run_for(60_000);
    world.assert_safe();
    assert!(world.active().is_some());
    // Whoever is Active, the restarted node never resumed its old epoch 1.
    for promotion in &world.promotions[1..] {
        assert!(promotion.2 >= 2, "{:?}", world.promotions);
    }
}

#[test]
fn stale_fence_results_are_ignored() {
    let mut world = started(two_seg_fenced());
    world.fence_mode = FenceMode::TimesOut;
    world.set_all_links(false);
    assert!(world.run_until(60_000, |w| w.log_contains("fencing the peer")));
    // Results of an operation id this incident never ran, in every shape.
    for event in [
        Event::VerifyDone {
            op_id: "00000000-0000-4000-8000-000000000000".into(),
            verdict: Verdict::Isolated,
        },
        Event::FenceActionDone {
            op_id: "00000000-0000-4000-8000-000000000000".into(),
            outcome: FenceAction::ReportedSuccess,
        },
    ] {
        world.send_event(B, event);
    }
    world.run_for(30_000);
    world.assert_safe();
    assert_ne!(world.active(), Some(B));
    assert!(world.log_contains("ignored"));
}

#[test]
fn a_confirmed_proof_of_a_previous_attempt_or_process_is_never_reused() {
    let mut world = started(two_seg_fenced());
    world.fence_mode = FenceMode::TimesOut;
    world.set_all_links(false);
    assert!(world.run_until(60_000, |w| w.log_contains("fencing the peer")));
    let first_op = world.durable(B).unwrap().incident.unwrap().op_id;
    // B restarts: the open incident is retired, never carried over.
    world.kill_process(B);
    world.start_process(B);
    world.run_for(1_000);
    let durable = world.durable(B).unwrap();
    assert!(durable.incident.is_none());
    assert!(
        durable
            .history
            .iter()
            .any(|r| r.op_id == first_op && r.outcome == "retired-restart")
    );
    // A late "isolated" for the old operation does nothing.
    world.send_event(
        B,
        Event::VerifyDone {
            op_id: first_op,
            verdict: Verdict::Isolated,
        },
    );
    world.run_for(120_000);
    world.assert_safe();
    assert_ne!(
        world.active(),
        Some(B),
        "a restarted process never fences on a guess"
    );
}

// ---- process vs OS --------------------------------------------------------------------------

#[test]
fn killed_mikagami_process_on_the_active_is_fenced_at_os_level() {
    let mut world = started(two_seg_fenced());
    world.kill_process(A);
    assert_eq!(
        world.holds(A),
        (true, true),
        "the service and VIP survive the process"
    );
    assert!(world.run_until(90_000, |w| w.active() == Some(B)));
    world.assert_safe();
    assert!(!world.powered(A));
}

#[test]
fn killed_process_restarting_quickly_returns_standby_and_hands_over_cooperatively() {
    let mut world = started(two_seg_fenced());
    world.kill_process(A);
    world.run_for(1_000);
    world.start_process(A);
    assert!(world.run_until(60_000, |w| w.active().is_some() && w.role(A).is_some()));
    world.run_for(10_000);
    world.assert_safe();
    assert!(world.promotions.len() >= 2);
    assert!(world.log_contains("a restart never resumes ownership"));
}

// ---- resource failures --------------------------------------------------------------------

#[test]
fn service_start_failure_rolls_back_and_the_peer_can_own() {
    let mut world = World::new(two_seg_fenced());
    world.set_acquire_fails(A, true);
    world.power_on(A);
    world.power_on(B);
    assert!(world.run_until(120_000, |w| w.active() == Some(B)));
    world.assert_safe();
    assert_eq!(world.holds(A), (false, false));
}

#[test]
fn start_failures_on_both_nodes_stop_at_the_failure_limit() {
    let mut world = World::new(one_seg_unfenced());
    world.set_acquire_fails(A, true);
    world.set_acquire_fails(B, true);
    world.power_on(A);
    world.power_on(B);
    world.run_for(400_000);
    world.assert_safe();
    assert!(world.active().is_none());
    assert!(world.promotions.len() <= 6, "{:?}", world.promotions.len());
}

#[test]
fn vip_release_failure_blocks_and_the_peer_never_takes_over_cooperatively() {
    let mut world = started(two_seg_fenced());
    world.set_release_fails(A, true);
    world.send_event(A, Event::Shutdown);
    world.run_for(1_000);
    // The process exits with the VIP possibly held; start it again (still failing).
    world.start_process(A);
    world.run_for(120_000);
    world.assert_safe();
    assert_eq!(world.role(A), Some(Role::Blocked));
    assert_ne!(world.active(), Some(B));
    world.set_release_fails(A, false);
    assert!(world.run_until(120_000, |w| w.active().is_some()));
    world.assert_safe();
}

#[test]
fn graceful_shutdown_of_the_active_hands_over() {
    let mut world = started(one_seg_unfenced());
    world.send_event(A, Event::Shutdown);
    assert!(world.run_until(60_000, |w| w.active() == Some(B)));
    world.assert_safe();
    assert!(world.controller(A).is_none());
    assert_eq!(world.holds(A), (false, false));
    assert!(matches!(basis_of(&world, B), Some(Basis::Grant { .. })));
}

// ---- power and persistence ----------------------------------------------------------------

#[test]
fn both_nodes_lose_power_and_recover_with_a_new_epoch() {
    let mut world = started(two_seg_fenced());
    let before = world.durable(A).unwrap().epoch;
    world.power_off(A);
    world.power_off(B);
    world.run_for(5_000);
    world.power_on(B);
    world.power_on(A);
    assert!(world.run_until(60_000, |w| w.active().is_some()));
    world.run_for(5_000);
    world.assert_safe();
    let active = world.active().unwrap();
    assert!(world.durable(active).unwrap().epoch > before);
}

#[test]
fn corrupt_record_means_cleanup_only_and_never_ownership() {
    let mut world = started(two_seg_fenced());
    world.corrupt_store(A);
    world.kill_process(A);
    world.start_process(A);
    assert!(world.run_until(60_000, |w| w.active() == Some(B)));
    world.run_for(60_000);
    world.assert_safe();
    let ctl = world.controller(A).unwrap();
    assert!(!ctl.store_ok());
    assert_eq!(ctl.role(), Role::Standby);
    assert!(world.log_contains("cleanup-only"));
    // B fails: the cleanup-only node never takes over.
    world.power_off(B);
    world.run_for(300_000);
    world.assert_safe();
    assert_eq!(world.role(A), Some(Role::Standby));
}

#[test]
fn a_failed_intent_write_never_starts_resources() {
    let mut world = World::new(one_seg_unfenced());
    world.power_on(A);
    world.power_on(B);
    world.run_for(1_000);
    world.set_store_failure(A, true);
    world.set_store_failure(B, true);
    world.run_for(120_000);
    world.assert_safe();
    assert!(world.promotions.is_empty(), "{:?}", world.promotions);
}

// ---- operator -----------------------------------------------------------------------------

#[test]
fn operator_attestation_is_refused_while_the_peer_is_connected_and_used_once() {
    let mut world = started(one_seg_unfenced());
    let id = "6f1c3b8e-2d4a-4c5b-9e7f-0a1b2c3d4e5f".to_string();
    world.send_event(
        B,
        Event::OperatorAttest {
            attestation_id: id.clone(),
            target: "node-a".into(),
        },
    );
    assert!(world.log_contains("peer is connected"));
    world.power_off(A);
    world.run_for(15_000);
    world.send_event(
        B,
        Event::OperatorAttest {
            attestation_id: id.clone(),
            target: "node-a".into(),
        },
    );
    assert!(world.run_until(10_000, |w| w.active() == Some(B)));
    world.assert_safe();
    assert!(
        world
            .durable(B)
            .unwrap()
            .consumed_attestations
            .contains(&id)
    );
    // The returning old Active stays Standby (newer epoch known).
    world.power_on(A);
    world.run_for(30_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(B));
}

#[test]
fn a_node_back_alone_after_a_total_outage_accepts_operator_failover() {
    // Attestation (no fencing needed).
    let mut world = started(one_seg_unfenced());
    world.power_off(A);
    world.power_off(B);
    world.run_for(2_000);
    world.power_on(B);
    world.run_for(60_000);
    assert_eq!(world.role(B), Some(Role::Standby), "never automatic alone");
    world.send_event(
        B,
        Event::OperatorAttest {
            attestation_id: "0b8e6c1a-1f2d-4e3c-8a5b-6c7d8e9f0a1b".into(),
            target: "node-a".into(),
        },
    );
    assert!(world.run_until(10_000, |w| w.active() == Some(B)));
    world.assert_safe();
    // Operator-requested fence (independent device).
    let mut world = started(two_seg_fenced());
    world.power_off(A);
    world.power_off(B);
    world.run_for(2_000);
    world.power_on(B);
    world.run_for(60_000);
    assert_eq!(world.role(B), Some(Role::Standby));
    world.send_event(
        B,
        Event::OperatorFence {
            target: "node-a".into(),
        },
    );
    assert!(world.run_until(20_000, |w| w.active() == Some(B)));
    world.assert_safe();
    // The same request while the peer is up and connected is refused.
    let mut world = started(two_seg_fenced());
    world.send_event(
        B,
        Event::OperatorFence {
            target: "node-a".into(),
        },
    );
    assert!(world.log_contains("the peer is connected"));
    world.run_for(20_000);
    assert_eq!(world.active(), Some(A));
    world.assert_safe();
}

#[test]
fn operator_fence_request_needs_an_independent_device() {
    let mut world = started(one_seg_unfenced());
    world.power_off(A);
    world.run_for(15_000);
    world.send_event(
        B,
        Event::OperatorFence {
            target: "node-a".into(),
        },
    );
    assert!(world.log_contains("no independent fence device"));
    world.run_for(30_000);
    assert_ne!(world.active(), Some(B));
    world.assert_safe();
}

// ---- returning nodes and lost messages ----------------------------------------------------

#[test]
fn old_active_returning_after_takeover_stays_standby() {
    let mut world = started(two_seg_fenced());
    world.set_all_links(false);
    assert!(world.run_until(90_000, |w| w.active() == Some(B)));
    world.run_for(5_000);
    world.set_all_links(true);
    world.power_on(A);
    world.run_for(60_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(B));
    assert_eq!(world.role(A), Some(Role::Standby));
    assert_eq!(
        world.durable(A).unwrap().epoch,
        world.durable(B).unwrap().epoch
    );
}

#[test]
fn a_lost_grant_never_promotes_and_resolves_later() {
    let mut world = World::new(one_seg_unfenced());
    world.power_on(A);
    world.power_on(B);
    // Cut B->A right when A claims, so B's grant never arrives.
    assert!(world.run_until(30_000, |w| w.log_contains("claiming epoch")));
    world.set_link(0, true, false);
    world.run_for(20_000);
    world.assert_safe();
    assert!(world.active().is_none());
    world.set_link(0, true, true);
    assert!(world.run_until(60_000, |w| w.active().is_some()));
    world.run_for(5_000);
    world.assert_safe();
    let active = world.active().unwrap();
    assert_eq!(world.durable(1 - active).unwrap().grant, None);
}

#[test]
fn lying_verify_is_an_explicit_assumption_and_contradiction_relinquishes() {
    // The safety model assumes a truthful, independent fence device. If verify lied
    // (isolated while the peer runs), a partition would allow two owners: the model
    // states this assumption instead of claiming safety without it.
    let mut world = started(two_seg_fenced());
    world.fence_mode = FenceMode::AcceptsWithoutStop;
    world.set_all_links(false);
    // Make the device lie by short-circuiting verify: deliver an isolated verdict for the
    // current operation.
    assert!(world.run_until(60_000, |w| {
        w.durable(B).and_then(|d| d.incident).is_some_and(|i| {
            matches!(
                i.state,
                crate::two_node::store::IncidentState::Verifying { .. }
            )
        })
    }));
    let op_id = world.durable(B).unwrap().incident.unwrap().op_id;
    world.send_event(
        B,
        Event::VerifyDone {
            op_id,
            verdict: Verdict::Isolated,
        },
    );
    world.run_for(5_000);
    assert!(
        !world.violations.is_empty(),
        "without the assumption two owners exist"
    );
    // On reconnection the contradiction is detected: the older owner relinquishes, the
    // newer epoch stays the only owner.
    world.set_all_links(true);
    world.run_for(20_000);
    assert!(world.log_contains("ownership contradiction"));
    assert_eq!(world.holds(A), (false, false));
    assert_eq!(world.active(), Some(B));
    world.violations.clear();
    world.run_for(120_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(B));
}

// ---- review findings (self-audit M-2..M-5, L-1) ------------------------------------------

#[test]
fn an_ineligible_node_never_fences() {
    let mut world = World::new(two_seg_fenced());
    world.set_acquire_fails(A, true);
    world.power_on(A);
    world.power_on(B);
    assert!(world.run_until(200_000, |w| w.active() == Some(B)));
    world.run_for(5_000);
    world.set_all_links(false);
    world.run_for(180_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(B), "the healthy owner is never fenced");
    assert!(world.powered(B));
    assert!(
        !world
            .logs
            .iter()
            .any(|l| l.contains("node-a") && l.contains("fencing the peer"))
    );
}

#[test]
fn a_save_failure_during_fencing_ends_the_incident_without_promotion() {
    let mut world = started(two_seg_fenced());
    world.fence_mode = FenceMode::TimesOut;
    world.set_all_links(false);
    assert!(world.run_until(60_000, |w| w.log_contains("fence action of op")));
    world.set_store_failure(B, true);
    world.fence_mode = FenceMode::Works;
    world.run_for(200_000);
    world.assert_safe();
    assert_ne!(world.active(), Some(B));
    assert!(
        world.log_contains("record cannot be written") || world.log_contains("durable save failed")
    );
    let verifies = world
        .logs
        .iter()
        .filter(|l| l.contains("node-b") && l.contains("verify"))
        .count();
    assert!(verifies < 40, "bounded: {verifies}");
}

#[test]
fn not_isolated_is_durable_and_lifted_only_by_an_authenticated_return() {
    let mut world = started(two_seg_fenced());
    world.fence_mode = FenceMode::AcceptsWithoutStop;
    world.set_all_links(false);
    assert!(world.run_until(60_000, |w| w.log_contains("NOT stopped")));
    assert!(world.durable(B).unwrap().fence_stopped);
    world.kill_process(B);
    world.start_process(B);
    world.run_for(1_000);
    assert!(
        world.durable(B).unwrap().fence_stopped,
        "kept across a restart"
    );
    world.set_all_links(true);
    world.run_for(10_000);
    assert!(
        !world.durable(B).unwrap().fence_stopped,
        "lifted by the peer's return"
    );
    world.assert_safe();
}

#[test]
fn a_promotion_request_never_lingers() {
    let mut world = World::new(Layout {
        segments: 1,
        fencing: false,
        fence_path_shared: false,
        auto: false,
    });
    world.power_on(A);
    world.run_for(2_000);
    world.send_event(A, Event::PromotionRequest);
    world.power_on(B);
    world.run_for(60_000);
    world.assert_safe();
    assert!(
        world.active().is_none(),
        "an old SIGUSR1 never claims later with auto = false"
    );
    world.send_event(A, Event::PromotionRequest);
    assert!(
        world.run_until(10_000, |w| w.active() == Some(A)),
        "a fresh request does"
    );
}

#[test]
fn shutdown_during_a_fence_step_exits_after_it() {
    let mut world = started(two_seg_fenced());
    world.fence_mode = FenceMode::TimesOut;
    world.set_all_links(false);
    assert!(world.run_until(60_000, |w| w.log_contains("fencing the peer")));
    world.send_event(B, Event::Shutdown);
    assert!(world.run_until(30_000, |w| w.controller(B).is_none()));
    world.assert_safe();
}

// ---- fencing integration cases (TWO_NODE_FENCING_INTEGRATION_REPORT.md) ----------------

#[test]
fn verify_unknown_never_promotes_and_every_attempt_has_a_fresh_operation_id() {
    let mut world = started(two_seg_fenced());
    world.fence_mode = FenceMode::Unreachable;
    world.set_all_links(false);
    world.run_for(15 * 60_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A), "the old Active keeps serving");
    let history = world.durable(B).unwrap().history;
    let ops: Vec<&String> = history.iter().map(|r| &r.op_id).collect();
    assert!(ops.len() >= 2, "{history:?}");
    let mut unique = ops.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        ops.len(),
        "an operation id is never reused: {ops:?}"
    );
    assert!(history.iter().all(|r| r.outcome != "confirmed-consumed"));
    // Attempts within an incident are numbered from 1 and the fresh id goes with each.
    assert!(history.iter().any(|r| r.attempt == 2));
}

#[test]
fn a_peer_that_returns_during_the_fence_step_voids_its_result() {
    let mut world = started(two_seg_fenced());
    // A slow stop: the action is accepted, the target is still up while it runs.
    world.fence_mode = FenceMode::SlowStop { delay_ms: 60_000 };
    world.set_all_links(false);
    assert!(world.run_until(60_000, |w| w.log_contains("fencing the peer")));
    // The peer answers again before any verify confirms anything.
    world.set_all_links(true);
    world.run_for(30_000);
    assert!(world.log_contains("its result is never used"));
    let retired_seq = world
        .durable(B)
        .unwrap()
        .history
        .iter()
        .find(|r| r.outcome.starts_with("retired-peer-returned"))
        .map(|r| r.seq)
        .expect("the incident was retired");
    // The delayed power-off still lands (the device was already asked). B may take over
    // later, but only through a new incident with its own confirmed verify, never through
    // the retired operation.
    world.run_for(120_000);
    world.assert_safe();
    if let Some(Basis::Fence { incident_seq, .. }) = basis_of(&world, B) {
        assert_ne!(incident_seq, retired_seq);
    }
}

// ---- randomized exploration ---------------------------------------------------------------

fn random_run(layout: Layout, seed: u64, steps: u64) -> World {
    let mut rng = Rng::new(seed);
    let mut world = World::new(layout);
    world.controls_first = rng.chance(50);
    world.power_on(A);
    if rng.chance(80) {
        world.power_on(B);
    }
    for _ in 0..steps {
        world.step();
        if rng.below(1000) >= 6 {
            continue;
        }
        match rng.below(14) {
            0 => {
                let segment = rng.below(layout.segments as u64) as usize;
                world.set_link(segment, rng.chance(60), rng.chance(60));
            }
            1 => world.set_all_links(rng.chance(50)),
            2 => {
                let i = rng.below(2) as usize;
                if world.powered(i) {
                    world.power_off(i);
                } else {
                    world.power_on(i);
                }
            }
            3 => {
                let i = rng.below(2) as usize;
                world.kill_process(i);
            }
            4 => {
                let i = rng.below(2) as usize;
                world.start_process(i);
            }
            5 => {
                world.fence_mode = match rng.below(5) {
                    0 => FenceMode::Fails,
                    1 => FenceMode::TimesOut,
                    2 => FenceMode::AcceptsWithoutStop,
                    3 => FenceMode::SlowStop {
                        delay_ms: rng.below(60_000),
                    },
                    _ => FenceMode::Works,
                }
            }
            6 => {
                let i = rng.below(2) as usize;
                world.set_acquire_fails(i, rng.chance(30));
            }
            7 => {
                let i = rng.below(2) as usize;
                world.set_release_fails(i, rng.chance(30));
            }
            8 => {
                let i = rng.below(2) as usize;
                world.send_event(i, Event::PromotionRequest);
            }
            9 => {
                let i = rng.below(2) as usize;
                world.set_store_failure(i, rng.chance(20));
            }
            10 => {
                let i = rng.below(2) as usize;
                if rng.chance(30) {
                    world.corrupt_store(i);
                }
            }
            11 => {
                // An honest operator attests only a peer that is powered off.
                let i = rng.below(2) as usize;
                if !world.powered(1 - i) {
                    // An attested promotion has no contact with the peer: it may reuse an
                    // epoch number the peer took meanwhile (S-4 is not claimed for it).
                    world.knowledge_lost = true;
                    let id = crate::node_mutation::generate_uuid().unwrap();
                    let target = if i == 0 { "node-b" } else { "node-a" };
                    world.send_event(
                        i,
                        Event::OperatorAttest {
                            attestation_id: id,
                            target: target.into(),
                        },
                    );
                }
            }
            12 => {
                let i = rng.below(2) as usize;
                let target = if i == 0 { "node-b" } else { "node-a" };
                // Likewise without contact: S-4 is not claimed after an operator request.
                world.knowledge_lost = true;
                world.send_event(
                    i,
                    Event::OperatorFence {
                        target: target.into(),
                    },
                );
            }
            _ => {
                let i = rng.below(2) as usize;
                world.send_event(i, Event::Shutdown);
            }
        }
    }
    world
}

#[test]
fn randomized_fault_schedules_never_violate_safety() {
    let layouts = [
        two_seg_fenced(),
        one_seg_fenced_shared(),
        one_seg_fenced_separate(),
        one_seg_unfenced(),
        two_seg_unfenced(),
    ];
    let mut runs = 0;
    for (index, layout) in layouts.iter().enumerate() {
        for seed in 0..120u64 {
            let world = random_run(*layout, seed * 7 + index as u64, 6_000);
            if !world.violations.is_empty() {
                panic!(
                    "layout {index} seed {seed}: {:#?}\n{}",
                    world.violations,
                    world
                        .logs
                        .iter()
                        .rev()
                        .take(80)
                        .rev()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
            runs += 1;
        }
    }
    assert_eq!(runs, 600);
}

#[test]
fn randomized_runs_make_progress_when_faults_stop() {
    // After random faults, healing everything (links, power, devices, stores) must lead
    // to exactly one Active again in the layouts that need no operator.
    for seed in 0..40u64 {
        let mut world = random_run(two_seg_fenced(), 10_000 + seed, 3_000);
        world.set_all_links(true);
        world.fence_mode = FenceMode::Works;
        for i in 0..2 {
            world.set_acquire_fails(i, false);
            world.set_release_fails(i, false);
            world.set_store_failure(i, false);
            if world.durable(i).is_none() {
                // An operator re-initialises a corrupt record.
                world.power_off(i);
                let id = if i == 0 { "node-a" } else { "node-b" };
                world.nodes_store_reset(i, id);
            }
            if !world.powered(i) {
                world.power_on(i);
            } else {
                world.kill_process(i);
                world.start_process(i);
            }
        }
        let ok = world.run_until(120_000, |w| w.active().is_some());
        world.assert_safe();
        assert!(
            ok,
            "seed {seed}: no Active after healing\n{}",
            world
                .logs
                .iter()
                .rev()
                .take(40)
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

// ---- configuration mismatch (shared configuration summary) --------------------------------

/// Both nodes see each other alive but incompatible (an authenticated `Hello` with another
/// configuration summary) and no compatible link.
fn mismatch(world: &mut World) {
    world.set_all_links(false);
    world.send_event(A, Event::PeerIncompatible(true));
    world.send_event(B, Event::PeerIncompatible(true));
}

#[test]
fn a_config_mismatch_is_never_a_peer_loss_and_never_fences() {
    // Control: the same link loss without the mismatch fences and promotes B
    // (both_segments_down_fences_then_promotes_the_standby).
    let mut world = started(two_seg_fenced());
    mismatch(&mut world);
    world.run_for(180_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A), "the Active keeps the service");
    assert!(world.powered(A) && world.powered(B));
    assert!(!world.log_contains("fencing the peer"));
    assert_eq!(world.promotions.len(), 1);
    assert!(world.controller(B).unwrap().peer_incompatible());
}

#[test]
fn a_mismatch_seen_after_the_loss_ends_the_episode_before_the_fence() {
    let mut world = started(two_seg_fenced());
    world.set_all_links(false);
    // The loss is detected (link timeout) but the dwell has not passed yet.
    world.run_for(4_000);
    assert!(world.log_contains("peer lost on every link"));
    world.send_event(B, Event::PeerIncompatible(true));
    world.send_event(A, Event::PeerIncompatible(true));
    world.run_for(180_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A));
    assert!(world.powered(A));
    assert!(!world.log_contains("fencing the peer"));
}

#[test]
fn the_end_of_a_mismatch_without_a_compatible_link_founds_no_takeover() {
    let mut world = started(two_seg_fenced());
    mismatch(&mut world);
    world.run_for(30_000);
    // The peer disappears (or the mismatch is no longer observed) without ever being
    // admitted: there is no loss episode, so no automatic fence.
    world.send_event(B, Event::PeerIncompatible(false));
    world.run_for(180_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A));
    assert!(!world.log_contains("fencing the peer"));
}

#[test]
fn a_cold_start_with_a_config_mismatch_elects_nobody() {
    let mut world = World::new(two_seg_fenced());
    world.power_on(A);
    world.power_on(B);
    mismatch(&mut world);
    world.run_for(120_000);
    world.assert_safe();
    assert_eq!(world.active(), None);
    assert!(world.promotions.is_empty());
    assert!(!world.log_contains("fencing the peer"));
}

#[test]
fn operator_takeovers_are_refused_while_the_peer_is_alive_with_another_configuration() {
    let mut world = started(two_seg_fenced());
    mismatch(&mut world);
    world.run_for(10_000);
    world.send_event(
        B,
        Event::OperatorAttest {
            attestation_id: crate::node_mutation::generate_uuid().unwrap(),
            target: "node-a".into(),
        },
    );
    world.send_event(
        B,
        Event::OperatorFence {
            target: "node-a".into(),
        },
    );
    world.run_for(60_000);
    world.assert_safe();
    assert!(world.log_contains(
        "operator attestation refused: the peer is alive with another configuration"
    ));
    assert!(world.log_contains(
        "operator fence request refused: the peer is alive with another configuration"
    ));
    assert_eq!(world.active(), Some(A));
    assert!(world.powered(A));
}

// ---- health on_failure ------------------------------------------------------------------

#[test]
fn a_health_failover_hands_over_only_through_a_confirmed_release_and_a_grant() {
    let mut world = started(two_seg_fenced());
    assert_eq!(world.active(), Some(A));
    world.send_event(A, Event::HealthFailover);
    assert!(world.run_until(30_000, |w| w.active() == Some(B)));
    world.assert_safe();
    assert!(world.log_contains("health failover: releasing"));
    assert!(world.log_contains("resources released for the health failover"));
    assert!(!world.log_contains("fencing the peer"), "never by fencing");
    assert!(world.powered(A) && world.powered(B));
    let basis = basis_of(&world, B).unwrap();
    assert!(matches!(basis, Basis::Grant { .. }), "{basis:?}");
    // A stays a Standby: it is not eligible to take the service back.
    world.run_for(120_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(B));
    assert_eq!(world.role(A), Some(Role::Standby));
}

#[test]
fn a_health_failover_back_is_refused_during_the_cooldown() {
    let mut world = started(two_seg_fenced());
    world.send_event(A, Event::HealthFailover);
    assert!(world.run_until(30_000, |w| w.active() == Some(B)));
    world.run_for(5_000);
    world.send_event(B, Event::HealthFailover);
    world.run_for(60_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(B), "no ping-pong");
    assert!(world.log_contains("health failover not started: the peer is not eligible"));
}

#[test]
fn a_health_failover_without_a_connected_peer_is_refused_and_never_fences() {
    let mut world = started(two_seg_fenced());
    world.power_off(B);
    world.run_for(10_000);
    world.send_event(A, Event::HealthFailover);
    world.run_for(60_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A));
    assert!(world.log_contains("health failover not started: the peer is not connected"));
    assert!(!world.log_contains("fencing the peer"));
}

#[test]
fn a_health_failover_whose_release_is_not_confirmed_keeps_the_ownership() {
    let mut world = started(two_seg_fenced());
    world.set_release_fails(A, true);
    world.send_event(A, Event::HealthFailover);
    world.run_for(60_000);
    world.assert_safe();
    assert_eq!(world.role(A), Some(Role::Blocked));
    assert_ne!(
        world.active(),
        Some(B),
        "no takeover while A may hold resources"
    );
    assert!(!world.log_contains("fencing the peer"));
}

#[test]
fn a_health_failover_is_refused_when_not_active() {
    let mut world = started(two_seg_fenced());
    world.send_event(B, Event::HealthFailover);
    world.run_for(20_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A));
    assert!(world.log_contains("health failover not started: this node is not an Active"));
}

#[test]
fn a_local_resource_failure_releases_and_the_peer_takes_over_cooperatively() {
    let mut world = started(two_seg_fenced());
    world.send_event(A, Event::LocalResourceFailure);
    assert!(world.run_until(120_000, |w| w.active() == Some(B)));
    world.assert_safe();
    assert!(!world.log_contains("fencing the peer"));
    let basis = basis_of(&world, B).unwrap();
    assert!(matches!(basis, Basis::Grant { .. }), "{basis:?}");
}

#[test]
fn a_mismatch_after_the_loss_that_then_ends_founds_no_takeover() {
    // Audit NB-3: loss detected, then the peer is seen alive with another configuration,
    // then that is no longer observed (still no compatible link): no fence, no takeover.
    let mut world = started(two_seg_fenced());
    world.set_all_links(false);
    world.run_for(4_000);
    assert!(world.log_contains("peer lost on every link"));
    world.send_event(B, Event::PeerIncompatible(true));
    world.run_for(5_000);
    world.send_event(B, Event::PeerIncompatible(false));
    world.run_for(180_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A));
    assert!(world.powered(A));
    assert!(!world.log_contains("fencing the peer"));
}

#[test]
fn a_health_failover_is_refused_without_automatic_cooperative_start() {
    // failover.auto = false: the peer would not claim, so the Active does not release.
    let mut world = World::new(Layout {
        auto: false,
        ..two_seg_fenced()
    });
    world.power_on(A);
    world.power_on(B);
    world.run_for(5_000);
    world.send_event(A, Event::PromotionRequest);
    assert!(world.run_until(30_000, |w| w.active() == Some(A)));
    world.run_for(3_000);
    world.send_event(A, Event::HealthFailover);
    world.run_for(30_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A));
    assert!(world.log_contains("health failover not started: automatic cooperative start is off"));
}

#[test]
fn a_health_failover_is_refused_while_the_peer_is_incompatible() {
    let mut world = started(two_seg_fenced());
    world.send_event(A, Event::PeerIncompatible(true));
    world.send_event(A, Event::HealthFailover);
    world.run_for(10_000);
    world.assert_safe();
    assert_eq!(world.active(), Some(A));
    assert!(
        world.log_contains(
            "health failover not started: the peer is alive with another configuration"
        )
    );
}
