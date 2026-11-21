//! Scenario tests of the VIP hand-over against the in-memory world.

use super::fakes::{ChangeBehavior, Fault, VIP_CIDR, World};
use super::gce::Alias;
use super::lease::Phase;
use super::proto::op;
use super::vip::*;
use super::{Failure, Res};
use serde_json::json;

fn mv(w: &World, to: &str) -> Res<MoveReport> {
    move_vip(
        &w.ctx(),
        &MoveRequest {
            target: to.to_string(),
            confirm_fenced: None,
        },
    )
}

fn mv_fenced(w: &World, to: &str, confirm: &str) -> Res<MoveReport> {
    move_vip(
        &w.ctx(),
        &MoveRequest {
            target: to.to_string(),
            confirm_fenced: Some(confirm.to_string()),
        },
    )
}

fn position(w: &World, needle: &str) -> usize {
    w.events
        .borrow()
        .iter()
        .position(|e| e.contains(needle))
        .unwrap_or_else(|| panic!("event {needle:?} not found in {:#?}", w.events.borrow()))
}

fn assert_untouched(w: &World) {
    assert_eq!(w.cloud_holders(), ["node-a"], "the VIP must not have moved");
    assert!(w.service_active("node-a"));
    assert!(!w.service_active("node-b"));
    assert_eq!(
        w.gce.change_count(),
        0,
        "no cloud change may have been made"
    );
    let lease = w.lease();
    assert_eq!(lease.owner.as_deref(), Some("node-a"));
    assert_eq!(lease.epoch, 1);
    w.assert_no_double_active();
}

fn assert_restored(w: &World) {
    assert_eq!(w.cloud_holders(), ["node-a"]);
    assert!(w.service_active("node-a"));
    assert!(!w.service_active("node-b"));
    let lease = w.lease();
    assert_eq!(lease.owner.as_deref(), Some("node-a"));
    assert_eq!(
        lease.epoch, 1,
        "a rolled-back move does not change the epoch"
    );
    assert!(
        lease.op.is_none(),
        "the lock record is cleared after a verified rollback"
    );
    assert_eq!(lease.history.last().unwrap().kind, "abort");
    w.assert_no_double_active();
}

// ---------------------------------------------------------------- success

#[test]
fn move_a_to_b_follows_the_safe_order_and_commits() {
    let w = World::new("vip-happy");
    let report = mv(&w, "node-b").unwrap();
    assert_eq!(
        (report.source.as_str(), report.target.as_str()),
        ("node-a", "node-b")
    );
    assert_eq!((report.epoch_before, report.epoch_after), (1, 2));
    assert_eq!(report.served_by, "node-b");
    assert!(!report.fenced_source);
    assert_eq!(w.cloud_holders(), ["node-b"]);
    assert!(w.service_active("node-b") && !w.service_active("node-a"));
    let lease = w.lease();
    assert_eq!((lease.owner.as_deref(), lease.epoch), (Some("node-b"), 2));
    assert!(lease.op.is_none());
    assert_eq!(lease.history.last().unwrap().kind, "move");
    // The order is the safety argument: stop -> release -> assign -> start.
    let stop = position(&w, "node-a service.control {\"action\":\"stop\"");
    let release = position(&w, "gce inst-a aliases -> [] ");
    let assign = position(&w, "gce inst-b aliases -> [10.0.0.130/32]");
    let start = position(&w, "node-b service.control {\"action\":\"start\"");
    assert!(
        stop < release && release < assign && assign < start,
        "{:#?}",
        w.events.borrow()
    );
    w.assert_no_double_active();
}

#[test]
fn consecutive_moves_alternate_and_each_increases_the_epoch() {
    let w = World::new("vip-consecutive");
    for (i, to) in ["node-b", "node-a", "node-b", "node-a"].iter().enumerate() {
        let report = mv(&w, to).unwrap();
        assert_eq!(report.epoch_after, 2 + i as u64);
        assert_eq!(w.cloud_holders(), [*to]);
        assert!(w.service_active(to));
    }
    w.assert_no_double_active();
    assert_eq!(
        w.lease()
            .history
            .iter()
            .filter(|h| h.kind == "move")
            .count(),
        4
    );
}

#[test]
fn a_second_identical_move_is_refused_without_side_effects() {
    let w = World::new("vip-double-move");
    mv(&w, "node-b").unwrap();
    let before = w.gce.change_count();
    let again = mv(&w, "node-b");
    assert!(matches!(again, Err(Failure::Refused(m)) if m.contains("already owns")));
    assert_eq!(w.gce.change_count(), before);
}

#[test]
fn cloud_read_lag_never_causes_an_early_assignment() {
    let w = World::new("vip-lag");
    w.gce.set_lag(3);
    mv(&w, "node-b").unwrap();
    assert_eq!(w.cloud_holders(), ["node-b"]);
    w.assert_no_double_active();
}

#[test]
fn flapping_cloud_reads_are_not_taken_for_a_settled_state() {
    // The first read after a change already shows the new state, the next one
    // the old state again. One matching read must not be enough.
    let w = World::new("vip-flap");
    w.gce.set_flap(true);
    let report = mv(&w, "node-b").unwrap();
    assert_eq!(report.target, "node-b");
    assert_eq!(w.cloud_holders(), ["node-b"]);
    w.assert_no_double_active();
}

#[test]
fn a_timed_out_cloud_change_is_verified_by_observation_not_retried() {
    let w = World::new("vip-timeout-after");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutAfterApply]);
    w.gce
        .script_changes("inst-b", &[ChangeBehavior::ErrorAfterApply]);
    mv(&w, "node-b").unwrap();
    let changes = w.gce.changes();
    assert_eq!(
        changes.iter().filter(|(i, _)| i == "inst-a").count(),
        1,
        "no blind retry"
    );
    assert_eq!(
        changes.iter().filter(|(i, _)| i == "inst-b").count(),
        1,
        "no blind retry"
    );
    w.assert_no_double_active();
}

#[test]
fn unrelated_alias_ranges_are_preserved() {
    let w = World::new("vip-other-aliases");
    w.gce
        .set_aliases_direct("inst-a", &["10.9.9.0/24", VIP_CIDR]);
    mv(&w, "node-b").unwrap();
    assert_eq!(w.gce.aliases_of("inst-a"), ["10.9.9.0/24"]);
    assert_eq!(w.gce.aliases_of("inst-b"), [VIP_CIDR]);
}

// ---------------------------------------------------------------- refusals

#[test]
fn unknown_target_and_uninitialised_ownership_are_refused() {
    let w = World::new("vip-refuse-basic");
    assert!(matches!(mv(&w, "node-z"), Err(Failure::Refused(_))));
    assert_untouched(&w);
    let w = World::build("vip-uninit", false);
    let r = mv(&w, "node-b");
    assert!(matches!(r, Err(Failure::Refused(m)) if m.contains("not initialised")));
    assert_eq!(w.gce.change_count(), 0);
    assert!(w.service_active("node-a"));
}

#[test]
fn witness_unreachable_means_no_move() {
    let w = World::new("vip-witness-down");
    w.remote.host("witness").reachable.set(false);
    let r = mv(&w, "node-b");
    assert!(matches!(r, Err(Failure::Refused(m)) if m.contains("Witness lease is unavailable")));
    assert_eq!(w.cloud_holders(), ["node-a"]);
    assert!(w.service_active("node-a"));
    assert_eq!(w.gce.change_count(), 0);
    assert_eq!(w.remote.count("node-a", op::SERVICE_CONTROL), 0);
}

#[test]
fn external_owner_change_is_respected_not_overwritten() {
    let w = World::new("vip-external");
    w.gce.set_aliases_direct("inst-a", &[]);
    w.gce.set_aliases_direct("inst-b", &[VIP_CIDR]);
    let r = mv(&w, "node-a");
    assert!(matches!(r, Err(Failure::Refused(m)) if m.contains("ownership conflict")));
    assert_eq!(w.gce.change_count(), 0);
    assert!(w.service_active("node-a"), "nothing was stopped");
    // Multiple holders and no holder are refused too.
    w.gce.set_aliases_direct("inst-a", &[VIP_CIDR]);
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(m)) if m.contains("several nodes")));
    w.gce.set_aliases_direct("inst-a", &[]);
    w.gce.set_aliases_direct("inst-b", &[]);
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(m)) if m.contains("no node holding")));
    assert_eq!(w.gce.change_count(), 0);
}

#[test]
fn target_problems_are_found_before_the_source_is_touched() {
    // Unreachable target.
    let w = World::new("vip-target-down");
    w.remote.host("node-b").reachable.set(false);
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(m)) if m.contains("unreachable")));
    assert_untouched(&w);
    // Target not RUNNING in the cloud.
    let w = World::new("vip-target-stopped");
    w.gce.set_status("inst-b", "TERMINATED");
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(m)) if m.contains("not RUNNING")));
    assert_untouched(&w);
    // HA daemon active on the target / the source (exclusive mode).
    for (label, active_on) in [("tgt", "node-b"), ("src", "node-a")] {
        let w = World::new(&format!("vip-ha-{label}"));
        w.remote
            .host(active_on)
            .sys
            .set_service("mikagami.service", "active");
        assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(m)) if m.contains("HA daemon")));
        assert_untouched(&w);
    }
    // A host answering as the wrong node.
    let w = World::new("vip-wrong-host");
    w.remote.redirect("node-b", "node-a");
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(m)) if m.contains("wrong host")));
    assert_untouched(&w);
}

#[test]
fn an_open_operation_blocks_a_second_move() {
    let w = World::new("vip-open-op");
    let ctx = w.ctx();
    lease_call(
        &ctx,
        op::LEASE_ACQUIRE,
        json!({"op_id": "other-controller-1", "source": "node-a", "target": "node-b",
               "ttl_s": 300, "controller": "x", "expect_epoch": 1}),
    )
    .unwrap();
    let r = mv(&w, "node-b");
    assert!(matches!(r, Err(Failure::Refused(m)) if m.contains("resolve it first")));
    assert_untouched(&w);
    // Once it expired without ever mutating, the lock is taken over.
    w.clock.advance_secs(301);
    mv(&w, "node-b").unwrap();
    assert!(w.lease().history.iter().any(|h| h.kind == "expired"));
}

// ------------------------------------------------------------ fenced path

#[test]
fn unreachable_source_needs_attestation_and_cloud_proof() {
    let w = World::new("vip-fence");
    w.remote.host("node-a").reachable.set(false);
    // No attestation.
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(m)) if m.contains("not attested")));
    // Attestation for the wrong node.
    assert!(
        matches!(mv_fenced(&w, "node-b", "node-b"), Err(Failure::Refused(m)) if m.contains("not attested"))
    );
    // Attested, but the cloud says the instance is still RUNNING: the
    // attestation alone is not proof.
    let r = mv_fenced(&w, "node-b", "node-a");
    assert!(matches!(r, Err(Failure::Refused(m)) if m.contains("fencing is not proven")));
    assert_eq!(w.gce.change_count(), 0);
    assert_eq!(w.cloud_holders(), ["node-a"]);
    assert!(w.lease().op.is_none(), "nothing was acquired");
    // Only the cloud's TERMINATED status unlocks the path.
    w.gce.set_status("inst-a", "TERMINATED");
    let report = mv_fenced(&w, "node-b", "node-a").unwrap();
    assert!(report.fenced_source);
    assert_eq!(w.cloud_holders(), ["node-b"]);
    let history = w.lease().history;
    let fence = &history.last().unwrap().evidence["fence"];
    assert_eq!(fence["source_status"], "TERMINATED");
    assert_eq!(fence["source_instance_id"], "id-inst-a");
    w.assert_no_double_active();
}

#[test]
fn fenced_move_works_when_the_terminated_source_has_no_external_address() {
    // In external-address mode a stopped instance has no address at all; that
    // must read as "unreachable", and the cloud status is still the proof.
    let w = World::build_with("vip-fence-external", true, true);
    w.remote.host("node-a").reachable.set(false);
    w.gce.set_status("inst-a", "TERMINATED");
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(m)) if m.contains("not attested")));
    let report = mv_fenced(&w, "node-b", "node-a").unwrap();
    assert!(report.fenced_source);
    assert_eq!(w.cloud_holders(), ["node-b"]);
    w.assert_no_double_active();
    // The same applies to the reconcile / status paths.
    let status = vip_status(&w.ctx());
    assert_eq!(status.verdict, "consistent", "{:?}", status.problems);
    assert!(reconcile_vip(&w.ctx(), None, false).is_ok());
}

#[test]
fn a_terminated_peer_is_quiet_in_internal_mode_too() {
    let w = World::new("vip-terminated-internal");
    w.gce.set_status("inst-b", "TERMINATED");
    w.remote.host("node-b").reachable.set(false);
    let status = vip_status(&w.ctx());
    assert_eq!(status.verdict, "consistent", "{:?}", status.problems);
}

#[test]
fn a_running_node_without_an_address_is_never_treated_as_fenced() {
    let w = World::build_with("vip-no-address", true, true);
    // The cloud says RUNNING but returns no external address: unreachable,
    // and RUNNING is not fencing proof.
    w.gce
        .inner
        .borrow_mut()
        .instances
        .get_mut("inst-a")
        .unwrap()
        .status = "RUNNING".to_string();
    w.remote.host("node-a").reachable.set(false);
    let r = mv_fenced(&w, "node-b", "node-a");
    assert!(
        matches!(&r, Err(Failure::Refused(m)) if m.contains("fencing is not proven")),
        "{r:?}"
    );
    assert_eq!(w.gce.change_count(), 0);
}

#[test]
fn a_reachable_source_that_the_cloud_calls_terminated_is_inconsistent() {
    let w = World::new("vip-fence-inconsistent");
    w.gce.set_status("inst-a", "TERMINATED");
    let r = mv_fenced(&w, "node-b", "node-a");
    assert!(matches!(r, Err(Failure::Refused(m)) if m.contains("inconsistent")));
    assert_eq!(w.gce.change_count(), 0);
}

#[test]
fn a_hung_source_is_treated_like_an_unreachable_one() {
    let w = World::new("vip-hung");
    w.remote.host("node-a").hung.set(true);
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(m)) if m.contains("not attested")));
    w.gce.set_status("inst-a", "TERMINATED");
    assert!(mv_fenced(&w, "node-b", "node-a").is_ok());
}

// ------------------------------------------------- failure and rollback

#[test]
fn source_stop_failure_rolls_back_to_a_verified_source() {
    let w = World::new("vip-stop-fails");
    w.remote.host("node-a").sys.fail_action("stop");
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("rolled back")),
        "{r:?}"
    );
    assert_restored(&w);
}

#[test]
fn recording_a_phase_is_a_precondition_for_acting() {
    let w = World::new("vip-phase-fails");
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("source_quiescing"),
        0,
        1,
        Fault::DropBefore,
    );
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("not proceeding")),
        "{r:?}"
    );
    // The phase record may have been written although its answer was lost, so
    // the rollback runs; it only (idempotently) starts the source service.
    assert!(
        !w.remote
            .calls
            .borrow()
            .iter()
            .any(|c| c.contains("\"action\":\"stop\"")),
        "no service was ever stopped"
    );
    assert_eq!(w.gce.change_count(), 0);
    assert!(w.lease().op.is_none(), "the lock was released");
    assert!(w.service_active("node-a"));
}

#[test]
fn failed_source_release_is_verified_and_the_service_comes_back() {
    // R6 (RA-C-01): a failed alias operation alone no longer proves "not
    // applied"; the refusal that is proven (explicit 4xx, no operation,
    // alias list unchanged) is the case that is rolled back.
    let w = World::new("vip-release-fails");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("rolled back")),
        "{r:?}"
    );
    assert_restored(&w);
    assert_eq!(
        w.gce
            .changes()
            .iter()
            .filter(|(i, _)| i == "inst-b")
            .count(),
        0,
        "target never given the VIP"
    );
}

#[test]
fn failed_target_assignment_restores_the_source() {
    let w = World::new("vip-assign-fails");
    w.gce
        .script_changes("inst-b", &[ChangeBehavior::Rejected(403)]);
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("rolled back")),
        "{r:?}"
    );
    assert_restored(&w);
}

#[test]
fn failed_target_start_removes_the_target_alias_and_restores_the_source() {
    let w = World::new("vip-start-fails");
    w.remote.host("node-b").sys.fail_action("start");
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("rolled back")),
        "{r:?}"
    );
    assert_restored(&w);
}

#[test]
fn a_vip_that_never_serves_the_target_is_rolled_back() {
    let w = World::new("vip-not-serving");
    w.remote.inject_when(
        "witness",
        op::PROBE,
        None,
        0,
        31,
        Fault::FailBefore("injected".into()),
    );
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("rolled back")),
        "{r:?}"
    );
    assert_restored(&w);
}

#[test]
fn rollback_that_cannot_be_proven_stops_as_unknown_and_blocks_further_moves() {
    let w = World::new("vip-rollback-incomplete");
    w.remote.host("node-b").sys.fail_action("start");
    w.remote.host("node-b").sys.fail_action("stop");
    let r = mv(&w, "node-b");
    let Err(Failure::Unknown(m)) = &r else {
        panic!("{r:?}")
    };
    assert!(m.contains("rollback incomplete"), "{m}");
    let lease = w.lease();
    assert!(lease.op.is_some(), "the operation record must remain");
    assert_eq!(
        lease.owner.as_deref(),
        Some("node-a"),
        "ownership is not changed on a failure"
    );
    // Another move is refused until somebody reconciles.
    w.remote.host("node-b").sys.clear_failures();
    let again = mv(&w, "node-b");
    assert!(matches!(again, Err(Failure::Refused(m)) if m.contains("resolve it first")));
    w.assert_no_double_active();
}

#[test]
fn an_external_change_during_the_move_is_respected() {
    let w = World::new("vip-external-race");
    // The 3rd cloud read is the observation right before the release.
    w.gce.schedule(3, |g| {
        g.instances
            .get_mut("inst-b")
            .unwrap()
            .aliases
            .push(Alias::plain(VIP_CIDR));
    });
    let r = mv(&w, "node-b");
    let Err(Failure::Unknown(m)) = &r else {
        panic!("{r:?}")
    };
    assert!(m.contains("external"), "{m}");
    assert_eq!(
        w.gce.change_count(),
        0,
        "this command never wrote to the cloud"
    );
    assert_eq!(
        w.gce.aliases_of("inst-b"),
        [VIP_CIDR],
        "the foreign assignment is left alone"
    );
    assert!(w.lease().op.is_some());
}

#[test]
fn a_vip_that_reappears_on_the_source_after_the_release_is_not_overridden() {
    let w = World::new("vip-reappears");
    // Cloud reads of the move: 2 pre-flight, 2 before the release, 3 for the
    // release itself (pre-read + two stable reads); the 8th is the check right
    // before the target is assigned.
    w.gce.schedule(8, |g| {
        g.instances
            .get_mut("inst-a")
            .unwrap()
            .aliases
            .push(Alias::plain(VIP_CIDR));
    });
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("reappeared") && m.contains("rolled back")),
        "{r:?}"
    );
    assert_eq!(
        w.gce
            .changes()
            .iter()
            .filter(|(i, _)| i == "inst-b")
            .count(),
        0
    );
    assert_eq!(w.cloud_holders(), ["node-a"]);
    assert!(w.service_active("node-a") && !w.service_active("node-b"));
    w.assert_no_double_active();
}

#[test]
fn an_alias_removed_by_somebody_else_is_not_recreated_by_the_rollback() {
    let w = World::new("vip-externally-removed");
    // The 3rd cloud read is the observation right before the release: the VIP
    // is already gone (somebody is moving it elsewhere).
    w.gce.schedule(3, |g| {
        g.instances.get_mut("inst-a").unwrap().aliases.clear()
    });
    let r = mv(&w, "node-b");
    let Err(Failure::Unknown(m)) = &r else {
        panic!("{r:?}")
    };
    assert!(m.contains("never removed it"), "{m}");
    assert_eq!(
        w.gce.change_count(),
        0,
        "this command wrote nothing to the cloud"
    );
    assert!(w.cloud_holders().is_empty());
    assert!(w.lease().op.is_some());
}

#[test]
fn a_lost_commit_is_never_rolled_back_and_reconcile_settles_it() {
    // The commit never reached the Witness.
    let w = World::new("vip-commit-lost");
    w.remote
        .inject("witness", op::LEASE_COMMIT, Fault::DropBefore);
    let r = mv(&w, "node-b");
    let Err(Failure::Unknown(m)) = &r else {
        panic!("{r:?}")
    };
    assert!(m.contains("commit"), "{m}");
    assert_eq!(
        w.cloud_holders(),
        ["node-b"],
        "no rollback after the target is serving"
    );
    assert!(w.service_active("node-b"));
    let lease = w.lease();
    assert_eq!(lease.owner.as_deref(), Some("node-a"));
    assert_eq!(lease.op.as_ref().unwrap().phase, Phase::TargetStarted);
    let status = vip_status(&w.ctx());
    assert_eq!(status.verdict, "unresolved_operation");
    // A mutating operation is cut only when the operator names it, and only
    // after its controller has been silent for a long time (audit B-01).
    let op_id = w.lease().op.unwrap().op_id;
    assert!(
        matches!(reconcile_vip(&w.ctx(), None, false), Err(Failure::Refused(m)) if m.contains("--abandon-op"))
    );
    assert!(
        matches!(reconcile_vip(&w.ctx(), Some(&op_id), false), Err(Failure::Refused(m)) if m.contains("may still be running"))
    );
    w.clock.advance_secs(901);
    let report = reconcile_vip(&w.ctx(), Some(&op_id), false).unwrap();
    assert!(report.changed);
    assert_eq!(report.owner, "node-b");
    let lease = w.lease();
    assert_eq!((lease.owner.as_deref(), lease.epoch), (Some("node-b"), 2));
    assert!(lease.op.is_none());
    assert_eq!(vip_status(&w.ctx()).verdict, "consistent");

    // The commit was applied but its answer was lost.
    let w = World::new("vip-commit-answer-lost");
    w.remote
        .inject("witness", op::LEASE_COMMIT, Fault::DropAfter);
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Unknown(_))));
    let report = reconcile_vip(&w.ctx(), None, false).unwrap();
    assert!(!report.changed, "already consistent");
    assert_eq!(w.lease().epoch, 2);
}

#[test]
fn fenced_source_cannot_be_restored_so_a_failed_move_stops_as_unknown() {
    let w = World::new("vip-fenced-fail");
    w.remote.host("node-a").reachable.set(false);
    w.gce.set_status("inst-a", "TERMINATED");
    w.remote.host("node-b").sys.fail_action("start");
    let r = mv_fenced(&w, "node-b", "node-a");
    let Err(Failure::Unknown(m)) = &r else {
        panic!("{r:?}")
    };
    assert!(m.contains("fenced"), "{m}");
    assert!(
        w.cloud_holders().is_empty(),
        "the VIP is left unassigned, not guessed"
    );
    assert!(w.lease().op.is_some());
    w.assert_no_double_active();
}

#[test]
fn a_lost_lease_answer_leaves_the_world_unchanged() {
    let w = World::new("vip-acquire-lost");
    w.remote
        .inject("witness", op::LEASE_ACQUIRE, Fault::DropAfter);
    let r = mv(&w, "node-b");
    // R4: the lease record may exist although the answer was lost, so this is
    // not a refusal; no resource was touched and the lock expires by itself.
    assert!(
        matches!(&r, Err(Failure::Unknown(m)) if m.contains("no VIP, alias or service was touched")),
        "{r:?}"
    );
    assert_eq!(w.gce.change_count(), 0);
    assert!(w.service_active("node-a"));
    assert!(
        matches!(mv(&w, "node-b"), Err(Failure::Refused(_))),
        "the orphan lock still blocks"
    );
    w.clock.advance_secs(301);
    mv(&w, "node-b").unwrap();
}

// ----------------------------------------------------- init / reconcile

#[test]
fn init_records_only_what_the_cloud_shows() {
    let w = World::build("vip-init", false);
    assert!(matches!(
        init_vip(&w.ctx(), "node-b", false),
        Err(Failure::Refused(_))
    ));
    let report = init_vip(&w.ctx(), "node-a", false).unwrap();
    assert_eq!((report.owner.as_str(), report.epoch), ("node-a", 1));
    assert!(
        matches!(init_vip(&w.ctx(), "node-a", false), Err(Failure::Refused(m)) if m.contains("already"))
    );
}

#[test]
fn reconcile_demands_proof_for_every_part_of_the_state() {
    // Consistent already: nothing changes.
    let w = World::new("vip-reconcile-noop");
    let r = reconcile_vip(&w.ctx(), None, false).unwrap();
    assert!(!r.changed);
    // The other node runs the service without the VIP.
    w.remote
        .host("node-b")
        .sys
        .set_service("mkg-demo.service", "active");
    assert!(
        matches!(reconcile_vip(&w.ctx(), None, false), Err(Failure::Unknown(m)) if m.contains("without holding"))
    );
    w.remote
        .host("node-b")
        .sys
        .set_service("mkg-demo.service", "inactive");
    // The holder's service is down.
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "inactive");
    assert!(matches!(
        reconcile_vip(&w.ctx(), None, false),
        Err(Failure::Unknown(_))
    ));
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "active");
    // The other node is unreachable but not terminated: it may still serve.
    w.remote.host("node-b").reachable.set(false);
    assert!(
        matches!(reconcile_vip(&w.ctx(), None, false), Err(Failure::Unknown(m)) if m.contains("may still serve"))
    );
    // Terminated counts as proof.
    w.gce.set_status("inst-b", "TERMINATED");
    assert!(reconcile_vip(&w.ctx(), None, false).is_ok());
    // Several holders cannot be reconciled.
    w.gce.set_aliases_direct("inst-b", &[VIP_CIDR]);
    assert!(
        matches!(reconcile_vip(&w.ctx(), None, false), Err(Failure::Unknown(m)) if m.contains("exactly one"))
    );
}

#[test]
fn reconcile_refuses_to_cut_into_a_live_unmutated_operation() {
    let w = World::new("vip-reconcile-live");
    lease_call(
        &w.ctx(),
        op::LEASE_ACQUIRE,
        json!({"op_id": "live-operation", "source": "node-a", "target": "node-b",
               "ttl_s": 300, "controller": "x", "expect_epoch": 1}),
    )
    .unwrap();
    assert!(
        matches!(reconcile_vip(&w.ctx(), None, false), Err(Failure::Refused(m)) if m.contains("in progress"))
    );
}

// --------------------------------------------------------------- status

#[test]
fn status_verdicts_distinguish_consistent_mismatch_and_unknown() {
    let w = World::new("vip-status");
    let status = vip_status(&w.ctx());
    assert_eq!(status.verdict, "consistent", "{:?}", status.problems);
    assert_eq!(status.served_by.as_deref(), Some("node-a"));
    assert_eq!(
        status.cloud_holders.as_deref(),
        Some(&["node-a".to_string()][..])
    );
    // A cloud/record mismatch.
    w.gce.set_aliases_direct("inst-a", &[]);
    w.gce.set_aliases_direct("inst-b", &[VIP_CIDR]);
    assert_eq!(vip_status(&w.ctx()).verdict, "mismatch");
    w.gce.set_aliases_direct("inst-a", &[VIP_CIDR]);
    w.gce.set_aliases_direct("inst-b", &[]);
    // The Witness is down: unknown, never healthy.
    w.remote.host("witness").reachable.set(false);
    let status = vip_status(&w.ctx());
    assert_eq!(status.verdict, "unknown");
    assert!(status.witness_error.is_some());
    w.remote.host("witness").reachable.set(true);
    // The cloud cannot be read.
    w.gce.fail_describe("inst-b", true);
    assert_eq!(vip_status(&w.ctx()).verdict, "unknown");
    w.gce.fail_describe("inst-b", false);
    // The owner's service stopped by hand.
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "inactive");
    assert_eq!(vip_status(&w.ctx()).verdict, "unknown");
}

#[test]
fn status_never_mutates_anything() {
    let w = World::new("vip-status-readonly");
    let before = w.events.borrow().len();
    let _ = vip_status(&w.ctx());
    assert_eq!(w.events.borrow().len(), before);
    assert_eq!(w.gce.change_count(), 0);
}

#[test]
fn only_moves_through_the_lease_are_possible_so_no_double_active_appears() {
    // A longer randomised-looking sequence of moves, failures and repairs,
    // checked by the double-Active monitor after every effect.
    let w = World::new("vip-soak");
    let mut to = "node-b";
    for round in 0..6 {
        if round % 3 == 1 {
            w.remote.host(to).sys.fail_action("start");
            assert!(mv(&w, to).is_err());
            w.remote.host(to).sys.clear_failures();
            // Back at the previous owner; the same move now works.
        }
        mv(&w, to).unwrap();
        to = if to == "node-b" { "node-a" } else { "node-b" };
    }
    w.assert_no_double_active();
}

#[test]
fn nv10_an_epoch_at_the_top_of_the_range_is_refused_and_never_overflows() {
    use super::proto::{PROTO_VERSION, Request, random_hex};
    // The record starts at the largest epoch: the next one does not exist.
    let w = World::build("nv10-epoch-max", false);
    let init = super::agent::handle(
        &w.remote.host("witness").env,
        &Request {
            v: PROTO_VERSION,
            id: random_hex(8),
            op: op::LEASE_INIT.into(),
            args: json!({"owner": "node-a", "reinit": false, "seq_floor": 1, "epoch_floor": u64::MAX}),
        },
    );
    assert!(init.ok, "{init:?}");
    assert_eq!(init.data["epoch"], u64::MAX);
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Refused(m)) if m.contains("exhausted")),
        "{r:?}"
    );
    assert_eq!(w.gce.change_count(), 0, "refused before any cloud change");
    // Nothing moved, no double Active.
    assert_eq!(w.cloud_holders(), ["node-a"], "{r:?}");
    w.assert_no_double_active();
}

#[test]
fn c09_an_alias_somebody_else_removed_is_not_given_back_after_a_change_that_was_never_sent() {
    // Somebody removes the alias from the source while the move is between
    // its checks and the release, and one listing of the cloud's operations
    // fails, so the release request is never sent. The flag "source alias
    // removal attempted" now means "the request was sent" (audit C-09), so a
    // rollback cannot mistake somebody else's removal for its own. Honest
    // note: reverting the flag to its old early setting does NOT make this
    // test fail (the rollback stops earlier for another reason), so it is a
    // regression guard for the invariant "the alias is never put back on a
    // node that this command did not take it from", not a mutation-killing test
    // of the flag itself (REMEDIATION_STATUS_R3, mutation survivors).
    let mut reached_the_corner = 0;
    for skip in 0..16 {
        let w = World::new(&format!("c09-{skip}"));
        let gce = w.gce.clone();
        w.remote.inject_when(
            "witness",
            op::PING,
            None,
            skip,
            1,
            Fault::Hook(std::rc::Rc::new(move || {
                gce.set_aliases_direct("inst-a", &[]);
                gce.fail_next_list_operations();
            })),
        );
        let r = mv(&w, "node-b");
        let removed_by_somebody_else = w.gce.aliases_of("inst-a").is_empty();
        if r.is_err() && removed_by_somebody_else && w.gce.change_count() == 0 {
            reached_the_corner += 1;
        }
        assert!(
            !(r.is_err()
                && w.gce.change_count() > 0
                && w.gce.aliases_of("inst-a").iter().any(|a| a == VIP_CIDR)
                && w.gce.aliases_of("inst-b").iter().any(|a| a == VIP_CIDR)),
            "skip {skip}: the VIP must never end on both nodes"
        );
        w.gce.fail_list_operations(false);
    }
    assert!(
        reached_the_corner >= 1,
        "the scenario never reached the release"
    );
}

// ---------------------------------------------------------------- v0.5 barrier

#[test]
fn a_move_writes_a_barrier_on_both_nodes_before_the_lease_and_clears_it_after_commit() {
    let w = World::new("barrier-happy");
    mv(&w, "node-b").unwrap();
    assert_eq!(w.count_agent_calls("node-a", op::CONTROL_INTENT_BEGIN), 1);
    assert_eq!(w.count_agent_calls("node-b", op::CONTROL_INTENT_BEGIN), 1);
    assert_eq!(w.count_agent_calls("node-a", op::CONTROL_INTENT_RESOLVE), 1);
    assert_eq!(w.count_agent_calls("node-b", op::CONTROL_INTENT_RESOLVE), 1);
    // The barrier must be written before the Witness lease: a crash after
    // begin but before acquire is exactly the case the barrier exists for.
    let calls = w.remote.calls.borrow();
    let begin = calls
        .iter()
        .position(|call| call.contains("control.intent.begin"))
        .expect("begin call");
    let acquire = calls
        .iter()
        .position(|call| call.contains("lease.acquire"))
        .expect("lease acquire");
    assert!(
        begin < acquire,
        "barrier begin must precede lease acquire: {calls:?}"
    );
    for host in ["node-a", "node-b"] {
        let state = crate::manual_barrier::check(
            &w.remote.host(host).env.cfg.manual_barrier_path,
            w.remote.host(host).env.owner_uid,
            "test",
            host,
        )
        .unwrap();
        assert_eq!(state, crate::manual_barrier::BarrierState::Clear, "{host}");
    }
}

#[test]
fn a_lost_begin_answer_that_cannot_be_cleaned_up_leaves_a_blocking_barrier() {
    let w = World::new("barrier-lost-begin");
    // The target agent writes the record but its answer is lost; the cleanup
    // resolve is lost too. Nothing on the cloud/service may have changed.
    w.remote
        .inject("node-b", op::CONTROL_INTENT_BEGIN, Fault::DropAfter);
    w.remote
        .inject("node-b", op::CONTROL_INTENT_RESOLVE, Fault::DropBefore);
    let result = mv(&w, "node-b");
    assert!(
        matches!(&result, Err(Failure::Unknown(m)) if m.contains("barrier")),
        "{result:?}"
    );
    assert_eq!(w.gce.change_count(), 0);
    assert_eq!(w.cloud_holders(), ["node-a"]);
    assert!(w.service_active("node-a"));
    let state = crate::manual_barrier::check(
        &w.remote.host("node-b").env.cfg.manual_barrier_path,
        w.remote.host("node-b").env.owner_uid,
        "test",
        "node-b",
    )
    .unwrap();
    assert!(state.is_open(), "the unresolved barrier must remain");
}

#[test]
fn a_verified_reconcile_clears_an_orphaned_barrier() {
    let w = World::new("barrier-reconcile");
    // A previous controller left a barrier behind, but the cloud and the
    // ownership record are consistent (the state a reconcile accepts).
    mv(&w, "node-b").unwrap();
    let host = w.remote.host("node-b");
    let record = crate::manual_barrier::ManualOperation {
        schema: crate::manual_barrier::SCHEMA.to_string(),
        cluster: "test".to_string(),
        node: "node-b".to_string(),
        op_id: "orphan-1".to_string(),
        source: "node-a".to_string(),
        target: "node-b".to_string(),
        epoch: 1,
        controller: "crashed-controller".to_string(),
        created_at: crate::manual::testkit::TEST_NOW,
    };
    crate::manual_barrier::begin(
        &host.env.cfg.manual_barrier_path,
        host.env.owner_uid,
        &record,
    )
    .unwrap();
    let report = reconcile_vip(&w.ctx(), Some("orphan-1"), false).unwrap();
    assert!(!report.changed);
    let state = crate::manual_barrier::check(
        &host.env.cfg.manual_barrier_path,
        host.env.owner_uid,
        "test",
        "node-b",
    )
    .unwrap();
    assert_eq!(state, crate::manual_barrier::BarrierState::Clear);

    // The same orphan without the explicit operation is not cleared.
    let record = crate::manual_barrier::ManualOperation {
        schema: crate::manual_barrier::SCHEMA.to_string(),
        cluster: "test".to_string(),
        node: "node-b".to_string(),
        op_id: "orphan-2".to_string(),
        source: "node-a".to_string(),
        target: "node-b".to_string(),
        epoch: 1,
        controller: "crashed-controller".to_string(),
        created_at: crate::manual::testkit::TEST_NOW,
    };
    crate::manual_barrier::begin(
        &host.env.cfg.manual_barrier_path,
        host.env.owner_uid,
        &record,
    )
    .unwrap();
    let report = reconcile_vip(&w.ctx(), None, false).unwrap();
    assert!(!report.changed);
    let state = crate::manual_barrier::check(
        &host.env.cfg.manual_barrier_path,
        host.env.owner_uid,
        "test",
        "node-b",
    )
    .unwrap();
    assert!(
        state.is_open(),
        "reconcile without --abandon-op must not clear it"
    );
}

#[test]
fn a_refused_lease_whose_barrier_cannot_be_cleared_is_unknown_not_refused() {
    let w = World::new("barrier-refused-cleanup");
    w.remote.inject(
        "witness",
        op::LEASE_ACQUIRE,
        Fault::RefuseBefore("no lease for you".to_string()),
    );
    w.remote
        .inject("node-a", op::CONTROL_INTENT_RESOLVE, Fault::DropBefore);
    let result = mv(&w, "node-b");
    assert!(
        matches!(&result, Err(Failure::Unknown(m)) if m.contains("barrier")),
        "{result:?}"
    );
    assert_eq!(w.gce.change_count(), 0);
    assert!(w.service_active("node-a"));
    assert!(
        crate::manual_barrier::check(
            &w.remote.host("node-a").env.cfg.manual_barrier_path,
            w.remote.host("node-a").env.owner_uid,
            "test",
            "node-a",
        )
        .unwrap()
        .is_open()
    );
}
