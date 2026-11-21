//! Regression tests for the round-1 independent audit (VIP / GCE / lease).
//!
//! Every test here reproduces a defect the auditors showed against candidate
//! `5f291ff` (their originals are kept under `prototype/v0.2/audit/repro/`)
//! and asserts the corrected behaviour: no double alias, no lost VIP reported
//! as restored, a controller without the lease touches nothing, and an
//! unresolved cloud change ends as UNKNOWN with the operation record kept.
//! The world's safety monitor (`fakes.rs`) is evaluated after every effect
//! and again whenever a request lands late.

use super::fakes::{ChangeBehavior, Fault, NIC_UPDATE, VIP_CIDR, World};
use super::gce::{Alias, Gce};
use super::lease::{ABANDON_QUIET_SECS, LeaseState, Phase};
use super::proto::{self, PROTO_VERSION, Request, op};
use super::vip::*;
use super::{Failure, Res};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::rc::Rc;

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

fn unknown(r: &Res<MoveReport>) -> String {
    match r {
        Err(Failure::Unknown(m)) => m.clone(),
        other => panic!("expected UNKNOWN, got {other:?}"),
    }
}

fn started(w: &World, node: &str) -> bool {
    w.remote
        .host(node)
        .sys
        .actions()
        .iter()
        .any(|a| a.starts_with("start "))
}

fn changes_of(w: &World, instance: &str) -> usize {
    w.gce
        .changes()
        .iter()
        .filter(|(i, _)| i == instance)
        .count()
}

/// The command ended without claiming a restored or completed world: the
/// operation record is kept, the monitor saw nothing wrong.
fn assert_locked_and_quiet(w: &World, r: &Res<MoveReport>) {
    let message = unknown(r);
    assert!(
        !message.contains("rolled back and verified") && !message.contains("owns the VIP again"),
        "an unresolved state must not be reported as restored: {message}"
    );
    assert!(w.lease().op.is_some(), "the operation record must remain");
    w.assert_no_double_active();
}

fn assert_restored(w: &World) {
    assert_eq!(w.cloud_holders(), ["node-a"]);
    assert!(w.service_active("node-a") && !w.service_active("node-b"));
    let lease = w.lease();
    assert_eq!((lease.owner.as_deref(), lease.epoch), (Some("node-a"), 1));
    assert!(lease.op.is_none());
    w.assert_settled();
}

fn agent(w: &'static World, operation: &str, args: Value) -> proto::Response {
    super::agent::handle(
        &w.remote.host("witness").env,
        &Request {
            v: PROTO_VERSION,
            id: proto::random_hex(8),
            op: operation.to_string(),
            args,
        },
    )
}

// ===================================================================== C-01

#[test]
fn c01_v1_a_pending_detach_is_unknown_and_nothing_is_restarted() {
    let w = World::new("r1-c01-v1");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let r = mv(&w, "node-b");
    let message = unknown(&r);
    assert!(message.contains("unresolved cloud change"), "{message}");
    assert_locked_and_quiet(&w, &r);
    // No rollback: the source service is neither restarted nor given the VIP
    // back while the detach may still land.
    assert!(
        !started(&w, "node-a"),
        "{:?}",
        w.remote.host("node-a").sys.actions()
    );
    assert_eq!(
        changes_of(&w, "inst-a"),
        1,
        "no second change to the source"
    );
    assert_eq!(changes_of(&w, "inst-b"), 0);
    assert!(!w.service_active("node-a") && !w.service_active("node-b"));
    // The pending change is stored in the lease record for status/reconcile.
    let op = w.lease().op.unwrap();
    assert_eq!(op.evidence["cloud_changes"][0]["action"], "detach");
    assert_eq!(vip_status(&w.ctx()).verdict, "unresolved_operation");
    assert!(
        vip_status(&w.ctx())
            .problems
            .iter()
            .any(|p| p.contains("still open")),
        "status shows the open cloud operation"
    );
    // The late landing removes the alias: the record still says node-a, but
    // the lock is held, so this is a visible, recoverable state.
    w.gce.land_all();
    w.check_now("late landing");
    w.assert_no_double_active();
    assert!(w.cloud_holders().is_empty());
}

#[test]
fn c01_v1_recovery_needs_the_landing_the_operator_and_the_silence() {
    let w = World::new("r1-c01-v1-recover");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let r = mv(&w, "node-b");
    assert_locked_and_quiet(&w, &r);
    let op_id = w.lease().op.unwrap().op_id;
    // The operator puts the source back by hand.
    w.gce.set_aliases_direct("inst-a", &[VIP_CIDR]);
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "active");
    w.clock.advance_secs(ABANDON_QUIET_SECS + 1);
    // While the cloud operation is still open nothing is reconciled.
    let r = reconcile_vip(&w.ctx(), Some(&op_id), false);
    assert!(
        matches!(&r, Err(Failure::Unknown(m)) if m.contains("still PENDING")),
        "{r:?}"
    );
    assert!(w.lease().op.is_some());
    // Once it has landed (and the alias is as the operator wants it) it works.
    w.gce.land_all();
    w.gce.set_aliases_direct("inst-a", &[VIP_CIDR]);
    let report = reconcile_vip(&w.ctx(), Some(&op_id), false).unwrap();
    assert!(report.changed && report.owner == "node-a");
    let cloud = &report.evidence["cloud_operations"];
    assert_eq!(cloud["confirmed_cloud_changes"][0]["action"], "detach");
    w.assert_settled();
}

#[test]
fn c01_v1_invisible_a_request_without_any_operation_is_unknown_too() {
    // The tool timed out and the cloud shows no operation (yet): the request
    // may not have been sent, or may still arrive. Silence is not proof.
    for behavior in [
        ChangeBehavior::TimeoutInvisible,
        ChangeBehavior::TimeoutNoApply,
        ChangeBehavior::ErrorNoOperation,
    ] {
        let w = World::new("r1-c01-v1-invisible");
        w.gce.script_changes("inst-a", &[behavior]);
        let r = mv(&w, "node-b");
        let message = unknown(&r);
        assert!(message.contains("no operation"), "{behavior:?}: {message}");
        assert_locked_and_quiet(&w, &r);
        assert!(!started(&w, "node-a"), "{behavior:?}");
        assert_eq!(changes_of(&w, "inst-a"), 1, "{behavior:?}");
        w.gce.land_all();
        w.check_now("late landing");
        w.assert_no_double_active();
    }
}

#[test]
fn c01_v2_a_pending_attach_never_triggers_a_re_add_to_the_source() {
    for behavior in [
        ChangeBehavior::TimeoutPending,
        ChangeBehavior::TimeoutInvisible,
    ] {
        let w = World::new("r1-c01-v2");
        w.gce.script_changes("inst-b", &[behavior]);
        let r = mv(&w, "node-b");
        assert_locked_and_quiet(&w, &r);
        assert_eq!(
            changes_of(&w, "inst-a"),
            1,
            "only the release, never a re-add"
        );
        assert_eq!(changes_of(&w, "inst-b"), 1);
        assert!(!w.service_active("node-a") && !w.service_active("node-b"));
        assert!(!started(&w, "node-a") && !started(&w, "node-b"));
        // The assign lands late: the VIP is on the target only, never on both.
        w.gce.land_all();
        w.check_now("late landing");
        w.assert_no_double_active();
        assert_eq!(w.cloud_holders(), ["node-b"], "{behavior:?}");
        assert_eq!(w.lease().owner.as_deref(), Some("node-a"));
        assert!(w.lease().op.is_some());
    }
}

#[test]
fn c01_v3b_a_stale_read_of_the_target_never_re_adds_to_the_source() {
    let w = World::new("r1-c01-v3b");
    let g = w.gce.clone();
    // The assignment to the target is applied, but reads stay stale for far
    // longer than the controller waits.
    w.remote.inject(
        "node-b",
        op::SERVICE_STATUS,
        Fault::Hook(Rc::new(move || g.set_lag(200))),
    );
    let r = mv(&w, "node-b");
    let message = unknown(&r);
    assert!(message.contains("not known to have finished"), "{message}");
    assert_locked_and_quiet(&w, &r);
    assert_eq!(
        changes_of(&w, "inst-a"),
        1,
        "the source was not given the VIP back"
    );
    w.gce.inner.borrow_mut().stale.clear();
    w.check_now("convergence");
    w.assert_no_double_active();
    assert_eq!(
        w.cloud_holders(),
        ["node-b"],
        "exactly one NIC holds the VIP"
    );
}

#[test]
fn c01_v4_a_pending_re_add_during_rollback_is_unknown_and_keeps_the_record() {
    let w = World::new("r1-c01-v4");
    w.remote.host("node-b").sys.fail_action("start");
    w.gce.script_changes(
        "inst-a",
        &[ChangeBehavior::Normal, ChangeBehavior::TimeoutPending],
    );
    let r = mv(&w, "node-b");
    assert_locked_and_quiet(&w, &r);
    assert!(
        !started(&w, "node-a"),
        "the source is not started while the add is open"
    );
    assert!(w.lease().op.unwrap().evidence["cloud_changes"][0]["action"] == "attach");
    w.gce.land_all();
    w.check_now("late landing");
    w.assert_no_double_active();
    assert_eq!(w.cloud_holders(), ["node-a"]);
}

#[test]
fn c01_a_change_finished_late_but_within_the_wait_is_accepted() {
    // The cloud operation is pending when the tool gives up and finishes while
    // the controller follows it: resolved by observation, not by the clock.
    let w = World::new("r1-c01-late-ok");
    w.gce
        .script_changes("inst-b", &[ChangeBehavior::PendingLandsAfterLists(3)]);
    let r = mv(&w, "node-b");
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(w.cloud_holders(), ["node-b"]);
    w.assert_settled();
}

#[test]
fn c01_an_operation_that_finished_with_an_error_is_unknown_not_a_clean_failure() {
    // Round R6 (RA-C-01) replaced the earlier rule "the only new alias
    // operation failed, so the request was not applied": operations cannot be
    // attributed to a request, so the request may still land. No rollback.
    let w = World::new("r1-c01-op-error");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::ErrorNoApply]);
    let r = mv(&w, "node-b");
    let message = unknown(&r);
    assert!(message.contains("cannot be attributed"), "{message}");
    assert_locked_and_quiet(&w, &r);
    assert!(!started(&w, "node-a"));
    assert_eq!(changes_of(&w, "inst-a"), 1, "no rollback change");
    // The same for a failed assignment.
    let w = World::new("r1-c01-op-error-assign");
    w.gce
        .script_changes("inst-b", &[ChangeBehavior::ErrorNoApply]);
    let r = mv(&w, "node-b");
    let message = unknown(&r);
    assert!(message.contains("cannot be attributed"), "{message}");
    assert_locked_and_quiet(&w, &r);
    assert_eq!(changes_of(&w, "inst-b"), 1, "no removal, no give-back");
    assert_eq!(changes_of(&w, "inst-a"), 1);
}

#[test]
fn c01_a_target_alias_that_vanished_is_not_given_back_to_the_source_blindly() {
    // The assignment was applied; before the rollback looks, the alias is gone
    // again (an external change or a stale read). "Nobody has it" is not
    // proof that the target never got it.
    let w: &'static World = Box::leak(Box::new(World::new("r1-c01-vanished")));
    w.remote.host("node-b").sys.fail_action("start");
    let g = w.gce.clone();
    w.remote.inject(
        "node-b",
        op::SERVICE_CONTROL,
        Fault::Hook(Rc::new(move || g.set_aliases_direct("inst-b", &[]))),
    );
    let r = mv(w, "node-b");
    let message = unknown(&r);
    assert!(message.contains("not giving the VIP back"), "{message}");
    assert_eq!(
        changes_of(w, "inst-a"),
        1,
        "the source did not get the VIP back"
    );
    assert!(w.lease().op.is_some());
    assert!(!started(w, "node-a"));
    w.assert_no_double_active();
}

#[test]
fn c01_earlier_operations_do_not_resolve_a_new_request() {
    // A finished alias operation from the past must not be mistaken for the
    // outcome of the request that was just made.
    let w = World::new("r1-c01-history");
    w.gce.seed_op("inst-a", NIC_UPDATE, "DONE", false);
    w.gce.seed_op("inst-a", NIC_UPDATE, "DONE", true);
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutNoApply]);
    let r = mv(&w, "node-b");
    assert!(unknown(&r).contains("no operation"), "{r:?}");
    assert_locked_and_quiet(&w, &r);
    assert!(!started(&w, "node-a"));
}

#[test]
fn c01_an_operation_that_is_open_before_the_request_blocks_it() {
    let w = World::new("r1-c01-open-before");
    w.gce.seed_op("inst-a", NIC_UPDATE, "RUNNING", false);
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("no change was sent")),
        "{r:?}"
    );
    assert_eq!(w.gce.change_count(), 0);
    assert_restored(&w);
    // The operation list that cannot be read blocks the request, too.
    let w = World::new("r1-c01-list-fails");
    w.gce.fail_list_operations(true);
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("cannot list")),
        "{r:?}"
    );
    assert_eq!(w.gce.change_count(), 0);
    assert_restored(&w);
}

#[test]
fn c01_an_unreadable_operation_list_after_the_request_is_unknown() {
    let w = World::new("r1-c01-list-after");
    // The listing before the request works; the one after it fails.
    w.gce.after_next_change(|g| g.fail_list = true);
    let r = mv(&w, "node-b");
    let message = unknown(&r);
    assert!(message.contains("cannot list operations"), "{message}");
    assert_locked_and_quiet(&w, &r);
    assert!(
        !started(&w, "node-a"),
        "no rollback while the change is unresolved"
    );
    assert_eq!(changes_of(&w, "inst-a"), 1);
}

// ===================================================================== C-02

fn flip_source_to_running(w: &'static World) -> Rc<dyn Fn()> {
    Rc::new(move || {
        w.gce.set_status("inst-a", "RUNNING");
        w.remote
            .host("node-a")
            .sys
            .set_service("mkg-demo.service", "active");
    })
}

fn fenced_world(label: &str) -> &'static World {
    let w: &'static World = Box::leak(Box::new(World::new(label)));
    w.remote.host("node-a").reachable.set(false);
    w.gce.set_status("inst-a", "TERMINATED");
    w
}

#[test]
fn c02_a_source_that_starts_after_the_proof_stops_the_move_before_the_release() {
    let w = fenced_world("r1-c02-release");
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("source_released"),
        0,
        1,
        Fault::Hook(flip_source_to_running(w)),
    );
    let r = mv_fenced(w, "node-b", "node-a");
    let message = unknown(&r);
    assert!(message.contains("fencing evidence"), "{message}");
    assert_eq!(w.gce.change_count(), 0, "no cloud change on a stale proof");
    assert!(w.lease().op.is_some());
    assert!(!started(w, "node-b"));
    w.assert_no_double_active();
}

#[test]
fn c02_a_source_that_starts_before_the_assignment_stops_the_move() {
    let w = fenced_world("r1-c02-assign");
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("target_assigning"),
        0,
        1,
        Fault::Hook(flip_source_to_running(w)),
    );
    let r = mv_fenced(w, "node-b", "node-a");
    assert!(unknown(&r).contains("fencing evidence"));
    assert_eq!(
        changes_of(w, "inst-b"),
        0,
        "the target never received the VIP"
    );
    assert!(!started(w, "node-b"));
    assert!(w.lease().op.is_some());
    w.assert_no_double_active();
}

#[test]
fn c02_a_source_that_starts_before_the_commit_is_unknown_and_nothing_is_undone() {
    let w = fenced_world("r1-c02-commit");
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("target_started"),
        0,
        1,
        Fault::Hook(flip_source_to_running(w)),
    );
    let r = mv_fenced(w, "node-b", "node-a");
    assert!(unknown(&r).contains("before_commit"));
    // No rollback: the VIP stays where it is and the record stays.
    assert_eq!(w.cloud_holders(), ["node-b"]);
    assert_eq!(changes_of(w, "inst-b"), 1);
    let lease = w.lease();
    assert_eq!(lease.owner.as_deref(), Some("node-a"));
    assert_eq!(lease.op.unwrap().phase, Phase::TargetStarted);
    w.assert_no_double_active();
}

#[test]
fn c02_a_replaced_instance_is_not_the_one_that_was_fenced() {
    let w = fenced_world("r1-c02-id");
    let g = w.gce.clone();
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("target_assigning"),
        0,
        1,
        Fault::Hook(Rc::new(move || {
            g.inner.borrow_mut().instances.get_mut("inst-a").unwrap().id = "id-other".into();
        })),
    );
    let r = mv_fenced(w, "node-b", "node-a");
    assert!(unknown(&r).contains("instance id or stop time changed"));
}

#[test]
fn c02_every_recheck_is_recorded_as_evidence() {
    let w = fenced_world("r1-c02-evidence");
    let report = mv_fenced(w, "node-b", "node-a").unwrap();
    let checks = report.evidence["fence_rechecks"].as_array().unwrap();
    let points: Vec<&str> = checks
        .iter()
        .map(|c| c["point"].as_str().unwrap())
        .collect();
    assert_eq!(points, ["before_release", "before_assign", "before_commit"]);
    for c in checks {
        assert_eq!(c["status"], "TERMINATED");
        assert!(c["at"].as_u64().unwrap() > 0);
        assert_eq!(c["instance_id"], "id-inst-a");
    }
    let history = w.lease().history;
    assert_eq!(
        history.last().unwrap().evidence["fence_rechecks"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

// ===================================================================== C-04

#[test]
fn c04_a_verified_rollback_does_not_turn_unknown_into_failed() {
    assert!(matches!(
        restored_failure(Failure::Unknown("cause".into()), "node-a"),
        Failure::Unknown(m) if m.contains("stays UNKNOWN") && m.contains("rolled back and verified")
    ));
    assert!(matches!(
        restored_failure(Failure::Failed("cause".into()), "node-a"),
        Failure::Failed(m) if m.contains("rolled back and verified")
    ));
    assert!(matches!(
        restored_failure(Failure::Refused("cause".into()), "node-a"),
        Failure::Failed(_)
    ));
}

// ===================================================================== C-06

#[test]
fn c06_a_source_service_that_was_down_is_not_started_by_the_rollback() {
    let w = World::new("r1-c06");
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "inactive");
    w.remote.host("node-b").sys.fail_action("start");
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("rolled back")),
        "{r:?}"
    );
    assert!(
        !started(&w, "node-a"),
        "{:?}",
        w.remote.host("node-a").sys.actions()
    );
    assert!(!w.service_active("node-a"));
    assert_eq!(w.cloud_holders(), ["node-a"]);
    assert!(w.lease().op.is_none());
    w.assert_settled();
}

// ===================================================================== C-07

#[test]
fn c07_a_target_that_dies_before_the_last_look_is_rolled_back() {
    let w: &'static World = Box::leak(Box::new(World::new("r1-c07")));
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("target_started"),
        0,
        1,
        Fault::Hook(Rc::new(move || {
            w.remote
                .host("node-b")
                .sys
                .set_service("mkg-demo.service", "inactive");
        })),
    );
    let r = mv(w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("just before the commit") && m.contains("rolled back")),
        "{r:?}"
    );
    assert_restored(w);
}

#[test]
fn c07_the_remaining_window_is_named_in_the_report() {
    // A failure after the last look cannot be seen; the report says so and the
    // status verdict shows it.
    let w: &'static World = Box::leak(Box::new(World::new("r1-c07-window")));
    w.remote.inject(
        "witness",
        op::LEASE_COMMIT,
        Fault::Hook(Rc::new(move || {
            w.remote
                .host("node-b")
                .sys
                .set_service("mkg-demo.service", "inactive");
        })),
    );
    let report = mv(w, "node-b").unwrap();
    assert!(
        report.advice.contains("resource status vip"),
        "{}",
        report.advice
    );
    assert_eq!(vip_status(&w.ctx()).verdict, "unknown");
}

// ===================================================================== C-08

#[test]
fn c08_a_unit_that_is_still_changing_state_is_not_stopped() {
    let w: &'static World = Box::leak(Box::new(World::new("r1-c08-activating")));
    // Skip the pre-flight read; the next read is the check after the stop.
    w.remote.inject_when(
        "node-a",
        op::SERVICE_STATUS,
        None,
        1,
        1,
        Fault::Hook(Rc::new(move || {
            w.remote
                .host("node-a")
                .sys
                .set_service("mkg-demo.service", "activating");
        })),
    );
    let r = mv(w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("still activating")),
        "{r:?}"
    );
    assert_restored(w);
}

#[test]
fn c08_a_probe_that_cannot_be_performed_is_retried_and_never_a_silent_pass() {
    // One lost probe call is retried.
    let w = World::new("r1-c08-probe-once");
    w.remote
        .inject_when("node-a", op::PROBE, None, 0, 1, Fault::DropBefore);
    assert!(mv(&w, "node-b").is_ok());
    // A probe that never works fails the step (and is rolled back).
    let w = World::new("r1-c08-probe-always");
    w.remote
        .inject_when("node-a", op::PROBE, None, 0, 3, Fault::DropBefore);
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("cannot confirm that nothing answers")),
        "{r:?}"
    );
    assert_restored(&w);
}

// ===================================================================== B-01

#[test]
fn b01_a_reconcile_cannot_cut_into_a_live_mutating_move() {
    let w: &'static World = Box::leak(Box::new(World::new("r1-b01")));
    let seen: Rc<RefCell<Vec<String>>> = Rc::default();
    let log = seen.clone();
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("target_started"),
        0,
        1,
        Fault::Hook(Rc::new(move || {
            let op_id = w.lease().op.unwrap().op_id;
            for abandon in [None, Some(op_id.as_str())] {
                let r = reconcile_vip(&w.ctx(), abandon, false);
                log.borrow_mut().push(format!("{r:?}"));
            }
        })),
    );
    let report = mv(w, "node-b").unwrap();
    assert_eq!(report.epoch_after, 2);
    let seen = seen.borrow();
    assert_eq!(seen.len(), 2);
    for r in seen.iter() {
        assert!(r.contains("Refused"), "a live operation was cut: {r}");
    }
    let l = w.lease();
    assert_eq!(l.owner.as_deref(), Some("node-b"));
    assert_eq!(w.cloud_holders(), ["node-b"], "record and reality agree");
    w.assert_settled();
}

// ===================================================================== B-02

#[test]
fn b02_a_controller_that_lost_the_lock_touches_nothing_when_it_resumes() {
    let w: &'static World = Box::leak(Box::new(World::new("r1-b02")));
    let ms = w.clock.handle();
    let hook = Rc::new(move || {
        // Controller 1 slept past the TTL; controller 2 took the lock over,
        // recorded the quiesce and stopped the source service.
        ms.set(ms.get() + 301_000);
        let r = agent(
            w,
            op::LEASE_ACQUIRE,
            json!({"op_id":"move-ctl2op","source":"node-a","target":"node-b",
                   "ttl_s":300,"controller":"c2","expect_epoch":1}),
        );
        assert!(r.ok, "{r:?}");
        let r = agent(
            w,
            op::LEASE_PHASE,
            json!({"op_id":"move-ctl2op","phase":"source_quiescing"}),
        );
        assert!(r.ok, "{r:?}");
        w.remote
            .host("node-a")
            .sys
            .set_service("mkg-demo.service", "inactive");
    });
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("source_quiescing"),
        0,
        1,
        Fault::Hook(hook),
    );
    let r = mv(w, "node-b");
    // R4: this controller recorded nothing and touched nothing before the
    // Witness refused its first phase: a refusal (exit 3), not UNKNOWN. The
    // other holder's operation is its own business.
    let message = match &r {
        Err(Failure::Refused(m)) => m.clone(),
        other => panic!("expected REFUSED, got {other:?}"),
    };
    assert!(message.contains("no longer holds the lease"), "{message}");
    assert!(
        !w.service_active("node-a"),
        "the new holder's quiesce was undone"
    );
    assert!(w.remote.host("node-a").sys.actions().is_empty());
    assert!(w.remote.host("node-b").sys.actions().is_empty());
    assert_eq!(w.gce.change_count(), 0);
    // It stopped at the refusal; it did not even re-read the lease to decide
    // about an undo (only the pre-flight read was made).
    assert_eq!(w.remote.count("witness", op::LEASE_STATUS), 1);
    let op = w.lease().op.unwrap();
    assert_eq!(
        (op.op_id.as_str(), op.phase),
        ("move-ctl2op", Phase::SourceQuiescing)
    );
    w.assert_no_double_active();
}

/// Replace the recorded operation by another one (a takeover that happened
/// while this controller was busy).
fn take_over_lease(w: &World, new_op: &str) {
    let path = w
        .remote
        .host("witness")
        .dir
        .join("lease")
        .join("lease.json");
    let mut state: LeaseState = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let op = state.op.as_mut().expect("an operation is recorded");
    op.op_id = new_op.to_string();
    op.seq += 1;
    state.seq += 1;
    state.checksum = state.compute_checksum();
    std::fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
}

#[test]
fn b02_a_rollback_stops_when_the_lease_is_gone() {
    let w: &'static World = Box::leak(Box::new(World::new("r1-b02-rollback")));
    w.remote.host("node-b").sys.fail_action("start");
    // The 1st lease read is the pre-flight; the 2nd is the rollback's check.
    w.remote.inject_when(
        "witness",
        op::LEASE_STATUS,
        None,
        1,
        1,
        Fault::Hook(Rc::new(move || take_over_lease(w, "move-ctl2op"))),
    );
    let r = mv(w, "node-b");
    let message = unknown(&r);
    assert!(message.contains("no longer holds the lease"), "{message}");
    // The rollback did not remove the target alias, stop services or restore
    // the source: the new holder owns that decision.
    assert_eq!(w.cloud_holders(), ["node-b"]);
    assert_eq!(changes_of(w, "inst-b"), 1);
    assert!(!started(w, "node-a"));
    assert_eq!(w.lease().op.unwrap().op_id, "move-ctl2op");
    w.assert_no_double_active();
}

// ===================================================================== B-04

#[test]
fn b04_a_record_restored_from_an_old_copy_is_detected_and_repaired_by_reconcile() {
    let w = World::new("r1-b04");
    let path = w
        .remote
        .host("witness")
        .dir
        .join("lease")
        .join("lease.json");
    let snapshot = std::fs::read(&path).unwrap();
    // A move that fails and is rolled back still advances the fencing mark
    // the nodes keep.
    w.remote.host("node-b").sys.fail_action("start");
    assert!(mv(&w, "node-b").is_err());
    w.remote.host("node-b").sys.clear_failures();
    assert_restored(&w);
    // The Witness disk is restored from the old copy: owner, epoch and cloud
    // all still agree, so nothing in the file itself looks wrong.
    std::fs::write(&path, &snapshot).unwrap();
    assert_eq!(w.lease().seq, 1);
    let changes_before = w.gce.change_count();
    let r = mv(&w, "node-b");
    let message = unknown(&r);
    assert!(message.contains("OLDER"), "{message}");
    assert_eq!(w.gce.change_count(), changes_before, "nothing was changed");
    assert!(
        !vip_status(&w.ctx()).problems.is_empty(),
        "status reports it too"
    );
    assert_ne!(vip_status(&w.ctx()).verdict, "consistent");
    // The operator repairs it with a reconcile: the record jumps above what
    // the nodes have seen and moves work again.
    let report = reconcile_vip(&w.ctx(), None, false).unwrap();
    assert!(report.changed);
    assert!(w.lease().seq > 2);
    assert_eq!(vip_status(&w.ctx()).verdict, "consistent");
    mv(&w, "node-b").unwrap();
    w.assert_settled();
}

#[test]
fn b04_a_node_refuses_the_token_of_a_controller_that_was_replaced() {
    // The node-side half of the fencing: after a newer operation has acted on
    // a node, the older operation's calls are refused there.
    let w = World::new("r1-b04-node");
    mv(&w, "node-b").unwrap();
    let ctx = w.ctx();
    let node_a = ctx.node_target("node-a").unwrap();
    let hw = w
        .remote
        .host("node-a")
        .env
        .fence_store()
        .current()
        .unwrap()
        .unwrap();
    let stale = json!({"unit": "mkg-demo.service", "action": "start",
        "fence": {"epoch": hw.epoch, "seq": hw.seq - 1, "op_id": "move-stale0000"}});
    let r = ctx.call(&node_a, op::SERVICE_CONTROL, stale, super::remote::LONG);
    assert!(
        matches!(&r, Err(super::remote::CallError::Refused(m)) if m.contains("stale fencing token")),
        "{r:?}"
    );
    assert!(
        !w.service_active("node-a"),
        "the stale start was not executed"
    );
    // The current token still works.
    let current = json!({"unit": "mkg-demo.service", "action": "stop",
        "fence": {"epoch": hw.epoch, "seq": hw.seq, "op_id": hw.op_id}});
    assert!(
        ctx.call(&node_a, op::SERVICE_CONTROL, current, super::remote::LONG)
            .is_ok()
    );
}

// ===================================================================== B-05

#[test]
fn b05_init_needs_the_same_evidence_as_a_reconcile() {
    let w = World::build("r1-b05-init", false);
    // The owner's service is down.
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "inactive");
    assert!(
        matches!(init_vip(&w.ctx(), "node-a", false), Err(Failure::Refused(m)) if m.contains("not recording"))
    );
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "active");
    // The other node runs the service too.
    w.remote
        .host("node-b")
        .sys
        .set_service("mkg-demo.service", "active");
    assert!(
        matches!(init_vip(&w.ctx(), "node-a", false), Err(Failure::Refused(m)) if m.contains("without holding"))
    );
    w.remote
        .host("node-b")
        .sys
        .set_service("mkg-demo.service", "inactive");
    // Nothing answers on the VIP.
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "active");
    w.remote.host("witness").sys.fail_probe(true);
    assert!(init_vip(&w.ctx(), "node-a", false).is_err());
    w.remote.host("witness").sys.clear_failures();
    assert!(w.lease().owner.is_none(), "nothing was recorded");
    init_vip(&w.ctx(), "node-a", false).unwrap();
}

#[test]
fn b05_a_lost_state_file_is_reinitialised_only_explicitly_and_above_the_marks() {
    let w = World::new("r1-b05-reinit");
    mv(&w, "node-b").unwrap();
    mv(&w, "node-a").unwrap();
    let path = w
        .remote
        .host("witness")
        .dir
        .join("lease")
        .join("lease.json");
    std::fs::remove_file(&path).unwrap();
    // Everything fails closed.
    assert!(matches!(mv(&w, "node-b"), Err(Failure::Refused(_))));
    assert!(init_vip(&w.ctx(), "node-a", false).is_err());
    let report = init_vip(&w.ctx(), "node-a", true).unwrap();
    // The record starts above what the nodes have already served.
    let hw = w
        .remote
        .host("node-a")
        .env
        .fence_store()
        .current()
        .unwrap()
        .unwrap();
    assert!(
        report.seq > hw.seq && report.epoch > hw.epoch,
        "{report:?} vs {hw:?}"
    );
    assert_eq!(w.lease().history.last().unwrap().kind, "reinit");
    mv(&w, "node-b").unwrap();
    w.assert_settled();
}

// ============================================================== C-03 / C-05

#[test]
fn c03_other_alias_ranges_changed_by_someone_else_during_the_change_are_unknown() {
    let w = World::new("r1-c03");
    w.gce
        .set_aliases_direct("inst-a", &["10.9.9.0/24", VIP_CIDR]);
    w.gce.after_next_change(|g| {
        g.instances
            .get_mut("inst-a")
            .unwrap()
            .aliases
            .push(Alias::plain("10.8.8.0/24"));
    });
    let r = mv(&w, "node-b");
    let message = unknown(&r);
    assert!(message.contains("other alias ranges differ"), "{message}");
    assert!(w.lease().op.is_some());
    // The foreign range is left alone.
    assert!(
        w.gce
            .aliases_of("inst-a")
            .contains(&"10.8.8.0/24".to_string())
    );
    w.assert_no_double_active();
}

// ============================================================ the monitor

#[test]
fn the_monitor_flags_a_late_landing_on_an_unlocked_lease() {
    let w = World::new("r1-monitor-late");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    // A change issued outside any operation (the lease is unlocked), then lost.
    w.gce.set_aliases("inst-a", &[], "move-ghost1");
    assert!(
        w.violations
            .borrow()
            .iter()
            .any(|v| v.contains("does not hold the lease"))
    );
    w.violations.borrow_mut().clear();
    w.gce.land_all();
    let seen = w.violations.borrow().join(" | ");
    assert!(seen.contains("VIP lost"), "{seen}");
    assert!(seen.contains("cloud holders"), "{seen}");
}

#[test]
fn the_monitor_flags_the_alias_on_two_nics_and_a_service_on_a_non_holder() {
    let w = World::new("r1-monitor-two");
    w.gce.set_aliases("inst-b", &[Alias::plain(VIP_CIDR)], "");
    assert!(
        w.violations
            .borrow()
            .iter()
            .any(|v| v.contains("several NICs")),
        "{:?}",
        w.violations.borrow()
    );
    let w = World::new("r1-monitor-nonholder");
    w.remote
        .host("node-b")
        .sys
        .set_service("mkg-demo.service", "active");
    w.check_now("late landing");
    assert!(
        w.violations
            .borrow()
            .iter()
            .any(|v| v.contains("node-b runs the service without being the owner")),
        "{:?}",
        w.violations.borrow()
    );
}

#[test]
fn the_monitor_flags_a_lock_released_while_a_cloud_request_is_pending() {
    let w = World::new("r1-monitor-released");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    w.gce.set_aliases("inst-a", &[], "");
    w.violations.borrow_mut().clear();
    // An operation is acquired and aborted by hand through the agent.
    let acquire = json!({"op_id":"move-manual00","source":"node-a","target":"node-b",
        "ttl_s":300,"controller":"x","expect_epoch":1});
    let c = w.ctx();
    lease_call(&c, op::LEASE_ACQUIRE, acquire).unwrap();
    lease_call(
        &c,
        op::LEASE_ABORT,
        json!({"op_id":"move-manual00","restored_owner":"node-a","reason":"x"}),
    )
    .unwrap();
    let seen = w.violations.borrow().join(" | ");
    assert!(seen.contains("still pending"), "{seen}");
}

#[test]
fn b04_a_mark_on_the_target_alone_stops_the_move() {
    use super::fence::Token;
    let w = World::new("r1-b04-target-only");
    w.remote
        .host("node-b")
        .env
        .fence_store()
        .admit(
            &crate::manual::exclusion::ExclusiveProof::for_test(),
            &Token {
                epoch: 9,
                seq: 90,
                op_id: "move-newer000".into(),
            },
        )
        .unwrap();
    let r = mv(&w, "node-b");
    assert!(unknown(&r).contains("OLDER"), "{r:?}");
    assert_eq!(w.gce.change_count(), 0);
    assert!(w.lease().op.is_none(), "nothing was acquired");
}

#[test]
fn c08_a_stale_target_service_that_does_not_stop_is_a_failure() {
    let w = World::new("r1-c08-stale-target");
    w.remote
        .host("node-b")
        .sys
        .set_service("mkg-demo.service", "active");
    w.remote
        .host("node-b")
        .sys
        .stop_leaves("mkg-demo.service", "deactivating");
    let r = mv(&w, "node-b");
    let message = match &r {
        Err(f) => f.message().to_string(),
        Ok(_) => panic!("the move must not complete"),
    };
    assert!(message.contains("still deactivating"), "{message}");
    assert!(!matches!(r, Err(Failure::Refused(_))));
    assert_eq!(
        changes_of(&w, "inst-b"),
        0,
        "the VIP never reached the target"
    );
}
