//! R4: REFUSED, FAILED and UNKNOWN (Owner decision A).
//!
//! The question behind the three kinds is "was a request that could change a
//! resource sent, and is the outcome known?" (`Failure`, `CLI_REFERENCE.md`).
//! This file holds
//!
//! * the boundary tests of the one place where a request the cloud rejected
//!   may be treated as *not applied* (`gce::classify_update_failure` +
//!   `vip::settle`): explicit 4xx, 4xx-looking but an operation is visible,
//!   5xx, timeout, killed, unknown output, listing failure, an external
//!   change or a foreign operation while the absence of an operation is being
//!   confirmed, a late landing at the edge of the confirmation window;
//! * the consistency of the other refusal paths (agent, lease, exclusion,
//!   chrony, configuration) with the same definition.
//!
//! The late-landing risk (C-01) must not come back: every doubt is UNKNOWN.

use super::clock::Clock;
use super::fakes::{ChangeBehavior, Fault, VIP_CIDR, World};
use super::proto::op;
use super::vip::*;
use super::{Failure, Res};
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

fn changes_of(w: &World, instance: &str) -> usize {
    w.gce
        .changes()
        .iter()
        .filter(|(i, _)| i == instance)
        .count()
}

fn restored(w: &World) {
    assert_eq!(w.cloud_holders(), ["node-a"]);
    assert!(w.service_active("node-a") && !w.service_active("node-b"));
    let lease = w.lease();
    assert_eq!((lease.owner.as_deref(), lease.epoch), (Some("node-a"), 1));
    assert!(lease.op.is_none(), "the lock must be released");
    w.assert_settled();
}

fn unknown_message(r: &Res<MoveReport>) -> String {
    match r {
        Err(Failure::Unknown(m)) => m.clone(),
        other => panic!("expected UNKNOWN, got {other:?}"),
    }
}

/// UNKNOWN, the operation record is kept, no rollback was attempted, and the
/// monitor saw nothing wrong.
fn assert_unknown_and_locked(w: &World, r: &Res<MoveReport>) -> String {
    let message = unknown_message(r);
    assert!(
        !message.contains("rolled back and verified"),
        "an unresolved state must not be reported as restored: {message}"
    );
    assert!(w.lease().op.is_some(), "the operation record must remain");
    w.assert_no_double_active();
    message
}

// ------------------------------------------------- the cloud refused it

#[test]
fn r4_an_explicit_4xx_for_the_release_is_refused_by_the_cloud_and_the_move_is_restored() {
    for status in [400, 401, 403, 404] {
        let w = World::new(&format!("r4-rej-release-{status}"));
        w.gce
            .script_changes("inst-a", &[ChangeBehavior::Rejected(status)]);
        let before = w.clock.now_ms();
        let r = mv(&w, "node-b");
        let Err(Failure::Failed(m)) = &r else {
            panic!("{status}: expected FAILED, got {r:?}");
        };
        assert!(m.contains("the cloud REFUSED the detach"), "{m}");
        assert!(m.contains(&format!("HTTP {status}")), "{m}");
        assert!(m.contains("verified unchanged"), "{m}");
        assert!(m.contains("rolled back and verified"), "{m}");
        // Exactly one request was made (no blind retry) ...
        assert_eq!(changes_of(&w, "inst-a"), 1);
        assert_eq!(changes_of(&w, "inst-b"), 0);
        // ... and the absence of an operation was watched for a while.
        assert!(
            w.clock.now_ms() - before >= 10_000,
            "the confirmation window was not waited for"
        );
        restored(&w);
    }
}

#[test]
fn r4_an_explicit_4xx_for_the_assignment_gives_the_vip_back() {
    let w = World::new("r4-rej-assign");
    w.gce
        .script_changes("inst-b", &[ChangeBehavior::Rejected(403)]);
    let r = mv(&w, "node-b");
    let Err(Failure::Failed(m)) = &r else {
        panic!("expected FAILED, got {r:?}");
    };
    assert!(m.contains("the cloud REFUSED the attach"), "{m}");
    assert_eq!(changes_of(&w, "inst-b"), 1, "the target was asked once");
    // The release did happen and was undone by the verified rollback.
    assert_eq!(changes_of(&w, "inst-a"), 2);
    restored(&w);
}

#[test]
fn r4_a_status_that_is_not_on_the_list_is_not_a_refusal() {
    // 409, 412, 429, 500, 503 are reported by the tool as plain errors (the
    // classifier maps them to `Error`; the fake's `ErrorNoOperation` stands
    // for all of them): no operation, nothing applied, still UNKNOWN.
    let w = World::new("r4-unlisted-status");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::ErrorNoOperation]);
    let r = mv(&w, "node-b");
    let message = assert_unknown_and_locked(&w, &r);
    assert!(message.contains("unresolved cloud change"), "{message}");
    assert!(
        !w.remote
            .host("node-a")
            .sys
            .actions()
            .iter()
            .any(|a| a.starts_with("start ")),
        "no rollback while the request may still land"
    );
    assert_eq!(changes_of(&w, "inst-a"), 1);
}

#[test]
fn r4_a_timeout_or_a_killed_tool_without_an_operation_stays_unknown() {
    for behavior in [
        ChangeBehavior::TimeoutNoApply,
        ChangeBehavior::TimeoutInvisible,
        ChangeBehavior::ErrorNoOperation,
    ] {
        let w = World::new("r4-no-op-unknown");
        w.gce.script_changes("inst-a", &[behavior]);
        let r = mv(&w, "node-b");
        assert_unknown_and_locked(&w, &r);
        assert_eq!(changes_of(&w, "inst-a"), 1, "{behavior:?}");
        // A request that may land later does so; the lock is still there.
        w.gce.land_all();
        w.check_now("late landing");
        w.assert_no_double_active();
    }
}

// --------------------------- looks like a refusal, but an operation exists

#[test]
fn r4_a_4xx_report_with_an_applied_operation_is_not_a_refusal() {
    // The error belonged to a later stage (for example no right to read the
    // operation); the change was accepted and applied. It is followed to its
    // end like any other change and the move simply succeeds.
    let w = World::new("r4-rej-but-applied");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::RejectedButApplied]);
    let r = mv(&w, "node-b");
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(w.cloud_holders(), ["node-b"]);
    w.assert_settled();
}

#[test]
fn r4_a_4xx_report_with_a_pending_operation_is_unknown_and_nothing_is_undone() {
    let w = World::new("r4-rej-but-pending");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::RejectedButPending]);
    let r = mv(&w, "node-b");
    let message = assert_unknown_and_locked(&w, &r);
    assert!(message.contains("unresolved cloud change"), "{message}");
    assert_eq!(changes_of(&w, "inst-a"), 1);
    assert!(!w.service_active("node-a"), "no rollback restart");
    // It lands: the world is as a pending detach leaves it, visibly.
    w.gce.land_all();
    w.check_now("late landing");
    w.assert_no_double_active();
    assert!(w.cloud_holders().is_empty());
}

#[test]
fn r4_an_operation_that_appears_inside_the_confirmation_window_is_seen() {
    // The listing lags: the operation of the "rejected" request shows up at
    // the n-th reading. Up to the last reading of the window it is seen and
    // the change is followed as applied (the move succeeds); this is what
    // the window is for.
    for lands_at in [1, 3, 6] {
        let w = World::new("r4-rej-late-visible");
        w.gce.script_changes(
            "inst-a",
            &[ChangeBehavior::RejectedButInvisibleUntilList(lands_at)],
        );
        let r = mv(&w, "node-b");
        assert!(r.is_ok(), "lands at reading {lands_at}: {r:?}");
        assert_eq!(w.cloud_holders(), ["node-b"]);
        w.assert_settled();
    }
}

#[test]
fn r4_a_foreign_operation_during_the_window_prevents_the_refusal() {
    // Something else happens to the instance while the absence of our
    // operation is being confirmed: "no operation" can no longer be shown.
    let w = World::new("r4-rej-foreign-op");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    w.gce.after_next_change(|inner| {
        inner.ops.push(super::fakes::FakeOp {
            name: "operation-foreign".into(),
            instance: "inst-a".into(),
            op_type: "compute.instances.stop".into(),
            status: "DONE".into(),
            failed: false,
            foreign: true,
        });
    });
    let r = mv(&w, "node-b");
    assert_unknown_and_locked(&w, &r);
    assert_eq!(changes_of(&w, "inst-a"), 1);
}

// ------------------------------------------ what the observation must show

#[test]
fn r4_a_failing_operation_listing_during_the_window_is_unknown() {
    let w = World::new("r4-rej-list-fails");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    w.gce.after_next_change(|inner| inner.fail_list = true);
    let r = mv(&w, "node-b");
    let message = assert_unknown_and_locked(&w, &r);
    assert!(message.contains("cannot list operations"), "{message}");
    assert_eq!(changes_of(&w, "inst-a"), 1);
}

#[test]
fn r4_one_failed_reading_only_restarts_the_confirmation() {
    let w = World::new("r4-rej-list-once");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    w.gce.after_next_change(|inner| inner.fail_list_once = true);
    let before = w.clock.now_ms();
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("REFUSED")),
        "{r:?}"
    );
    // The failed reading cost one poll on top of the window.
    assert!(w.clock.now_ms() - before >= 12_000);
    restored(&w);
}

#[test]
fn r4_an_alias_list_that_is_not_as_before_is_unknown_even_without_an_operation() {
    // Somebody else removed the VIP from the source while the refusal was
    // being confirmed: the claim "unchanged" cannot be made.
    let w = World::new("r4-rej-changed-under-us");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    w.gce.after_next_change(|inner| {
        inner.instances.get_mut("inst-a").unwrap().aliases.clear();
    });
    let r = mv(&w, "node-b");
    let message = unknown_message(&r);
    assert!(message.contains("not as before"), "{message}");
    assert!(w.lease().op.is_some());
    w.assert_no_double_active();
}

#[test]
fn r4_another_alias_range_appearing_during_the_window_is_unknown() {
    let w = World::new("r4-rej-other-range");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    w.gce.after_next_change(|inner| {
        inner
            .instances
            .get_mut("inst-a")
            .unwrap()
            .aliases
            .push(super::gce::Alias::plain("10.9.0.0/24"));
    });
    let r = mv(&w, "node-b");
    let message = unknown_message(&r);
    assert!(message.contains("not as before"), "{message}");
}

// ------------------------------------------- a rollback request is refused

#[test]
fn r4_a_refused_rollback_request_is_not_a_clean_failure() {
    // The forward path fails (the target service cannot start); the rollback
    // must take the alias off the target and the cloud refuses that request.
    // The alias is still on the target: nothing is restored, UNKNOWN, lock
    // kept.
    let w = World::new("r4-rej-in-rollback");
    w.remote.host("node-b").sys.fail_action("start");
    w.gce.script_changes(
        "inst-b",
        &[ChangeBehavior::Normal, ChangeBehavior::Rejected(403)],
    );
    let r = mv(&w, "node-b");
    let message = assert_unknown_and_locked(&w, &r);
    assert!(message.contains("rollback incomplete"), "{message}");
    assert!(
        message.contains("cannot remove the target alias"),
        "{message}"
    );
    assert_eq!(w.cloud_holders(), ["node-b"]);
    assert_eq!(VIP_CIDR, "10.0.0.130/32");
}

// ------------------------------------ the other refusal paths (definition)

#[test]
fn r4_a_lost_phase_before_anything_was_touched_is_a_refusal() {
    // The Witness refuses the very first phase (another operation holds the
    // lease): this command recorded and changed nothing. Exit 3.
    let w: &'static World = Box::leak(Box::new(World::new("r4-first-phase-refused")));
    let hook = Rc::new(move || {
        let state_path = w
            .remote
            .host("witness")
            .dir
            .join("lease")
            .join("lease.json");
        let mut state: super::lease::LeaseState =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        let held = state.op.as_mut().expect("the move holds the lock");
        held.op_id = "move-someone-else".to_string();
        held.seq += 1;
        state.seq += 1;
        state.checksum = state.compute_checksum();
        std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
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
    assert!(matches!(&r, Err(Failure::Refused(_))), "{r:?}");
    assert_eq!(r.as_ref().unwrap_err().exit_code(), 3);
    assert_eq!(w.gce.change_count(), 0);
    assert!(w.remote.host("node-a").sys.actions().is_empty());
}

#[test]
fn r4_a_lost_phase_after_a_change_stays_unknown() {
    // The second phase is refused after the source service was stopped: the
    // command did change something, so it cannot call this a refusal.
    let w: &'static World = Box::leak(Box::new(World::new("r4-later-phase-refused")));
    let hook = Rc::new(move || {
        let state_path = w
            .remote
            .host("witness")
            .dir
            .join("lease")
            .join("lease.json");
        let mut state: super::lease::LeaseState =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        let held = state.op.as_mut().expect("the move holds the lock");
        held.op_id = "move-someone-else".to_string();
        held.seq += 1;
        state.seq += 1;
        state.checksum = state.compute_checksum();
        std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    });
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("source_released"),
        0,
        1,
        Fault::Hook(hook),
    );
    let r = mv(w, "node-b");
    let message = unknown_message(&r);
    assert!(message.contains("no longer holds the lease"), "{message}");
}

#[test]
fn r4_a_lease_request_without_a_clear_answer_is_unknown_and_touches_nothing() {
    for fault in [Fault::DropAfter, Fault::DropBefore, Fault::TimeoutAfter] {
        let w = World::new("r4-acquire-lost");
        w.remote.inject("witness", op::LEASE_ACQUIRE, fault);
        let r = mv(&w, "node-b");
        let message = unknown_message(&r);
        assert!(
            message.contains("no VIP, alias or service was touched"),
            "{message}"
        );
        assert_eq!(w.gce.change_count(), 0);
        assert!(w.service_active("node-a"));
    }
}

#[test]
fn r4_a_refused_lease_request_is_a_refusal() {
    let w = World::new("r4-acquire-refused");
    w.remote.inject(
        "witness",
        op::LEASE_ACQUIRE,
        Fault::RefuseBefore("busy".into()),
    );
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Refused(m)) if m.contains("busy")),
        "{r:?}"
    );
    assert_eq!(w.gce.change_count(), 0);
}

#[test]
fn r4_an_agent_that_did_not_understand_the_request_did_nothing() {
    use super::remote::{CallError, invoke};
    let w = World::new("r4-bad-request");
    let target = w.ctx().node_target("node-a").unwrap();
    // An unknown operation is a `bad_request` answer from the real agent.
    let r = invoke(
        &w.remote,
        &target,
        "no.such.operation",
        serde_json::json!({}),
        std::time::Duration::from_secs(5),
    );
    assert!(matches!(r, Err(CallError::Refused(_))), "{r:?}");
    // An in-band failure of an operation stays a failure (it may be partial).
    w.remote.inject(
        "node-a",
        op::SERVICE_CONTROL,
        Fault::FailBefore("systemctl failed".into()),
    );
    let r = invoke(
        &w.remote,
        &target,
        op::SERVICE_CONTROL,
        serde_json::json!({"unit": "mkg-demo.service", "action": "stop"}),
        std::time::Duration::from_secs(5),
    );
    assert!(matches!(r, Err(CallError::Failed(_))), "{r:?}");
}

#[test]
fn r4_an_init_without_a_clear_answer_is_unknown() {
    let w = World::build("r4-init-lost", false);
    w.remote.inject("witness", op::LEASE_INIT, Fault::DropAfter);
    let r = init_vip(&w.ctx(), "node-a", false);
    assert!(
        matches!(&r, Err(Failure::Unknown(m)) if m.contains("may or may not have been written")),
        "{r:?}"
    );
    // The record was in fact written: the next init is refused as such.
    assert!(matches!(
        init_vip(&w.ctx(), "node-a", false),
        Err(Failure::Refused(m)) if m.contains("already")
    ));
}

#[test]
fn r4_an_observation_that_fails_before_the_first_request_is_a_refusal() {
    // A move, an init: the cloud cannot be read at the start; nothing was
    // sent, so the command refuses to start (it used to be FAILED).
    let w = World::new("r4-preflight-describe");
    w.gce.fail_describe("inst-a", true);
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Refused(m)) if m.contains("cannot observe")),
        "{r:?}"
    );
    assert_eq!(w.gce.change_count(), 0);
    let w = World::build("r4-preflight-describe-init", false);
    w.gce.fail_describe("inst-a", true);
    let r = init_vip(&w.ctx(), "node-a", false);
    assert!(matches!(&r, Err(Failure::Refused(_))), "{r:?}");
}

#[test]
fn r4_init_is_refused_while_a_cloud_operation_is_open_or_unreadable() {
    // Everything else is in order (the owner runs the service and answers on
    // the VIP): only the open operation, or the unreadable listing, stops it.
    let w = World::build("r4-init-open-op", false);
    w.gce
        .seed_op("inst-b", super::fakes::NIC_UPDATE, "RUNNING", false);
    let r = init_vip(&w.ctx(), "node-a", false);
    assert!(
        matches!(&r, Err(Failure::Refused(m)) if m.contains("still RUNNING")),
        "{r:?}"
    );
    let w = World::build("r4-init-list-fails", false);
    w.gce.fail_list_operations(true);
    let r = init_vip(&w.ctx(), "node-a", false);
    assert!(
        matches!(&r, Err(Failure::Refused(m)) if m.contains("cannot list")),
        "{r:?}"
    );
    // With a finished history it works.
    let w = World::build("r4-init-history", false);
    w.gce
        .seed_op("inst-a", super::fakes::NIC_UPDATE, "DONE", false);
    assert!(init_vip(&w.ctx(), "node-a", false).is_ok());
}

#[test]
fn r4_a_failed_reading_in_the_middle_of_the_window_restarts_the_whole_confirmation() {
    // Readings 2, 3 and 4 (counted from the look before the request) are
    // fine, the 5th fails: the quiet time already collected is worth nothing,
    // the full 10 s must be seen again after it.
    let w = World::new("r4-rej-list-middle");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    let failed_at = std::rc::Rc::new(std::cell::Cell::new(0u64));
    let (clock, mark) = (w.clock.handle(), failed_at.clone());
    w.gce.schedule_at_list(5, move |inner| {
        inner.fail_list_once = true;
        mark.set(clock.get());
    });
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("REFUSED")),
        "{r:?}"
    );
    assert!(
        failed_at.get() > 0,
        "the failing reading was never scheduled"
    );
    // Looks at the operation list: 1 before the request, 3 good readings and
    // the failed one, then a full new window (10 s = 6 readings), and the look
    // right before the lock is released. Without the restart the decision
    // would come 4 readings earlier.
    let looks = w.gce.inner.borrow().list_calls;
    assert!(looks >= 12, "only {looks} looks at the operation list");
    restored(&w);
}

#[test]
fn r4_an_unknown_node_is_a_refusal_and_never_a_host_that_is_down() {
    // `reach_node` turns an address that cannot be resolved into "down"; the
    // refusal of an unknown node name must not be swallowed by that.
    let w = World::new("r4-reach-unknown");
    assert!(matches!(
        reach_node(&w.ctx(), "node-z"),
        Err(Failure::Refused(_))
    ));
    assert!(reach_node(&w.ctx(), "node-a").is_ok());
}
