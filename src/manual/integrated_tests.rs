//! R4: integrated abnormal-case tests (Owner decision B).
//!
//! The three rounds of remediation were tested one at a time. This file tests
//! what only exists in combination: R1 (cloud change tracking, lease,
//! fencing) x R2 (exclusion from the HA daemon) x R3 (chrony apply and
//! rollback, signals, authorisation), always in the fake world, always
//! against the world's **ground truth** (the cloud's real alias lists, the
//! real unit tables, the real files) and its safety monitor (double alias,
//! double Active, a destructive action without the lease, an alias change
//! while an HA daemon runs, a lock released over an unsettled world).
//!
//! The central idea is the **claim check**: whatever fault is injected, the
//! words REFUSED, FAILED and OK are claims about the world and are compared
//! with it —
//!
//! * OK: the target holds the VIP and serves it, the record agrees, no lock;
//! * FAILED: the source holds it and serves it again, the record is back, no
//!   lock (a verified restore);
//! * REFUSED: *nothing* changed: no cloud request, no service action;
//! * UNKNOWN: no claim, but the world must be in a state a later `status`
//!   shows (the lock is recorded) or in a state that is one of the two ends.
//!
//! The matrices below inject every cloud behaviour at every alias change and
//! every agent fault at every agent operation of a move, and every fault at
//! every agent operation of a chrony apply (also during its rollback).

use super::fakes::{ChangeBehavior, Fault, World};
use super::lease::{ABANDON_QUIET_SECS, LeaseState};
use super::proto::{self, PROTO_VERSION, Request, op};
use super::vip::*;
use super::{Failure, Res};
use serde_json::{Value, json};
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

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    holders: Vec<String>,
    active_a: bool,
    active_b: bool,
    owner: Option<String>,
    epoch: u64,
    lock: bool,
}

fn snap(w: &World) -> Snapshot {
    let lease = w.lease();
    Snapshot {
        holders: w.cloud_holders(),
        active_a: w.service_active("node-a"),
        active_b: w.service_active("node-b"),
        owner: lease.owner.clone(),
        epoch: lease.epoch,
        lock: lease.op.is_some(),
    }
}

fn start_state() -> Snapshot {
    Snapshot {
        holders: vec!["node-a".into()],
        active_a: true,
        active_b: false,
        owner: Some("node-a".into()),
        epoch: 1,
        lock: false,
    }
}

fn target_state() -> Snapshot {
    Snapshot {
        holders: vec!["node-b".into()],
        active_a: false,
        active_b: true,
        owner: Some("node-b".into()),
        epoch: 2,
        lock: false,
    }
}

/// The violations the monitor collected, named with the case that caused them.
fn assert_clean(case: &str, w: &World) {
    let violations = w.violations.borrow();
    assert!(violations.is_empty(), "{case}: monitor: {violations:?}");
}

/// Compare the words of a result with the world. See the module comment.
fn assert_claims(case: &str, w: &World, r: &Res<MoveReport>) {
    let now = snap(w);
    let without_lock = |s: &Snapshot| Snapshot {
        holders: s.holders.clone(),
        lock: false,
        owner: s.owner.clone(),
        ..*s
    };
    match r {
        Ok(_) => assert_eq!(now, target_state(), "{case}: OK, but the world is not done"),
        Err(Failure::Failed(m)) => assert_eq!(
            now,
            start_state(),
            "{case}: FAILED claims a verified restore ({m})"
        ),
        Err(Failure::Refused(m)) => {
            // Nothing changed. A lock that this command took before it was
            // refused may still be recorded; it never mutated and expires.
            assert_eq!(
                without_lock(&now),
                start_state(),
                "{case}: REFUSED claims that nothing changed ({m})"
            );
            if let Some(held) = w.lease().op {
                assert!(
                    !held.phase.mutating(),
                    "{case}: REFUSED with a mutating operation recorded ({m})"
                );
            }
            assert_eq!(
                w.gce.change_count(),
                0,
                "{case}: REFUSED after a cloud request"
            );
            for node in ["node-a", "node-b"] {
                assert!(
                    w.remote.host(node).sys.actions().is_empty(),
                    "{case}: REFUSED after a service action on {node}"
                );
            }
        }
        Err(Failure::Unknown(m)) => assert!(
            now.lock || now == start_state() || now == target_state(),
            "{case}: UNKNOWN left no trace and neither end state ({now:?}): {m}"
        ),
    }
    assert_clean(case, w);
}

/// After a result the cloud may still land late requests; the monitor must
/// stay clean, and a command that claimed a finished world must still be one.
fn land_and_recheck(case: &str, w: &World, r: &Res<MoveReport>) {
    w.gce.land_all();
    w.check_now("late landing");
    assert_clean(case, w);
    if matches!(r, Ok(_) | Err(Failure::Failed(_))) {
        assert!(!snap(w).lock, "{case}: a finished command left a lock");
    }
}

const GCE_BEHAVIORS: &[ChangeBehavior] = &[
    ChangeBehavior::Normal,
    ChangeBehavior::ErrorAfterApply,
    ChangeBehavior::ErrorNoApply,
    ChangeBehavior::TimeoutFailedOp,
    ChangeBehavior::RejectedButFailedOp,
    ChangeBehavior::ErrorNoOperation,
    ChangeBehavior::TimeoutAfterApply,
    ChangeBehavior::TimeoutNoApply,
    ChangeBehavior::TimeoutPending,
    ChangeBehavior::TimeoutInvisible,
    ChangeBehavior::PendingLandsAfterLists(1),
    ChangeBehavior::PendingLandsAfterLists(3),
    ChangeBehavior::Rejected(400),
    ChangeBehavior::Rejected(403),
    ChangeBehavior::Rejected(404),
    ChangeBehavior::RejectedButApplied,
    ChangeBehavior::RejectedButPending,
    ChangeBehavior::RejectedButInvisibleUntilList(2),
    ChangeBehavior::RejectedButInvisibleUntilList(7),
];

#[test]
fn matrix_every_cloud_behaviour_at_every_alias_change_of_a_move() {
    // Base scenarios decide which alias changes exist: a plain move (release
    // on inst-a, assign on inst-b) and a move whose target service does not
    // start (so the rollback makes two more changes: remove on inst-b, give
    // back on inst-a).
    let mut runs = 0;
    // Runs in which the scripted behaviour was really applied to a request
    // (the move made at least `position + 1` changes to that instance). The
    // others are plain repeats of a normal move (audit RA-F-03).
    let mut effective = 0;
    for (base, start_fails) in [("plain", false), ("start-fails", true)] {
        for instance in ["inst-a", "inst-b"] {
            for position in 0..2usize {
                for behavior in GCE_BEHAVIORS {
                    let case = format!("{base} {instance}#{position} {behavior:?}");
                    let w = World::new("it-matrix-gce");
                    if start_fails {
                        w.remote.host("node-b").sys.fail_action("start");
                    }
                    let mut script = vec![ChangeBehavior::Normal; position];
                    script.push(*behavior);
                    w.gce.script_changes(instance, &script);
                    let r = mv(&w, "node-b");
                    let applied = w
                        .gce
                        .changes()
                        .iter()
                        .filter(|(i, _)| i == instance)
                        .count();
                    if applied > position {
                        effective += 1;
                    }
                    assert_claims(&case, &w, &r);
                    land_and_recheck(&case, &w, &r);
                    runs += 1;
                }
            }
        }
    }
    assert_eq!(runs, 2 * 2 * 2 * GCE_BEHAVIORS.len());
    println!("cloud matrix: {effective} of {runs} runs applied the scripted behaviour");
    assert!(
        effective >= EFFECTIVE_CLOUD_MIN,
        "only {effective} of {runs} runs injected anything: the matrix lost coverage"
    );
}

/// Floors for the number of runs of each matrix in which the fault was really
/// injected (measured in round R6; the matrices are deterministic). A floor
/// below the measurement leaves room for a change of order inside a move but
/// not for a matrix that silently stops injecting.
const EFFECTIVE_CLOUD_MIN: usize = 105;
const EFFECTIVE_AGENT_MOVE_MIN: usize = 280;
const EFFECTIVE_CHRONY_MIN: usize = 105;

#[test]
fn matrix_every_agent_fault_at_every_agent_operation_of_a_move() {
    let faults: Vec<(&str, Fault)> = vec![
        ("drop-before", Fault::DropBefore),
        ("drop-after", Fault::DropAfter),
        ("timeout-after", Fault::TimeoutAfter),
        ("refuse", Fault::RefuseBefore("injected refusal".into())),
        ("fail", Fault::FailBefore("injected failure".into())),
    ];
    // (host, operation, how many occurrences are tried)
    let points: &[(&str, &str, u32)] = &[
        ("witness", op::LEASE_ACQUIRE, 1),
        ("witness", op::LEASE_PHASE, 6),
        ("witness", op::LEASE_COMMIT, 1),
        ("witness", op::LEASE_ABORT, 1),
        ("witness", op::LEASE_STATUS, 3),
        ("witness", op::PING, 4),
        ("witness", op::PROBE, 2),
        ("node-a", op::PING, 4),
        ("node-b", op::PING, 4),
        ("node-a", op::SERVICE_CONTROL, 3),
        ("node-b", op::SERVICE_CONTROL, 3),
        ("node-a", op::SERVICE_STATUS, 3),
        ("node-b", op::SERVICE_STATUS, 3),
        ("node-a", op::PROBE, 3),
        ("node-b", op::PROBE, 2),
    ];
    let mut runs = 0;
    let mut effective = 0;
    for start_fails in [false, true] {
        for (host, operation, count) in points {
            for skip in 0..*count {
                for (fault_name, fault) in &faults {
                    let case =
                        format!("start-fails={start_fails} {host} {operation}#{skip} {fault_name}");
                    let w = World::new("it-matrix-agent");
                    if start_fails {
                        w.remote.host("node-b").sys.fail_action("start");
                    }
                    w.remote
                        .inject_when(host, operation, None, skip, 1, fault.clone());
                    let r = mv(&w, "node-b");
                    effective += usize::from(w.remote.fired(host, operation) > 0);
                    assert_claims(&case, &w, &r);
                    land_and_recheck(&case, &w, &r);
                    runs += 1;
                }
            }
        }
    }
    assert_eq!(runs, 430);
    println!("agent-fault move matrix: {effective} of {runs} runs injected the fault");
    assert!(
        effective >= EFFECTIVE_AGENT_MOVE_MIN,
        "only {effective} of {runs} runs injected anything: the matrix lost coverage"
    );
}

#[test]
fn the_documented_limit_of_a_proven_refusal_is_an_operation_that_shows_up_very_late() {
    // LIMITATIONS 22: the cloud's explicit 4xx is believed after four readings
    // over 10 s and once more before the lock is released. An operation of the
    // "refused" request that becomes visible later than that (the tool said
    // 4xx *and* the cloud created an operation, which an HTTP client error
    // does not do) lands on a world that was reported restored; the monitor
    // sees the lock released over a pending request. This pins the boundary:
    // if the window changes, the documentation must change with it.
    let w = World::new("it-refusal-limit");
    w.gce.script_changes(
        "inst-a",
        &[ChangeBehavior::RejectedButInvisibleUntilList(20)],
    );
    let r = mv(&w, "node-b");
    assert!(
        matches!(&r, Err(Failure::Failed(m)) if m.contains("REFUSED")),
        "{r:?}"
    );
    w.gce.land_all();
    w.check_now("late landing");
    assert!(
        !w.violations.borrow().is_empty(),
        "the boundary of the confirmation moved: update LIMITATIONS 22 and CLI_REFERENCE"
    );
}

// ===================================================== chrony claim checks

const OLD: &str = "pool 2.pool.ntp.org iburst\n";
const NEW: &str = "pool time.example.invalid iburst\nmakestep 1 3\n";

fn live(w: &World, node: &str) -> String {
    std::fs::read_to_string(&w.remote.host(node).env.cfg.chrony_conf).unwrap()
}

fn chrony_active(w: &World, node: &str) -> bool {
    w.remote.host(node).sys.service("chrony.service").as_deref() == Some("active")
}

/// The words of an apply compared with the real file: OK means the new file is
/// live and chrony runs; REFUSED and FAILED mean the old file is live; the
/// file is always one of the two; leftovers never replace the live file.
fn assert_apply_claims(case: &str, w: &World, r: &Res<super::chrony_ctl::ApplyReport>) {
    let file = live(w, "node-a");
    assert!(
        file == OLD || file == NEW,
        "{case}: the live file is neither ({file:?})"
    );
    match r {
        Ok(report) if report.changed => {
            assert_eq!(file, NEW, "{case}");
            assert!(
                chrony_active(w, "node-a"),
                "{case}: OK but chrony is not active"
            );
        }
        Ok(_) => {}
        Err(Failure::Refused(m)) | Err(Failure::Failed(m)) => {
            assert_eq!(
                file, OLD,
                "{case}: the old file is claimed to be live ({m})"
            );
        }
        Err(Failure::Unknown(_)) => {}
    }
    w.assert_no_double_active();
}

#[test]
fn matrix_every_agent_fault_at_every_operation_of_a_chrony_apply() {
    let faults: Vec<(&str, Fault)> = vec![
        ("drop-before", Fault::DropBefore),
        ("drop-after", Fault::DropAfter),
        ("timeout-after", Fault::TimeoutAfter),
        ("refuse", Fault::RefuseBefore("injected refusal".into())),
        ("fail", Fault::FailBefore("injected failure".into())),
    ];
    let points: &[(&str, u32)] = &[
        (op::PING, 2),
        (op::CHRONY_STATE, 4),
        (op::CHRONY_VALIDATE, 1),
        (op::CHRONY_READ, 1),
        (op::CHRONY_BACKUP, 1),
        (op::CHRONY_STAGE, 1),
        (op::CHRONY_PUBLISH, 1),
        (op::CHRONY_CLEANUP, 2),
        (op::SERVICE_CONTROL, 2),
        (op::SERVICE_STATUS, 3),
    ];
    let mut runs = 0;
    let mut effective = 0;
    // `restart_fails`: the first restart (after the publish) fails, so the
    // rollback (restore, restart) is exercised as well.
    for restart_fails in [false, true] {
        for (operation, count) in points {
            for skip in 0..*count {
                for (fault_name, fault) in &faults {
                    let case =
                        format!("restart-fails={restart_fails} {operation}#{skip} {fault_name}");
                    let w = World::new("it-matrix-chrony");
                    if restart_fails {
                        w.remote.inject_when(
                            "node-a",
                            op::SERVICE_CONTROL,
                            Some("restart"),
                            0,
                            1,
                            Fault::FailBefore("restart failed".into()),
                        );
                    }
                    w.remote
                        .inject_when("node-a", operation, None, skip, 1, fault.clone());
                    let r = super::chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
                    // The restart-fails rule is on SERVICE_CONTROL too: count
                    // only the matrix rule's own firing.
                    let own = w.remote.fired("node-a", operation);
                    let extra = u32::from(restart_fails && *operation == op::SERVICE_CONTROL);
                    effective += usize::from(own > extra);
                    assert_apply_claims(&case, &w, &r);
                    runs += 1;
                }
            }
        }
    }
    assert_eq!(runs, 180);
    println!("chrony apply matrix: {effective} of {runs} runs injected the fault");
    assert!(
        effective >= EFFECTIVE_CHRONY_MIN,
        "only {effective} of {runs} runs injected anything: the matrix lost coverage"
    );
}

// ==================================================== R2 x R3: HA x chrony

/// An HA daemon appears on `host` right before the agent call number `skip`
/// of `operation` on that host: the unit is unmasked and started, as an
/// administrator or a boot would.
fn ha_before(w: &World, host: &str, operation: &str, skip: u32) {
    let sys = w.remote.host(host).sys.clone();
    w.remote.inject_when(
        host,
        operation,
        None,
        skip,
        1,
        Fault::Hook(Rc::new(move || {
            sys.unmask("mikagami.service");
            sys.ha_start("mikagami.service");
        })),
    );
}

#[test]
fn an_ha_daemon_at_every_agent_operation_of_a_chrony_apply_never_gets_a_gated_change() {
    let points: &[(&str, u32)] = &[
        (op::PING, 0),
        (op::CHRONY_STATE, 0),
        (op::CHRONY_STATE, 1),
        (op::CHRONY_VALIDATE, 0),
        (op::CHRONY_READ, 0),
        (op::CHRONY_BACKUP, 0),
        (op::CHRONY_STAGE, 0),
        (op::CHRONY_PUBLISH, 0),
        (op::SERVICE_CONTROL, 0),
        (op::SERVICE_CONTROL, 1),
        (op::SERVICE_STATUS, 0),
        (op::CHRONY_RESTORE, 0),
    ];
    let mut ha_ran = 0;
    for restart_fails in [false, true] {
        for (operation, skip) in points {
            let case = format!("restart-fails={restart_fails} HA before {operation}#{skip}");
            let w = World::new("it-ha-chrony");
            if restart_fails {
                w.remote.inject_when(
                    "node-a",
                    op::SERVICE_CONTROL,
                    Some("restart"),
                    0,
                    1,
                    Fault::FailBefore("restart failed".into()),
                );
            }
            ha_before(&w, "node-a", operation, *skip);
            let r = super::chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
            // The monitor flags a gated operation (a service change) that
            // succeeded on a host where an HA daemon runs; the file claims
            // must hold as well.
            assert_apply_claims(&case, &w, &r);
            if w.remote.host("node-a").sys.ha_running() {
                ha_ran += 1;
            }
        }
    }
    // The HA daemon really appeared in most of the cases (an operation that
    // does not occur in a run, such as a restore without a failed restart,
    // never fires its hook).
    assert!(
        ha_ran >= 18,
        "the injected HA start fired in only {ha_ran} cases"
    );
}

// ============================================ R1 x R2: cloud change x HA

#[test]
fn an_ha_daemon_that_appears_while_the_absence_of_an_operation_is_confirmed_stops_everything() {
    // The cloud answered the release with a 403. While the controller
    // confirms that no operation appears, an HA daemon starts on the source.
    // The refusal is proven, but the rollback must not start the source
    // service next to an HA daemon: UNKNOWN, the lock stays.
    let w = World::new("it-ha-in-window");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    let sys = w.remote.host("node-a").sys.clone();
    // list #1 is the look before the request; #4 is the third look of the
    // confirmation window.
    w.gce.schedule_at_list(4, move |_| {
        sys.unmask("mikagami.service");
        sys.ha_start("mikagami.service");
    });
    let r = mv(&w, "node-b");
    let Err(Failure::Unknown(m)) = &r else {
        panic!("expected UNKNOWN, got {r:?}");
    };
    assert!(m.contains("rollback incomplete"), "{m}");
    assert!(
        !w.remote
            .host("node-a")
            .sys
            .actions()
            .iter()
            .any(|a| a.starts_with("start ")),
        "no service start next to an HA daemon"
    );
    assert!(w.lease().op.is_some());
    assert_eq!(w.gce.change_count(), 1, "no further cloud change");
    w.check_now("ha start");
    w.assert_no_double_active();
}

#[test]
fn a_pending_change_that_lands_next_to_an_ha_daemon_is_not_adopted_by_a_reconcile() {
    let w = World::new("it-pending-then-ha");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let r = mv(&w, "node-b");
    assert!(matches!(r, Err(Failure::Unknown(_))), "{r:?}");
    let op_id = w.lease().op.unwrap().op_id;
    // The cloud finishes the detach; later an HA daemon appears on node-b.
    w.gce.land_all();
    w.check_now("late landing");
    let sys = w.remote.host("node-b").sys.clone();
    sys.unmask("mikagami.service");
    sys.ha_start("mikagami.service");
    w.clock.advance_secs(ABANDON_QUIET_SECS + 1);
    // The VIP is on nobody; whatever the operator hopes, a reconcile needs the
    // proof of exclusion on every host and one holder.
    let r = reconcile_vip(&w.ctx(), Some(&op_id), false);
    assert!(r.is_err(), "{r:?}");
    assert!(w.lease().op.is_some(), "the record is untouched");
    w.assert_no_double_active();
}

// ========================================= R1 x R3: move state x chrony

#[test]
fn chrony_operations_work_on_nodes_whose_fencing_mark_a_move_has_raised() {
    // The fencing token guards service and lease changes of a move. A chrony
    // apply and a chrony service action send none and must not be refused by
    // the mark a previous move left on the node.
    let w = World::new("it-fence-vs-chrony");
    mv(&w, "node-b").unwrap();
    mv(&w, "node-a").unwrap();
    for node in ["node-a", "node-b"] {
        let r = super::chrony_ctl::apply(&w.ctx(), node, NEW, false);
        assert!(r.is_ok(), "{node}: {r:?}");
        assert_eq!(live(&w, node), NEW);
        let r = super::chrony_ctl::service_action(&w.ctx(), node, "restart");
        assert!(r.is_ok(), "{node}: {r:?}");
    }
    w.assert_settled();
}

#[test]
fn a_chrony_apply_does_not_disturb_an_unresolved_vip_operation() {
    let w = World::new("it-chrony-vs-pending");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let r = mv(&w, "node-b");
    assert!(matches!(r, Err(Failure::Unknown(_))), "{r:?}");
    let before = w.lease();
    let r = super::chrony_ctl::apply(&w.ctx(), "node-b", NEW, false);
    assert!(r.is_ok(), "{r:?}");
    let after = w.lease();
    assert_eq!(before.op, after.op, "the chrony apply left the lease alone");
    assert_eq!(before.seq, after.seq);
    assert_eq!(w.gce.change_count(), 1, "no cloud change from the apply");
    w.assert_no_double_active();
}

// ============================================ stale controller (SIGSTOP)

fn take_over(dir: &std::path::Path, new_op: &str) {
    let path = dir.join("lease").join("lease.json");
    let mut state: LeaseState = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let held = state.op.as_mut().expect("an operation is recorded");
    held.op_id = new_op.to_string();
    held.seq += 1;
    state.seq += 1;
    state.checksum = state.compute_checksum();
    std::fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
}

#[test]
fn a_controller_that_wakes_up_in_the_confirmation_window_after_a_takeover_touches_nothing() {
    // SIGSTOP / resume: while this controller waits to see whether the
    // cloud's refusal is real, another controller took the lock over.
    let w = World::new("it-stale-in-window");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    let dir = w.remote.host("witness").dir.clone();
    w.gce
        .schedule_at_list(4, move |_| take_over(&dir, "move-takeover1"));
    let r = mv(&w, "node-b");
    let Err(Failure::Unknown(m)) = &r else {
        panic!("expected UNKNOWN, got {r:?}");
    };
    assert!(m.contains("no longer holds the lease"), "{m}");
    assert_eq!(
        w.gce.change_count(),
        1,
        "no cloud change after the takeover"
    );
    assert!(
        !w.remote
            .host("node-a")
            .sys
            .actions()
            .iter()
            .any(|a| a.starts_with("start ")),
        "the stale controller did not restart the source"
    );
    assert_eq!(w.lease().op.unwrap().op_id, "move-takeover1");
    w.assert_no_double_active();
}

#[test]
fn a_stale_controller_with_a_pending_change_does_not_overwrite_the_new_holders_record() {
    let w = World::new("it-stale-pending");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let dir = w.remote.host("witness").dir.clone();
    w.gce
        .schedule_at_list(3, move |_| take_over(&dir, "move-takeover2"));
    let r = mv(&w, "node-b");
    let Err(Failure::Unknown(m)) = &r else {
        panic!("expected UNKNOWN, got {r:?}");
    };
    assert!(m.contains("unresolved cloud change"), "{m}");
    let held = w.lease().op.unwrap();
    assert_eq!(held.op_id, "move-takeover2");
    assert!(
        held.evidence.get("cloud_changes").is_none(),
        "the stale controller wrote into the new holder's record"
    );
    w.assert_no_double_active();
}

#[test]
fn a_stale_controller_after_a_completed_takeover_move_is_refused_by_the_nodes() {
    // Another controller completed a move A -> B. The stale one wakes up and
    // sends its old token to the nodes: both refuse (B-01 / B-02 x R1).
    let w = World::new("it-stale-token");
    let ctx = w.ctx();
    let node_a = ctx.node_target("node-a").unwrap();
    let node_b = ctx.node_target("node-b").unwrap();
    mv(&w, "node-b").unwrap();
    // The stale controller's token comes from before that move: epoch 1 and a
    // sequence below everything the nodes have served since.
    for (target, action) in [(&node_a, "start"), (&node_b, "stop")] {
        let stale = json!({"unit": "mkg-demo.service", "action": action,
            "fence": {"epoch": 1, "seq": 0, "op_id": "move-stale-old0"}});
        let r = ctx.call(target, op::SERVICE_CONTROL, stale, super::remote::LONG);
        assert!(
            matches!(&r, Err(super::remote::CallError::Refused(m)) if m.contains("stale fencing token")),
            "{r:?}"
        );
    }
    assert_eq!(snap(&w), target_state());
}

#[test]
fn a_node_that_lost_its_mark_cannot_refuse_a_stale_token_the_documented_limit() {
    // LIMITATIONS 24: "A rebuilt node loses its mark." The token is enforced
    // only against a mark; this test pins the behaviour so that a change
    // would be noticed. (The Witness still shows the newer record, and any
    // controller that reads the lease first sees it; the node cannot.)
    let w = World::new("it-mark-lost");
    mv(&w, "node-b").unwrap();
    std::fs::remove_file(&w.remote.host("node-a").env.cfg.fence_state).unwrap();
    let ctx = w.ctx();
    let node_a = ctx.node_target("node-a").unwrap();
    let stale = json!({"unit": "mkg-demo.service", "action": "start",
        "fence": {"epoch": 1, "seq": 1, "op_id": "move-stale-old0"}});
    let r = ctx.call(&node_a, op::SERVICE_CONTROL, stale, super::remote::LONG);
    assert!(r.is_ok(), "{r:?}");
    // ... and the monitor sees the consequence: node-a runs the service
    // without holding the VIP; that is not a double Active, and the record
    // and `status` show the truth.
    assert_ne!(vip_status(&w.ctx()).verdict, "consistent");
}

#[test]
fn a_node_mark_newer_than_the_lease_stops_a_move_before_it_starts() {
    // The Witness record is older than what a node has served (a restored
    // snapshot): the move does not start. Combined with a 4xx scripted for
    // later, nothing is ever sent.
    let w = World::new("it-mark-newer");
    mv(&w, "node-b").unwrap();
    // Restore the Witness record from before that move.
    let path = w
        .remote
        .host("witness")
        .dir
        .join("lease")
        .join("lease.json");
    let mut state: LeaseState = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    state.seq -= 2;
    state.checksum = state.compute_checksum();
    std::fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    w.gce
        .script_changes("inst-b", &[ChangeBehavior::Rejected(403)]);
    let changes = w.gce.change_count();
    let r = mv(&w, "node-a");
    assert!(
        matches!(&r, Err(Failure::Unknown(m)) if m.contains("OLDER than what")),
        "{r:?}"
    );
    assert_eq!(w.gce.change_count(), changes);
}

// ============================================ lease loss and restoration

fn agent_call(w: &World, host: &str, operation: &str, args: Value) -> proto::Response {
    super::agent::handle(
        &w.remote.host(host).env,
        &Request {
            v: PROTO_VERSION,
            id: proto::random_hex(8),
            op: operation.to_string(),
            args,
        },
    )
}

#[test]
fn a_lost_lease_file_with_an_unresolved_cloud_change_is_never_adopted_blindly() {
    // R1 x lease loss: a pending detach is recorded in the lease; the lease
    // file is then lost. Without `--reinit` everything is refused; with it,
    // the open cloud operation must still stop an `init`.
    let w = World::new("it-lease-lost-pending");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let r = mv(&w, "node-b");
    assert!(matches!(r, Err(Failure::Unknown(_))), "{r:?}");
    let lease_file = w
        .remote
        .host("witness")
        .dir
        .join("lease")
        .join("lease.json");
    std::fs::remove_file(&lease_file).unwrap();
    // The state is not a fresh start.
    let r = init_vip(&w.ctx(), "node-a", false);
    assert!(r.is_err(), "{r:?}");
    assert_ne!(vip_status(&w.ctx()).verdict, "consistent");
    // With --reinit the cloud still has an open operation: it must not be
    // recorded as owner while a change may still land.
    let r = init_vip(&w.ctx(), "node-a", true);
    assert!(
        r.is_err(),
        "init --reinit over an open cloud operation: {r:?}"
    );
    w.assert_no_double_active();
}

#[test]
fn a_restored_old_lease_copy_with_an_ha_daemon_is_not_repaired_by_a_reconcile() {
    // R1 x R2: the record was restored from an old copy (B-04) and an HA
    // daemon runs on a node. The repair (reconcile) needs the proof of
    // exclusion on every host, so it refuses and changes nothing.
    let w = World::new("it-restored-and-ha");
    mv(&w, "node-b").unwrap();
    let path = w
        .remote
        .host("witness")
        .dir
        .join("lease")
        .join("lease.json");
    let mut state: LeaseState = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    state.seq -= 2;
    state.checksum = state.compute_checksum();
    std::fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    let sys = w.remote.host("node-a").sys.clone();
    sys.unmask("mikagami.service");
    sys.ha_start("mikagami.service");
    let before = std::fs::read(&path).unwrap();
    let r = reconcile_vip(&w.ctx(), None, false);
    assert!(r.is_err(), "{r:?}");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the record is untouched"
    );
    // Without the HA daemon the same reconcile repairs it.
    let sys = w.remote.host("node-a").sys.clone();
    sys.set_service("mikagami.service", "inactive");
    sys.mask("mikagami.service");
    let r = reconcile_vip(&w.ctx(), None, false);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(vip_status(&w.ctx()).verdict, "consistent");
}

#[test]
fn the_sentinel_of_an_initialised_store_survives_a_pending_change() {
    // R1 x R1: with the state file gone but the store initialised, even a
    // reconcile is refused (B-05); a pending cloud change makes no
    // difference to that.
    let w = World::new("it-sentinel-pending");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let _ = mv(&w, "node-b");
    let lease_dir = w.remote.host("witness").dir.join("lease");
    std::fs::remove_file(lease_dir.join("lease.json")).unwrap();
    let r = reconcile_vip(&w.ctx(), None, false);
    assert!(r.is_err(), "{r:?}");
    let r = agent_call(&w, "witness", op::LEASE_STATUS, json!({}));
    assert!(
        !r.ok,
        "a missing state file of an initialised store is not a fresh start"
    );
}

// ============================ GCE late landing x rollback x HA (R1 x R2)

#[test]
fn a_late_landing_before_during_or_after_the_rollback_never_makes_a_double_alias() {
    // The assignment to the target is pending; the target service cannot be
    // started anyway. Whatever the order, the world never holds the alias on
    // two NICs and never runs two services.
    for lands_at in [1usize, 2, 3, 5, 8, 13, 21] {
        let w = World::new("it-late-vs-rollback");
        w.remote.host("node-b").sys.fail_action("start");
        w.gce
            .script_changes("inst-b", &[ChangeBehavior::TimeoutInvisible]);
        w.gce.land_at_describe(lands_at);
        let r = mv(&w, "node-b");
        assert!(matches!(r, Err(Failure::Unknown(_))), "{lands_at}: {r:?}");
        w.assert_no_double_active();
        w.gce.land_all();
        w.check_now("late landing");
        w.assert_no_double_active();
    }
}

#[test]
fn the_world_stays_clean_when_a_pending_change_and_an_ha_start_race_a_reconcile() {
    let w = World::new("it-race-reconcile");
    w.gce
        .script_changes("inst-b", &[ChangeBehavior::TimeoutPending]);
    let r = mv(&w, "node-b");
    assert!(matches!(r, Err(Failure::Unknown(_))), "{r:?}");
    let op_id = w.lease().op.unwrap().op_id;
    w.clock.advance_secs(ABANDON_QUIET_SECS + 1);
    // The reconcile is refused while a cloud operation is open ...
    let r = reconcile_vip(&w.ctx(), Some(&op_id), false);
    assert!(r.is_err(), "{r:?}");
    // ... the operation lands, and an HA daemon starts at the same moment:
    w.gce.land_all();
    let sys = w.remote.host("node-b").sys.clone();
    sys.unmask("mikagami.service");
    sys.ha_start("mikagami.service");
    w.check_now("late landing");
    let r = reconcile_vip(&w.ctx(), Some(&op_id), false);
    assert!(r.is_err(), "no adoption next to an HA daemon: {r:?}");
    assert!(w.lease().op.is_some());
    w.assert_no_double_active();
}

// ===================================== chrony rollback with lost answers

#[test]
fn a_lost_answer_at_each_step_of_a_chrony_rollback_is_never_reported_as_a_clean_failure() {
    // The restart after the publish fails, so the rollback runs: restore the
    // backup, restart, verify. A lost answer at each of those steps must end
    // UNKNOWN or in a state where the claim is true.
    let steps: &[(&str, &str, u32)] = &[
        ("publish answer", op::CHRONY_PUBLISH, 0),
        ("restore", op::CHRONY_RESTORE, 0),
        ("rollback restart", op::SERVICE_CONTROL, 1),
        ("state read after restore", op::CHRONY_STATE, 2),
        ("state read after restart", op::CHRONY_STATE, 3),
    ];
    for (name, operation, skip) in steps {
        for (fault_name, fault) in [
            ("drop-before", Fault::DropBefore),
            ("drop-after", Fault::DropAfter),
            ("timeout-after", Fault::TimeoutAfter),
        ] {
            let case = format!("{name} {fault_name}");
            let w = World::new("it-chrony-rollback-loss");
            w.remote.inject_when(
                "node-a",
                op::SERVICE_CONTROL,
                Some("restart"),
                0,
                1,
                Fault::FailBefore("restart failed".into()),
            );
            w.remote
                .inject_when("node-a", operation, None, *skip, 1, fault);
            let r = super::chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
            assert_apply_claims(&case, &w, &r);
            assert!(
                !matches!(&r, Ok(report) if !report.changed),
                "{case}: {r:?}"
            );
        }
    }
}

// ================================================= C: back to HA mode

/// The conditions of `QUICKSTART.md` §6 ("Manual -> HA", step 1) that can be
/// read from `mkg status --json` of the VIP, which is read-only: the
/// predicate an operator evaluates (with `jq` or by eye) before running
/// `install.sh --ha-mode --confirm-manual-stopped` on `host`. Returns the
/// reasons it is not safe yet.
fn ha_return_blockers(status: &Value, host: &str) -> Vec<String> {
    let mut out = Vec::new();
    if status["verdict"] != "consistent" {
        out.push(format!("verdict is {}", status["verdict"]));
    }
    if !status["operation"].is_null() {
        out.push("an operation is recorded".to_string());
    }
    if status["recorded_owner"] == host {
        out.push("this host is the recorded VIP owner".to_string());
    }
    let node = &status["nodes"][host];
    if node["holds_vip"] != json!(false) {
        out.push("this host holds the VIP alias (or it is unknown)".to_string());
    }
    if node["service_active"] != json!(false) {
        out.push("the managed service runs here (or it is unknown)".to_string());
    }
    if node["ha_daemon"] != "masked" && node["ha_daemon"] != "absent" {
        out.push("the HA exclusion is not proven here".to_string());
    }
    if status["cloud_holders"].as_array().is_none_or(Vec::is_empty) {
        out.push("nobody holds the VIP".to_string());
    }
    out
}

#[test]
fn the_return_to_ha_mode_is_checkable_from_the_read_only_status() {
    let w = World::new("it-ha-return");
    let status = |w: &World| serde_json::to_value(vip_status(&w.ctx())).unwrap();
    // node-a owns and serves the VIP: it must not go back to HA yet, node-b
    // (which holds nothing and runs nothing) may.
    let s = status(&w);
    assert!(!ha_return_blockers(&s, "node-a").is_empty());
    assert_eq!(ha_return_blockers(&s, "node-b"), Vec::<String>::new());
    // The operator stops the managed service on node-b ... it was stopped.
    // An operation in progress anywhere blocks both.
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let _ = mv(&w, "node-b");
    let s = status(&w);
    for host in ["node-a", "node-b"] {
        assert!(
            !ha_return_blockers(&s, host).is_empty(),
            "{host}: an unresolved operation blocks the return"
        );
    }
    // A host that does not answer is never "safe".
    let w = World::new("it-ha-return-down");
    w.remote.host("node-b").reachable.set(false);
    let s = status(&w);
    assert!(!ha_return_blockers(&s, "node-b").is_empty());
    // A running service on the host blocks it.
    let w = World::new("it-ha-return-running");
    w.remote
        .host("node-b")
        .sys
        .set_service("mkg-demo.service", "active");
    let s = status(&w);
    assert!(!ha_return_blockers(&s, "node-b").is_empty());
    // An HA daemon already running there blocks it as well.
    let w = World::new("it-ha-return-ha");
    let sys = w.remote.host("node-b").sys.clone();
    sys.unmask("mikagami.service");
    sys.ha_start("mikagami.service");
    let s = status(&w);
    assert!(!ha_return_blockers(&s, "node-b").is_empty());
}

#[test]
fn the_manual_plane_refuses_every_change_on_a_host_that_went_back_to_ha_mode() {
    // The other half of the return (QUICKSTART §6, step 4): once the units
    // are unmasked, everything the manual plane could still do there is
    // refused, and nothing is changed.
    let w = World::new("it-after-ha-return");
    let node_b = w.remote.host("node-b").sys.clone();
    node_b.unmask("mikagami.service");
    let before = snap(&w);
    let r = mv(&w, "node-b");
    assert!(matches!(&r, Err(Failure::Refused(_))), "{r:?}");
    let r = super::chrony_ctl::service_action(&w.ctx(), "node-b", "restart");
    assert!(matches!(&r, Err(Failure::Refused(_))), "{r:?}");
    let r = super::chrony_ctl::apply(&w.ctx(), "node-b", NEW, false);
    assert!(matches!(&r, Err(Failure::Refused(_))), "{r:?}");
    assert_eq!(live(&w, "node-b"), OLD);
    assert_eq!(snap(&w), before);
    assert_eq!(w.gce.change_count(), 0);
    // "unknown" is a refusal too: the host does not answer.
    let w = World::new("it-after-ha-return-down");
    w.remote.host("node-b").reachable.set(false);
    let r = mv(&w, "node-b");
    assert!(matches!(&r, Err(Failure::Refused(_))), "{r:?}");
    assert_eq!(snap(&w), start_state());
}

// ============================ the first audit's reproductions stay covered

/// Every reproduction of the first independent audit (`audit/repro/*.rs`,
/// kept unmodified) and the regression test that carries it, with its
/// expectation turned round. The guard below fails when a reproduction has no
/// entry, or an entry's test no longer exists, so the set cannot shrink
/// silently.
const REPRO_MAP: &[(&str, &str, &str)] = &[
    (
        "audit_b_vip_tests.rs",
        "b_v1_stale_controller_rollback_undoes_the_new_holders_quiesce",
        "safety_tests.rs::b02_a_controller_that_lost_the_lock_touches_nothing_when_it_resumes",
    ),
    (
        "audit_b_vip_tests.rs",
        "b_v2_reconcile_cuts_into_a_live_mutating_move",
        "safety_tests.rs::b01_a_reconcile_cannot_cut_into_a_live_mutating_move",
    ),
    (
        "audit_c_tests.rs",
        "v1_late_detach_after_verified_rollback",
        "safety_tests.rs::c01_v1_a_pending_detach_is_unknown_and_nothing_is_restarted",
    ),
    (
        "audit_c_tests.rs",
        "v2_late_attach_after_verified_rollback",
        "safety_tests.rs::c01_v2_a_pending_attach_never_triggers_a_re_add_to_the_source",
    ),
    (
        "audit_c_tests.rs",
        "v3_done_but_lagging_reads_is_caught_by_the_serve_probe",
        "vip_tests.rs::cloud_read_lag_never_causes_an_early_assignment",
    ),
    (
        "audit_c_tests.rs",
        "v3b_stale_target_read_creates_double_alias_and_false_restored",
        "safety_tests.rs::c01_v3b_a_stale_read_of_the_target_never_re_adds_to_the_source",
    ),
    (
        "audit_c_tests.rs",
        "d1_rollback_starts_a_source_service_that_was_down_before",
        "safety_tests.rs::c06_a_source_service_that_was_down_is_not_started_by_the_rollback",
    ),
    (
        "audit_c_tests.rs",
        "d2_fence_proof_is_not_rechecked_before_assign_or_commit",
        "safety_tests.rs::c02_a_source_that_starts_after_the_proof_stops_the_move_before_the_release",
    ),
    (
        "audit_c_tests.rs",
        "d3_target_dies_between_verification_and_commit",
        "safety_tests.rs::c07_a_target_that_dies_before_the_last_look_is_rolled_back",
    ),
    (
        "audit_c_tests.rs",
        "d4_source_stop_check_accepts_deactivating",
        "safety_tests.rs::c08_a_unit_that_is_still_changing_state_is_not_stopped",
    ),
    (
        "audit_c_tests.rs",
        "d5_source_local_probe_error_is_ignored",
        "safety_tests.rs::c08_a_probe_that_cannot_be_performed_is_retried_and_never_a_silent_pass",
    ),
    (
        "audit_d_tests.rs",
        "d01_late_publish_between_reread_and_cleanup_gives_false_unchanged",
        "chrony_ctl.rs::d01_a_publish_that_arrives_after_the_fence_cannot_change_the_file",
    ),
    (
        "audit_d_tests.rs",
        "d02_edit_inside_cas_window_is_lost_and_apply_succeeds",
        "chrony_agent.rs::d02_an_edit_inside_the_compare_window_is_put_back_and_the_publish_refused",
    ),
    (
        "audit_d_tests.rs",
        "d03_mode_not_preserved_on_apply_and_rollback",
        "chrony_ctl.rs::d03_the_mode_and_group_of_the_live_file_survive_apply_and_rollback",
    ),
    (
        "audit_d_tests.rs",
        "d04_unit_mismatch_between_controller_and_agent_is_a_false_success",
        "chrony_ctl.rs::d04_a_controller_and_agent_that_disagree_on_the_unit_change_nothing",
    ),
    (
        "audit_b_lease_tests.rs",
        "b_l1_unlinked_lock_file_admits_a_second_holder",
        "lease.rs::unlinking_the_lock_file_does_not_admit_a_second_holder",
    ),
    (
        "audit_b_lease_tests.rs",
        "b_l2_restored_old_backup_double_grants_epoch_and_erases_the_mutating_op",
        "safety_tests.rs::b04_a_record_restored_from_an_old_copy_is_detected_and_repaired_by_reconcile",
    ),
    (
        "audit_b_lease_tests.rs",
        "b_l3_missing_op_key_is_read_as_no_operation",
        "lease.rs::every_key_is_required_and_unknown_keys_are_damage",
    ),
    (
        "audit_b_lease_tests.rs",
        "b_l4_missing_file_is_a_fresh_start_and_epoch_restarts",
        "lease.rs::a_missing_state_file_of_an_initialised_store_is_not_a_fresh_start",
    ),
    (
        "audit_b_lease_tests.rs",
        "b_l5_world_writable_dir_and_state_are_accepted",
        "lease.rs::the_state_directory_and_file_must_be_private_and_owned",
    ),
    (
        "audit_b_lease_tests.rs",
        "b_l6_epoch_at_start_is_never_compared",
        "lease.rs::the_epoch_recorded_at_the_start_is_checked_by_every_later_step",
    ),
    (
        "audit_b_lease_tests.rs",
        "b_l7_clock_steps",
        "lease.rs::wall_clock_steps_only_affect_liveness_of_an_unmutated_lock",
    ),
    (
        "audit_b_lease_tests.rs",
        "b_l8_rename_failure_keeps_old_state_and_cleans_tmp",
        "lease.rs::a_refused_write_to_a_read_only_directory_keeps_the_old_state",
    ),
    (
        "audit_b_lease_tests.rs",
        "b_l9_large_evidence_bricks_the_store",
        "lease.rs::evidence_is_capped_so_the_store_can_never_be_bricked",
    ),
];

/// `name` is declared in `source` as a function that carries `#[test]` and
/// no `#[ignore]` (audit RA-F-04: the map used to look for the text
/// `fn name(` only, which a helper, a commented-out test or an ignored test
/// satisfies). The attributes are the lines directly above the declaration.
/// Whether the test fails against the code before the fix is not checked here;
/// that was shown by the auditors' runs of the reproductions.
fn is_a_test(source: &str, name: &str) -> bool {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    lines.iter().enumerate().any(|(at, line)| {
        let declares = line
            .strip_prefix("fn ")
            .or_else(|| line.strip_prefix("pub fn "))
            .or_else(|| line.strip_prefix("pub(crate) fn "))
            .is_some_and(|rest| {
                rest.strip_prefix(name)
                    .is_some_and(|tail| tail.starts_with('(') || tail.starts_with('<'))
            });
        if !declares {
            return false;
        }
        let mut attributes = Vec::new();
        for above in lines[..at].iter().rev() {
            if above.starts_with("#[") {
                attributes.push(*above);
            } else {
                break;
            }
        }
        attributes.contains(&"#[test]") && !attributes.iter().any(|a| a.starts_with("#[ignore"))
    })
}

#[test]
fn the_map_check_tells_a_test_from_a_function_that_only_has_the_name() {
    let src = "#[test]\nfn real() {}\n\nfn helper() {}\n\n// #[test]\n// fn commented() {}\n\n#[test]\n#[ignore]\nfn ignored() {}\n\n#[test]\n#[should_panic]\nfn with_other_attribute() {}\n\nconst S: &str = \"fn in_a_string(\";\n\n#[test]\nfn real_two_words_after() {}\n\nfn real_prefix() {}\n";
    assert!(is_a_test(src, "real"));
    assert!(is_a_test(src, "with_other_attribute"));
    assert!(is_a_test(src, "real_two_words_after"));
    for not in [
        "helper",
        "commented",
        "ignored",
        "in_a_string",
        "missing",
        "real_prefix",
        "rea",
    ] {
        assert!(!is_a_test(src, not), "{not}");
    }
}

#[test]
fn every_reproduction_of_the_first_audit_has_a_regression_test_that_exists() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let repro = root.join("prototype/v0.2/audit/repro");
    let manual = root.join("src/manual");
    let mut found = 0;
    for file in [
        "audit_b_vip_tests.rs",
        "audit_c_tests.rs",
        "audit_d_tests.rs",
        "audit_b_lease_tests.rs",
    ] {
        let text = std::fs::read_to_string(repro.join(file)).unwrap();
        let mut previous_was_test = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed == "#[test]" {
                previous_was_test = true;
                continue;
            }
            if previous_was_test && let Some(rest) = trimmed.strip_prefix("fn ") {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let entry = REPRO_MAP
                    .iter()
                    .find(|(f, n, _)| *f == file && *n == name)
                    .unwrap_or_else(|| {
                        panic!("{file}::{name} has no regression test in REPRO_MAP")
                    });
                let (target_file, target_name) = entry.2.split_once("::").unwrap();
                let source = std::fs::read_to_string(manual.join(target_file)).unwrap();
                assert!(
                    is_a_test(&source, target_name),
                    "{}: the test {} no longer exists or is no `#[test]` that runs",
                    name,
                    entry.2
                );
                found += 1;
            }
            previous_was_test = false;
        }
    }
    assert_eq!(
        found,
        REPRO_MAP.len(),
        "REPRO_MAP lists a reproduction that is not in the files"
    );
}
