//! Regression tests for the round-1 audit findings on the exclusion between
//! the manual control plane and the production HA daemon (EX-01 .. EX-06).
//!
//! The central scenario is "the HA daemon appears in the middle of an
//! operation": at each phase boundary of a move, on each of the three hosts,
//! the host's state is flipped in one of several ways (unmasked, started,
//! unit gone, job queued, daemon started by hand, ...). The world's safety
//! monitor (`fakes.rs`) knows the ground truth (is an HA daemon running?) and
//! reports any manual change that happens while one is.

use super::fakes::{Fault, World};
use super::proto::op;
use super::vip::*;
use super::{Failure, Res};
use serde_json::{Value, json};
use std::cell::Cell;
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

fn ha_unit_of(host: &str) -> &'static str {
    if host == "witness" {
        "mikagami-witness.service"
    } else {
        "mikagami.service"
    }
}

/// Ways a host can stop being provably free of the HA daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flip {
    /// Unmasked and started (a boot, or `systemctl unmask && start`).
    Started,
    /// Unmasked, still inactive.
    Unmasked,
    /// The unit is starting.
    Activating,
    /// The unit file disappeared (or was renamed).
    NotFound,
    /// Only a runtime mask is left.
    RuntimeMask,
    /// A start job is queued.
    Job,
    /// `mikagami daemon run` started by hand.
    Process,
}

const ALL_FLIPS: [Flip; 7] = [
    Flip::Started,
    Flip::Unmasked,
    Flip::Activating,
    Flip::NotFound,
    Flip::RuntimeMask,
    Flip::Job,
    Flip::Process,
];

fn apply_flip(w: &World, host: &str, flip: Flip) {
    let sys = &w.remote.host(host).sys;
    let unit = ha_unit_of(host);
    match flip {
        Flip::Started => {
            sys.unmask(unit);
            assert!(w.ha_start(host, unit), "an unmasked unit starts");
        }
        Flip::Unmasked => sys.unmask(unit),
        Flip::Activating => {
            sys.unmask(unit);
            sys.set_service(unit, "activating");
        }
        Flip::NotFound => sys.remove_unit(unit),
        Flip::RuntimeMask => sys.runtime_mask(unit),
        Flip::Job => sys.set_jobs(&[unit]),
        Flip::Process => sys.set_ha_processes(&["pid 4242: mikagami daemon run"]),
    }
}

/// The move did not complete and did not claim anything it cannot prove.
fn assert_stopped(r: &Res<MoveReport>, context: &str) -> String {
    match r {
        Err(f) => f.message().to_string(),
        Ok(report) => panic!("{context}: the move must not succeed: {report:?}"),
    }
}

fn assert_nothing_changed(w: &World, context: &str) {
    assert_eq!(w.gce.change_count(), 0, "{context}: cloud changed");
    assert!(
        w.remote.host("node-a").sys.actions().is_empty()
            && w.remote.host("node-b").sys.actions().is_empty(),
        "{context}: a service was touched"
    );
    assert_eq!(w.cloud_holders(), ["node-a"], "{context}");
    w.assert_no_double_active();
}

// ---------------------------------------------------------------------------
// the normal case
// ---------------------------------------------------------------------------

#[test]
fn a_move_on_masked_hosts_records_every_recheck_as_evidence() {
    let w = World::new("excl-normal");
    let report = mv(&w, "node-b").expect("masked hosts allow a move");
    let rechecks = report.evidence["ha_rechecks"].as_array().expect("recorded");
    let points: Vec<&str> = rechecks
        .iter()
        .map(|c| c["point"].as_str().unwrap())
        .collect();
    assert_eq!(
        points,
        [
            "before_quiesce",
            "before_release",
            "before_assign",
            "before_commit"
        ]
    );
    for check in rechecks {
        for host in ["node-a", "node-b", "witness"] {
            assert_eq!(check["hosts"][host], "masked", "{check}");
        }
    }
    w.assert_settled();
}

#[test]
fn a_mask_stops_an_ha_start_in_the_middle_of_a_move() {
    // The administrator (or a reboot) tries to start the HA units at every
    // phase boundary. The mask refuses; the move completes; no HA unit ever
    // ran, so nothing could have been duplicated.
    let w = World::new("excl-mask-holds");
    for host in ["node-a", "node-b", "witness"] {
        for phase in [
            "source_quiescing",
            "source_released",
            "target_assigning",
            "target_assigned",
            "target_started",
        ] {
            let ww = w_handle(&w);
            let needle = format!("\"phase\":\"{phase}\"");
            w.remote.inject_when(
                "witness",
                op::LEASE_PHASE,
                Some(needle.as_str()),
                0,
                1,
                Fault::Hook(Rc::new(move || {
                    for unit in ["mikagami.service", "mikagami-witness.service"] {
                        assert!(!ww.ha_start(host, unit), "a masked unit must not start");
                    }
                })),
            );
        }
    }
    mv(&w, "node-b").expect("the move is not disturbed");
    for host in ["node-a", "node-b", "witness"] {
        assert!(w.remote.host(host).sys.ha_starts().is_empty());
    }
    w.assert_settled();
}

/// A shared handle to the world for hooks (the world itself is not `Clone`).
struct WorldHandle {
    remote: super::fakes::FakeRemote,
    events: Rc<std::cell::RefCell<Vec<String>>>,
}

impl WorldHandle {
    fn ha_start(&self, host: &str, unit: &str) -> bool {
        let started = self.remote.host(host).sys.ha_start(unit);
        if started {
            self.events
                .borrow_mut()
                .push(format!("ha start {host} {unit}"));
        }
        started
    }
}

fn w_handle(w: &World) -> Rc<WorldHandle> {
    Rc::new(WorldHandle {
        remote: w.remote.clone(),
        events: w.events.clone(),
    })
}

// ---------------------------------------------------------------------------
// before anything is touched
// ---------------------------------------------------------------------------

#[test]
fn an_unproven_exclusion_on_any_host_refuses_the_move_before_anything_changes() {
    for host in ["node-a", "node-b", "witness"] {
        for flip in ALL_FLIPS {
            let w = World::new(&format!("excl-pre-{host}-{flip:?}"));
            apply_flip(&w, host, flip);
            let r = mv(&w, "node-b");
            let context = format!("{host} {flip:?}");
            assert!(
                matches!(&r, Err(Failure::Refused(_))),
                "{context}: expected REFUSED, got {r:?}"
            );
            assert_nothing_changed(&w, &context);
            // The preflight stops it: not even the lease was asked for.
            assert_eq!(
                w.count_agent_calls("witness", op::LEASE_ACQUIRE),
                0,
                "{context}: the lease was requested although the exclusion was not proven"
            );
        }
    }
}

#[test]
fn an_unmasked_but_inactive_unit_is_refused_with_the_reason_and_the_remedy() {
    let w = World::new("excl-reason");
    w.remote.host("node-b").sys.unmask("mikagami.service");
    let message = assert_stopped(&mv(&w, "node-b"), "unmasked target");
    assert!(
        message.contains("unmasked") && message.contains("loaded") && message.contains("masked"),
        "{message}"
    );
}

// ---------------------------------------------------------------------------
// the HA daemon appears during the move
// ---------------------------------------------------------------------------

#[test]
fn an_ha_daemon_that_appears_at_any_phase_boundary_stops_the_move_without_a_further_change() {
    let phases = [
        "lease.acquire",
        "source_quiescing",
        "source_released",
        "target_assigning",
        "target_assigned",
        "target_started",
    ];
    for phase in phases {
        for host in ["node-a", "node-b", "witness"] {
            for flip in ALL_FLIPS {
                let context = format!("{phase} / {host} / {flip:?}");
                let w = World::new(&format!("excl-mid-{phase}-{host}-{flip:?}"));
                let changes_at_flip = Rc::new(Cell::new(usize::MAX));
                let handle = w_handle(&w);
                let gce = w.gce.clone();
                let sys = w.remote.host(host).sys.clone();
                let unit = ha_unit_of(host);
                let seen = changes_at_flip.clone();
                let hook: Rc<dyn Fn()> = Rc::new(move || {
                    seen.set(gce.change_count());
                    match flip {
                        Flip::Started => {
                            sys.unmask(unit);
                            assert!(handle.ha_start(host, unit));
                        }
                        Flip::Unmasked => sys.unmask(unit),
                        Flip::Activating => {
                            sys.unmask(unit);
                            sys.set_service(unit, "activating");
                        }
                        Flip::NotFound => sys.remove_unit(unit),
                        Flip::RuntimeMask => sys.runtime_mask(unit),
                        Flip::Job => sys.set_jobs(&[unit]),
                        Flip::Process => {
                            sys.set_ha_processes(&["pid 4242: mikagami daemon run"]);
                        }
                    }
                });
                if phase == "lease.acquire" {
                    w.remote.inject_when(
                        "witness",
                        op::LEASE_ACQUIRE,
                        None,
                        0,
                        1,
                        Fault::Hook(hook),
                    );
                } else {
                    let needle = format!("\"phase\":\"{phase}\"");
                    w.remote.inject_when(
                        "witness",
                        op::LEASE_PHASE,
                        Some(needle.as_str()),
                        0,
                        1,
                        Fault::Hook(hook),
                    );
                }
                let r = mv(&w, "node-b");
                let message = assert_stopped(&r, &context);
                assert_ne!(changes_at_flip.get(), usize::MAX, "{context}: hook ran");
                assert_eq!(
                    w.gce.change_count(),
                    changes_at_flip.get(),
                    "{context}: an alias was changed after the HA daemon appeared: {message}"
                );
                // Never reported as a clean outcome.
                assert!(
                    !message.contains("rolled back and verified"),
                    "{context}: {message}"
                );
                w.assert_no_double_active();
            }
        }
    }
}

#[test]
fn a_halt_after_a_change_keeps_the_record_and_does_not_roll_back() {
    // HA appears on the target after the source has been released: the
    // controller must not "restore" anything (an HA daemon may be acting).
    let w = World::new("excl-halt-record");
    let handle = w_handle(&w);
    let sys = w.remote.host("node-b").sys.clone();
    w.remote.inject_when(
        "witness",
        op::LEASE_PHASE,
        Some("\"phase\":\"target_assigning\""),
        0,
        1,
        Fault::Hook(Rc::new(move || {
            sys.unmask("mikagami.service");
            assert!(handle.ha_start("node-b", "mikagami.service"));
        })),
    );
    let r = mv(&w, "node-b");
    let message = assert_stopped(&r, "halt");
    assert!(matches!(r, Err(Failure::Unknown(_))), "{message}");
    assert!(
        message.contains("re-confirmed") && message.contains("before_assign"),
        "{message}"
    );
    assert!(w.lease().op.is_some(), "the operation stays recorded");
    // Source released, nothing else done: no restore, no start.
    assert_eq!(w.gce.change_count(), 1);
    assert!(
        w.remote.host("node-a").sys.actions() == ["stop mkg-demo.service"],
        "{:?}",
        w.remote.host("node-a").sys.actions()
    );
}

#[test]
fn before_the_first_change_the_lock_is_released_cleanly() {
    let w = World::new("excl-before-first");
    let sys = w.remote.host("node-b").sys.clone();
    w.remote.inject_when(
        "witness",
        op::LEASE_ACQUIRE,
        None,
        0,
        1,
        Fault::Hook(Rc::new(move || sys.unmask("mikagami.service"))),
    );
    let r = mv(&w, "node-b");
    // R4: the move did not start and nothing changed, exactly as when the
    // same condition is found by the pre-flight check: a refusal (exit 3).
    assert!(
        matches!(&r, Err(Failure::Refused(m)) if m.contains("before_quiesce")),
        "{r:?}"
    );
    assert!(
        w.lease().op.is_none(),
        "nothing was changed, so the lock is released"
    );
    assert_nothing_changed(&w, "before the first change");
}

#[test]
fn rollback_rechecks_the_exclusion_before_it_changes_an_alias() {
    // The move fails after the assignment (target service will not start);
    // while the rollback is running an HA daemon appears on the witness: the
    // alias removal must not happen.
    let w = World::new("excl-rollback");
    w.remote.host("node-b").sys.fail_action("start");
    let sys = w.remote.host("witness").sys.clone();
    let handle = w_handle(&w);
    let gce = w.gce.clone();
    let seen = Rc::new(Cell::new(usize::MAX));
    let seen_in = seen.clone();
    // The target's start fails; right before it is attempted the HA daemon
    // appears on the Witness, so the rollback that follows must not start by
    // removing the alias it just assigned.
    w.remote.inject_when(
        "node-b",
        op::SERVICE_CONTROL,
        Some("\"action\":\"start\""),
        0,
        1,
        Fault::Hook(Rc::new(move || {
            seen_in.set(gce.change_count());
            sys.unmask("mikagami-witness.service");
            assert!(handle.ha_start("witness", "mikagami-witness.service"));
        })),
    );
    let r = mv(&w, "node-b");
    let message = assert_stopped(&r, "rollback");
    assert_ne!(seen.get(), usize::MAX, "the hook ran");
    assert_eq!(seen.get(), 2, "release and assignment had happened");
    assert_eq!(
        w.gce.change_count(),
        2,
        "no alias change after the flip: {message}"
    );
    assert!(message.contains("rollback_remove_target"), "{message}");
    w.assert_no_double_active();
}

#[test]
fn rollback_rechecks_again_before_it_gives_the_alias_back_to_the_source() {
    // The move fails after the assignment; the rollback removes the target's
    // alias and stops its service. An HA daemon appears on the Witness in
    // between: the source must not get the alias back.
    let w = World::new("excl-rollback-source");
    w.remote.host("node-b").sys.fail_action("start");
    let sys = w.remote.host("witness").sys.clone();
    let handle = w_handle(&w);
    let gce = w.gce.clone();
    let seen = Rc::new(Cell::new(usize::MAX));
    let seen_in = seen.clone();
    // The first `stop` on the target is the rollback's.
    w.remote.inject_when(
        "node-b",
        op::SERVICE_CONTROL,
        Some("\"action\":\"stop\""),
        0,
        1,
        Fault::Hook(Rc::new(move || {
            seen_in.set(gce.change_count());
            sys.unmask("mikagami-witness.service");
            assert!(handle.ha_start("witness", "mikagami-witness.service"));
        })),
    );
    let r = mv(&w, "node-b");
    let message = assert_stopped(&r, "rollback source");
    assert_eq!(
        seen.get(),
        3,
        "release, assignment and the target removal had happened"
    );
    assert_eq!(
        w.gce.change_count(),
        3,
        "no alias change after the flip: {message}"
    );
    assert!(message.contains("rollback_restore_source"), "{message}");
    w.assert_no_double_active();
}

#[test]
fn a_ping_answer_without_an_explicit_proof_is_not_a_proof() {
    let masked = json!({"node": "n", "ha_daemon": "masked", "ha_proven": true});
    assert!(parse_ping(&masked).ha_safe());
    for answer in [
        json!({"node": "n", "ha_daemon": "masked"}),
        json!({"node": "n", "ha_daemon": "masked", "ha_proven": "true"}),
        json!({"node": "n", "ha_daemon": "masked", "ha_proven": null}),
        json!({"node": "n", "ha_proven": true}),
        json!({"node": "n", "ha_daemon": "inactive", "ha_proven": true}),
        json!({"node": "n", "ha_daemon": "active", "ha_proven": true}),
        json!({"node": "n"}),
    ] {
        assert!(!parse_ping(&answer).ha_safe(), "{answer}");
    }
    let rich = parse_ping(&json!({
        "node": "n", "ha_daemon": "unmasked", "ha_proven": false,
        "ha_units": {"mikagami.service": "loaded", "bad": 3},
        "ha_detail": ["x".repeat(500), 7],
    }));
    assert_eq!(rich.ha_units.len(), 1);
    assert_eq!(rich.ha_detail.len(), 1);
    assert_eq!(rich.ha_detail[0].chars().count(), 200);
}

// ---------------------------------------------------------------------------
// the monitor itself
// ---------------------------------------------------------------------------

#[test]
fn the_monitor_flags_an_alias_change_while_an_ha_daemon_runs() {
    use super::gce::{Alias, Gce};
    let w = World::new("excl-monitor");
    w.remote.host("node-b").sys.unmask("mikagami.service");
    assert!(w.ha_start("node-b", "mikagami.service"));
    // A controller without the re-check would go on to change an alias.
    let _ = w.gce.set_aliases(
        "inst-b",
        &[Alias {
            cidr: "10.9.9.9/32".to_string(),
            range_name: None,
        }],
        "x",
    );
    assert!(
        w.violations
            .borrow()
            .iter()
            .any(|v| v.contains("alias change while an HA daemon runs")),
        "{:?}",
        w.violations.borrow()
    );
}

// ---------------------------------------------------------------------------
// status / init / reconcile
// ---------------------------------------------------------------------------

#[test]
fn status_contains_the_ha_state_of_every_host() {
    let w = World::new("excl-status");
    let status = vip_status(&w.ctx());
    assert_eq!(status.verdict, "consistent", "{:?}", status.problems);
    assert_eq!(status.witness_ha.as_deref(), Some("masked"));
    for n in status.nodes.values() {
        assert_eq!(n.ha_daemon.as_deref(), Some("masked"));
        assert_eq!(n.ha_units["mikagami.service"], "masked");
    }
    // A host that merely is not masked: consistent no more.
    for host in ["node-a", "node-b", "witness"] {
        let w = World::new(&format!("excl-status-unmasked-{host}"));
        w.remote.host(host).sys.unmask(ha_unit_of(host));
        let status = vip_status(&w.ctx());
        assert_eq!(status.verdict, "unknown", "{host}: {:?}", status.problems);
        assert!(
            status.problems.iter().any(|p| p.contains("not proven")),
            "{host}: {:?}",
            status.problems
        );
    }
    // A running one beats everything.
    for host in ["node-a", "node-b", "witness"] {
        let w = World::new(&format!("excl-status-active-{host}"));
        apply_flip(&w, host, Flip::Started);
        let status = vip_status(&w.ctx());
        assert_eq!(
            status.verdict, "ha_conflict",
            "{host}: {:?}",
            status.problems
        );
    }
    // Pending job / hand-started daemon also count as running.
    for flip in [Flip::Job, Flip::Process, Flip::Activating] {
        let w = World::new(&format!("excl-status-{flip:?}"));
        apply_flip(&w, "node-b", flip);
        assert_eq!(vip_status(&w.ctx()).verdict, "ha_conflict", "{flip:?}");
    }
}

#[test]
fn a_status_never_mutates_even_when_an_ha_daemon_runs() {
    let w = World::new("excl-status-readonly");
    apply_flip(&w, "node-b", Flip::Started);
    let before = w.events.borrow().len();
    let _ = vip_status(&w.ctx());
    assert_eq!(w.events.borrow().len(), before);
    assert_eq!(w.gce.change_count(), 0);
}

#[test]
fn init_and_reconcile_need_the_exclusion_on_the_owner_the_other_node_and_the_witness() {
    for host in ["node-a", "node-b", "witness"] {
        for flip in [Flip::Unmasked, Flip::NotFound, Flip::Started, Flip::Job] {
            // reconcile
            let w = World::new(&format!("excl-rec-{host}-{flip:?}"));
            apply_flip(&w, host, flip);
            let r = reconcile_vip(&w.ctx(), None, false);
            assert!(r.is_err(), "reconcile {host} {flip:?}: {r:?}");
            // init
            let w = World::build(&format!("excl-init-{host}-{flip:?}"), false);
            apply_flip(&w, host, flip);
            let r = init_vip(&w.ctx(), "node-a", false);
            assert!(
                matches!(&r, Err(Failure::Refused(_))),
                "init {host} {flip:?}: {r:?}"
            );
            assert!(w.lease().owner.is_none(), "nothing was recorded");
        }
    }
    // `init` reports what its record rests on, HA state included.
    let w = World::build("excl-init-ok", false);
    let r = init_vip(&w.ctx(), "node-a", false).unwrap();
    assert_eq!(r.evidence["ha"]["node-a"], "masked");
    assert_eq!(r.evidence["ha"]["witness"], "masked");
    // And the happy path writes its HA evidence into the record.
    let w = World::new("excl-rec-ok");
    w.remote
        .host("node-b")
        .sys
        .set_service("mkg-demo.service", "inactive");
    let r = reconcile_vip(&w.ctx(), None, false).unwrap();
    assert_eq!(r.evidence["ha"]["witness"], "masked");
    assert_eq!(r.evidence["ha"]["node-a"], "masked");
    assert_eq!(r.evidence["ha"]["node-b"], "masked");
}

#[test]
fn a_terminated_other_node_is_not_asked_and_does_not_block_a_reconcile() {
    let w = World::new("excl-terminated-other");
    w.gce.set_status("inst-b", "TERMINATED");
    w.remote.host("node-b").reachable.set(false);
    let r = reconcile_vip(&w.ctx(), None, false).unwrap();
    assert!(r.evidence["ha"].get("node-b").is_none());
    assert_eq!(r.evidence["ha"]["witness"], "masked");
}

#[test]
fn an_agent_that_only_says_inactive_is_not_a_proof() {
    // An older agent (or a damaged answer) without the proof fields.
    let w = World::new("excl-old-agent");
    let ctx = w.ctx();
    let target = ctx.node_target("node-b").unwrap();
    // Answer a ping by hand the way an old agent would.
    let p = Ping {
        ha_daemon: "inactive".to_string(),
        ha_proven: false,
        ha_units: Default::default(),
        ha_detail: vec![],
        fence: None,
        fence_error: None,
        manual_barrier: None,
    };
    assert!(!p.ha_safe());
    let lying = Ping {
        ha_daemon: "active".to_string(),
        ha_proven: true,
        ..p.clone()
    };
    assert!(!lying.ha_safe(), "flag and word must agree");
    let _ = target;
    let ok = Ping {
        ha_daemon: "masked".to_string(),
        ha_proven: true,
        ..p
    };
    assert!(ok.ha_safe());
    let _: Value = json!({});
}

// ---------------------------------------------------------------------------
// chronyd (audit EX-06)
// ---------------------------------------------------------------------------

mod chrony {
    use super::*;
    use crate::manual::chrony_ctl::apply;
    use std::fs;

    const OLD: &str = "pool 2.pool.ntp.org iburst\n";
    const NEW: &str = "pool time.example.invalid iburst\nmakestep 1 3\n";

    fn live(w: &World, node: &str) -> String {
        fs::read_to_string(&w.remote.host(node).env.cfg.chrony_conf).unwrap()
    }

    fn leftovers(w: &World, node: &str) -> Vec<String> {
        let dir = w
            .remote
            .host(node)
            .env
            .cfg
            .chrony_conf
            .parent()
            .unwrap()
            .to_path_buf();
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".mkg-"))
            .collect()
    }

    #[test]
    fn an_apply_starts_only_when_the_exclusion_is_proven() {
        for flip in ALL_FLIPS {
            let w = World::new(&format!("excl-chrony-pre-{flip:?}"));
            apply_flip(&w, "node-a", flip);
            let r = apply(&w.ctx(), "node-a", NEW, false);
            assert!(
                matches!(&r, Err(Failure::Refused(m)) if m.contains("not proven")),
                "{flip:?}: {r:?}"
            );
            assert_eq!(live(&w, "node-a"), OLD);
            assert!(leftovers(&w, "node-a").is_empty());
            assert_eq!(
                w.count_agent_calls("node-a", op::CHRONY_BACKUP),
                0,
                "{flip:?}"
            );
        }
        // A dry run changes nothing and needs no proof.
        let w = World::new("excl-chrony-dry");
        apply_flip(&w, "node-a", Flip::Unmasked);
        assert!(apply(&w.ctx(), "node-a", NEW, true).is_ok());
    }

    #[test]
    fn an_ha_daemon_appearing_mid_apply_still_gets_the_file_restored_and_an_honest_report() {
        let w = World::new("excl-chrony-mid");
        let handle = w_handle(&w);
        let sys = w.remote.host("node-a").sys.clone();
        // Right before the restart that ends the apply.
        w.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("\"action\":\"restart\""),
            0,
            1,
            Fault::Hook(Rc::new(move || {
                sys.unmask("mikagami.service");
                assert!(handle.ha_start("node-a", "mikagami.service"));
            })),
        );
        let r = apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(message)) = r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        // The rollback's file restore ran even though the HA daemon is up.
        assert_eq!(live(&w, "node-a"), OLD, "{message}");
        assert!(
            leftovers(&w, "node-a").is_empty(),
            "stage files are cleaned up"
        );
        // The report says what happened instead of blaming a failed rollback.
        assert!(
            message.contains("previous file is back")
                && message.contains("did not restart chronyd"),
            "{message}"
        );
        assert!(!message.contains("ROLLBACK FAILED"), "{message}");
        // The running unit was never restarted by the controller.
        assert!(
            !w.remote
                .host("node-a")
                .sys
                .actions()
                .iter()
                .any(|a| a.starts_with("restart")),
            "{:?}",
            w.remote.host("node-a").sys.actions()
        );
    }

    #[test]
    fn the_refusal_text_names_the_real_cause() {
        let w = World::new("excl-chrony-text");
        apply_flip(&w, "node-a", Flip::Unmasked);
        let r = crate::manual::chrony_ctl::service_action(&w.ctx(), "node-a", "restart");
        let Err(Failure::Refused(message)) = r else {
            panic!("{r:?}");
        };
        assert!(
            message.contains("not proven") && message.contains("loaded"),
            "{message}"
        );
        assert!(!message.contains("is active"), "{message}");
    }
}
