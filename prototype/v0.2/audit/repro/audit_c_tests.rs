//! AUDIT C adversarial tests (not part of the product).
use super::fakes::{ChangeBehavior, Fault, VIP_CIDR, World};
use super::proto::op;
use super::vip::*;
use super::{Failure, Res};
use std::rc::Rc;

fn mv(w: &World, to: &str) -> Res<MoveReport> {
    move_vip(&w.ctx(), &MoveRequest { target: to.to_string(), confirm_fenced: None })
}
fn mv_fenced(w: &World, to: &str, confirm: &str) -> Res<MoveReport> {
    move_vip(&w.ctx(), &MoveRequest { target: to.to_string(), confirm_fenced: Some(confirm.to_string()) })
}
fn dump(w: &World, tag: &str, r: &Res<MoveReport>) {
    let lease = w.lease();
    eprintln!(
        "[{tag}] result={:?}\n  cloud a={:?} b={:?} svc a={} b={} lease owner={:?} epoch={} op={:?}",
        r.as_ref().map(|m| m.target.clone()),
        w.gce.aliases_of("inst-a"), w.gce.aliases_of("inst-b"),
        w.service_active("node-a"), w.service_active("node-b"),
        lease.owner, lease.epoch, lease.op.as_ref().map(|o| o.phase),
    );
}

/// V1: the release request times out, the controller rolls back and says
/// "rolled back and verified"; the release then lands late.
#[test]
fn v1_late_detach_after_verified_rollback() {
    let w = World::new("ac-v1");
    w.gce.script_changes("inst-a", &[ChangeBehavior::TimeoutNoApply]);
    let r = mv(&w, "node-b");
    dump(&w, "V1 before landing", &r);
    let Err(Failure::Failed(m)) = &r else { panic!("{r:?}") };
    assert!(m.contains("rolled back and verified"), "{m}");
    assert!(w.lease().op.is_none(), "lock is cleared");
    // late landing of the original request (list without the VIP)
    w.gce.set_aliases_direct("inst-a", &[]);
    dump(&w, "V1 after landing", &r);
    assert!(w.cloud_holders().is_empty(), "VIP lost although lease says node-a and report said restored");
    assert!(w.service_active("node-a"));
}

/// V2: the assign request times out; rollback re-adds to the source and says
/// restored; the assign then lands late => VIP on both NICs.
#[test]
fn v2_late_attach_after_verified_rollback() {
    let w = World::new("ac-v2");
    w.gce.script_changes("inst-b", &[ChangeBehavior::TimeoutNoApply]);
    let r = mv(&w, "node-b");
    dump(&w, "V2 before landing", &r);
    let Err(Failure::Failed(m)) = &r else { panic!("{r:?}") };
    assert!(m.contains("rolled back and verified"), "{m}");
    w.gce.set_aliases_direct("inst-b", &[VIP_CIDR]);
    dump(&w, "V2 after landing", &r);
    assert_eq!(w.cloud_holders(), ["node-a", "node-b"]);
    assert!(w.lease().op.is_none());
}

/// V3: gcloud says Done but the read path lags longer than the 90 s window.
/// POSITIVE control: here the Witness probe of the rolled-back source fails
/// (the release really applied), so the rollback ends as UNKNOWN.
#[test]
fn v3_done_but_lagging_reads_is_caught_by_the_serve_probe() {
    let w = World::new("ac-v3");
    w.gce.set_lag(200);
    let r = mv(&w, "node-b");
    dump(&w, "V3", &r);
    assert!(matches!(&r, Err(Failure::Unknown(m)) if m.contains("rollback incomplete")), "{r:?}");
}

/// V3b: assign is Done but target reads lag; rollback decides from a single
/// stale read that the target does not hold the VIP and re-adds to the source.
#[test]
fn v3b_stale_target_read_creates_double_alias_and_false_restored() {
    let w = World::new("ac-v3b");
    let g = w.gce.clone();
    // lag only for the second change (assign to b)
    w.remote.inject("node-b", op::SERVICE_STATUS, Fault::Hook(Rc::new(move || g.set_lag(200))));
    let g2 = w.gce.clone();
    // clear the lag before the rollback re-adds to the source
    w.remote.inject("node-b", op::SERVICE_CONTROL, Fault::Hook(Rc::new(move || g2.set_lag(0))));
    let r = mv(&w, "node-b");
    dump(&w, "V3b (reads still stale)", &r);
    let Err(Failure::Failed(m)) = &r else { panic!("{r:?}") };
    assert!(m.contains("rolled back and verified"), "{m}");
    w.gce.inner.borrow_mut().stale.clear();
    dump(&w, "V3b after convergence", &r);
    assert_eq!(w.cloud_holders(), ["node-a", "node-b"], "VIP on both NICs");
}

/// D1: rollback starts the source service even if it was inactive before the move.
#[test]
fn d1_rollback_starts_a_source_service_that_was_down_before() {
    let w = World::new("ac-d1");
    w.remote.host("node-a").sys.set_service("mkg-demo.service", "inactive");
    w.remote.host("node-b").sys.fail_action("start");
    let r = mv(&w, "node-b");
    dump(&w, "D1", &r);
    assert!(matches!(&r, Err(Failure::Failed(m)) if m.contains("rolled back")));
    assert!(w.service_active("node-a"), "rollback started a service that was down at the beginning");
}

/// D2: fencing proof is read once; the instance is RUNNING again before the
/// assign and at commit; nothing re-checks.
#[test]
fn d2_fence_proof_is_not_rechecked_before_assign_or_commit() {
    let w = World::new("ac-d2");
    w.remote.host("node-a").reachable.set(false);
    w.gce.set_status("inst-a", "TERMINATED");
    let g = w.gce.clone();
    let remote = w.remote.clone();
    // hook runs on the lease acquire, i.e. after the 'fresh' TERMINATED read
    w.remote.inject("witness", op::LEASE_ACQUIRE, Fault::Hook(Rc::new(move || {
        g.set_status("inst-a", "RUNNING");
        remote.host("node-a").sys.set_service("mkg-demo.service", "active");
    })));
    let r = mv_fenced(&w, "node-b", "node-a");
    dump(&w, "D2", &r);
    let rep = r.expect("move completes");
    assert!(rep.fenced_source);
    assert_eq!(rep.evidence["fence"]["source_status"], "TERMINATED");
    assert_eq!(w.gce.inner.borrow().instances["inst-a"].status, "RUNNING");
    assert!(w.service_active("node-a") && w.service_active("node-b"), "both services run at commit");
}

/// D3: the target service dies after the serving check and before commit.
#[test]
fn d3_target_dies_between_verification_and_commit() {
    let w = World::new("ac-d3");
    let remote = w.remote.clone();
    w.remote.inject("witness", op::LEASE_COMMIT, Fault::Hook(Rc::new(move || {
        remote.host("node-b").sys.set_service("mkg-demo.service", "inactive");
    })));
    let r = mv(&w, "node-b");
    dump(&w, "D3", &r);
    assert!(r.is_ok(), "success reported");
    assert!(!w.service_active("node-b"));
    assert_eq!(vip_status(&w.ctx()).verdict, "unknown");
}

/// D4: 'deactivating' / 'activating' counts as 'stopped' for the source.
#[test]
fn d4_source_stop_check_accepts_deactivating() {
    // the agent computes active := (ActiveState == "active"); anything else
    // (activating, deactivating, reloading) passes `!s.active` in vip.rs:619.
    let w = World::new("ac-d4");
    w.remote.host("node-a").sys.set_service("mkg-demo.service", "deactivating");
    // service_action("stop") in the fake sets inactive, so simulate via a Hook
    // that re-sets deactivating right after the stop (FakeRemote runs hook BEFORE handle,
    // so use the status call instead).
    let remote = w.remote.clone();
    w.remote.inject("node-a", op::SERVICE_STATUS, Fault::Hook(Rc::new(move || {
        remote.host("node-a").sys.set_service("mkg-demo.service", "activating");
    })));
    let r = mv(&w, "node-b");
    dump(&w, "D4", &r);
    assert!(r.is_ok(), "move proceeds although the source unit is 'activating' at the check");
}

/// D5: quiet-source probe is fail-open: probe error is ignored.
#[test]
fn d5_source_local_probe_error_is_ignored() {
    let w = World::new("ac-d5");
    w.remote.inject_when("node-a", op::PROBE, None, 0, 1, Fault::DropBefore);
    let r = mv(&w, "node-b");
    assert!(r.is_ok());
}
