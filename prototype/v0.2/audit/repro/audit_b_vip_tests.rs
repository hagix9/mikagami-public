//! AUDIT B adversarial tests (copy only).
use super::fakes::{Fault, World};
use super::proto::{self, PROTO_VERSION, Request, op};
use super::agent::handle;
use super::vip::*;
use super::Failure;
use serde_json::json;
use std::rc::Rc;

fn agent(w: &'static World, operation: &str, args: serde_json::Value) -> proto::Response {
    handle(
        &w.remote.host("witness").env,
        &Request { v: PROTO_VERSION, id: proto::random_hex(8), op: operation.to_string(), args },
    )
}

fn mv(w: &World, to: &str) -> super::Res<MoveReport> {
    move_vip(&w.ctx(), &MoveRequest { target: to.to_string(), confirm_fenced: None })
}

/// B-V1: controller 1 is paused (laptop sleep) between acquire and first phase
/// record; controller 2 takes over the expired non-mutating lock and has
/// quiesced the source. Controller 1 resumes.
#[test]
fn b_v1_stale_controller_rollback_undoes_the_new_holders_quiesce() {
    let w: &'static World = Box::leak(Box::new(World::new("b-v1")));
    let handle_ms = w.clock.handle();
    let hook = Rc::new(move || {
        handle_ms.set(handle_ms.get() + 301_000); // > TTL
        let r = agent(w, op::LEASE_ACQUIRE, json!({"op_id":"move-ctl2op","source":"node-a","target":"node-b","ttl_s":300,"controller":"c2","expect_epoch":1}));
        assert!(r.ok, "{r:?}");
        let r = agent(w, op::LEASE_PHASE, json!({"op_id":"move-ctl2op","phase":"source_quiescing"}));
        assert!(r.ok, "{r:?}");
        // controller 2 has stopped the source service and verified it
        w.remote.host("node-a").sys.set_service("mkg-demo.service", "inactive");
    });
    w.remote.inject_when("witness", op::LEASE_PHASE, Some("source_quiescing"), 0, 1, Fault::Hook(hook));
    let r = mv(w, "node-b");
    eprintln!("ctl1 result: {r:?}");
    eprintln!("node-a service active after ctl1 returned: {}", w.service_active("node-a"));
    eprintln!("lease op: {:?}", w.lease().op.map(|o| (o.op_id, o.phase)));
    eprintln!("actions on node-a: {:?}", w.remote.host("node-a").sys.actions());
    assert!(!w.service_active("node-a"), "stale controller's rollback restarted the source service that the lease holder had quiesced");
}

/// B-V2: reconcile (second operator) clears a LIVE mutating operation between
/// the "target started+serving" observation and the TargetStarted record.
#[test]
fn b_v2_reconcile_cuts_into_a_live_mutating_move() {
    let w: &'static World = Box::leak(Box::new(World::new("b-v2")));
    let hook = Rc::new(move || {
        let r = reconcile_vip(&w.ctx());
        eprintln!("concurrent reconcile: {:?}", r.as_ref().map(|x| (x.owner.clone(), x.changed, x.epoch)));
    });
    w.remote.inject_when("witness", op::LEASE_PHASE, Some("target_started"), 0, 1, Fault::Hook(hook));
    let r = mv(w, "node-b");
    eprintln!("ctl1 result: {r:?}");
    let l = w.lease();
    eprintln!("lease owner={:?} epoch={} op={:?}", l.owner, l.epoch, l.op.as_ref().map(|o| &o.op_id));
    eprintln!("cloud holders={:?} a_active={} b_active={}", w.cloud_holders(), w.service_active("node-a"), w.service_active("node-b"));
    let st = vip_status(&w.ctx());
    eprintln!("status verdict={} problems={:?}", st.verdict, st.problems);
    assert_eq!(l.owner.as_deref().map(str::to_string), w.cloud_holders().first().cloned(), "record and reality diverged");
    let _ = Failure::Failed(String::new());
}
