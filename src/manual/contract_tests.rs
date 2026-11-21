//! R4: the exit code, the `--json` document and the message of every command
//! family agree, in every outcome class (Owner decision A).
//!
//! The commands are run through `run::execute_resource` / `execute_chronyd` /
//! `status_overview_in` (the very functions the binary runs after it has
//! loaded its configuration) in the fake world; the exit code and the JSON are
//! produced by `run::success_document` / `failure_document`, which the binary
//! prints. Each case names the expected exit code, so this file is also the
//! executable form of the table in `CLI_REFERENCE.md`:
//!
//! | 0 | success, postconditions verified / status consistent |
//! | 1 | FAILED: a change was attempted, outcome known "not done / undone";
//! |   |   or a read-only command that could not give its answer |
//! | 3 | REFUSED: nothing was sent that could change a resource |
//! | 4 | UNKNOWN: outcome of a change, or the state itself, not established |

use super::cli_def::ServiceResource;
use super::cli_def::{ChronydCommands, Common, MovableResource, ResourceCommands, ResourceName};
use super::fakes::{ChangeBehavior, Fault, World};
use super::proto::op;
use super::run::{
    Output, execute_chronyd, execute_resource, failure_document, status_overview_in,
    success_document,
};
use super::{EXIT_FAILED, EXIT_REFUSED, EXIT_UNKNOWN, Failure, Res, result_word};
use serde_json::Value;
use std::path::PathBuf;

fn common() -> Common {
    Common {
        config: None,
        json: true,
    }
}

fn res(w: &World, command: ResourceCommands) -> Res<Output> {
    execute_resource(&w.ctx(), command)
}

fn chr(w: &World, command: ChronydCommands) -> Res<Output> {
    execute_chronyd(&w.ctx(), command)
}

fn mv(to: &str) -> ResourceCommands {
    ResourceCommands::Move {
        resource: MovableResource::Vip,
        to: to.to_string(),
        confirm_fenced: None,
        common: common(),
    }
}

fn init(owner: &str) -> ResourceCommands {
    ResourceCommands::Init {
        resource: MovableResource::Vip,
        owner: owner.to_string(),
        reinit: false,
        common: common(),
    }
}

fn reconcile() -> ResourceCommands {
    ResourceCommands::Reconcile {
        resource: MovableResource::Vip,
        abandon_op: None,
        accept_unconfirmed_cloud_change: false,
        common: common(),
    }
}

fn status(name: ResourceName) -> ResourceCommands {
    ResourceCommands::Status {
        resource: name,
        node: None,
        common: common(),
    }
}

fn service(action: &str, node: &str) -> ResourceCommands {
    let node = node.to_string();
    match action {
        "start" => ResourceCommands::Start {
            resource: ServiceResource::Chronyd,
            node,
            common: common(),
        },
        "stop" => ResourceCommands::Stop {
            resource: ServiceResource::Chronyd,
            node,
            common: common(),
        },
        _ => ResourceCommands::Restart {
            resource: ServiceResource::Chronyd,
            node,
            common: common(),
        },
    }
}

fn candidate(w: &World, text: &str) -> PathBuf {
    let path = w.dir.join("candidate.conf");
    std::fs::write(&path, text).unwrap();
    path
}

const OLD: &str = "pool 2.pool.ntp.org iburst\n";
const NEW: &str = "pool time.example.invalid iburst\nmakestep 1 3\n";

/// What the shell would see and what `--json` would print.
fn parts(result: &Res<Output>) -> (u8, Value, Option<Failure>) {
    match result {
        Ok(output) => (output.exit, success_document(output), None),
        Err(failure) => (
            failure.exit_code(),
            failure_document(failure),
            Some(failure.clone()),
        ),
    }
}

/// The invariants that hold for every command and every outcome, and the
/// exit code the case expects.
fn check(case: &str, result: Res<Output>, expected: u8) -> Value {
    let (exit, document, failure) = parts(&result);
    assert_eq!(exit, expected, "{case}: exit code ({document})");
    assert!(
        [0, EXIT_FAILED, EXIT_REFUSED, EXIT_UNKNOWN].contains(&exit),
        "{case}: {exit} is not a documented exit code"
    );
    assert_eq!(document["exit"], exit, "{case}: json exit");
    assert_eq!(document["ok"], exit == 0, "{case}: json ok");
    assert_eq!(document["result"], result_word(exit), "{case}: json result");
    match failure {
        Some(failure) => {
            // The message says the same word as the exit code.
            let word = match exit {
                EXIT_FAILED => "FAILED",
                EXIT_REFUSED => "REFUSED",
                _ => "UNKNOWN",
            };
            assert!(
                failure.to_string().starts_with(&format!("{word}: ")),
                "{case}: {failure}"
            );
            assert_eq!(document["result"], word.to_lowercase(), "{case}");
            assert!(
                document["error"].as_str().is_some_and(|e| !e.is_empty()),
                "{case}: an error needs a reason"
            );
        }
        None => {
            assert!(
                document.get("error").is_none() || exit != 0,
                "{case}: a success carries no error"
            );
        }
    }
    document
}

// ------------------------------------------------------------- the table

#[test]
fn json_and_exit_code_agree_for_the_resource_commands() {
    // list: always a report
    let w = World::new("ct-list");
    check(
        "list",
        res(&w, ResourceCommands::List { common: common() }),
        0,
    );

    // status vip
    let w = World::new("ct-status-vip");
    let d = check(
        "status vip consistent",
        res(&w, status(ResourceName::Vip)),
        0,
    );
    assert_eq!(d["verdict"], "consistent");
    let w = World::new("ct-status-vip-mismatch");
    w.gce.set_aliases_direct("inst-b", &["10.0.0.130/32"]);
    let d = check("status vip mismatch", res(&w, status(ResourceName::Vip)), 4);
    assert_ne!(d["verdict"], "consistent");
    let w = World::new("ct-status-vip-unknown");
    w.remote.host("witness").reachable.set(false);
    let d = check("status vip unknown", res(&w, status(ResourceName::Vip)), 4);
    assert_eq!(d["verdict"], "unknown");

    // status chronyd / demo
    let w = World::new("ct-status-chronyd");
    let d = check(
        "status chronyd healthy",
        res(&w, status(ResourceName::Chronyd)),
        0,
    );
    assert_eq!(d["healthy"], true);
    w.remote
        .host("node-b")
        .sys
        .set_service("chrony.service", "inactive");
    let d = check(
        "status chronyd stopped",
        res(&w, status(ResourceName::Chronyd)),
        4,
    );
    assert_eq!(d["healthy"], false);
    let w = World::new("ct-status-demo");
    check("status demo", res(&w, status(ResourceName::Demo)), 0);
    w.remote.host("node-b").reachable.set(false);
    check(
        "status demo node down",
        res(&w, status(ResourceName::Demo)),
        4,
    );

    // the cluster overview of `status --control-config`
    let w = World::new("ct-overview");
    let r = status_overview_in(&w.ctx());
    let d = check("overview consistent", r, 0);
    assert_eq!(d["vip"]["verdict"], "consistent");
    w.remote.host("witness").reachable.set(false);
    check("overview not consistent", status_overview_in(&w.ctx()), 4);
}

#[test]
fn json_and_exit_code_agree_for_move() {
    let w = World::new("ct-move-ok");
    let d = check("move ok", res(&w, mv("node-b")), 0);
    assert_eq!(d["target"], "node-b");

    // REFUSED: nothing was sent
    let w = World::new("ct-move-unknown-node");
    check("move to an unknown node", res(&w, mv("node-z")), 3);
    let w = World::new("ct-move-owner");
    check("move to the owner", res(&w, mv("node-a")), 3);
    let w = World::new("ct-move-ha");
    w.remote
        .host("node-b")
        .sys
        .set_service("mikagami.service", "active");
    check("move, HA daemon on the target", res(&w, mv("node-b")), 3);
    let w = World::new("ct-move-describe");
    w.gce.fail_describe("inst-a", true);
    check("move, the cloud cannot be read", res(&w, mv("node-b")), 3);
    let w = World::new("ct-move-agent-refuses");
    w.remote.inject(
        "node-b",
        op::PING,
        Fault::RefuseBefore("not for you".into()),
    );
    check("move, the target agent refuses", res(&w, mv("node-b")), 3);
    assert_eq!(w.gce.change_count(), 0);
    let w = World::new("ct-move-lease-refused");
    w.remote.inject(
        "witness",
        op::LEASE_ACQUIRE,
        Fault::RefuseBefore("busy".into()),
    );
    check("move, the lease is refused", res(&w, mv("node-b")), 3);

    // FAILED: attempted, outcome known (verified rollback)
    let w = World::new("ct-move-failed-4xx");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::Rejected(403)]);
    let d = check(
        "move, the cloud refused the request (4xx)",
        res(&w, mv("node-b")),
        1,
    );
    assert!(d["error"].as_str().unwrap().contains("REFUSED the detach"));
    let w = World::new("ct-move-failed-start");
    w.remote.host("node-b").sys.fail_action("start");
    check(
        "move, the target service does not start",
        res(&w, mv("node-b")),
        1,
    );

    // UNKNOWN: outcome not established
    // R6 (RA-C-01): an operation that ended in an error cannot be attributed
    // to the request, so it is not a known failure any more.
    let w = World::new("ct-move-failed-cloud");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::ErrorNoApply]);
    check(
        "move, the only new operation ended in an error",
        res(&w, mv("node-b")),
        4,
    );
    let w = World::new("ct-move-pending");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    check("move, a cloud change is pending", res(&w, mv("node-b")), 4);
    let w = World::new("ct-move-5xx");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::ErrorNoOperation]);
    check(
        "move, an unclassified error without an operation",
        res(&w, mv("node-b")),
        4,
    );
    let w = World::new("ct-move-lease-lost-answer");
    w.remote
        .inject("witness", op::LEASE_ACQUIRE, Fault::DropAfter);
    check("move, the lease answer is lost", res(&w, mv("node-b")), 4);
}

#[test]
fn json_and_exit_code_agree_for_init_and_reconcile() {
    let w = World::build("ct-init-ok", false);
    check("init ok", res(&w, init("node-a")), 0);
    let w = World::build("ct-init-wrong-owner", false);
    check(
        "init, the cloud shows another owner",
        res(&w, init("node-b")),
        3,
    );
    let w = World::build("ct-init-lost", false);
    w.remote.inject("witness", op::LEASE_INIT, Fault::DropAfter);
    check("init, the answer is lost", res(&w, init("node-a")), 4);
    let w = World::build("ct-init-describe", false);
    w.gce.fail_describe("inst-a", true);
    check("init, the cloud cannot be read", res(&w, init("node-a")), 3);

    let w = World::build("ct-init-witness-down", false);
    w.remote.host("witness").reachable.set(false);
    check("init, the Witness is down", res(&w, init("node-a")), 3);

    let w = World::new("ct-reconcile-consistent");
    let d = check("reconcile, nothing to do", res(&w, reconcile()), 0);
    assert_eq!(d["changed"], false);
    let w = World::build("ct-reconcile-uninit", false);
    check(
        "reconcile, ownership not initialised",
        res(&w, reconcile()),
        3,
    );
    let w = World::new("ct-reconcile-no-holder");
    w.gce.set_aliases_direct("inst-a", &[]);
    check("reconcile, the VIP is nowhere", res(&w, reconcile()), 4);
    let w = World::new("ct-reconcile-two-holders");
    w.gce.set_aliases_direct("inst-b", &["10.0.0.130/32"]);
    check("reconcile, the VIP is on both", res(&w, reconcile()), 4);
}

#[test]
fn json_and_exit_code_agree_for_the_service_commands() {
    let w = World::new("ct-svc-ok");
    for (action, node) in [
        ("stop", "node-b"),
        ("start", "node-b"),
        ("restart", "node-a"),
    ] {
        let d = check(&format!("{action} ok"), res(&w, service(action, node)), 0);
        assert_eq!(d["action"], action);
    }
    check(
        "start on an unknown node",
        res(&w, service("start", "node-z")),
        3,
    );
    let w = World::new("ct-svc-ha");
    w.remote
        .host("node-a")
        .sys
        .set_service("mikagami.service", "active");
    check(
        "restart, HA daemon on the node",
        res(&w, service("restart", "node-a")),
        3,
    );
    let w = World::new("ct-svc-agent-fails");
    w.remote.host("node-b").sys.fail_action("restart");
    check(
        "restart, the agent reports a failure",
        res(&w, service("restart", "node-b")),
        4,
    );
    let w = World::new("ct-svc-lost");
    w.remote
        .inject("node-b", op::SERVICE_CONTROL, Fault::DropAfter);
    check(
        "stop, the answer is lost",
        res(&w, service("stop", "node-b")),
        4,
    );
    let w = World::new("ct-svc-unreachable");
    w.remote.host("node-b").reachable.set(false);
    check(
        "stop, the node is unreachable",
        res(&w, service("stop", "node-b")),
        4,
    );
}

#[test]
fn json_and_exit_code_agree_for_the_chronyd_commands() {
    let show = |node: &str| ChronydCommands::Show {
        node: Some(node.to_string()),
        common: common(),
    };
    let w = World::new("ct-chrony-show");
    check("show ok", chr(&w, show("node-a")), 0);
    w.remote
        .host("node-a")
        .sys
        .set_service("chrony.service", "inactive");
    check("show, the unit is stopped", chr(&w, show("node-a")), 4);
    let w = World::new("ct-chrony-show-down");
    w.remote.host("node-a").reachable.set(false);
    // A read-only command that cannot answer: FAILED, nothing was changed.
    check("show, the node is unreachable", chr(&w, show("node-a")), 1);

    let w = World::new("ct-chrony-validate");
    let file = candidate(&w, NEW);
    let validate = |file: &PathBuf| ChronydCommands::Validate {
        file: file.clone(),
        node: Some("node-a".to_string()),
        common: common(),
    };
    check("validate ok", chr(&w, validate(&file)), 0);
    w.remote.host("node-a").sys.reject_config("makestep");
    check(
        "validate, chronyd rejects the file",
        chr(&w, validate(&file)),
        3,
    );
    check(
        "validate, the file does not exist",
        chr(&w, validate(&w.dir.join("missing.conf"))),
        3,
    );

    let w = World::new("ct-chrony-diff");
    let file = candidate(&w, NEW);
    let diff = |file: &PathBuf, node: &str| ChronydCommands::Diff {
        file: file.clone(),
        node: node.to_string(),
        common: common(),
    };
    check("diff ok", chr(&w, diff(&file, "node-a")), 0);
    w.remote.host("node-a").reachable.set(false);
    check(
        "diff, the node is unreachable",
        chr(&w, diff(&file, "node-a")),
        1,
    );

    let apply = |file: &PathBuf, dry_run: bool| ChronydCommands::Apply {
        file: file.clone(),
        node: "node-a".to_string(),
        dry_run,
        common: common(),
    };
    let w = World::new("ct-chrony-apply-ok");
    let file = candidate(&w, NEW);
    check("apply dry run", chr(&w, apply(&file, true)), 0);
    let d = check("apply", chr(&w, apply(&file, false)), 0);
    assert_eq!(d["changed"], true);
    check("apply, nothing to change", chr(&w, apply(&file, false)), 0);

    let w = World::new("ct-chrony-apply-ha");
    let file = candidate(&w, NEW);
    w.remote
        .host("node-a")
        .sys
        .set_service("mikagami.service", "active");
    check(
        "apply, HA daemon on the node",
        chr(&w, apply(&file, false)),
        3,
    );
    let w = World::new("ct-chrony-apply-down");
    let file = candidate(&w, NEW);
    w.remote.host("node-a").reachable.set(false);
    check(
        "apply, the node is unreachable (nothing sent)",
        chr(&w, apply(&file, false)),
        3,
    );
    let w = World::new("ct-chrony-apply-rejected");
    let file = candidate(&w, "bogus\n");
    w.remote.host("node-a").sys.reject_config("bogus");
    check(
        "apply, chronyd rejects the file",
        chr(&w, apply(&file, false)),
        3,
    );

    let w = World::new("ct-chrony-apply-rolled-back");
    let file = candidate(&w, NEW);
    w.remote.inject_when(
        "node-a",
        op::SERVICE_CONTROL,
        Some("restart"),
        0,
        1,
        Fault::FailBefore("injected".into()),
    );
    let d = check(
        "apply, rolled back and verified",
        chr(&w, apply(&file, false)),
        1,
    );
    assert!(d["error"].as_str().unwrap().contains("rolled back"));
    assert_eq!(
        std::fs::read_to_string(&w.remote.host("node-a").env.cfg.chrony_conf).unwrap(),
        OLD
    );
    let w = World::new("ct-chrony-apply-unknown");
    let file = candidate(&w, OLD);
    w.remote
        .host("node-a")
        .sys
        .set_service("chrony.service", "failed");
    check(
        "apply, identical but chrony is not healthy",
        chr(&w, apply(&file, false)),
        4,
    );
}

#[test]
fn every_failure_kind_has_one_exit_code_one_word_and_one_json_result() {
    for (failure, exit, word) in [
        (Failure::Failed("x".into()), 1, "failed"),
        (Failure::Refused("x".into()), 3, "refused"),
        (Failure::Unknown("x".into()), 4, "unknown"),
    ] {
        assert_eq!(failure.exit_code(), exit);
        let d = failure_document(&failure);
        assert_eq!(d["result"], word);
        assert_eq!(d["exit"], exit);
        assert_eq!(d["ok"], false);
        assert_eq!(result_word(exit), word);
        assert!(failure.to_string().starts_with(&word.to_uppercase()));
    }
    assert_eq!(result_word(0), "ok");
    // Only a pre-flight failure becomes a refusal; the other kinds are kept.
    assert_eq!(
        Failure::Failed("x".into()).before_any_change(),
        Failure::Refused("x".into())
    );
    for kept in [Failure::Refused("x".into()), Failure::Unknown("x".into())] {
        assert_eq!(kept.clone().before_any_change(), kept);
    }
}

#[test]
fn a_success_document_cannot_claim_a_different_exit_code() {
    // A command that put its own `ok`/`exit`/`result` into the document
    // cannot make them disagree with the exit code.
    for (exit, expected_ok) in [(0, true), (4, false)] {
        let output = Output {
            text: String::new(),
            json: serde_json::json!({"ok": !expected_ok, "exit": 99, "result": "wrong", "a": 1}),
            exit,
        };
        let d = success_document(&output);
        assert_eq!(d["ok"], expected_ok);
        assert_eq!(d["exit"], exit);
        assert_eq!(d["result"], result_word(exit));
        assert_eq!(d["a"], 1);
    }
}
