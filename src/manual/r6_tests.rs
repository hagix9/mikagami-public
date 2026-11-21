//! Regression tests of remediation round R6 (findings of the second
//! independent re-audit, `prototype/v0.2/audit/REAUDIT_ROUND2_FINDINGS.md`).
//! Every test names the finding it pins. The reproductions of the auditors are
//! kept in the form they were reported.

use super::fakes::{ChangeBehavior, World};
use super::lease::ABANDON_QUIET_SECS;
use super::vip::*;
use super::{Failure, Res};

fn mv(w: &World, to: &str) -> Res<MoveReport> {
    move_vip(
        &w.ctx(),
        &MoveRequest {
            target: to.to_string(),
            confirm_fenced: None,
        },
    )
}

fn unknown(r: &Res<MoveReport>) -> &str {
    match r {
        Err(Failure::Unknown(m)) => m,
        other => panic!("expected UNKNOWN, got {other:?}"),
    }
}

fn changes_of(w: &World, instance: &str) -> usize {
    w.gce
        .changes()
        .iter()
        .filter(|(i, _)| i == instance)
        .count()
}

// ------------------------------------------------------------------ RA-C-01

/// A failed alias operation of somebody else appears while this request is
/// still on its way (it lands only after the controller gave up looking).
fn foreign_failed_operation_after_the_request(w: &World, instance: &'static str) {
    w.gce.after_next_change(move |inner| {
        inner.new_op(instance, "DONE", true);
    });
}

#[test]
fn ra_c01_a_foreign_failed_operation_does_not_prove_a_release_was_not_applied() {
    // Auditor's A1b: the detach request times out without an operation, it
    // lands later; a failed operation of somebody else is the only operation
    // in view. The audited code declared the request "not applied", rolled
    // back ("rolled back and verified") and released the lock; the late
    // detach then left the VIP on nobody while the lease still named node-a.
    let w = World::new("ra-c01-release");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutInvisible]);
    foreign_failed_operation_after_the_request(&w, "inst-a");
    let r = mv(&w, "node-b");
    let message = unknown(&r);
    assert!(
        !message.contains("rolled back and verified"),
        "no verified-rollback claim: {message}"
    );
    assert!(
        message.contains("cannot be attributed"),
        "the reason is named: {message}"
    );
    // No rollback was attempted: nothing but the one request was sent and the
    // lock is still recorded (the recovery is `reconcile`, by an operator).
    assert_eq!(w.gce.change_count(), 1, "{:?}", w.gce.changes());
    assert!(w.lease().op.is_some(), "the lock was not released");
    // The late request lands: the world is what the UNKNOWN said it could be
    // (VIP on nobody) - and nothing claimed otherwise.
    w.gce.land_all();
    assert!(w.cloud_holders().is_empty());
    assert_eq!(w.lease().owner.as_deref(), Some("node-a"));
}

#[test]
fn ra_c01_a_foreign_failed_operation_does_not_prove_an_assignment_was_not_applied() {
    // Auditor's A1: the same on the attach side. The audited code rolled
    // back and gave the VIP back to the source; the late attach then left
    // both instances holding the alias.
    let w = World::new("ra-c01-attach");
    w.gce
        .script_changes("inst-b", &[ChangeBehavior::TimeoutInvisible]);
    foreign_failed_operation_after_the_request(&w, "inst-b");
    let r = mv(&w, "node-b");
    let message = unknown(&r);
    assert!(!message.contains("rolled back and verified"), "{message}");
    assert_eq!(changes_of(&w, "inst-a"), 1, "release only, no give-back");
    assert_eq!(changes_of(&w, "inst-b"), 1, "assignment only, no removal");
    assert!(w.lease().op.is_some());
    assert!(!w.service_active("node-a"), "the source was not restarted");
    assert!(!w.service_active("node-b"));
    // The late request lands: the alias is on the target only, the source
    // does not hold it - no double alias came out of the UNKNOWN.
    w.gce.land_all();
    assert_eq!(w.cloud_holders(), ["node-b"]);
}

#[test]
fn ra_c01_every_report_other_than_the_tools_success_leaves_a_failed_operation_unresolved() {
    // The operation of the request itself that finished with an error is the
    // same observation as a foreign one: with the tool's own error or
    // timeout report it is UNKNOWN, never a verified rollback.
    for behavior in [
        ChangeBehavior::ErrorNoApply,
        ChangeBehavior::TimeoutFailedOp,
        ChangeBehavior::RejectedButFailedOp,
    ] {
        for instance in ["inst-a", "inst-b"] {
            let w = World::new("ra-c01-own-failure");
            w.gce.script_changes(instance, &[behavior]);
            let r = mv(&w, "node-b");
            let message = unknown(&r);
            assert!(
                message.contains("may still land"),
                "{behavior:?}: {message}"
            );
            assert!(w.lease().op.is_some(), "{behavior:?} {instance}");
            assert!(!message.contains("rolled back"), "{behavior:?}: {message}");
        }
    }
}

// ------------------------------------------------------------------ RA-B-01

/// The auditor's reproduction: a release whose request is lost (UNKNOWN),
/// the operator starts the source service by hand and, after the silence,
/// declares the operation dead.
fn lost_release_and_a_hand_started_source() -> (World, String) {
    let w = World::new("ra-b01");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutInvisible]);
    let r = mv(&w, "node-b");
    let _ = unknown(&r);
    let op_id = w.lease().op.expect("the lock is held").op_id;
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "active");
    w.clock.advance_secs(ABANDON_QUIET_SECS + 1);
    (w, op_id)
}

#[test]
fn ra_b01_reconcile_does_not_adopt_a_state_while_a_recorded_cloud_change_is_unconfirmed() {
    let (w, op_id) = lost_release_and_a_hand_started_source();
    let r = reconcile_vip(&w.ctx(), Some(&op_id), false);
    let message = match &r {
        Err(Failure::Unknown(m)) => m.clone(),
        other => panic!("expected UNKNOWN, got {other:?}"),
    };
    assert!(
        message.contains("--accept-unconfirmed-cloud-change"),
        "{message}"
    );
    assert!(message.contains("detach (node-a)"), "{message}");
    // Nothing was written: the interrupted operation is still recorded.
    assert_eq!(w.lease().op.map(|o| o.op_id), Some(op_id));
    // The request lands afterwards (this is what the audited code allowed
    // after a successful reconcile): the record was not touched, so the
    // damage is visible in `status`, not hidden behind a cleared lock.
    w.gce.land_all();
    assert!(w.cloud_holders().is_empty());
    assert!(w.lease().op.is_some());
}

#[test]
fn ra_b01_the_explicit_acknowledgement_is_recorded_in_the_evidence() {
    let (w, op_id) = lost_release_and_a_hand_started_source();
    let report = reconcile_vip(&w.ctx(), Some(&op_id), true).unwrap();
    assert!(report.changed);
    let cloud = &report.evidence["cloud_operations"];
    assert_eq!(cloud["unconfirmed_cloud_changes"][0]["action"], "detach");
    assert_eq!(
        cloud["unconfirmed_cloud_changes_accepted_by_operator"], true,
        "the operator's statement is part of the record"
    );
    // The acknowledgement does not weaken the other gates: an open cloud
    // operation still blocks (the world below has one).
    let w = World::new("ra-b01-open-op");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let r = mv(&w, "node-b");
    let _ = unknown(&r);
    let op_id = w.lease().op.unwrap().op_id;
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "active");
    w.gce
        .set_aliases_direct("inst-a", &[super::fakes::VIP_CIDR]);
    w.clock.advance_secs(ABANDON_QUIET_SECS + 1);
    let r = reconcile_vip(&w.ctx(), Some(&op_id), true);
    assert!(
        matches!(&r, Err(Failure::Unknown(m)) if m.contains("still PENDING")),
        "{r:?}"
    );
}

#[test]
fn ra_b01_a_failed_operation_does_not_confirm_a_recorded_change() {
    // The recorded request finished with an operation error (RA-C-01 leaves it
    // unresolved): a failed operation cannot be attributed to the request, so
    // the reconcile does not count it as confirmation either.
    let w = World::new("ra-b01-failed-op");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::ErrorNoApply]);
    let r = mv(&w, "node-b");
    let _ = unknown(&r);
    let op_id = w.lease().op.unwrap().op_id;
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "active");
    w.clock.advance_secs(ABANDON_QUIET_SECS + 1);
    let refused = reconcile_vip(&w.ctx(), Some(&op_id), false);
    assert!(
        matches!(&refused, Err(Failure::Unknown(m)) if m.contains("--accept-unconfirmed-cloud-change")),
        "{refused:?}"
    );
    let accepted = reconcile_vip(&w.ctx(), Some(&op_id), true).unwrap();
    assert!(accepted.changed);
}

#[test]
fn ra_b01_a_confirmed_change_needs_no_acknowledgement() {
    // The recorded detach finished (a successful operation is listed after
    // its anchor): the ordinary recovery works without the flag.
    let w = World::new("ra-b01-confirmed");
    w.gce
        .script_changes("inst-a", &[ChangeBehavior::TimeoutPending]);
    let r = mv(&w, "node-b");
    let _ = unknown(&r);
    let op_id = w.lease().op.unwrap().op_id;
    w.gce.land_all();
    w.gce
        .set_aliases_direct("inst-a", &[super::fakes::VIP_CIDR]);
    w.remote
        .host("node-a")
        .sys
        .set_service("mkg-demo.service", "active");
    w.clock.advance_secs(ABANDON_QUIET_SECS + 1);
    let report = reconcile_vip(&w.ctx(), Some(&op_id), false).unwrap();
    assert!(report.changed);
    assert!(
        report.evidence["cloud_operations"]["unconfirmed_cloud_changes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

// ------------------------------------------------------------------ RA-D-01

pub(crate) mod chrony_displaced {
    use crate::manual::Failure;
    use crate::manual::chrony_agent::PRE_SWAP;
    use crate::manual::chrony_ctl;
    use crate::manual::fakes::World;
    use crate::manual::fsutil;
    use crate::manual::proto::op;
    use std::fs;
    use std::path::PathBuf;

    pub(crate) const OLD: &str = "pool 2.pool.ntp.org iburst\n";
    pub(crate) const NEW: &str = "pool time.example.invalid iburst\nmakestep 1 3\n";
    pub(crate) const THIRD: &str = "server admin-edit.example.invalid\n";

    /// Hook state is thread-local: always reset, also when a test panics.
    pub(crate) struct Hooks;
    impl Hooks {
        pub(crate) fn arm(conf: PathBuf, edit_on_call: usize, fail_exchange_at: usize) -> Self {
            let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
            PRE_SWAP.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || {
                    calls.set(calls.get() + 1);
                    if calls.get() == edit_on_call {
                        fs::write(&conf, THIRD).unwrap();
                    }
                }));
            });
            fsutil::EXCHANGE_CALLS.with(|c| c.set(0));
            fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(Some(fail_exchange_at)));
            Hooks
        }
    }
    impl Drop for Hooks {
        fn drop(&mut self) {
            PRE_SWAP.with(|h| *h.borrow_mut() = None);
            fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(None));
            fsutil::EXCHANGE_CALLS.with(|c| c.set(0));
        }
    }

    /// Makes every way of giving the displaced file a protected name fail:
    /// no hard link, no move that refuses to replace. Reset on drop.
    pub(crate) struct FailLinks;
    impl FailLinks {
        pub(crate) fn arm() -> Self {
            fsutil::LINK_FAIL.with(|c| c.set(Some(1))); // EPERM
            fsutil::NOREPLACE_FAIL.with(|c| c.set(Some(Some(5)))); // EIO
            FailLinks
        }
    }
    impl Drop for FailLinks {
        fn drop(&mut self) {
            fsutil::LINK_FAIL.with(|c| c.set(None));
            fsutil::NOREPLACE_FAIL.with(|c| c.set(None));
            fsutil::PLAIN_RENAME_FAIL.with(|c| c.set(None));
        }
    }

    pub(crate) fn conf_dir(w: &World) -> PathBuf {
        w.remote
            .host("node-a")
            .env
            .cfg
            .chrony_conf
            .parent()
            .unwrap()
            .to_path_buf()
    }

    pub(crate) fn live(w: &World) -> String {
        fs::read_to_string(&w.remote.host("node-a").env.cfg.chrony_conf).unwrap()
    }

    /// The files of the directory whose name starts with `prefix`.
    pub(crate) fn named(w: &World, prefix: &str) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = fs::read_dir(conf_dir(w))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
            .map(|e| e.path())
            .collect();
        found.sort();
        found
    }

    /// Somebody's version is somewhere in the directory under a name that no
    /// clean-up or sweep deletes.
    pub(crate) fn kept_copies(w: &World) -> Vec<PathBuf> {
        named(w, ".mkg-displaced-")
            .into_iter()
            .filter(|p| fs::read_to_string(p).is_ok_and(|t| t == THIRD))
            .collect()
    }

    pub(crate) fn calls(w: &World, operation: &str) -> usize {
        w.count_agent_calls("node-a", operation)
    }

    #[test]
    fn ra_d01_a_failed_put_back_after_an_edit_in_the_window_is_unknown_and_keeps_their_version() {
        // The auditor's reproduction (EXCH_FAIL_AT=2 plus the PRE_SWAP hook):
        // `apply` used to answer Ok(changed: true) and delete the only copy of
        // the edit.
        let w = World::new("ra-d01-publish");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 2);
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert!(message.contains(".mkg-displaced-"), "{message}");
        assert!(message.contains("nothing deletes it"), "{message}");
        assert!(message.contains("NOT restarted"), "{message}");
        assert_eq!(
            live(&w),
            NEW,
            "the candidate is live (their edit was displaced)"
        );
        assert_eq!(kept_copies(&w).len(), 1, "their version is kept");
        // Nothing restarted chronyd, restored a backup or cleaned up.
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
        assert_eq!(calls(&w, op::CHRONY_RESTORE), 0);
        assert_eq!(calls(&w, op::CHRONY_CLEANUP), 0, "no cleanup is asked for");
    }

    #[test]
    fn ra_d01_nothing_the_agent_does_later_deletes_the_kept_version() {
        let w = World::new("ra-d01-sweep");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        {
            let _hooks = Hooks::arm(conf, 1, 2);
            let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
            assert!(matches!(r, Err(Failure::Unknown(_))), "{r:?}");
        }
        let kept = kept_copies(&w);
        assert_eq!(kept.len(), 1);
        // Age everything: the sweep that runs inside `backup` removes stale
        // `.mkg-stage-*` files (the stage name still exists, it is the same
        // file as the kept one) but must not touch the kept name.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        for path in named(&w, ".mkg-") {
            if let Ok(file) = fs::OpenOptions::new().append(true).open(&path) {
                let _ = file.set_modified(old);
            }
        }
        // Make the live file differ from the backup base: the sweep runs in
        // `backup`, whose argument is the live hash.
        let backup = w.ctx().call(
            &w.ctx().node_target("node-a").unwrap(),
            op::CHRONY_BACKUP,
            serde_json::json!({"expect_sha256": fsutil::sha256_hex(NEW.as_bytes())}),
            crate::manual::remote::SHORT,
        );
        assert!(backup.is_ok(), "{backup:?}");
        assert_eq!(kept_copies(&w), kept, "the kept version survived the sweep");
        // And a cleanup of the stage id (which a retry of the controller could
        // send) removes only the stage name.
        for stage in named(&w, ".mkg-stage-") {
            let id = stage
                .file_name()
                .unwrap()
                .to_string_lossy()
                .trim_start_matches(".mkg-stage-")
                .trim_end_matches(".conf")
                .to_string();
            let cleaned = w.ctx().call(
                &w.ctx().node_target("node-a").unwrap(),
                op::CHRONY_CLEANUP,
                serde_json::json!({ "stage_id": id }),
                crate::manual::remote::SHORT,
            );
            assert!(cleaned.is_ok(), "{cleaned:?}");
        }
        assert_eq!(
            kept_copies(&w),
            kept,
            "the kept version survived the cleanup"
        );
    }

    #[test]
    fn ra_d01_when_no_protected_name_can_be_made_the_file_stays_and_is_made_fresh() {
        // The agent-level fallback: the place for the kept name is taken (by a
        // directory, or by a file that must not be replaced), so the link
        // fails. The other version then stays under its staged name, with a
        // fresh time so that the sweep (which goes by age) leaves it alone, and
        // whatever held the name is untouched.
        for occupant in ["directory", "file"] {
            let _refused = FailLinks::arm();
            let w = World::new("ra-d01-fallback");
            let host = w.remote.host("node-a");
            let conf = host.env.cfg.chrony_conf.clone();
            let stage = crate::manual::agent::handle(
                &host.env,
                &crate::manual::testkit::req(
                    op::CHRONY_STAGE,
                    serde_json::json!({"content": NEW, "sha256": fsutil::sha256_hex(NEW.as_bytes())}),
                ),
            );
            let stage_id = stage.data["stage_id"].as_str().unwrap().to_string();
            let dir = conf_dir(&w);
            let taken = dir.join(format!(".mkg-displaced-mkg-stage-{stage_id}.conf"));
            if occupant == "directory" {
                fs::create_dir(&taken).unwrap();
            } else {
                fs::write(&taken, "an earlier kept version\n").unwrap();
            }
            let hook_conf = conf.clone();
            let _hooks = Hooks::arm(hook_conf.clone(), 1, 2);
            // The hook writes an OLD mtime; the fallback has to refresh it.
            PRE_SWAP.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || {
                    fs::write(&hook_conf, THIRD).unwrap();
                    let f = fs::OpenOptions::new()
                        .append(true)
                        .open(&hook_conf)
                        .unwrap();
                    f.set_modified(
                        std::time::SystemTime::now() - std::time::Duration::from_secs(86_400),
                    )
                    .unwrap();
                }));
            });
            let r = crate::manual::agent::handle(
                &host.env,
                &crate::manual::testkit::req(
                    op::CHRONY_PUBLISH,
                    serde_json::json!({
                        "stage_id": stage_id,
                        "expect_current": fsutil::sha256_hex(OLD.as_bytes()),
                        "expect_new": fsutil::sha256_hex(NEW.as_bytes()),
                    }),
                ),
            );
            assert!(!r.ok, "{occupant}: {r:?}");
            assert_eq!(
                r.error.as_ref().unwrap().code,
                crate::manual::proto::code::DISPLACED_KEPT
            );
            let staged = dir.join(format!(".mkg-stage-{stage_id}.conf"));
            assert!(
                r.error
                    .as_ref()
                    .unwrap()
                    .message
                    .contains(&staged.display().to_string()),
                "{occupant}: the message names the file: {r:?}"
            );
            assert_eq!(fs::read_to_string(&staged).unwrap(), THIRD);
            // The message does not claim that nothing deletes this name: a
            // clean-up of the stage id does (final re-audit N-1), and it says so.
            let message = &r.error.as_ref().unwrap().message;
            assert!(
                !message.contains("nothing deletes it"),
                "{occupant}: {message}"
            );
            assert!(
                message.contains("NO protected name") && message.contains("NOW"),
                "{occupant}: {message}"
            );
            let age = std::time::SystemTime::now()
                .duration_since(fs::metadata(&staged).unwrap().modified().unwrap())
                .unwrap();
            assert!(
                age.as_secs() < 3600,
                "{occupant}: the file looks fresh: {age:?}"
            );
            // What held the name is exactly as it was.
            if occupant == "directory" {
                assert!(taken.is_dir());
            } else {
                assert_eq!(
                    fs::read_to_string(&taken).unwrap(),
                    "an earlier kept version\n",
                    "an earlier kept file was replaced"
                );
            }
            // And the text is true: the clean-up of the stage id leaves a file
            // whose content is not the staged content (final R7, audit H-2).
            let cleaned = crate::manual::agent::handle(
                &host.env,
                &crate::manual::testkit::req(
                    op::CHRONY_CLEANUP,
                    serde_json::json!({ "stage_id": stage_id }),
                ),
            );
            assert!(cleaned.ok, "{occupant}: {cleaned:?}");
            assert_eq!(
                fs::read_to_string(&staged).unwrap(),
                THIRD,
                "{occupant}: the clean-up left it"
            );
            if occupant == "directory" {
                assert!(taken.is_dir());
            } else {
                assert_eq!(
                    fs::read_to_string(&taken).unwrap(),
                    "an earlier kept version\n"
                );
            }
        }
    }

    /// Resets the injected link failure when dropped (also on a panic).
    struct LinkFailReset(bool);
    impl Drop for LinkFailReset {
        fn drop(&mut self) {
            if self.0 {
                fsutil::LINK_FAIL.with(|c| c.set(None));
            }
        }
    }
    fn scopeguard_reset(armed: bool) -> LinkFailReset {
        LinkFailReset(armed)
    }

    #[test]
    fn ra_d01_the_kept_version_is_their_file_itself_with_its_mode_and_owner_in_every_way() {
        // Neither way of keeping the displaced version copies it: the hard
        // link and the "stays under the staged name" fallback both hand back
        // the very file the other party wrote (same inode, same mode and
        // owner, same content), so nothing about it can be lost or widened.
        use std::cell::Cell;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::rc::Rc;
        for way in ["hard link", "name taken", "links refused"] {
            let w = World::new("ra-d01-attributes");
            let host = w.remote.host("node-a");
            let conf = host.env.cfg.chrony_conf.clone();
            let stage = crate::manual::agent::handle(
                &host.env,
                &crate::manual::testkit::req(
                    op::CHRONY_STAGE,
                    serde_json::json!({"content": NEW, "sha256": fsutil::sha256_hex(NEW.as_bytes())}),
                ),
            );
            let stage_id = stage.data["stage_id"].as_str().unwrap().to_string();
            let dir = conf_dir(&w);
            let staged = dir.join(format!(".mkg-stage-{stage_id}.conf"));
            let keep = dir.join(format!(".mkg-displaced-mkg-stage-{stage_id}.conf"));
            if way == "name taken" {
                fs::write(&keep, "an earlier kept version\n").unwrap();
            }
            // No hard link can be made: the file is moved without replacing.
            if way == "links refused" {
                fsutil::LINK_FAIL.with(|c| c.set(Some(1)));
            }
            let _reset = scopeguard_reset(way == "links refused");
            let identity: Rc<Cell<(u64, u32, u32, u32)>> = Rc::new(Cell::new((0, 0, 0, 0)));
            let (hook_conf, seen) = (conf.clone(), Rc::clone(&identity));
            let _hooks = Hooks::arm(conf.clone(), 1, 2);
            PRE_SWAP.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || {
                    fs::write(&hook_conf, THIRD).unwrap();
                    fs::set_permissions(&hook_conf, fs::Permissions::from_mode(0o640)).unwrap();
                    let m = fs::metadata(&hook_conf).unwrap();
                    seen.set((m.ino(), m.mode() & 0o7777, m.uid(), m.gid()));
                }));
            });
            let r = crate::manual::agent::handle(
                &host.env,
                &crate::manual::testkit::req(
                    op::CHRONY_PUBLISH,
                    serde_json::json!({
                        "stage_id": stage_id,
                        "expect_current": fsutil::sha256_hex(OLD.as_bytes()),
                        "expect_new": fsutil::sha256_hex(NEW.as_bytes()),
                    }),
                ),
            );
            assert_eq!(
                r.error.as_ref().unwrap().code,
                crate::manual::proto::code::DISPLACED_KEPT,
                "{way}: {r:?}"
            );
            let (ino, mode, uid, gid) = identity.get();
            assert_ne!(ino, 0, "{way}: the hook ran");
            // Where the other party's file is now: under the second name; with
            // a taken name under the next free one; with no links it was moved.
            let keep_next = dir.join(format!(".mkg-displaced-mkg-stage-{stage_id}.conf-1"));
            let kept = match way {
                "hard link" | "links refused" => &keep,
                _ => &keep_next,
            };
            let m = fs::metadata(kept).unwrap();
            assert_eq!(
                (m.ino(), m.mode() & 0o7777, m.uid(), m.gid()),
                (ino, mode, uid, gid),
                "{way}: the kept file is their file with its attributes"
            );
            assert_eq!(fs::read_to_string(kept).unwrap(), THIRD, "{way}");
            // Moved or linked, the staged name is gone once the data has its
            // protected name: exactly one name is left to look at.
            assert!(!staged.exists(), "{way}: the staged name was removed");
            if way == "name taken" {
                assert_eq!(
                    fs::read_to_string(&keep).unwrap(),
                    "an earlier kept version\n",
                    "the earlier file was not replaced"
                );
            }
            // The live file is the candidate, written by the staged file itself.
            assert_eq!(live(&w), NEW, "{way}");
        }
    }

    #[test]
    fn ra_d01_a_good_put_back_never_removes_an_earlier_kept_file() {
        // The second name is taken by an earlier kept version and the put-back
        // works: the link was never made, so nothing of ours is removed, and
        // the earlier file is exactly as it was (final re-audit N-1, gap).
        let w = World::new("ra-d01-earlier-kept");
        let host = w.remote.host("node-a");
        let conf = host.env.cfg.chrony_conf.clone();
        let stage = crate::manual::agent::handle(
            &host.env,
            &crate::manual::testkit::req(
                op::CHRONY_STAGE,
                serde_json::json!({"content": NEW, "sha256": fsutil::sha256_hex(NEW.as_bytes())}),
            ),
        );
        let stage_id = stage.data["stage_id"].as_str().unwrap().to_string();
        let taken = conf_dir(&w).join(format!(".mkg-displaced-mkg-stage-{stage_id}.conf"));
        fs::write(&taken, "an earlier kept version\n").unwrap();
        let _hooks = Hooks::arm(conf, 1, 99);
        let r = crate::manual::agent::handle(
            &host.env,
            &crate::manual::testkit::req(
                op::CHRONY_PUBLISH,
                serde_json::json!({
                    "stage_id": stage_id,
                    "expect_current": fsutil::sha256_hex(OLD.as_bytes()),
                    "expect_new": fsutil::sha256_hex(NEW.as_bytes()),
                }),
            ),
        );
        assert!(!r.ok, "{r:?}");
        assert_eq!(live(&w), THIRD, "their edit is the live file again");
        assert_eq!(
            fs::read_to_string(&taken).unwrap(),
            "an earlier kept version\n",
            "the earlier kept file was removed"
        );
    }

    #[test]
    fn ra_d01_a_successful_put_back_leaves_no_second_name_behind() {
        // The ordinary window refusal (the existing D-02 behaviour): the edit
        // is back at the live path and the extra name is removed.
        let w = World::new("ra-d01-ok-put-back");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let _hooks = Hooks::arm(conf, 1, 99);
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        assert!(matches!(r, Err(Failure::Refused(_))), "{r:?}");
        assert_eq!(live(&w), THIRD, "their edit is the live file again");
        assert!(named(&w, ".mkg-displaced-").is_empty());
    }

    #[test]
    fn ra_d01_a_failed_put_back_during_the_rollback_restore_keeps_their_version_too() {
        // The same double fault on the restore side: the restart is a no-op, so
        // the apply rolls back; inside the restore's window somebody edits the
        // file and the put-back fails.
        let w = World::new("ra-d01-restore");
        w.remote
            .host("node-a")
            .sys
            .restart_does_nothing("chrony.service");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        // PRE_SWAP runs once for the publish and once for the restore; the
        // exchanges are: publish #1, restore #2, put-back #3.
        let _hooks = Hooks::arm(conf, 2, 3);
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert!(message.contains(".mkg-displaced-"), "{message}");
        assert!(!message.contains("rolled back to the previous configuration and verified"));
        assert_eq!(kept_copies(&w).len(), 1, "their version is kept");
        assert_eq!(live(&w), OLD, "the previous configuration is the live file");
    }

    #[test]
    fn ra_d02_the_report_says_whether_chronyd_was_restarted_before_the_failure() {
        // The first restart ran (it is the verification that failed); the HA
        // daemon then appears, so the restart that would follow the restore is
        // refused. The text used to say "never restarted chronyd".
        let w = World::new("ra-d02-restarted");
        let sys = w.remote.host("node-a").sys.clone();
        sys.fail_tracking(true);
        let handle = std::rc::Rc::new(w);
        let w2 = handle.clone();
        handle.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("\"action\":\"restart\""),
            1,
            1,
            crate::manual::fakes::Fault::Hook(std::rc::Rc::new(move || {
                sys.unmask("mikagami.service");
                assert!(w2.ha_start("node-a", "mikagami.service"));
            })),
        );
        let r = chrony_ctl::apply(&handle.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert!(message.contains("previous file is back"), "{message}");
        assert!(message.contains("WAS requested"), "{message}");
        assert!(!message.contains("never restarted"), "{message}");
        assert!(!message.contains("did not restart chronyd"), "{message}");
    }
}

// ------------------------------------------------------------------ RA-A-01

mod unreachable_host_halts_the_move {
    use crate::manual::fakes::{Fault, World};
    use crate::manual::proto::op;
    use crate::manual::vip::*;
    use crate::manual::{Failure, Res};
    use std::rc::Rc;

    fn mv(w: &World) -> Res<MoveReport> {
        move_vip(
            &w.ctx(),
            &MoveRequest {
                target: "node-b".to_string(),
                confirm_fenced: None,
            },
        )
    }

    /// `silent` stops answering right when the source service is stopped, i.e.
    /// before the first change of the cloud.
    fn move_with_a_host_that_goes_quiet(silent: &'static str) -> World {
        let w = World::new(&format!("ra-a01-{silent}"));
        let hosts = w.remote.hosts.clone();
        w.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("\"action\":\"stop\""),
            0,
            1,
            Fault::Hook(Rc::new(move || hosts[silent].reachable.set(false))),
        );
        let r = mv(&w);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("{silent}: expected UNKNOWN, got {r:?}");
        };
        assert!(
            message.contains("could not be re-confirmed"),
            "{silent}: {message}"
        );
        assert!(
            message.contains(&format!("{silent} does not answer")),
            "{silent}: {message}"
        );
        assert!(message.contains("without any rollback"), "{message}");
        w
    }

    #[test]
    fn ra_a01_a_host_that_stops_answering_stops_the_move_with_no_cloud_change_and_no_rollback() {
        // The branch `Reach::Down` of the re-check was not pinned by any test
        // (mutant M04 of the audit survived): a quiet host was read as "no
        // HA daemon found" and the move went on.
        let silent = "node-b";
        {
            let w = move_with_a_host_that_goes_quiet(silent);
            assert_eq!(
                w.gce.change_count(),
                0,
                "{silent}: the alias was not touched"
            );
            assert!(w.lease().op.is_some(), "{silent}: the lock stays recorded");
            assert!(
                !w.service_active("node-a") && !w.service_active("node-b"),
                "{silent}: nobody was started again (no rollback)"
            );
            assert_eq!(w.cloud_holders(), ["node-a"], "{silent}");
        }
    }

    #[test]
    fn ra_a01_a_source_that_stops_answering_after_the_release_halts_too() {
        // The source answers everything up to the record of the release and
        // then goes quiet (the host died): the next re-check treats "does not
        // answer" as "not proven" (LIMITATIONS 36), so the target never gets
        // the alias.
        let w = World::new("ra-a01-source");
        let hosts = w.remote.hosts.clone();
        w.remote.inject_when(
            "witness",
            op::LEASE_PHASE,
            Some("\"phase\":\"source_released\""),
            0,
            1,
            Fault::Hook(Rc::new(move || hosts["node-a"].reachable.set(false))),
        );
        let r = mv(&w);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert!(message.contains("node-a does not answer"), "{message}");
        assert!(message.contains("without any rollback"), "{message}");
        assert_eq!(
            w.gce
                .changes()
                .iter()
                .filter(|(i, _)| i == "inst-b")
                .count(),
            0,
            "the target never got the alias"
        );
        assert!(w.lease().op.is_some());
    }
}

// ------------------------------------------------------------------ RA-E-07

mod status_text_is_clean {
    use crate::manual::fakes::{Fault, World};
    use crate::manual::proto::op;
    use crate::manual::run::status_overview_in;
    use serde_json::{Value, json};
    use std::rc::Rc;

    const EVIL: &str = "\u{1b}[31mred\u{202e}gnp\u{200b}\u{2066}x\u{7}";

    fn has_unsafe(text: &str) -> bool {
        text.chars().any(|c| {
            (c.is_control() && c != '\n' && c != '\t')
                || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
        })
    }

    fn strings(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
            Value::Object(m) => {
                for (k, v) in m {
                    out.push(k.clone());
                    strings(v, out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn ra_e07_the_status_overview_text_and_json_carry_no_terminal_control_from_a_remote_host() {
        // The auditor's reproduction: a fake agent answers with an escape
        // sequence and bidirectional controls; `status --control-config`
        // printed them raw.
        let w = World::new("ra-e07");
        w.remote.inject_when(
            "node-a",
            op::PING,
            None,
            0,
            100,
            Fault::Rewrite(Rc::new(|data| {
                data["ha_daemon"] = json!(EVIL);
                data["ha_detail"] = json!([EVIL]);
                data["ha_units"] = json!({ EVIL: EVIL });
            })),
        );
        let out = status_overview_in(&w.ctx()).unwrap();
        assert!(!has_unsafe(&out.text), "text: {:?}", out.text);
        let mut all = Vec::new();
        strings(&out.json, &mut all);
        assert!(all.iter().all(|s| !has_unsafe(s)), "json: {all:?}");
        // The evidence is still shown, made visible rather than dropped.
        assert!(out.text.contains("red?gnp"), "{}", out.text);
    }

    #[test]
    fn ra_e07_the_cleaner_covers_keys_nested_values_and_failures() {
        let mut v = json!({ EVIL: [EVIL, {"k": EVIL}], "n": 1, "b": true, "z": null });
        crate::manual::clean_json_for_terminal(&mut v);
        let mut all = Vec::new();
        strings(&v, &mut all);
        assert!(all.iter().all(|s| !has_unsafe(s)), "{all:?}");
        assert_eq!(v["n"], 1);
        assert_eq!(v["b"], true);
        let f = crate::manual::Failure::Unknown(format!("a {EVIL} b")).cleaned();
        assert!(matches!(&f, crate::manual::Failure::Unknown(m) if !has_unsafe(m)));
        // The kind survives the cleaning.
        assert_eq!(f.label(), "UNKNOWN");
        let doc =
            crate::manual::run::failure_document(&crate::manual::Failure::Failed(EVIL.into()));
        assert!(!has_unsafe(doc["error"].as_str().unwrap()));
    }
}

// ------------------------------------------------------------------ RA-E-09

mod request_read_backstop {
    use crate::manual::agent::{READ_BACKSTOP, read_request};
    use crate::manual::proto::AGENT_BUDGET_SHORT;
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// A pipe whose writer never closes it: `read` blocks until a byte
    /// arrives; `None` over the channel stands for "the process was killed,
    /// the read returns".
    struct Hanging(Receiver<Option<Vec<u8>>>);
    impl Read for Hanging {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.recv() {
                Ok(Some(bytes)) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    Ok(n)
                }
                _ => Ok(0),
            }
        }
    }

    #[test]
    fn ra_e09_a_session_that_never_sends_eof_is_ended_by_the_backstop() {
        let (tx, rx): (Sender<Option<Vec<u8>>>, _) = channel();
        let tx = Arc::new(Mutex::new(tx));
        let fired = Arc::new(AtomicBool::new(false));
        let (fired2, tx2) = (Arc::clone(&fired), Arc::clone(&tx));
        // A partial request, then silence.
        tx.lock().unwrap().send(Some(b"{\"v\":1".to_vec())).unwrap();
        let started = Instant::now();
        // A net for a broken backstop: without it this test would wait for ever
        // instead of failing.
        let net = Arc::clone(&tx);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            let _ = net.lock().unwrap().send(None);
        });
        let input = read_request(
            Hanging(rx),
            1 << 20,
            Duration::from_millis(150),
            move || {
                fired2.store(true, Ordering::SeqCst);
                // In production the process exits here; the test lets the read
                // return instead.
                let _ = tx2.lock().unwrap().send(None);
            },
        )
        .unwrap();
        assert!(fired.load(Ordering::SeqCst), "the backstop ran");
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert_eq!(input, b"{\"v\":1");
    }

    #[test]
    fn ra_e09_a_request_that_arrives_in_time_is_not_cut_by_the_backstop() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired2 = Arc::clone(&fired);
        let input = read_request(
            &b"{\"v\":1}"[..],
            1 << 20,
            Duration::from_millis(100),
            move || fired2.store(true, Ordering::SeqCst),
        )
        .unwrap();
        assert_eq!(input, b"{\"v\":1}");
        // Wait beyond the delay: a finished read releases the backstop, so a
        // long operation that follows is not killed by it.
        std::thread::sleep(Duration::from_millis(350));
        assert!(!fired.load(Ordering::SeqCst));
    }

    #[test]
    fn ra_e09_the_read_limit_is_still_enforced_and_the_wait_is_bounded() {
        let big = vec![b'x'; 5000];
        let input = read_request(&big[..], 100, Duration::from_secs(5), || {}).unwrap();
        assert_eq!(input.len(), 100, "reads at most the limit");
        // The wait is shorter than every controller timeout for the request.
        assert!(READ_BACKSTOP <= AGENT_BUDGET_SHORT + Duration::from_secs(5));
        assert!(READ_BACKSTOP >= Duration::from_secs(5));
    }
}

// ------------------------------------------------------------------ RA-C-05

mod probe_silence {
    use crate::manual::agent::PROBE_REFUSED;
    use crate::manual::fakes::{Fault, World};
    use crate::manual::proto::op;
    use crate::manual::vip::*;
    use crate::manual::{Failure, Res};
    use std::rc::Rc;

    fn mv(w: &World) -> Res<MoveReport> {
        move_vip(
            &w.ctx(),
            &MoveRequest {
                target: "node-b".to_string(),
                confirm_fenced: None,
            },
        )
    }

    #[test]
    fn ra_c05_only_a_refused_connection_counts_as_silence() {
        // Every other failure of the source's local probe (a read timeout, a
        // reply that is not HTTP, a write error) may mean that something
        // accepted the connection: the move may not go on to the release.
        for failure in [
            "timed out",
            "Resource temporarily unavailable (os error 35)",
            "malformed HTTP reply",
            "Broken pipe (os error 32)",
        ] {
            let w = World::new("ra-c05-not-silent");
            let text = format!("probe failed: {failure}");
            w.remote
                .inject_when("node-a", op::PROBE, None, 0, 100, Fault::FailBefore(text));
            let r = mv(&w);
            assert!(
                matches!(&r, Err(Failure::Failed(m)) if m.contains("cannot confirm that nothing answers")),
                "{failure}: {r:?}"
            );
            // The move stopped before the release; the verified rollback ran.
            assert!(
                w.gce.changes().iter().all(|(i, _)| i != "inst-a"),
                "{failure}: the alias was not touched"
            );
            assert!(w.service_active("node-a"), "{failure}");
        }
    }

    #[test]
    fn ra_c05_an_answer_with_neither_a_body_nor_a_refusal_is_not_silence() {
        // An older or damaged agent answers `ok` without saying what it saw.
        for rewritten in [
            serde_json::json!({}),
            serde_json::json!({"status": 200}),
            serde_json::json!({"refused": false}),
            serde_json::json!({"refused": "true"}),
            serde_json::json!({"body": 5}),
        ] {
            let w = World::new("ra-c05-no-body");
            let data = rewritten.clone();
            w.remote.inject_when(
                "node-a",
                op::PROBE,
                None,
                0,
                100,
                Fault::Rewrite(Rc::new(move |d| *d = data.clone())),
            );
            let r = mv(&w);
            assert!(
                matches!(&r, Err(Failure::Failed(m)) if m.contains("cannot confirm that nothing answers")),
                "{rewritten}: {r:?}"
            );
        }
    }

    #[test]
    fn ra_c05_no_failure_of_the_transport_or_of_the_agent_counts_as_silence() {
        // A lost request, a lost answer, a timeout and an in-band refusal of
        // the PROBE operation itself (not the `refused` flag of its answer)
        // say nothing about what listens on the port.
        for (name, fault) in [
            ("request lost", Fault::DropBefore),
            ("answer lost", Fault::DropAfter),
            ("timeout", Fault::TimeoutAfter),
            (
                "agent refuses the operation",
                Fault::RefuseBefore("busy".into()),
            ),
        ] {
            let w = World::new("ra-c05-transport");
            w.remote
                .inject_when("node-a", op::PROBE, None, 0, 100, fault);
            let r = mv(&w);
            assert!(
                matches!(&r, Err(Failure::Failed(m)) if m.contains("cannot confirm that nothing answers")),
                "{name}: {r:?}"
            );
            assert!(
                w.gce.changes().iter().all(|(i, _)| i != "inst-a"),
                "{name}: the alias was not touched"
            );
        }
    }

    #[test]
    fn ra_c05_any_present_body_is_an_answer_also_next_to_a_refusal_flag() {
        // A body that is not text (a damaged reply) or empty text is still the
        // sign of something that accepted the connection (final re-audit N-2).
        for (rewritten, expect) in [
            (
                serde_json::json!({"refused": true, "body": 5}),
                "cannot confirm that nothing answers",
            ),
            (
                serde_json::json!({"refused": true, "body": null}),
                "cannot confirm that nothing answers",
            ),
            (
                serde_json::json!({"refused": true, "body": ["x"]}),
                "cannot confirm that nothing answers",
            ),
            (
                serde_json::json!({"refused": true, "body": ""}),
                "something still answers",
            ),
        ] {
            let w = World::new("ra-c05-body-kinds");
            let data = rewritten.clone();
            w.remote.inject_when(
                "node-a",
                op::PROBE,
                None,
                0,
                100,
                Fault::Rewrite(Rc::new(move |d| *d = data.clone())),
            );
            let r = mv(&w);
            assert!(
                matches!(&r, Err(Failure::Failed(m)) if m.contains(expect)),
                "{rewritten}: {r:?}"
            );
            assert!(
                w.gce.changes().iter().all(|(i, _)| i != "inst-a"),
                "{rewritten}: the alias was not touched"
            );
        }
    }

    #[test]
    fn ra_c05_a_body_wins_over_a_refusal_flag_in_the_same_answer() {
        // `refused: true` next to a body is contradictory: something answered.
        let w = World::new("ra-c05-both");
        w.remote.inject_when(
            "node-a",
            op::PROBE,
            None,
            0,
            100,
            Fault::Rewrite(Rc::new(|d| {
                *d = serde_json::json!({"refused": true, "body": "node-a"});
            })),
        );
        let r = mv(&w);
        assert!(
            matches!(&r, Err(Failure::Failed(m)) if m.contains("something still answers")),
            "{r:?}"
        );
    }

    #[test]
    fn ra_c05_a_refused_connection_is_silence_and_the_move_goes_on() {
        let w = World::new("ra-c05-refused");
        let r = mv(&w);
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn ra_c05_the_agent_tells_a_refusal_from_every_other_failure() {
        use crate::manual::testkit::{FakeSystem, agent_env, req};
        let sys = FakeSystem::default();
        let (env, dir) = agent_env("ra-c05-agent", sys.clone());
        let ask = || {
            crate::manual::agent::handle(
                &env,
                &req(
                    op::PROBE,
                    serde_json::json!({"addr": "127.0.0.1", "port": 8080, "path": "/id"}),
                ),
            )
        };
        sys.set_probe_fn(Box::new(|_, _| Err(PROBE_REFUSED.to_string())));
        let r = ask();
        assert!(r.ok, "{r:?}");
        assert_eq!(r.data["refused"], true);
        assert!(r.data.get("body").is_none());
        for other in [
            "timed out",
            "Connection reset by peer (os error 54)",
            "refused", // not the exact marker
            "connection refused by the proxy",
        ] {
            let text = other.to_string();
            sys.set_probe_fn(Box::new(move |_, _| Err(text.clone())));
            let r = ask();
            assert!(!r.ok, "{other}: {r:?}");
            assert_eq!(
                r.error.as_ref().unwrap().code,
                crate::manual::proto::code::FAILED
            );
        }
        sys.set_probe_fn(Box::new(|_, _| Ok((200, "node-a".to_string()))));
        let r = ask();
        assert!(r.ok);
        assert_eq!(r.data["body"], "node-a");
        let _ = Rc::new(());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

// ------------------------------------------------------------------ RA-D-03

mod chrony_mutant_guards {
    use crate::manual::Failure;
    use crate::manual::chrony_ctl;
    use crate::manual::fakes::{Fault, World};
    use crate::manual::fsutil;
    use crate::manual::proto::{code, op};
    use crate::manual::testkit::{FakeSystem, agent_env, req};
    use serde_json::json;
    use std::fs;
    use std::rc::Rc;

    const OLD: &str = "pool 2.pool.ntp.org iburst\n";
    const NEW: &str = "pool time.example.invalid iburst\nmakestep 1 3\n";
    const THIRD: &str = "server admin-edit.example.invalid\n";

    fn sha(text: &str) -> String {
        fsutil::sha256_hex(text.as_bytes())
    }

    #[test]
    fn ra_d03_m14_an_edit_between_the_restart_and_the_verification_is_not_a_success() {
        // The verification must look at the live hash: without that look the
        // apply answered Ok(changed: true) for a file nobody applied.
        let w = World::new("ra-d03-m14");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        // chrony.state #1 observes the file, #2 is the verification's first
        // look after the restart.
        w.remote.inject_when(
            "node-a",
            op::CHRONY_STATE,
            None,
            1,
            1,
            Fault::Hook(Rc::new(move || fs::write(&conf, THIRD).unwrap())),
        );
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        assert!(
            matches!(&r, Err(Failure::Unknown(m)) if m.contains("hash differs")),
            "{r:?}"
        );
        let live = fs::read_to_string(&w.remote.host("node-a").env.cfg.chrony_conf).unwrap();
        assert_eq!(live, THIRD, "their file is not overwritten by the rollback");
    }

    #[test]
    fn ra_d03_m18_a_damaged_backup_is_never_written_over_the_live_file() {
        let w = World::new("ra-d03-m18");
        w.remote
            .host("node-a")
            .sys
            .restart_does_nothing("chrony.service");
        let backups = w.remote.host("node-a").env.cfg.backup_dir.clone();
        w.remote.inject_when(
            "node-a",
            op::CHRONY_RESTORE,
            None,
            0,
            1,
            Fault::Hook(Rc::new(move || {
                for entry in fs::read_dir(&backups).unwrap().flatten() {
                    if entry.file_name().to_string_lossy().starts_with("chrony-") {
                        fs::write(entry.path(), "garbage\n").unwrap();
                    }
                }
            })),
        );
        let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(message)) = &r else {
            panic!("expected UNKNOWN, got {r:?}");
        };
        assert!(message.contains("ROLLBACK FAILED"), "{message}");
        assert!(
            message.contains("does not match its recorded hash"),
            "{message}"
        );
        let live = fs::read_to_string(&w.remote.host("node-a").env.cfg.chrony_conf).unwrap();
        assert_eq!(
            live, NEW,
            "the damaged backup was not copied to the live file"
        );
    }

    #[test]
    fn ra_d03_m23_an_exchange_error_other_than_unsupported_never_falls_back_to_a_rename() {
        let sys = FakeSystem::default();
        let (env, dir) = agent_env("ra-d03-m23", sys);
        fs::write(&env.cfg.chrony_conf, OLD).unwrap();
        let stage = crate::manual::agent::handle(
            &env,
            &req(
                op::CHRONY_STAGE,
                json!({"content": NEW, "sha256": sha(NEW)}),
            ),
        );
        let stage_id = stage.data["stage_id"].as_str().unwrap().to_string();
        fsutil::EXCHANGE_CALLS.with(|c| c.set(0));
        fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(Some(1)));
        let r = crate::manual::agent::handle(
            &env,
            &req(
                op::CHRONY_PUBLISH,
                json!({"stage_id": stage_id, "expect_current": sha(OLD), "expect_new": sha(NEW)}),
            ),
        );
        fsutil::EXCHANGE_FAIL_AT.with(|c| c.set(None));
        assert!(!r.ok, "{r:?}");
        assert_eq!(r.error.as_ref().unwrap().code, code::FAILED);
        assert_eq!(
            fs::read_to_string(&env.cfg.chrony_conf).unwrap(),
            OLD,
            "no plain rename replaced the live file"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ra_d03_m04_a_restore_over_a_file_that_is_neither_ours_nor_the_backup_exchanges_nothing() {
        // The refusal must come from the comparison, before any file is moved;
        // the put-back of the exchange would also end "refused" but only after
        // the live path had been touched.
        let sys = FakeSystem::default();
        let (env, dir) = agent_env("ra-d03-m04", sys);
        fs::write(&env.cfg.chrony_conf, OLD).unwrap();
        let backup = crate::manual::agent::handle(
            &env,
            &req(op::CHRONY_BACKUP, json!({"expect_sha256": sha(OLD)})),
        );
        assert!(backup.ok, "{backup:?}");
        fs::write(&env.cfg.chrony_conf, THIRD).unwrap();
        fsutil::EXCHANGE_CALLS.with(|c| c.set(0));
        let r = crate::manual::agent::handle(
            &env,
            &req(
                op::CHRONY_RESTORE,
                json!({
                    "backup_id": backup.data["backup_id"],
                    "expect_backup": sha(OLD),
                    "expect_current": sha(NEW),
                }),
            ),
        );
        let exchanges = fsutil::EXCHANGE_CALLS.with(std::cell::Cell::get);
        fsutil::EXCHANGE_CALLS.with(|c| c.set(0));
        assert!(!r.ok, "{r:?}");
        assert_eq!(r.error.as_ref().unwrap().code, code::REFUSED);
        assert_eq!(exchanges, 0, "nothing was exchanged");
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), THIRD);
        fs::remove_dir_all(dir).unwrap();
    }
}
