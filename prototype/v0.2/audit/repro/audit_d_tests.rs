//! AUDIT D adversarial tests (copy only).
use super::chrony_agent::PRE_RENAME;
use super::fakes::{Fault, World};
use super::proto::{PROTO_VERSION, Request, op, random_hex};
use super::{Failure, chrony_ctl, fsutil};
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;

const OLD: &str = "pool 2.pool.ntp.org iburst\n";
const NEW: &str = "pool time.example.invalid iburst\nmakestep 1 3\n";
fn sha(s: &str) -> String { fsutil::sha256_hex(s.as_bytes()) }

/// D-01: a late-running publish (agent outlived the ssh timeout) lands between
/// the controller's re-read ("unchanged") and its cleanup.
#[test]
fn d01_late_publish_between_reread_and_cleanup_gives_false_unchanged() {
    let w = World::new("auditd-late");
    w.remote.inject("node-a", op::CHRONY_PUBLISH, Fault::DropBefore);
    let hosts = w.remote.hosts.clone();
    let new_sha = sha(NEW);
    let old_sha = sha(OLD);
    // Hook runs just before the controller's CLEANUP call is handled, i.e.
    // after the controller concluded "live file unchanged" from its re-read.
    w.remote.inject("node-a", op::CHRONY_CLEANUP, Fault::Hook(std::rc::Rc::new(move || {
        let host = &hosts["node-a"];
        let dir = host.env.cfg.chrony_conf.parent().unwrap().to_path_buf();
        let name = fs::read_dir(&dir).unwrap().filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| n.starts_with(".mkg-stage-")).unwrap();
        let stage_id = name.trim_start_matches(".mkg-stage-").trim_end_matches(".conf").to_string();
        let r = super::agent::handle(&host.env, &Request { v: PROTO_VERSION, id: random_hex(8),
            op: op::CHRONY_PUBLISH.into(),
            args: json!({"stage_id": stage_id, "expect_current": old_sha, "expect_new": new_sha}) });
        assert!(r.ok, "late publish must succeed in this interleaving: {r:?}");
    })));
    let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
    let live = fs::read_to_string(&w.remote.host("node-a").env.cfg.chrony_conf).unwrap();
    println!("apply result: {r:?}\nlive == NEW: {}\nrestart actions: {:?}", live == NEW, w.remote.host("node-a").sys.actions());
    assert!(matches!(&r, Err(Failure::Failed(m)) if m.contains("unchanged")));
    assert_eq!(live, NEW, "DEFECT: reported 'unchanged' but the new file is live and chronyd was not restarted");
}

/// D-02: foreign edit between CAS check and rename is silently destroyed and apply reports success.
#[test]
fn d02_edit_inside_cas_window_is_lost_and_apply_succeeds() {
    let w = World::new("auditd-window");
    let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
    let c2 = conf.clone();
    PRE_RENAME.with(|h| *h.borrow_mut() = Some(Box::new(move || fs::write(&c2, "server admin-edit.example.invalid\n").unwrap())));
    let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
    PRE_RENAME.with(|h| *h.borrow_mut() = None);
    println!("apply result ok={} ; live == NEW: {}", r.is_ok(), fs::read_to_string(&conf).unwrap() == NEW);
    assert!(r.is_ok());
    assert_eq!(fs::read_to_string(&conf).unwrap(), NEW);
    // the admin's edit exists nowhere: backups hold only OLD
    let backups = w.remote.host("node-a").env.cfg.backup_dir.clone();
    for e in fs::read_dir(backups).unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with("chrony-") {
            assert!(!fs::read_to_string(e.path()).unwrap().contains("admin-edit"));
        }
    }
}

/// D-03: mode is normalised to 0644 on apply and rollback.
#[test]
fn d03_mode_not_preserved_on_apply_and_rollback() {
    let w = World::new("auditd-mode");
    let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
    fs::set_permissions(&conf, fs::Permissions::from_mode(0o600)).unwrap();
    chrony_ctl::apply(&w.ctx(), "node-a", NEW, false).unwrap();
    let mode = fs::metadata(&conf).unwrap().permissions().mode() & 0o777;
    println!("mode after apply: {mode:o} (was 600)");
    assert_eq!(mode, 0o644);
}

/// D-04: controller restarts cluster.chrony_unit, verification observes agent chrony.unit.
#[test]
fn d04_unit_mismatch_between_controller_and_agent_is_a_false_success() {
    let mut w = World::new("auditd-unit");
    // (a) unit not in agent allowlist: published, restart refused, rollback restart refused
    w.cfg.chrony_unit = "chronyd.service".to_string();
    let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
    println!("(a) apply result: {r:?}");
    // (b) a different but allowed unit
    let w = World::new("auditd-unit2");
    let mut w = w;
    w.cfg.chrony_unit = "mkg-demo.service".to_string();
    w.remote.host("node-a").sys.set_service("mkg-demo.service", "active");
    let r = chrony_ctl::apply(&w.ctx(), "node-a", NEW, false);
    println!("(b) apply result ok={} actions={:?}", r.is_ok(), w.remote.host("node-a").sys.actions());
    assert!(r.is_ok());
    assert_eq!(w.remote.host("node-a").sys.actions(), vec!["restart mkg-demo.service"]);
}
