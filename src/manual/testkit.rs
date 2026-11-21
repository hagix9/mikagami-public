#![allow(dead_code)]
//! Test doubles shared by the manual control plane tests (`cfg(test)` only).

use super::agent::{AgentConfig, AgentEnv, CheckResult, ServiceState, SystemOps};
use super::fsutil::tests::{my_uid, temp_dir};
use super::proto::{self, PROTO_VERSION, Request};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[derive(Default)]
struct SysInner {
    services: BTreeMap<String, String>,
    actions: Vec<String>,
    fail_queries: bool,
    fail_actions: Vec<String>,
    fail_action_units: Vec<String>,
    /// `stop` leaves the unit in this state instead of `inactive`.
    stop_leaves: BTreeMap<String, String>,
    reject: Option<String>,
    fail_check: bool,
    fail_tracking: bool,
    probe_body: Option<String>,
    probe_fails: bool,
    probe_fn: Option<ProbeFn>,
    /// Units whose symlink to /dev/null exists (persistent mask).
    masked: BTreeSet<String>,
    /// Units masked only until the next reboot (`mask --runtime`).
    runtime_masked: BTreeSet<String>,
    /// Pending systemd jobs, as unit names.
    jobs: Vec<String>,
    fail_jobs: bool,
    /// Processes that look like a manually started HA daemon.
    ha_processes: Vec<String>,
    fail_processes: bool,
    /// Names of the HA units of this host (ground truth for the monitor).
    ha_names: Vec<String>,
    /// Every successful start of an HA unit, in order.
    ha_starts: Vec<String>,
    /// How many times a unit was (re)started: the fake `MainPID` and
    /// `ActiveEnterTimestampMonotonic` change with it.
    incarnation: BTreeMap<String, u32>,
    /// Units for which `restart` reports success but does nothing.
    restart_is_noop: BTreeSet<String>,
}

pub(crate) type ProbeFn = Box<dyn Fn(Ipv4Addr, u16) -> Result<(u16, String), String>>;

/// In-memory operating system for one fake host. Cloning shares the state.
#[derive(Clone)]
pub(crate) struct FakeSystem(Rc<RefCell<SysInner>>);

pub(crate) const HA_UNITS: [&str; 2] = ["mikagami.service", "mikagami-witness.service"];

impl Default for FakeSystem {
    /// A manual-mode host: both HA units are masked (and inactive).
    fn default() -> Self {
        let mut inner = SysInner::default();
        inner
            .services
            .insert("chrony.service".to_string(), "active".to_string());
        for unit in HA_UNITS {
            inner.masked.insert(unit.to_string());
            inner.ha_names.push(unit.to_string());
        }
        Self(Rc::new(RefCell::new(inner)))
    }
}

impl FakeSystem {
    pub(crate) fn set_service(&self, unit: &str, active_state: &str) {
        self.0
            .borrow_mut()
            .services
            .insert(unit.to_string(), active_state.to_string());
    }

    pub(crate) fn service(&self, unit: &str) -> Option<String> {
        self.0.borrow().services.get(unit).cloned()
    }

    /// Persistently mask `unit` (a running unit keeps running).
    pub(crate) fn mask(&self, unit: &str) {
        let mut inner = self.0.borrow_mut();
        inner.runtime_masked.remove(unit);
        inner.masked.insert(unit.to_string());
    }

    pub(crate) fn runtime_mask(&self, unit: &str) {
        let mut inner = self.0.borrow_mut();
        inner.masked.remove(unit);
        inner.runtime_masked.insert(unit.to_string());
    }

    /// Unmask: the unit is loaded again (inactive unless it was running).
    pub(crate) fn unmask(&self, unit: &str) {
        let mut inner = self.0.borrow_mut();
        inner.masked.remove(unit);
        inner.runtime_masked.remove(unit);
        inner
            .services
            .entry(unit.to_string())
            .or_insert_with(|| "inactive".to_string());
    }

    /// The unit file is gone: `LoadState=not-found`.
    pub(crate) fn remove_unit(&self, unit: &str) {
        let mut inner = self.0.borrow_mut();
        inner.masked.remove(unit);
        inner.runtime_masked.remove(unit);
        inner.services.remove(unit);
    }

    /// Register one more unit as an HA unit (ground truth for the monitor).
    pub(crate) fn track_ha_unit(&self, unit: &str) {
        self.0.borrow_mut().ha_names.push(unit.to_string());
    }

    pub(crate) fn set_jobs(&self, units: &[&str]) {
        self.0.borrow_mut().jobs = units.iter().map(|u| (*u).to_string()).collect();
    }

    pub(crate) fn fail_jobs(&self, on: bool) {
        self.0.borrow_mut().fail_jobs = on;
    }

    pub(crate) fn set_ha_processes(&self, hits: &[&str]) {
        self.0.borrow_mut().ha_processes = hits.iter().map(|h| (*h).to_string()).collect();
    }

    pub(crate) fn fail_processes(&self, on: bool) {
        self.0.borrow_mut().fail_processes = on;
    }

    /// What a boot or an administrator's `systemctl start` would do. A
    /// masked or missing unit refuses to start. Returns whether it started.
    pub(crate) fn ha_start(&self, unit: &str) -> bool {
        let mut inner = self.0.borrow_mut();
        if inner.masked.contains(unit)
            || inner.runtime_masked.contains(unit)
            || !inner.services.contains_key(unit)
        {
            return false;
        }
        inner
            .services
            .insert(unit.to_string(), "active".to_string());
        inner.ha_starts.push(unit.to_string());
        true
    }

    pub(crate) fn ha_starts(&self) -> Vec<String> {
        self.0.borrow().ha_starts.clone()
    }

    /// Ground truth, independent of the agent's own classification: an HA
    /// unit is running (or starting) or an HA process exists.
    pub(crate) fn ha_running(&self) -> bool {
        let inner = self.0.borrow();
        !inner.ha_processes.is_empty()
            || inner.ha_names.iter().any(|name| {
                matches!(
                    inner.services.get(name).map(String::as_str),
                    Some("active" | "activating" | "reloading" | "deactivating")
                )
            })
    }

    pub(crate) fn fail_queries(&self, on: bool) {
        self.0.borrow_mut().fail_queries = on;
    }

    pub(crate) fn fail_action(&self, action: &str) {
        self.0.borrow_mut().fail_actions.push(action.to_string());
    }

    pub(crate) fn fail_action_on(&self, unit: &str) {
        self.0.borrow_mut().fail_action_units.push(unit.to_string());
    }

    pub(crate) fn stop_leaves(&self, unit: &str, state: &str) {
        self.0
            .borrow_mut()
            .stop_leaves
            .insert(unit.to_string(), state.to_string());
    }

    pub(crate) fn clear_failures(&self) {
        let mut inner = self.0.borrow_mut();
        inner.fail_actions.clear();
        inner.fail_action_units.clear();
        inner.stop_leaves.clear();
        inner.fail_queries = false;
        inner.fail_check = false;
        inner.fail_tracking = false;
        inner.probe_fails = false;
        inner.reject = None;
    }

    pub(crate) fn actions(&self) -> Vec<String> {
        self.0.borrow().actions.clone()
    }

    pub(crate) fn set_probe_body(&self, body: &str) {
        self.0.borrow_mut().probe_body = Some(body.to_string());
    }

    pub(crate) fn set_probe_fn(&self, f: ProbeFn) {
        self.0.borrow_mut().probe_fn = Some(f);
    }

    pub(crate) fn fail_probe(&self, on: bool) {
        self.0.borrow_mut().probe_fails = on;
    }

    pub(crate) fn reject_config(&self, needle: &str) {
        self.0.borrow_mut().reject = Some(needle.to_string());
    }

    pub(crate) fn fail_check(&self) {
        self.0.borrow_mut().fail_check = true;
    }

    /// `restart` of `unit` succeeds without restarting anything (the process
    /// and its start time stay the same).
    pub(crate) fn restart_does_nothing(&self, unit: &str) {
        self.0.borrow_mut().restart_is_noop.insert(unit.to_string());
    }

    pub(crate) fn fail_tracking(&self, on: bool) {
        self.0.borrow_mut().fail_tracking = on;
    }
}

impl SystemOps for FakeSystem {
    fn service_state(&self, unit: &str) -> Result<ServiceState, String> {
        let inner = self.0.borrow();
        if inner.fail_queries {
            return Err("injected query failure".to_string());
        }
        let masked = inner.masked.contains(unit);
        let runtime_masked = inner.runtime_masked.contains(unit);
        Ok(match inner.services.get(unit) {
            Some(active) => ServiceState {
                load_state: if masked || runtime_masked {
                    "masked"
                } else {
                    "loaded"
                }
                .to_string(),
                active_state: active.clone(),
                sub_state: if active == "active" {
                    "running"
                } else {
                    "dead"
                }
                .to_string(),
                unit_file_state: if masked {
                    "masked"
                } else if runtime_masked {
                    "masked-runtime"
                } else {
                    "enabled"
                }
                .to_string(),
                main_pid: inner
                    .incarnation
                    .get(unit)
                    .map_or_else(|| "0".to_string(), |n| (4000 + n).to_string()),
                active_enter: inner
                    .incarnation
                    .get(unit)
                    .map_or_else(|| "0".to_string(), |n| (1_000_000 * n).to_string()),
            },
            None if masked || runtime_masked => ServiceState {
                load_state: "masked".to_string(),
                active_state: "inactive".to_string(),
                sub_state: "dead".to_string(),
                unit_file_state: if masked { "masked" } else { "masked-runtime" }.to_string(),
                ..ServiceState::default()
            },
            None => ServiceState {
                load_state: "not-found".to_string(),
                active_state: "inactive".to_string(),
                sub_state: "dead".to_string(),
                ..ServiceState::default()
            },
        })
    }

    fn service_action(
        &self,
        _proof: &crate::manual::exclusion::ExclusiveProof,
        unit: &str,
        action: &str,
    ) -> Result<(), String> {
        let mut inner = self.0.borrow_mut();
        if inner.masked.contains(unit) || inner.runtime_masked.contains(unit) {
            return Err(format!("Unit {unit} is masked."));
        }
        if inner.fail_actions.iter().any(|a| a == action)
            || inner.fail_action_units.iter().any(|u| u == unit)
        {
            return Err(format!("injected {action} failure"));
        }
        inner.actions.push(format!("{action} {unit}"));
        if action != "stop" && !(action == "restart" && inner.restart_is_noop.contains(unit)) {
            *inner.incarnation.entry(unit.to_string()).or_insert(1) += 1;
        }
        let state = match action {
            "stop" => inner
                .stop_leaves
                .get(unit)
                .cloned()
                .unwrap_or_else(|| "inactive".to_string()),
            _ => "active".to_string(),
        };
        inner.services.insert(unit.to_string(), state);
        Ok(())
    }

    fn chronyd_check(&self, conf: &Path) -> CheckResult {
        let inner = self.0.borrow();
        if inner.fail_check {
            return CheckResult::ToolFailure("injected tool failure".to_string());
        }
        let text = std::fs::read_to_string(conf).unwrap_or_default();
        match &inner.reject {
            Some(needle) if text.contains(needle.as_str()) => {
                CheckResult::Rejected("configuration rejected by chronyd".to_string())
            }
            _ => CheckResult::Valid,
        }
    }

    fn chronyc_tracking(&self) -> Result<String, String> {
        if self.0.borrow().fail_tracking {
            Err("injected tracking failure".to_string())
        } else {
            Ok("Reference ID    : 00000000 ()".to_string())
        }
    }

    fn probe(&self, addr: Ipv4Addr, port: u16, _path: &str) -> Result<(u16, String), String> {
        let inner = self.0.borrow();
        if inner.probe_fails {
            return Err("injected probe failure".to_string());
        }
        if let Some(f) = &inner.probe_fn {
            return f(addr, port);
        }
        match &inner.probe_body {
            Some(body) => Ok((200, body.clone())),
            None => Err("connection refused".to_string()),
        }
    }

    fn boot_id(&self) -> String {
        "00000000-0000-0000-0000-000000000000".to_string()
    }

    fn pending_jobs(&self) -> Result<Vec<String>, String> {
        let inner = self.0.borrow();
        if inner.fail_jobs {
            return Err("injected list-jobs failure".to_string());
        }
        Ok(inner.jobs.clone())
    }

    fn ha_processes(&self) -> Result<Vec<String>, String> {
        let inner = self.0.borrow();
        if inner.fail_processes {
            return Err("injected /proc failure".to_string());
        }
        Ok(inner.ha_processes.clone())
    }
}

pub(crate) fn req(op: &str, args: Value) -> Request {
    Request {
        v: PROTO_VERSION,
        id: proto::random_hex(8),
        op: op.to_string(),
        args,
    }
}

pub(crate) const TEST_NOW: u64 = 1_700_000_000;

/// An agent environment rooted in a private temporary directory.
pub(crate) fn agent_env(label: &str, sys: FakeSystem) -> (AgentEnv, PathBuf) {
    agent_env_named(label, "node-a", sys)
}

pub(crate) fn agent_env_named(label: &str, node: &str, sys: FakeSystem) -> (AgentEnv, PathBuf) {
    agent_env_with_now(label, node, sys, Box::new(|| TEST_NOW))
}

pub(crate) fn agent_env_with_now(
    label: &str,
    node: &str,
    sys: FakeSystem,
    now: Box<dyn Fn() -> u64>,
) -> (AgentEnv, PathBuf) {
    agent_env_custom(label, node, sys, now, &|_| {})
}

/// Like [`agent_env_with_now`], with a last-moment edit of the configuration.
pub(crate) fn agent_env_custom(
    label: &str,
    node: &str,
    sys: FakeSystem,
    now: Box<dyn Fn() -> u64>,
    tweak: &dyn Fn(&mut AgentConfig),
) -> (AgentEnv, PathBuf) {
    let dir = temp_dir(label);
    let chrony_dir = dir.join("etc-chrony");
    std::fs::create_dir_all(&chrony_dir).unwrap();
    let mut cfg = AgentConfig {
        cluster: "test".to_string(),
        node: node.to_string(),
        nodes: vec!["node-a".to_string(), "node-b".to_string()],
        systemctl: "/unused".to_string(),
        chronyd: "/unused".to_string(),
        chronyc: "/unused".to_string(),
        allowed_units: vec!["mkg-demo.service".to_string(), "chrony.service".to_string()],
        ha_units: vec![
            "mikagami.service".to_string(),
            "mikagami-witness.service".to_string(),
        ],
        chrony_conf: chrony_dir.join("chrony.conf"),
        chrony_unit: "chrony.service".to_string(),
        backup_dir: dir.join("backups"),
        lease_state: Some(dir.join("lease").join("lease.json")),
        fence_state: dir.join("fence").join("fence.json"),
        ha_absent_ack: false,
        ha_config: dir.join("etc-mikagami").join("mikagami.toml"),
        ha_config_ack: false,
        manual_vips: vec!["10.0.0.130".to_string()],
        control_lock_path: dir.join("control").join("control.lock"),
        manual_barrier_path: dir.join("control").join("manual-operation.json"),
    };
    tweak(&mut cfg);
    let env = AgentEnv {
        cfg,
        sys: Box::new(sys),
        owner_uid: my_uid(),
        now,
    };
    (env, dir)
}
