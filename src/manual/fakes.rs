#![allow(dead_code)]
//! A complete in-memory world for the controller tests: a fake cloud, fake
//! hosts running the *real* agent code, a virtual clock and fault injection.
//!
//! The fake cloud models requests that land *after* the caller gave up
//! (operations that stay `PENDING`, optionally invisible, and are applied
//! later as a full alias-list replacement), and lists its operations.
//!
//! A monitor checks after every effect (including a late landing) that
//!
//! * at most one node both holds the VIP alias and runs the service,
//! * the alias is never on two NICs at once,
//! * a destructive action (cloud change or `service.control`) is performed
//!   only by the controller whose operation currently holds the lease, and
//! * whenever the lease lock is released (commit / abort / reconcile) or a
//!   late request lands on an unlocked lease: no cloud operation is still
//!   pending, exactly the recorded owner holds the alias, and no other node
//!   runs the service.

use super::agent::{AgentEnv, handle};
use super::clock::Clock;
use super::config::{ControlConfig, tests::sample};
use super::fsutil::tests::temp_dir;
use super::gce::{Alias, ChangeReport, CloudOp, Gce, InstanceInfo, OPS_LIMIT, OpList, Unavailable};
use super::proto::{self, PROTO_VERSION, Request, Response, code, op};
use super::remote::{Remote, Target, TransportError};
use super::testkit::{FakeSystem, agent_env_custom};
use super::{Ctx, Reporter};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

pub(crate) const VIP: &str = "10.0.0.130";
pub(crate) const VIP_CIDR: &str = "10.0.0.130/32";

// ------------------------------------------------------------------ clock

pub(crate) struct FakeClock {
    ms: Rc<Cell<u64>>,
}

impl FakeClock {
    pub(crate) fn new() -> Self {
        Self {
            ms: Rc::new(Cell::new(1_000)),
        }
    }

    pub(crate) fn handle(&self) -> Rc<Cell<u64>> {
        self.ms.clone()
    }

    pub(crate) fn advance_secs(&self, secs: u64) {
        self.ms.set(self.ms.get() + secs * 1000);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.ms.get()
    }

    fn sleep(&self, duration: Duration) {
        self.ms
            .set(self.ms.get() + u64::try_from(duration.as_millis()).unwrap());
    }

    fn unix_secs(&self) -> u64 {
        super::testkit::TEST_NOW + self.ms.get() / 1000
    }
}

// --------------------------------------------------------------- reporter

#[derive(Default)]
pub(crate) struct VecLog(RefCell<Vec<String>>);

impl Reporter for VecLog {
    fn info(&self, message: &str) {
        self.0.borrow_mut().push(message.to_string());
    }
}

impl VecLog {
    pub(crate) fn lines(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

// -------------------------------------------------------------------- gce

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChangeBehavior {
    Normal,
    /// The change is applied (operation DONE), the tool reports an error.
    ErrorAfterApply,
    /// The operation finishes with an error and is not applied; the tool
    /// reports an error.
    ErrorNoApply,
    /// The request is rejected before any operation exists (for example a
    /// permission error); the tool reports an error.
    ErrorNoOperation,
    /// The operation finishes with an error and is not applied, but the tool
    /// reports a timeout instead of the error.
    TimeoutFailedOp,
    /// The operation finishes with an error and is not applied, but the tool's
    /// message looks like an explicit client error (HTTP 403).
    RejectedButFailedOp,
    /// The change is applied (operation DONE), the tool times out.
    TimeoutAfterApply,
    /// The request never reaches the cloud (no operation, never lands); the
    /// tool times out.
    TimeoutNoApply,
    /// The tool times out while the operation is still `PENDING`; it is
    /// applied later (see [`FakeGce::land_all`]).
    TimeoutPending,
    /// The tool times out and no operation is visible yet; the request lands
    /// later and only then shows up as a finished operation.
    TimeoutInvisible,
    /// The tool times out while the operation is `PENDING`; it finishes (and
    /// is applied) at the n-th listing of operations after the request.
    PendingLandsAfterLists(u32),
    /// The cloud answers the request with an explicit client error (HTTP
    /// status given): no operation exists, nothing is applied, and the tool
    /// reports [`ChangeReport::Rejected`].
    Rejected(u16),
    /// The tool reports an explicit client error although the request was
    /// accepted and applied (the error belonged to a later stage, for example
    /// waiting for the operation): the operation is `DONE`.
    RejectedButApplied,
    /// ... and the operation is still `PENDING` (lands later).
    RejectedButPending,
    /// ... and the operation is not visible yet: it appears, applied, at the
    /// n-th listing of operations after the request (a lagging listing).
    RejectedButInvisibleUntilList(u32),
}

pub(crate) struct FakeInstance {
    pub(crate) id: String,
    pub(crate) status: String,
    pub(crate) aliases: Vec<Alias>,
}

/// One operation as the fake cloud lists it.
#[derive(Clone, Debug)]
pub(crate) struct FakeOp {
    pub(crate) name: String,
    pub(crate) instance: String,
    pub(crate) op_type: String,
    pub(crate) status: String,
    pub(crate) failed: bool,
    /// Created by somebody else (history); never counts as this
    /// controller's pending request.
    pub(crate) foreign: bool,
}

/// A request the caller gave up on; it replaces the whole alias list when it
/// lands.
#[derive(Clone, Debug)]
pub(crate) struct LateRequest {
    pub(crate) instance: String,
    pub(crate) aliases: Vec<Alias>,
    /// The visible `PENDING` operation, if any.
    pub(crate) op_name: Option<String>,
    /// Land when the operation list has been read this many more times.
    pub(crate) land_after_lists: Option<u32>,
}

/// A hook run on the cloud's internal state at a chosen moment.
pub(crate) type GceHook = Box<dyn FnOnce(&mut GceInner)>;
/// The safety monitor, shared by the fake cloud and the fake hosts.
type MonitorSlot = Rc<RefCell<Option<Rc<dyn Fn(&str)>>>>;

pub(crate) const NIC_UPDATE: &str = "compute.instances.updateNetworkInterface";

#[derive(Default)]
pub(crate) struct GceInner {
    pub(crate) instances: BTreeMap<String, FakeInstance>,
    /// After a change, the next N reads of that instance return the old list.
    pub(crate) stale: BTreeMap<String, (Vec<Alias>, u32)>,
    pub(crate) lag_reads: u32,
    /// After a change the first read shows the new state, the second the old
    /// one again, then the new state for good (an inconsistent read replica).
    pub(crate) flap: bool,
    pub(crate) flap_plan: BTreeMap<String, (Vec<Alias>, Vec<bool>)>,
    pub(crate) behavior: BTreeMap<String, Vec<ChangeBehavior>>,
    pub(crate) describe_fail: Vec<String>,
    pub(crate) describe_calls: usize,
    pub(crate) scheduled: Vec<(usize, GceHook)>,
    /// Hooks run at the n-th listing of operations (counted in
    /// `list_calls`), before the listing is made.
    pub(crate) scheduled_lists: Vec<(usize, GceHook)>,
    pub(crate) changes: Vec<(String, Vec<String>)>,
    /// The audit tag (operation id) of every change, parallel to `changes`.
    pub(crate) change_tags: Vec<String>,
    pub(crate) ops: Vec<FakeOp>,
    pub(crate) late: Vec<LateRequest>,
    /// Land every queued request at this describe count.
    pub(crate) land_at: Vec<usize>,
    pub(crate) fail_list: bool,
    /// The next listing fails, the ones after it work again.
    pub(crate) fail_list_once: bool,
    pub(crate) list_calls: usize,
    /// Run once right after the next change was applied (an external actor
    /// racing the controller).
    pub(crate) after_change: Vec<GceHook>,
    next_op: usize,
    landed_flag: bool,
}

impl GceInner {
    pub(crate) fn new_op(&mut self, instance: &str, status: &str, failed: bool) -> String {
        self.next_op += 1;
        let name = format!("operation-{:04}", self.next_op);
        self.ops.push(FakeOp {
            name: name.clone(),
            instance: instance.to_string(),
            op_type: NIC_UPDATE.to_string(),
            status: status.to_string(),
            failed,
            foreign: false,
        });
        name
    }

    /// Apply one queued request and finish its operation.
    fn land(&mut self, request: LateRequest) {
        if let Some(instance) = self.instances.get_mut(&request.instance) {
            instance.aliases = request.aliases.clone();
        }
        match &request.op_name {
            Some(name) => {
                if let Some(op) = self.ops.iter_mut().find(|o| &o.name == name) {
                    op.status = "DONE".to_string();
                }
            }
            None => {
                self.new_op(&request.instance, "DONE", false);
            }
        }
        self.landed_flag = true;
    }

    fn land_all(&mut self) {
        for request in std::mem::take(&mut self.late) {
            self.land(request);
        }
    }

    /// `true` while any request can still change the cloud.
    pub(crate) fn has_pending(&self) -> bool {
        !self.late.is_empty() || self.ops.iter().any(|o| !o.foreign && o.status != "DONE")
    }
}

#[derive(Clone)]
pub(crate) struct FakeGce {
    pub(crate) inner: Rc<RefCell<GceInner>>,
    monitor: MonitorSlot,
    events: Rc<RefCell<Vec<String>>>,
}

impl FakeGce {
    fn new(events: Rc<RefCell<Vec<String>>>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(GceInner::default())),
            monitor: Rc::new(RefCell::new(None)),
            events,
        }
    }

    pub(crate) fn add_instance(&self, name: &str, aliases: &[&str]) {
        self.inner.borrow_mut().instances.insert(
            name.to_string(),
            FakeInstance {
                id: format!("id-{name}"),
                status: "RUNNING".to_string(),
                aliases: aliases.iter().map(|a| Alias::plain(a)).collect(),
            },
        );
    }

    pub(crate) fn set_status(&self, name: &str, status: &str) {
        self.inner
            .borrow_mut()
            .instances
            .get_mut(name)
            .unwrap()
            .status = status.to_string();
    }

    pub(crate) fn set_aliases_direct(&self, name: &str, aliases: &[&str]) {
        self.inner
            .borrow_mut()
            .instances
            .get_mut(name)
            .unwrap()
            .aliases = aliases.iter().map(|a| Alias::plain(a)).collect();
    }

    pub(crate) fn aliases_of(&self, name: &str) -> Vec<String> {
        self.inner.borrow().instances[name]
            .aliases
            .iter()
            .map(|a| a.cidr.clone())
            .collect()
    }

    pub(crate) fn set_flap(&self, on: bool) {
        self.inner.borrow_mut().flap = on;
    }

    pub(crate) fn set_lag(&self, reads: u32) {
        self.inner.borrow_mut().lag_reads = reads;
    }

    /// Queue behaviours for successive changes to `instance`.
    pub(crate) fn script_changes(&self, instance: &str, behaviors: &[ChangeBehavior]) {
        self.inner
            .borrow_mut()
            .behavior
            .insert(instance.to_string(), behaviors.to_vec());
    }

    pub(crate) fn fail_describe(&self, instance: &str, on: bool) {
        let mut inner = self.inner.borrow_mut();
        inner.describe_fail.retain(|n| n != instance);
        if on {
            inner.describe_fail.push(instance.to_string());
        }
    }

    /// Run `f` just before the `n`-th (1-based, counted from now) describe.
    pub(crate) fn schedule<F: FnOnce(&mut GceInner) + 'static>(&self, n: usize, f: F) {
        let mut inner = self.inner.borrow_mut();
        let at = inner.describe_calls + n;
        inner.scheduled.push((at, Box::new(f)));
    }

    /// Run `f` when the `n`-th (1-based, counted from now) listing of
    /// operations happens: something that happens while the controller is
    /// waiting on the operation list.
    pub(crate) fn schedule_at_list<F: FnOnce(&mut GceInner) + 'static>(&self, n: usize, f: F) {
        let mut inner = self.inner.borrow_mut();
        let at = inner.list_calls + n;
        inner.scheduled_lists.push((at, Box::new(f)));
    }

    /// Requests that were issued and given up on but have not landed yet.
    pub(crate) fn late_count(&self) -> usize {
        self.inner.borrow().late.len()
    }

    /// Land every queued request now (each replaces the whole alias list of
    /// its instance with the list it was sent with) and evaluate the monitor.
    pub(crate) fn land_all(&self) {
        self.inner.borrow_mut().land_all();
        self.notify_landing();
    }

    /// Land every queued request when the `n`-th (1-based, counted from now)
    /// describe happens.
    pub(crate) fn land_at_describe(&self, n: usize) {
        let mut inner = self.inner.borrow_mut();
        let at = inner.describe_calls + n;
        inner.land_at.push(at);
    }

    /// An operation that finished with an error without applying anything.
    pub(crate) fn fail_pending_ops(&self) {
        let mut inner = self.inner.borrow_mut();
        let names: Vec<String> = inner
            .late
            .iter()
            .filter_map(|r| r.op_name.clone())
            .collect();
        inner.late.clear();
        for op in inner.ops.iter_mut().filter(|o| names.contains(&o.name)) {
            op.status = "DONE".to_string();
            op.failed = true;
        }
    }

    /// Add an unrelated, already existing operation (history).
    pub(crate) fn seed_op(&self, instance: &str, op_type: &str, status: &str, failed: bool) {
        let mut inner = self.inner.borrow_mut();
        let name = inner.new_op(instance, status, failed);
        let op = inner.ops.last_mut().unwrap();
        op.op_type = op_type.to_string();
        op.foreign = true;
        let _ = name;
    }

    /// Run `f` right after the next alias change was applied.
    pub(crate) fn after_next_change<F: FnOnce(&mut GceInner) + 'static>(&self, f: F) {
        self.inner.borrow_mut().after_change.push(Box::new(f));
    }

    pub(crate) fn fail_next_list_operations(&self) {
        self.inner.borrow_mut().fail_list_once = true;
    }

    pub(crate) fn fail_list_operations(&self, on: bool) {
        self.inner.borrow_mut().fail_list = on;
    }

    pub(crate) fn last_tag(&self) -> Option<String> {
        self.inner.borrow().change_tags.last().cloned()
    }

    fn notify_landing(&self) {
        let landed = std::mem::take(&mut self.inner.borrow_mut().landed_flag);
        if landed && let Some(monitor) = self.monitor.borrow().clone() {
            monitor("late landing");
        }
    }

    pub(crate) fn change_count(&self) -> usize {
        self.inner.borrow().changes.len()
    }

    pub(crate) fn changes(&self) -> Vec<(String, Vec<String>)> {
        self.inner.borrow().changes.clone()
    }
}

impl Gce for FakeGce {
    fn describe(&self, instance: &str) -> Result<InstanceInfo, Unavailable> {
        let result = {
            let mut inner = self.inner.borrow_mut();
            inner.describe_calls += 1;
            let now = inner.describe_calls;
            let (due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut inner.scheduled)
                .into_iter()
                .partition(|(at, _)| *at <= now);
            inner.scheduled = rest;
            for (_, action) in due {
                action(&mut inner);
            }
            if inner.land_at.iter().any(|at| *at <= now) {
                inner.land_at.retain(|at| *at > now);
                inner.land_all();
            }
            Self::read(&mut inner, instance)
        };
        self.notify_landing();
        result
    }

    fn list_operations(&self, instance: &str) -> Result<OpList, Unavailable> {
        let result = {
            let mut inner = self.inner.borrow_mut();
            inner.list_calls += 1;
            let now = inner.list_calls;
            let (due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut inner.scheduled_lists)
                .into_iter()
                .partition(|(at, _)| *at <= now);
            inner.scheduled_lists = rest;
            for (_, action) in due {
                action(&mut inner);
            }
            if std::mem::take(&mut inner.fail_list_once) {
                return Err(Unavailable("injected operations listing failure".into()));
            }
            // Requests that are due to finish at this listing.
            let mut due = Vec::new();
            for request in std::mem::take(&mut inner.late) {
                match request.land_after_lists {
                    Some(1) => due.push(request),
                    Some(n) => {
                        let mut r = request;
                        r.land_after_lists = Some(n - 1);
                        inner.late.push(r);
                    }
                    None => inner.late.push(request),
                }
            }
            for request in due {
                inner.land(request);
            }
            Self::list(&inner, instance)
        };
        self.notify_landing();
        result
    }

    fn set_aliases(&self, instance: &str, aliases: &[Alias], tag: &str) -> ChangeReport {
        self.apply_change(instance, aliases, tag)
    }
}

impl FakeGce {
    fn list(inner: &GceInner, instance: &str) -> Result<OpList, Unavailable> {
        if inner.fail_list {
            return Err(Unavailable("injected operations listing failure".into()));
        }
        // Newest first; a request that is still invisible is not listed.
        let ops = inner
            .ops
            .iter()
            .rev()
            .filter(|o| o.instance == instance)
            .map(|o| CloudOp {
                name: o.name.clone(),
                op_type: o.op_type.clone(),
                status: o.status.clone(),
                failed: o.failed,
            })
            .collect::<Vec<_>>();
        Ok(OpList {
            complete: ops.len() < OPS_LIMIT,
            ops,
        })
    }

    fn apply_change(&self, instance: &str, aliases: &[Alias], tag: &str) -> ChangeReport {
        let behavior = {
            let mut inner = self.inner.borrow_mut();
            let queue = inner.behavior.entry(instance.to_string()).or_default();
            if queue.is_empty() {
                ChangeBehavior::Normal
            } else {
                queue.remove(0)
            }
        };
        let apply = matches!(
            behavior,
            ChangeBehavior::Normal
                | ChangeBehavior::ErrorAfterApply
                | ChangeBehavior::TimeoutAfterApply
                | ChangeBehavior::RejectedButApplied
        );
        {
            let mut inner = self.inner.borrow_mut();
            inner.changes.push((
                instance.to_string(),
                aliases.iter().map(|a| a.cidr.clone()).collect(),
            ));
            inner.change_tags.push(tag.to_string());
            match behavior {
                ChangeBehavior::Normal
                | ChangeBehavior::ErrorAfterApply
                | ChangeBehavior::TimeoutAfterApply
                | ChangeBehavior::RejectedButApplied => {
                    inner.new_op(instance, "DONE", false);
                }
                ChangeBehavior::ErrorNoApply
                | ChangeBehavior::TimeoutFailedOp
                | ChangeBehavior::RejectedButFailedOp => {
                    inner.new_op(instance, "DONE", true);
                }
                ChangeBehavior::ErrorNoOperation
                | ChangeBehavior::TimeoutNoApply
                | ChangeBehavior::Rejected(_) => {}
                ChangeBehavior::RejectedButPending => {
                    let name = inner.new_op(instance, "PENDING", false);
                    inner.late.push(LateRequest {
                        instance: instance.to_string(),
                        aliases: aliases.to_vec(),
                        op_name: Some(name),
                        land_after_lists: None,
                    });
                }
                ChangeBehavior::RejectedButInvisibleUntilList(n) => {
                    inner.late.push(LateRequest {
                        instance: instance.to_string(),
                        aliases: aliases.to_vec(),
                        op_name: None,
                        land_after_lists: Some(n),
                    });
                }
                ChangeBehavior::TimeoutPending => {
                    let name = inner.new_op(instance, "PENDING", false);
                    inner.late.push(LateRequest {
                        instance: instance.to_string(),
                        aliases: aliases.to_vec(),
                        op_name: Some(name),
                        land_after_lists: None,
                    });
                }
                ChangeBehavior::PendingLandsAfterLists(n) => {
                    let name = inner.new_op(instance, "PENDING", false);
                    inner.late.push(LateRequest {
                        instance: instance.to_string(),
                        aliases: aliases.to_vec(),
                        op_name: Some(name),
                        land_after_lists: Some(n),
                    });
                }
                ChangeBehavior::TimeoutInvisible => {
                    inner.late.push(LateRequest {
                        instance: instance.to_string(),
                        aliases: aliases.to_vec(),
                        op_name: None,
                        land_after_lists: None,
                    });
                }
            }
            if apply {
                let lag = inner.lag_reads;
                let old = inner.instances[instance].aliases.clone();
                inner.instances.get_mut(instance).unwrap().aliases = aliases.to_vec();
                if inner.flap {
                    inner
                        .flap_plan
                        .insert(instance.to_string(), (old.clone(), vec![false, true]));
                }
                if lag > 0 {
                    inner.stale.insert(instance.to_string(), (old, lag));
                }
            }
            for action in std::mem::take(&mut inner.after_change) {
                action(&mut inner);
            }
        }
        self.events.borrow_mut().push(format!(
            "gce {instance} aliases -> [{}] ({behavior:?})",
            aliases
                .iter()
                .map(|a| a.cidr.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
        if let Some(monitor) = self.monitor.borrow().clone() {
            monitor("gce change");
        }
        match behavior {
            ChangeBehavior::Normal => ChangeReport::Done,
            ChangeBehavior::ErrorAfterApply
            | ChangeBehavior::ErrorNoApply
            | ChangeBehavior::ErrorNoOperation => ChangeReport::Error("injected error".to_string()),
            ChangeBehavior::Rejected(status) => ChangeReport::Rejected {
                status,
                detail: format!("injected HTTPError {status}"),
            },
            ChangeBehavior::RejectedButApplied
            | ChangeBehavior::RejectedButFailedOp
            | ChangeBehavior::RejectedButPending
            | ChangeBehavior::RejectedButInvisibleUntilList(_) => ChangeReport::Rejected {
                status: 403,
                detail: "injected HTTPError 403 (belonged to a later stage)".to_string(),
            },
            ChangeBehavior::TimeoutAfterApply
            | ChangeBehavior::TimeoutFailedOp
            | ChangeBehavior::TimeoutNoApply
            | ChangeBehavior::TimeoutPending
            | ChangeBehavior::PendingLandsAfterLists(_)
            | ChangeBehavior::TimeoutInvisible => ChangeReport::TimedOut,
        }
    }
}

impl FakeGce {
    fn read(inner: &mut GceInner, instance: &str) -> Result<InstanceInfo, Unavailable> {
        if inner.describe_fail.iter().any(|n| n == instance) {
            return Err(Unavailable("injected describe failure".to_string()));
        }
        let flap_old = match inner.flap_plan.get_mut(instance) {
            Some((old, plan)) if !plan.is_empty() => {
                let use_old = plan.remove(0);
                use_old.then(|| old.clone())
            }
            _ => None,
        };
        let aliases = match inner.stale.get_mut(instance) {
            _ if flap_old.is_some() => flap_old.clone().unwrap_or_default(),
            Some((old, remaining)) if *remaining > 0 => {
                *remaining -= 1;
                old.clone()
            }
            _ => inner
                .instances
                .get(instance)
                .ok_or_else(|| Unavailable(format!("no such instance {instance}")))?
                .aliases
                .clone(),
        };
        let item = inner
            .instances
            .get(instance)
            .ok_or_else(|| Unavailable(format!("no such instance {instance}")))?;
        Ok(InstanceInfo {
            name: instance.to_string(),
            id: item.id.clone(),
            status: item.status.clone(),
            aliases,
            internal_ip: None,
            nat_ip: if item.status == "RUNNING" {
                Some("203.0.113.7".to_string())
            } else {
                None
            },
            last_stop: if item.status == "TERMINATED" {
                Some("2026-10-24T00:00:00.000+00:00".to_string())
            } else {
                None
            },
        })
    }
}

// ----------------------------------------------------------------- remote

#[derive(Clone)]
pub(crate) enum Fault {
    /// The request never reaches the agent.
    DropBefore,
    /// The agent executes the request; the answer is lost.
    DropAfter,
    /// The agent executes the request; the transport times out.
    TimeoutAfter,
    /// The request is refused in-band without executing.
    RefuseBefore(String),
    /// The agent is not executed; an in-band failure is returned.
    FailBefore(String),
    /// Run a hook (e.g. an external change), then handle normally.
    Hook(Rc<dyn Fn()>),
    /// The agent executes the request; the answer's data is rewritten before
    /// the controller sees it (a damaged or hostile agent).
    Rewrite(Rc<dyn Fn(&mut Value)>),
}

struct Rule {
    label: String,
    op: String,
    needle: Option<String>,
    skip: u32,
    times: u32,
    fault: Fault,
    /// How many times the rule actually injected its fault. A matrix that
    /// asks for "the n-th call" injects nothing when the run makes fewer
    /// calls (audit RA-F-03), so its size is not its coverage.
    fired: u32,
}

pub(crate) struct FakeHost {
    pub(crate) env: AgentEnv,
    pub(crate) sys: FakeSystem,
    pub(crate) reachable: Cell<bool>,
    pub(crate) hung: Cell<bool>,
    pub(crate) dir: PathBuf,
}

#[derive(Clone)]
pub(crate) struct FakeRemote {
    pub(crate) hosts: Rc<BTreeMap<String, FakeHost>>,
    rules: Rc<RefCell<Vec<Rule>>>,
    pub(crate) calls: Rc<RefCell<Vec<String>>>,
    events: Rc<RefCell<Vec<String>>>,
    monitor: MonitorSlot,
    redirect: Rc<RefCell<BTreeMap<String, String>>>,
    /// The operation id carried by the last `service.control` (its fencing
    /// token), for the "destructive action without the lease" monitor.
    last_actor: Rc<RefCell<Option<String>>>,
    /// The host that executed the last mutating operation.
    last_host: Rc<RefCell<Option<String>>>,
}

const MUTATING_OPS: &[&str] = &[
    op::SERVICE_CONTROL,
    op::CHRONY_BACKUP,
    op::CHRONY_STAGE,
    op::CHRONY_PUBLISH,
    op::CHRONY_RESTORE,
    op::LEASE_INIT,
    op::LEASE_ACQUIRE,
    op::LEASE_PHASE,
    op::LEASE_COMMIT,
    op::LEASE_ABORT,
    op::LEASE_RECONCILE,
];

impl FakeRemote {
    /// Make requests addressed to `from` reach the host `to` (wrong host).
    pub(crate) fn redirect(&self, from: &str, to: &str) {
        self.redirect
            .borrow_mut()
            .insert(from.to_string(), to.to_string());
    }

    pub(crate) fn inject(&self, label: &str, operation: &str, fault: Fault) {
        self.inject_when(label, operation, None, 0, 1, fault);
    }

    pub(crate) fn inject_when(
        &self,
        label: &str,
        operation: &str,
        needle: Option<&str>,
        skip: u32,
        times: u32,
        fault: Fault,
    ) {
        self.rules.borrow_mut().push(Rule {
            label: label.to_string(),
            op: operation.to_string(),
            needle: needle.map(str::to_string),
            skip,
            times,
            fault,
            fired: 0,
        });
    }

    /// How many faults were injected so far into calls of `operation` on
    /// `label` (all rules together).
    pub(crate) fn fired(&self, label: &str, operation: &str) -> u32 {
        self.rules
            .borrow()
            .iter()
            .filter(|r| r.label == label && r.op == operation)
            .map(|r| r.fired)
            .sum()
    }

    pub(crate) fn host(&self, label: &str) -> &FakeHost {
        &self.hosts[label]
    }

    pub(crate) fn last_actor(&self) -> Option<String> {
        self.last_actor.borrow().clone()
    }

    pub(crate) fn last_host(&self) -> Option<String> {
        self.last_host.borrow().clone()
    }

    /// Hosts on which an HA daemon is (ground truth) running now.
    pub(crate) fn ha_running_hosts(&self) -> Vec<String> {
        self.hosts
            .iter()
            .filter(|(_, h)| h.sys.ha_running())
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub(crate) fn count(&self, label: &str, operation: &str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with(&format!("{label} {operation}")))
            .count()
    }

    fn matching_fault(&self, label: &str, operation: &str, args: &Value) -> Option<Fault> {
        let text = args.to_string();
        let mut rules = self.rules.borrow_mut();
        for rule in rules.iter_mut() {
            if rule.label != label || rule.op != operation || rule.times == 0 {
                continue;
            }
            if let Some(needle) = &rule.needle
                && !text.contains(needle.as_str())
            {
                continue;
            }
            if rule.skip > 0 {
                rule.skip -= 1;
                continue;
            }
            rule.times -= 1;
            rule.fired += 1;
            return Some(rule.fault.clone());
        }
        None
    }
}

impl Remote for FakeRemote {
    fn call(
        &self,
        target: &Target,
        operation: &str,
        args: Value,
        _timeout: Duration,
    ) -> Result<Response, TransportError> {
        let redirected = self.redirect.borrow().get(&target.label).cloned();
        let label = redirected.as_deref().unwrap_or(target.label.as_str());
        self.calls
            .borrow_mut()
            .push(format!("{label} {operation} {args}"));
        let host = self
            .hosts
            .get(label)
            .ok_or_else(|| TransportError::Unreachable(format!("no such host {label}")))?;
        if host.hung.get() {
            return Err(TransportError::Timeout(format!("{operation} on {label}")));
        }
        if !host.reachable.get() {
            return Err(TransportError::Unreachable(
                "Connection timed out".to_string(),
            ));
        }
        let request = Request {
            v: PROTO_VERSION,
            id: proto::random_hex(8),
            op: operation.to_string(),
            args: args.clone(),
        };
        let fault = self.matching_fault(label, operation, &args);
        match &fault {
            Some(Fault::DropBefore) => {
                return Err(TransportError::Unreachable("Connection reset".to_string()));
            }
            Some(Fault::RefuseBefore(m)) => {
                let mut response = Response::err(&request.id, code::REFUSED, m.clone());
                response.node = label.to_string();
                return Ok(response);
            }
            Some(Fault::FailBefore(m)) => {
                let mut response = Response::err(&request.id, code::FAILED, m.clone());
                response.node = label.to_string();
                return Ok(response);
            }
            Some(Fault::Hook(hook)) => hook(),
            _ => {}
        }
        // A test can let the agent "die": a panic inside the agent is then what
        // the controller sees as a lost connection (the process is gone, the
        // file system keeps whatever it had done so far).
        let response = if AGENT_MAY_DIE.with(Cell::get) {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle(&host.env, &request)
            })) {
                Ok(response) => response,
                Err(_) => {
                    return Err(TransportError::Unreachable(
                        "Connection closed (the agent died)".to_string(),
                    ));
                }
            }
        } else {
            handle(&host.env, &request)
        };
        if MUTATING_OPS.contains(&operation) && response.ok {
            self.events
                .borrow_mut()
                .push(format!("{label} {operation} {args}"));
            *self.last_host.borrow_mut() = Some(label.to_string());
            *self.last_actor.borrow_mut() = args
                .get("fence")
                .and_then(|f| f.get("op_id"))
                .and_then(Value::as_str)
                .map(str::to_string);
            if let Some(monitor) = self.monitor.borrow().clone() {
                monitor(operation);
            }
        }
        match fault {
            Some(Fault::DropAfter) => Err(TransportError::Unreachable("Connection closed".into())),
            Some(Fault::TimeoutAfter) => {
                Err(TransportError::Timeout(format!("{operation} on {label}")))
            }
            Some(Fault::Rewrite(rewrite)) => {
                let mut response = response;
                rewrite(&mut response.data);
                Ok(response)
            }
            _ => Ok(response),
        }
    }
}

thread_local! {
    /// See [`FakeRemote::call`]: a panic inside the agent becomes a lost connection.
    pub(crate) static AGENT_MAY_DIE: Cell<bool> = const { Cell::new(false) };
}

/// Sets [`AGENT_MAY_DIE`] and clears it again, also when a test panics.
pub(crate) struct AgentMayDie;
impl AgentMayDie {
    pub(crate) fn arm() -> Self {
        AGENT_MAY_DIE.with(|c| c.set(true));
        AgentMayDie
    }
}
impl Drop for AgentMayDie {
    fn drop(&mut self) {
        AGENT_MAY_DIE.with(|c| c.set(false));
    }
}

// ------------------------------------------------------------------ world

pub(crate) struct World {
    pub(crate) cfg: ControlConfig,
    pub(crate) gce: FakeGce,
    pub(crate) remote: FakeRemote,
    pub(crate) clock: FakeClock,
    pub(crate) log: VecLog,
    pub(crate) events: Rc<RefCell<Vec<String>>>,
    pub(crate) violations: Rc<RefCell<Vec<String>>>,
    pub(crate) dir: PathBuf,
}

impl World {
    /// node-a owns the VIP, serves it, and is recorded as owner at epoch 1.
    pub(crate) fn new(label: &str) -> Self {
        Self::build(label, true)
    }

    pub(crate) fn build(label: &str, initialise: bool) -> Self {
        Self::build_with(label, initialise, false)
    }

    /// `external`: reach hosts by the external address the cloud reports
    /// (a stopped instance has none).
    pub(crate) fn build_with(label: &str, initialise: bool, external: bool) -> Self {
        Self::build_full(label, initialise, external, &|_, _| {})
    }

    /// `tweak(host, config)` edits each host's agent configuration.
    pub(crate) fn build_full(
        label: &str,
        initialise: bool,
        external: bool,
        tweak: &dyn Fn(&str, &mut super::agent::AgentConfig),
    ) -> Self {
        let cfg = if external {
            super::config::ControlConfig::parse(
                std::path::Path::new("/x.toml"),
                super::config::tests::SAMPLE,
                None,
                Some("external".to_string()),
            )
            .unwrap()
        } else {
            sample()
        };
        let dir = temp_dir(label);
        let events = Rc::new(RefCell::new(Vec::new()));
        let gce = FakeGce::new(events.clone());
        gce.add_instance("inst-a", &[VIP_CIDR]);
        gce.add_instance("inst-b", &[]);
        gce.add_instance("witness", &[]);

        let clock = FakeClock::new();
        let mut hosts = BTreeMap::new();
        for (name, node_label) in [
            ("node-a", "node-a"),
            ("node-b", "node-b"),
            ("witness", "witness"),
        ] {
            let sys = FakeSystem::default();
            let handle = clock.handle();
            let (env, host_dir) = agent_env_custom(
                &format!("{label}-{name}"),
                node_label,
                sys.clone(),
                Box::new(move || super::testkit::TEST_NOW + handle.get() / 1000),
                &|c| tweak(name, c),
            );
            std::fs::write(&env.cfg.chrony_conf, "pool 2.pool.ntp.org iburst\n").unwrap();
            std::fs::set_permissions(
                &env.cfg.chrony_conf,
                std::os::unix::fs::PermissionsExt::from_mode(0o644),
            )
            .unwrap();
            hosts.insert(
                name.to_string(),
                FakeHost {
                    env,
                    sys,
                    reachable: Cell::new(true),
                    hung: Cell::new(false),
                    dir: host_dir,
                },
            );
        }
        hosts["node-a"]
            .sys
            .set_service("mkg-demo.service", "active");
        hosts["node-b"]
            .sys
            .set_service("mkg-demo.service", "inactive");
        let remote = FakeRemote {
            hosts: Rc::new(hosts),
            rules: Rc::new(RefCell::new(Vec::new())),
            calls: Rc::new(RefCell::new(Vec::new())),
            events: events.clone(),
            monitor: Rc::new(RefCell::new(None)),
            redirect: Rc::new(RefCell::new(BTreeMap::new())),
            last_actor: Rc::new(RefCell::new(None)),
            last_host: Rc::new(RefCell::new(None)),
        };
        let world = Self {
            cfg,
            gce,
            remote,
            clock,
            log: VecLog::default(),
            events,
            violations: Rc::new(RefCell::new(Vec::new())),
            dir,
        };
        world.wire_probes();
        world.install_monitor();
        if !initialise {
            return world;
        }
        // Record the initial owner through the real agent code.
        let init = handle(
            &world.remote.host("witness").env,
            &Request {
                v: PROTO_VERSION,
                id: proto::random_hex(8),
                op: op::LEASE_INIT.to_string(),
                args: json!({"owner": "node-a"}),
            },
        );
        assert!(init.ok, "{init:?}");
        world
    }

    fn serving_nodes(gce: &FakeGce, remote: &FakeRemote) -> Vec<String> {
        ["node-a", "node-b"]
            .iter()
            .filter(|n| {
                let inst = if **n == "node-a" { "inst-a" } else { "inst-b" };
                let holds = gce.inner.borrow().instances[inst]
                    .aliases
                    .iter()
                    .any(|a| a.cidr == VIP_CIDR);
                let active =
                    remote.host(n).sys.service("mkg-demo.service").as_deref() == Some("active");
                holds && active
            })
            .map(|n| (*n).to_string())
            .collect()
    }

    fn install_monitor(&self) {
        let gce = self.gce.clone();
        let remote = self.remote.clone();
        let violations = self.violations.clone();
        let monitor: Rc<dyn Fn(&str)> = Rc::new(move |what: &str| {
            for v in Self::evaluate(&gce, &remote, what) {
                violations.borrow_mut().push(v);
            }
        });
        *self.gce.monitor.borrow_mut() = Some(monitor.clone());
        *self.remote.monitor.borrow_mut() = Some(monitor);
    }

    fn lease_of(remote: &FakeRemote) -> super::lease::LeaseState {
        let response = handle(
            &remote.host("witness").env,
            &Request {
                v: PROTO_VERSION,
                id: proto::random_hex(8),
                op: op::LEASE_STATUS.to_string(),
                args: json!({}),
            },
        );
        parse_lease_value(response.data)
    }

    fn holders_now(gce: &FakeGce) -> Vec<String> {
        let inner = gce.inner.borrow();
        [("node-a", "inst-a"), ("node-b", "inst-b")]
            .iter()
            .filter(|(_, i)| {
                inner.instances[*i]
                    .aliases
                    .iter()
                    .any(|a| a.cidr == VIP_CIDR)
            })
            .map(|(n, _)| (*n).to_string())
            .collect()
    }

    /// Everything the safety monitor checks after one effect (`what`).
    fn evaluate(gce: &FakeGce, remote: &FakeRemote, what: &str) -> Vec<String> {
        let mut out = Vec::new();
        let serving = Self::serving_nodes(gce, remote);
        if serving.len() > 1 {
            out.push(format!("double active after {what}: {serving:?}"));
        }
        let holders = Self::holders_now(gce);
        if holders.len() > 1 {
            out.push(format!(
                "the alias is on several NICs after {what}: {holders:?}"
            ));
        }
        // An HA daemon that is running (ground truth, independent of what any
        // agent concluded) must never coexist with a manual change: an alias
        // change while one runs anywhere, or a gated agent operation that
        // succeeded on the very host it runs on (audit EX-01).
        let ha_hosts = remote.ha_running_hosts();
        if !ha_hosts.is_empty() {
            if what == "gce change" {
                out.push(format!(
                    "alias change while an HA daemon runs on {ha_hosts:?}"
                ));
            }
            let gated_agent_op = what == "service.control" || what.starts_with("lease.");
            if gated_agent_op
                && let Some(host) = remote.last_host()
                && ha_hosts.contains(&host)
            {
                out.push(format!(
                    "{what} succeeded on {host} while an HA daemon runs there"
                ));
            }
        }
        // A destructive action only by the holder of the lease.
        let actor = match what {
            "gce change" => gce.last_tag(),
            "service.control" => remote.last_actor(),
            _ => None,
        };
        if let Some(actor) = actor.filter(|a| !a.is_empty()) {
            let held = Self::lease_of(remote).op.map(|o| o.op_id);
            if held.as_deref() != Some(actor.as_str()) {
                out.push(format!(
                    "destructive action ({what}) by {actor}, which does not hold the lease \
                     (holder: {held:?})"
                ));
            }
        }
        // Lock released, or a late request landed on an unlocked lease: the
        // recorded truth must match the world.
        let released = matches!(what, "lease.commit" | "lease.abort" | "lease.reconcile");
        if released || what == "late landing" {
            let lease = Self::lease_of(remote);
            if released && gce.inner.borrow().has_pending() {
                out.push(format!(
                    "the lock was released ({what}) while a cloud request is still pending"
                ));
            }
            if lease.op.is_none() {
                let owner = lease.owner.clone();
                if holders.as_slice() != owner.as_slice() {
                    out.push(format!(
                        "after {what} the lease owner is {owner:?} but the cloud holders are \
                         {holders:?} (VIP lost, duplicated or not owned by the record)"
                    ));
                }
                for (node, inst) in [("node-a", "inst-a"), ("node-b", "inst-b")] {
                    // A terminated instance runs nothing, whatever its unit
                    // table (which the fake never clears) says.
                    let running = gce.inner.borrow().instances[inst].status == "RUNNING";
                    let active = running
                        && remote.host(node).sys.service("mkg-demo.service").as_deref()
                            == Some("active");
                    if active && owner.as_deref() != Some(node) {
                        out.push(format!(
                            "after {what} {node} runs the service without being the owner"
                        ));
                    }
                }
            }
        }
        out
    }

    /// VIP/local probes answer according to the fake cloud and services.
    fn wire_probes(&self) {
        for (node, inst) in [("node-a", "inst-a"), ("node-b", "inst-b")] {
            let gce = self.gce.clone();
            let remote = self.remote.clone();
            let name = node.to_string();
            let own_inst = inst.to_string();
            let _ = own_inst;
            let probe: super::testkit::ProbeFn =
                Box::new(move |addr: Ipv4Addr, _port: u16| probe_world(&gce, &remote, &name, addr));
            self.remote.host(node).sys.set_probe_fn(probe);
        }
        let gce = self.gce.clone();
        let remote = self.remote.clone();
        self.remote
            .host("witness")
            .sys
            .set_probe_fn(Box::new(move |addr, _port| {
                probe_world(&gce, &remote, "witness", addr)
            }));
    }

    pub(crate) fn ctx(&self) -> Ctx<'_> {
        Ctx::new(&self.cfg, &self.gce, &self.remote, &self.clock, &self.log)
    }

    pub(crate) fn lease(&self) -> super::lease::LeaseState {
        Self::lease_of(&self.remote)
    }

    /// Re-evaluate the safety monitor now (for example after the test landed
    /// a late request or finished a command) and record violations.
    pub(crate) fn check_now(&self, what: &str) {
        for v in Self::evaluate(&self.gce, &self.remote, what) {
            self.violations.borrow_mut().push(v);
        }
    }

    /// The lock is released and the world matches the record. Call after a
    /// command that claims to have finished (success or verified rollback).
    pub(crate) fn assert_settled(&self) {
        assert!(self.lease().op.is_none(), "the lock is still recorded");
        self.check_now("late landing");
        self.assert_no_double_active();
    }

    pub(crate) fn cloud_holders(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (n, i) in [("node-a", "inst-a"), ("node-b", "inst-b")] {
            if self.gce.aliases_of(i).iter().any(|a| a == VIP_CIDR) {
                out.push(n.to_string());
            }
        }
        out
    }

    /// What a boot or an administrator would do: start an HA unit on `host`.
    /// A masked unit refuses. Recorded in the event log when it starts.
    pub(crate) fn ha_start(&self, host: &str, unit: &str) -> bool {
        let started = self.remote.host(host).sys.ha_start(unit);
        if started {
            self.events
                .borrow_mut()
                .push(format!("ha start {host} {unit}"));
            self.check_now("ha start");
        }
        started
    }

    pub(crate) fn count_agent_calls(&self, host: &str, operation: &str) -> usize {
        self.remote.count(host, operation)
    }

    pub(crate) fn service_active(&self, node: &str) -> bool {
        self.remote
            .host(node)
            .sys
            .service("mkg-demo.service")
            .as_deref()
            == Some("active")
    }

    pub(crate) fn assert_no_double_active(&self) {
        assert!(
            self.violations.borrow().is_empty(),
            "double Active observed: {:?}",
            self.violations.borrow()
        );
    }
}

fn probe_world(
    gce: &FakeGce,
    remote: &FakeRemote,
    from: &str,
    addr: Ipv4Addr,
) -> Result<(u16, String), String> {
    if addr.is_loopback() {
        return if from != "witness"
            && remote.host(from).sys.service("mkg-demo.service").as_deref() == Some("active")
        {
            Ok((200, from.to_string()))
        } else {
            Err("connection refused".to_string())
        };
    }
    if addr.to_string() != VIP {
        return Err("no route".to_string());
    }
    for (node, inst) in [("node-a", "inst-a"), ("node-b", "inst-b")] {
        let holds = gce.inner.borrow().instances[inst]
            .aliases
            .iter()
            .any(|a| a.cidr == VIP_CIDR);
        let up = remote.host(node).reachable.get()
            && gce.inner.borrow().instances[inst].status == "RUNNING"
            && remote.host(node).sys.service("mkg-demo.service").as_deref() == Some("active");
        if holds && up {
            return Ok((200, node.to_string()));
        }
    }
    Err("connection refused".to_string())
}

/// The agent answers a lease read with the state plus the Witness clock
/// (`now`); the state itself is parsed strictly.
pub(crate) fn parse_lease_value(mut data: Value) -> super::lease::LeaseState {
    if let Some(map) = data.as_object_mut() {
        map.remove("now");
    }
    serde_json::from_value(data).expect("lease state")
}
