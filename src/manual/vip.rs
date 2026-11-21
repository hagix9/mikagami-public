//! The VIP resource: GCE alias IP plus the service that answers on it.
//!
//! `move_vip` is the manual hand-over. Its order is fixed and every step is
//! verified by observation, never by the success report of the step itself:
//!
//! 1. read-only pre-flight (durable owner, cloud owner, both nodes, the
//!    fencing marks the nodes keep),
//! 2. acquire the operation lease at the Witness (compare-and-swap on owner
//!    and epoch),
//! 3. write ahead the next phase, then quiesce the source (service stopped and
//!    verified; or fencing evidence for an unreachable source),
//! 4. remove the VIP alias from the source until the cloud shows it absent,
//! 5. only then add the alias to the target until the cloud shows it present,
//! 6. start the target service, verify it serves the VIP from a third host,
//! 7. commit the new durable owner.
//!
//! Cloud changes are asynchronous and a request the caller gave up on can
//! still land (round-1 audit, C-01). Every alias change is therefore tracked
//! through the zonal operations of the instance: it counts as resolved only
//! when an operation for it is observed finished (or the tool reported
//! success and no operation is outstanding) *and* the alias list is then
//! observed. Time alone never resolves a change. While a change is unresolved
//! the command stops with UNKNOWN, keeps the operation record, and performs
//! no further cloud or service action (in particular no rollback).
//!
//! A failure after the first mutation triggers a *verified* rollback toward
//! the source, but only while this command still holds the lease and only
//! when every cloud change it made is resolved; otherwise the command stops
//! with UNKNOWN and leaves the operation record in place
//! (`resource reconcile vip` after inspection).

use super::config::NodeConfig;
use super::fence::Token;
use super::gce::{Alias, ChangeReport, CloudOp, InstanceInfo, OpList};
use super::lease::{ABANDON_QUIET_SECS, LeaseState, Phase};
use super::proto::{self, op};
use super::remote::{CallError, LONG, PING as PING_TIMEOUT, SHORT, Target, TransportError};
use super::{Ctx, Failure, Res};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

const ALIAS_STABLE_READS: u32 = 2;
const ALIAS_TIMEOUT_MS: u64 = 90_000;
const ALIAS_POLL: Duration = Duration::from_secs(2);
/// How long a change is followed through the cloud's operation list.
const OPS_SETTLE_MS: u64 = 90_000;
/// A request that the cloud answered with an explicit client error counts as
/// refused only after the operation list was read this many times in a row
/// without a new operation of the instance, over at least this long (R4).
/// Both must hold: a late-appearing operation is the C-01 risk.
const REFUSAL_QUIET_READS: u32 = 4;
const REFUSAL_QUIET_MS: u64 = 10_000;
const SERVE_TIMEOUT_MS: u64 = 60_000;
const SERVE_POLL: Duration = Duration::from_secs(2);
const LEASE_TTL_SECS: u64 = 300;
const FENCE_STATUS: &str = "TERMINATED";
/// Attempts of a probe that could not even be performed.
const PROBE_TRIES: u32 = 3;
/// Most recent operation names kept in the lease record per change.
const EVIDENCE_CHANGES_MAX: usize = 8;

// ---------------------------------------------------------------------------
// observation helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct NodeView {
    pub(crate) node: NodeConfig,
    pub(crate) info: InstanceInfo,
}

pub(crate) fn describe_node(ctx: &Ctx<'_>, node: &NodeConfig) -> Res<NodeView> {
    let info = ctx
        .gce
        .describe(&node.instance)
        .map_err(|e| Failure::Failed(format!("cannot observe {}: {e}", node.name)))?;
    Ok(NodeView {
        node: node.clone(),
        info,
    })
}

pub(crate) fn observe_all(ctx: &Ctx<'_>) -> Res<Vec<NodeView>> {
    ctx.cfg
        .nodes
        .iter()
        .map(|n| describe_node(ctx, n))
        .collect()
}

pub(crate) fn owners(ctx: &Ctx<'_>, views: &[NodeView]) -> Vec<String> {
    let cidr = ctx.cfg.vip_cidr();
    views
        .iter()
        .filter(|v| v.info.has_alias(&cidr))
        .map(|v| v.node.name.clone())
        .collect()
}

/// The holders of the VIP, established by two consecutive identical
/// observations a poll apart. A negative finding ("nobody has it") from a
/// single, possibly stale read is never enough to act on (audit C-01, V3b).
fn stable_holders(ctx: &Ctx<'_>) -> Result<Vec<String>, String> {
    let started = ctx.clock.now_ms();
    let mut previous: Option<Vec<String>> = None;
    loop {
        let views = observe_all(ctx).map_err(|e| e.message().to_string())?;
        let now = owners(ctx, &views);
        if previous.as_ref() == Some(&now) {
            return Ok(now);
        }
        previous = Some(now);
        if ctx.clock.now_ms().saturating_sub(started) >= ALIAS_TIMEOUT_MS {
            return Err("the VIP holders did not settle on two consecutive reads".to_string());
        }
        ctx.sleep(ALIAS_POLL);
    }
}

/// The alias ranges of the interface other than the VIP.
fn others(info: &InstanceInfo, cidr: &str) -> Vec<Alias> {
    let mut rest: Vec<Alias> = info
        .aliases
        .iter()
        .filter(|a| a.cidr != cidr)
        .cloned()
        .collect();
    rest.sort_by(|a, b| (&a.cidr, &a.range_name).cmp(&(&b.cidr, &b.range_name)));
    rest
}

fn aliases_with(info: &InstanceInfo, cidr: &str) -> Vec<Alias> {
    let mut aliases: Vec<Alias> = info
        .aliases
        .iter()
        .filter(|a| a.cidr != cidr)
        .cloned()
        .collect();
    aliases.push(Alias::plain(cidr));
    aliases
}

fn aliases_without(info: &InstanceInfo, cidr: &str) -> Vec<Alias> {
    info.aliases
        .iter()
        .filter(|a| a.cidr != cidr)
        .cloned()
        .collect()
}

/// Poll the cloud until `node` shows the alias as wanted — and its other
/// alias ranges exactly as they were sent — for [`ALIAS_STABLE_READS`]
/// consecutive reads. The cloud API may serve stale reads right after a
/// change, so a single matching read is not enough.
fn wait_alias(
    ctx: &Ctx<'_>,
    node: &NodeConfig,
    wanted_present: bool,
    expected_others: &[Alias],
) -> Res<()> {
    let cidr = ctx.cfg.vip_cidr();
    let started = ctx.clock.now_ms();
    let mut stable = 0;
    #[allow(unused_assignments)]
    let mut last = String::from("no observation");
    loop {
        match ctx.gce.describe(&node.instance) {
            Ok(info) => {
                let present = info.has_alias(&cidr);
                last = format!("alias {}", if present { "present" } else { "absent" });
                let rest_ok = others(&info, &cidr) == expected_others;
                if !rest_ok {
                    last.push_str(", other alias ranges differ from what was sent");
                }
                if present == wanted_present && rest_ok {
                    stable += 1;
                    if stable >= ALIAS_STABLE_READS {
                        return Ok(());
                    }
                } else {
                    stable = 0;
                }
            }
            Err(e) => {
                stable = 0;
                last = format!("observation failed: {e}");
            }
        }
        if ctx.clock.now_ms().saturating_sub(started) >= ALIAS_TIMEOUT_MS {
            return Err(Failure::Unknown(format!(
                "{}: the VIP alias did not become {} ({last})",
                node.name,
                if wanted_present { "present" } else { "absent" }
            )));
        }
        ctx.sleep(ALIAS_POLL);
    }
}

// ---------------------------------------------------------------------------
// cloud change tracking (audit C-01)
// ---------------------------------------------------------------------------

/// A cloud change that is not known to have finished. Recorded in the lease
/// record so that `status` and `reconcile` can follow it after this command
/// has exited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingChange {
    pub(crate) node: String,
    pub(crate) instance: String,
    /// `detach` or `attach`.
    pub(crate) action: String,
    /// Newest operation of the instance known before the request; every
    /// operation listed above it is newer.
    pub(crate) anchor: Option<String>,
    pub(crate) why: String,
}

/// What one [`change_aliases`] call tells its caller besides the result.
#[derive(Default)]
struct Sent {
    /// A request exists and may take effect, whatever follows (audit C-09).
    attempted: bool,
    /// The cloud refused the request and this was proven (R4): the instance
    /// and the operation that preceded the request, so that the end of the
    /// move can look once more before it releases the lock.
    refused: Option<PendingChange>,
}

/// Operations of the listing created after `anchor`, newest first. `None`
/// when the anchor is no longer in the listing: "newer than" is then unknown.
fn ops_after<'a>(list: &'a OpList, anchor: &Option<String>) -> Option<Vec<&'a CloudOp>> {
    match anchor {
        None if list.complete => Some(list.ops.iter().collect()),
        None => None,
        Some(name) => {
            let at = list.ops.iter().position(|o| &o.name == name)?;
            Some(list.ops[..at].iter().collect())
        }
    }
}

/// What the operation list says about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Settled {
    /// The tool reported success and no operation is outstanding.
    Reported,
    /// An operation for the request finished successfully.
    Applied,
    /// The cloud answered with an explicit client error (HTTP 4xx), no
    /// operation of the instance appeared for [`REFUSAL_QUIET_MS`], and the
    /// request is therefore treated as not applied (the text says why).
    Refused(String),
    /// Still unknown after following the list for the allowed time.
    Unresolved(String),
}

/// One reading of the operation list against one request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Judged {
    Final(Settled),
    /// Not decided yet; the text says what is awaited.
    Wait(String),
    /// A rejected request and no new operation in this reading.
    NoNewOperation,
}

fn judge(list: &OpList, anchor: &Option<String>, report: &ChangeReport) -> Judged {
    let Some(new) = ops_after(list, anchor) else {
        return Judged::Final(Settled::Unresolved(
            "the operation that preceded the request is no longer listed".to_string(),
        ));
    };
    if let Some(open) = new.iter().find(|o| !o.is_done()) {
        return Judged::Wait(format!("operation {} is {}", open.name, open.status));
    }
    let nic: Vec<&&CloudOp> = new.iter().filter(|o| o.is_nic_update()).collect();
    // Any new operation at all (also a foreign one) makes a "no operation was
    // created" claim impossible to attribute: the claim needs an empty list.
    if matches!(report, ChangeReport::Rejected { .. }) && new.is_empty() {
        return Judged::NoNewOperation;
    }
    Judged::Final(match (report, nic.as_slice()) {
        (ChangeReport::Done, []) => Settled::Reported,
        (ChangeReport::Done, [one]) if !one.failed => Settled::Applied,
        (ChangeReport::Done, _) => Settled::Unresolved(
            "the tool reported success but the operations do not agree".to_string(),
        ),
        // A failed alias operation is NOT evidence that this request did not
        // land (audit RA-C-01): operations carry no request identifier, so
        // the failed one may belong to somebody else while this request is
        // still on its way. Only the tool's own success report (above) lets a
        // single failed operation count; for every other report it stays
        // unresolved (UNKNOWN, no rollback).
        (_, [one]) if one.failed => Settled::Unresolved(format!(
            "an alias operation ({}) finished with an error, but it cannot be attributed to \
             this request (operations carry no request identifier); the request may still land",
            one.name
        )),
        (_, [_]) => Settled::Applied,
        (_, []) => {
            return Judged::Wait(
                "no operation for the request is visible (it may not have been sent, \
                 or may still arrive)"
                    .to_string(),
            );
        }
        (_, _) => {
            Settled::Unresolved("several alias operations appeared for one request".to_string())
        }
    })
}

/// Follow the operation list until the request is resolved, or the allowed
/// time is over (then `Unresolved`).
///
/// A request the tool reported as an explicit client error is resolved as
/// [`Settled::Refused`] only after [`REFUSAL_QUIET_READS`] readings in a row,
/// spanning [`REFUSAL_QUIET_MS`], showed no new operation. A failed reading,
/// or any new operation, restarts the count (a new operation is then judged
/// like any other).
fn settle(
    ctx: &Ctx<'_>,
    instance: &str,
    anchor: &Option<String>,
    report: &ChangeReport,
) -> Settled {
    let started = ctx.clock.now_ms();
    #[allow(unused_assignments)]
    let mut waiting = String::from("not yet looked");
    let mut quiet_since: Option<u64> = None;
    let mut quiet_reads: u32 = 0;
    loop {
        let now = ctx.clock.now_ms();
        match ctx.gce.list_operations(instance) {
            Ok(list) => match judge(&list, anchor, report) {
                Judged::Final(done) => return done,
                Judged::Wait(why) => {
                    waiting = why;
                    quiet_since = None;
                    quiet_reads = 0;
                }
                Judged::NoNewOperation => {
                    let since = *quiet_since.get_or_insert(now);
                    quiet_reads += 1;
                    if quiet_reads >= REFUSAL_QUIET_READS
                        && now.saturating_sub(since) >= REFUSAL_QUIET_MS
                        && let ChangeReport::Rejected { status, detail } = report
                    {
                        return Settled::Refused(format!(
                            "HTTP {status}: {detail}; no operation of the instance appeared in \
                             {quiet_reads} readings over {} s",
                            now.saturating_sub(since) / 1000
                        ));
                    }
                    waiting = format!(
                        "the request was rejected; confirming that no operation appears \
                         ({quiet_reads} reading(s) so far)"
                    );
                }
            },
            Err(e) => {
                waiting = format!("cannot list operations: {e}");
                quiet_since = None;
                quiet_reads = 0;
            }
        }
        if ctx.clock.now_ms().saturating_sub(started) >= OPS_SETTLE_MS {
            return Settled::Unresolved(waiting);
        }
        ctx.sleep(ALIAS_POLL);
    }
}

/// Change the VIP alias of `node`. `Ok` only when the change is resolved and
/// the resulting alias list is observed. A change that cannot be resolved is
/// pushed onto `pending` and reported as UNKNOWN: it may still land.
fn change_aliases(
    ctx: &Ctx<'_>,
    node: &NodeConfig,
    add: bool,
    why: &str,
    tag: &str,
    pending: &mut Vec<PendingChange>,
    sent: &mut Sent,
) -> Res<()> {
    let action = if add { "attach" } else { "detach" };
    // Read the live alias list immediately before the change so that unrelated
    // alias ranges of the interface are preserved.
    let view = describe_node(ctx, node)?;
    let cidr = ctx.cfg.vip_cidr();
    let wanted = if add {
        aliases_with(&view.info, &cidr)
    } else {
        aliases_without(&view.info, &cidr)
    };
    let expected_others = others(&view.info, &cidr);

    // Before the request: the operation list must be readable and nothing may
    // be outstanding, or a later finding could not be attributed to us.
    let before = ctx.gce.list_operations(&node.instance).map_err(|e| {
        Failure::Failed(format!(
            "{}: cannot list cloud operations ({e}); no change was sent",
            node.name
        ))
    })?;
    if let Some(open) = before.ops.iter().find(|o| !o.is_done()) {
        return Err(Failure::Failed(format!(
            "{}: cloud operation {} ({}) is still {}; no change was sent",
            node.name, open.name, open.op_type, open.status
        )));
    }
    let anchor = before.ops.first().map(|o| o.name.clone());

    ctx.log.info(&format!(
        "{why}: {} VIP alias {} on {}",
        if add { "adding" } else { "removing" },
        cidr,
        node.name
    ));
    // From here on the request exists and may take effect, whatever follows
    // (audit C-09: the caller's "attempted" flag means this, not "was about
    // to try").
    sent.attempted = true;
    let report = ctx.gce.set_aliases(&node.instance, &wanted, tag);
    match &report {
        ChangeReport::Done => {}
        ChangeReport::Error(message) => ctx.log.info(&format!(
            "{}: cloud change reported an error ({message}); following its operation",
            node.name
        )),
        ChangeReport::Rejected { status, .. } => ctx.log.info(&format!(
            "{}: the cloud answered the change with HTTP {status}; confirming that it created no \
             operation",
            node.name
        )),
        ChangeReport::TimedOut => ctx.log.info(&format!(
            "{}: cloud change timed out; following its operation (no blind retry)",
            node.name
        )),
    }
    let unresolved = |reason: String, pending: &mut Vec<PendingChange>| {
        pending.push(PendingChange {
            node: node.name.clone(),
            instance: node.instance.clone(),
            action: action.to_string(),
            anchor: anchor.clone(),
            why: reason.chars().take(200).collect(),
        });
        Failure::Unknown(format!(
            "{}: the cloud change ({action}) is not known to have finished: {reason}; it may \
             still land",
            node.name
        ))
    };
    match settle(ctx, &node.instance, &anchor, &report) {
        Settled::Refused(why) => {
            // The unchanged state is proven by observation, not assumed: the
            // alias list must still be exactly what it was before the
            // request, on consecutive reads. Anything else (an external
            // change, a late effect, an unreadable cloud) is UNKNOWN.
            // Kept for the end of the move: before the lock is released the
            // instance is looked at once more (a last guard against a request
            // that was refused and still shows up).
            sent.refused = Some(PendingChange {
                node: node.name.clone(),
                instance: node.instance.clone(),
                action: action.to_string(),
                anchor: anchor.clone(),
                why: why.chars().take(200).collect(),
            });
            wait_alias(ctx, node, !add, &expected_others).map_err(|e| {
                unresolved(
                    format!(
                        "the request looked refused ({why}) but the alias list is not as before: {}",
                        e.message()
                    ),
                    pending,
                )
            })?;
            Err(Failure::Failed(format!(
                "{}: the cloud REFUSED the {action} ({why}); the alias list is verified unchanged",
                node.name
            )))
        }
        Settled::Unresolved(reason) => Err(unresolved(reason, pending)),
        Settled::Reported | Settled::Applied => wait_alias(ctx, node, add, &expected_others)
            .map_err(|e| unresolved(e.message().to_string(), pending)),
    }
}

// ---------------------------------------------------------------------------
// agent helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct Ping {
    /// The agent's verdict over the HA daemon: `masked` / `absent` are the
    /// only proofs; anything else (including a missing field) is not.
    pub(crate) ha_daemon: String,
    pub(crate) ha_proven: bool,
    pub(crate) ha_units: std::collections::BTreeMap<String, String>,
    pub(crate) ha_detail: Vec<String>,
    /// The highest fencing token the node accepted: `(epoch, seq)`.
    pub(crate) fence: Option<(u64, u64)>,
    /// The node's fencing record is unusable.
    pub(crate) fence_error: Option<String>,
    /// The agent's read-only view of the durable manual-operation barrier.
    pub(crate) manual_barrier: Option<Value>,
}

impl Ping {
    /// The exclusion from the HA daemon is positively proven on this host.
    /// Both the verdict word and the flag must agree: an old agent that only
    /// says `inactive` is not a proof.
    pub(crate) fn ha_safe(&self) -> bool {
        self.ha_proven && matches!(self.ha_daemon.as_str(), "masked" | "absent")
    }

    /// `state (detail; detail)` for messages.
    pub(crate) fn ha_text(&self) -> String {
        if self.ha_detail.is_empty() {
            self.ha_daemon.clone()
        } else {
            format!("{} ({})", self.ha_daemon, self.ha_detail.join("; "))
        }
    }
}

pub(crate) enum Reach {
    Up(Ping),
    /// No answer from the host (transport failure or timeout).
    Down(String),
}

/// The agent's answer to `ping`. A missing or malformed field never turns
/// into a proof: `ha_proven` must be an explicit `true`.
pub(crate) fn parse_ping(data: &Value) -> Ping {
    let fence = data
        .get("fence")
        .filter(|f| !f.is_null())
        .and_then(|f| Some((f.get("epoch")?.as_u64()?, f.get("seq")?.as_u64()?)));
    Ping {
        ha_daemon: data
            .get("ha_daemon")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        ha_proven: data.get("ha_proven").and_then(Value::as_bool) == Some(true),
        ha_units: data
            .get("ha_units")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default(),
        ha_detail: data
            .get("ha_detail")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(|t| t.chars().take(200).collect())
                    .collect()
            })
            .unwrap_or_default(),
        fence,
        fence_error: data
            .get("fence_error")
            .and_then(Value::as_str)
            .map(str::to_string),
        manual_barrier: data.get("manual_barrier").cloned(),
    }
}

/// `Err` means the host answered but cannot be used (wrong identity, agent
/// refusing, malformed answer): that is *not* "down".
pub(crate) fn ping(ctx: &Ctx<'_>, label: &str, target: &Target) -> Res<Reach> {
    match ctx.call(target, op::PING, json!({}), PING_TIMEOUT) {
        Ok(data) => {
            let node = data.get("node").and_then(Value::as_str).unwrap_or("");
            if node != label {
                return Err(Failure::Refused(format!(
                    "{} answered as {node:?}, not {label:?}; refusing to act on the wrong host",
                    target.host
                )));
            }
            Ok(Reach::Up(parse_ping(&data)))
        }
        Err(CallError::Transport(TransportError::Unreachable(m)))
        | Err(CallError::Transport(TransportError::Timeout(m))) => Ok(Reach::Down(m)),
        Err(e) => Err(Failure::Refused(format!("{label}: agent unusable: {e}"))),
    }
}

/// Resolve a node's address and ping it. A node whose address cannot be
/// resolved (for example a TERMINATED instance has no external address) is
/// reported as `Down`, never as healthy; whether that is acceptable is decided
/// by the caller from independent cloud evidence.
pub(crate) fn reach_node(ctx: &Ctx<'_>, name: &str) -> Res<(Target, Reach)> {
    // An unknown node name is a refusal of the request; only an address that
    // cannot be resolved makes the host "down" (below).
    ctx.node(name)?;
    match ctx.node_target(name) {
        Ok(target) => {
            let reach = ping(ctx, name, &target)?;
            Ok((target, reach))
        }
        Err(Failure::Refused(message)) => {
            let placeholder = Target {
                label: name.to_string(),
                host: String::new(),
                host_key_alias: String::new(),
            };
            Ok((placeholder, Reach::Down(message)))
        }
        Err(other) => Err(other),
    }
}

/// The Witness record must not be older than what a node has already seen
/// (a restored snapshot, audit B-04), and the node's own mark must be usable.
fn check_fence_floor(label: &str, ping: &Ping, lease: &LeaseState) -> Res<()> {
    if let Some(error) = &ping.fence_error {
        return Err(Failure::Refused(format!(
            "{label}: its fencing record is unusable ({error}); refusing"
        )));
    }
    if let Some((epoch, seq)) = ping.fence
        && (seq > lease.seq || epoch > lease.epoch)
    {
        return Err(Failure::Unknown(format!(
            "the Witness record (epoch {}, seq {}) is OLDER than what {label} has already served \
             (epoch {epoch}, seq {seq}): it may have been restored from an old copy. Nothing was \
             changed; inspect the Witness, then `resource reconcile vip`",
            lease.epoch, lease.seq
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SvcState {
    pub(crate) active: bool,
    pub(crate) active_state: String,
    /// `MainPID` / `ActiveEnterTimestampMonotonic` as the agent reported them
    /// (empty when it did not). Restart evidence for chronyd (audit D-04).
    pub(crate) main_pid: String,
    pub(crate) active_enter: String,
}

impl SvcState {
    /// Only `inactive` and `failed` mean stopped; `activating`,
    /// `deactivating` and `reloading` are transitions (audit C-08).
    pub(crate) fn is_stopped(&self) -> bool {
        matches!(self.active_state.as_str(), "inactive" | "failed")
    }
}

fn parse_svc(data: &Value) -> Option<SvcState> {
    Some(SvcState {
        active: data.get("active")?.as_bool()?,
        active_state: data.get("active_state")?.as_str()?.to_string(),
        main_pid: data
            .get("main_pid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        active_enter: data
            .get("active_enter")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

pub(crate) fn svc_status(
    ctx: &Ctx<'_>,
    target: &Target,
    unit: &str,
) -> Result<SvcState, CallError> {
    let data = ctx.call(target, op::SERVICE_STATUS, json!({"unit": unit}), SHORT)?;
    parse_svc(&data).ok_or_else(|| CallError::Failed("service status not understood".to_string()))
}

pub(crate) fn svc_control(
    ctx: &Ctx<'_>,
    target: &Target,
    unit: &str,
    action: &str,
) -> Result<SvcState, CallError> {
    svc_control_with(ctx, target, unit, action, None)
}

/// `service.control` carrying the fencing token of the calling operation.
fn svc_control_fenced(
    ctx: &Ctx<'_>,
    target: &Target,
    unit: &str,
    action: &str,
    plan: &Plan,
) -> Result<SvcState, CallError> {
    svc_control_with(ctx, target, unit, action, Some(&plan.token))
}

fn svc_control_with(
    ctx: &Ctx<'_>,
    target: &Target,
    unit: &str,
    action: &str,
    token: Option<&Token>,
) -> Result<SvcState, CallError> {
    let mut args = json!({"unit": unit, "action": action});
    if let Some(token) = token {
        args["fence"] = json!(token);
    }
    let data = ctx.call(target, op::SERVICE_CONTROL, args, LONG)?;
    parse_svc(&data).ok_or_else(|| CallError::Failed("service state not understood".to_string()))
}

/// `Ok(Some(body))` when something answered on the port, `Ok(None)` when the
/// connection failed, `Err` when the probe itself could not be performed.
pub(crate) fn probe(
    ctx: &Ctx<'_>,
    from: &Target,
    addr: &str,
    port: u16,
) -> Result<Option<String>, CallError> {
    match ctx.call(
        from,
        op::PROBE,
        json!({"addr": addr, "port": port, "path": "/id"}),
        SHORT,
    ) {
        Ok(data) => Ok(data.get("body").and_then(Value::as_str).map(str::to_string)),
        Err(CallError::Failed(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Like [`probe`], but `Ok(None)` only when the agent says the connection was
/// **refused** (nothing listens). Any other failure of the probe (a timeout, a
/// reply that is not understood, a write error, an old agent that cannot say)
/// may mean that something accepted the connection, so it is an error: used
/// where silence is a safety claim (audit RA-C-05).
pub(crate) fn probe_refused_or_answer(
    ctx: &Ctx<'_>,
    from: &Target,
    addr: &str,
    port: u16,
) -> Result<Option<String>, CallError> {
    let data = ctx.call(
        from,
        op::PROBE,
        json!({"addr": addr, "port": port, "path": "/id"}),
        SHORT,
    )?;
    // Any `body` that is present is an answer of something that accepted the
    // connection, also one that is not text (a damaged reply): it is never
    // silence, even next to `refused: true`.
    match data.get("body") {
        Some(Value::String(body)) => return Ok(Some(body.clone())),
        Some(other) => {
            return Err(CallError::Failed(format!(
                "the probe answered with a body that is not text ({other})"
            )));
        }
        None => {}
    }
    if data.get("refused").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    Err(CallError::Failed(
        "the probe answered neither with a body nor with a refusal".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// lease helpers
// ---------------------------------------------------------------------------

pub(crate) struct LeaseView {
    pub(crate) state: LeaseState,
    /// Witness wall clock (seconds) at the time of the read.
    pub(crate) now: u64,
}

fn parse_lease(data: &Value, fallback_now: u64) -> Res<LeaseView> {
    let now = data
        .get("now")
        .and_then(Value::as_u64)
        .unwrap_or(fallback_now);
    let mut bare = data.clone();
    if let Some(map) = bare.as_object_mut() {
        map.remove("now");
    }
    let state: LeaseState = serde_json::from_value(bare)
        .map_err(|e| Failure::Failed(format!("lease record not understood: {e}")))?;
    Ok(LeaseView { state, now })
}

pub(crate) fn lease_call(ctx: &Ctx<'_>, op_name: &str, args: Value) -> Result<Value, CallError> {
    let witness = ctx
        .witness_target()
        .map_err(|f| CallError::Failed(f.message().to_string()))?;
    ctx.call(&witness, op_name, args, SHORT)
}

/// Write the durable manual-operation barrier on every reachable node that
/// takes part in the move. It is written before the Witness lease and before
/// any resource change, so a controller crash later always leaves a visible,
/// HA-blocking record. If a write fails, every record this call did write is
/// removed again; a cleanup that cannot be verified is an UNKNOWN, never a
/// silent success.
#[allow(clippy::too_many_arguments)]
fn begin_intents(
    ctx: &Ctx<'_>,
    op_id: &str,
    source: &str,
    target: &str,
    epoch: u64,
    source_target: &Target,
    target_target: &Target,
    source_up: bool,
) -> Result<(), Failure> {
    let mut nodes: Vec<(&str, &Target)> = Vec::new();
    if source_up {
        nodes.push((source, source_target));
    }
    nodes.push((target, target_target));
    let args = json!({
        "op_id": op_id,
        "source": source,
        "target": target,
        "epoch": epoch,
        "controller": format!("mkg-v{}", env!("CARGO_PKG_VERSION")),
    });
    let mut written: Vec<(&str, &Target)> = Vec::new();
    for (name, target) in nodes {
        match ctx.call(target, op::CONTROL_INTENT_BEGIN, args.clone(), SHORT) {
            Ok(_) => written.push((name, target)),
            Err(error) => {
                // The failed call may have written the record despite a lost
                // answer, so try to resolve it as well. Only a verified clear
                // allows the command to say "nothing changed".
                let mut cleanup_failed = Vec::new();
                for (other_name, other_target) in written.iter().copied().chain([(name, target)]) {
                    if let Err(cleanup) = ctx.call(
                        other_target,
                        op::CONTROL_INTENT_RESOLVE,
                        json!({"op_id": op_id}),
                        SHORT,
                    ) {
                        cleanup_failed.push(format!("{other_name}: {cleanup}"));
                    }
                }
                if !cleanup_failed.is_empty() {
                    return Err(Failure::Unknown(format!(
                        "cannot record the manual-operation barrier on {name} ({error}); the                          cleanup of a partial record also failed ({}). HA will refuse to start                          on that host until the record is resolved; run `resource reconcile vip`",
                        cleanup_failed.join("; ")
                    )));
                }
                return Err(match error {
                    CallError::Refused(message) => Failure::Refused(format!(
                        "the node agent refused the manual-operation barrier on {name}: {message}"
                    )),
                    CallError::Failed(message) => Failure::Failed(format!(
                        "the node agent failed to record the manual-operation barrier on {name}:                          {message}"
                    )),
                    other => Failure::Unknown(format!(
                        "the manual-operation barrier on {name} has no clear outcome: {other}"
                    )),
                });
            }
        }
    }
    Ok(())
}

/// Remove the barrier for `op_id` from every node that took part. A missing
/// record is success (idempotent). This is called only after the move is
/// committed or verified rolled back; an UNKNOWN leaves the record in place.
fn resolve_intents(
    ctx: &Ctx<'_>,
    op_id: &str,
    source: &str,
    target: &str,
    source_target: &Target,
    target_target: &Target,
    source_up: bool,
) -> Result<(), String> {
    let mut nodes: Vec<(&str, &Target)> = Vec::new();
    if source_up {
        nodes.push((source, source_target));
    }
    nodes.push((target, target_target));
    let mut failures = Vec::new();
    for (name, target) in nodes {
        if let Err(error) = ctx.call(
            target,
            op::CONTROL_INTENT_RESOLVE,
            json!({"op_id": op_id}),
            SHORT,
        ) {
            failures.push(format!("{name}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Resolve whatever barrier is present on one node. Used by `reconcile`,
/// where the operator's verified state is the authority and the record's
/// op_id may come from a controller that is already gone.
fn resolve_any_barrier(
    ctx: &Ctx<'_>,
    name: &str,
    target: &Target,
    allowed_op: Option<&str>,
) -> Result<Option<String>, String> {
    let status = ctx
        .call(target, op::CONTROL_INTENT_STATUS, json!({}), SHORT)
        .map_err(|error| format!("{name}: {error}"))?;
    if status.get("present").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    let op_id = status
        .get("intent")
        .and_then(|intent| intent.get("op_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name}: the barrier is present but has no op_id"))?;
    // A barrier written before the lease can look exactly like an orphan.
    // Do not clear it unless the operator explicitly names this operation;
    // otherwise a controller paused between `begin` and the lease could
    // resume after reconcile and act while HA is starting.
    if allowed_op != Some(op_id) {
        return Err(format!(
            "{name}: barrier {op_id} is open; verify the cloud/lease yourself and pass              `--abandon-op {op_id}` to clear it"
        ));
    }
    ctx.call(
        target,
        op::CONTROL_INTENT_RESOLVE,
        json!({"op_id": op_id}),
        SHORT,
    )
    .map_err(|error| format!("{name}: cannot clear barrier {op_id}: {error}"))?;
    Ok(Some(op_id.to_string()))
}

pub(crate) fn lease_status(ctx: &Ctx<'_>) -> Res<LeaseView> {
    let data = lease_call(ctx, op::LEASE_STATUS, json!({}))
        .map_err(|e| Failure::Refused(format!("the Witness lease is unavailable: {e}")))?;
    parse_lease(&data, ctx.clock.unix_secs())
}

/// How recording a phase at the Witness ended.
enum PhaseRecord {
    Recorded,
    /// The Witness refused: this command does not (or no longer) hold the
    /// lease. Nothing was recorded.
    NotHolder(String),
    /// No usable answer: the record may or may not have been written.
    Unclear(String),
}

fn record_phase(ctx: &Ctx<'_>, op_id: &str, phase: Phase, evidence: Option<Value>) -> PhaseRecord {
    let mut args = json!({"op_id": op_id, "phase": phase.name()});
    if let Some(evidence) = evidence {
        args["evidence"] = evidence;
    }
    match lease_call(ctx, op::LEASE_PHASE, args) {
        Ok(_) => PhaseRecord::Recorded,
        Err(CallError::Refused(m)) => PhaseRecord::NotHolder(m),
        Err(e) => PhaseRecord::Unclear(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// move
// ---------------------------------------------------------------------------

pub(crate) struct MoveRequest {
    pub(crate) target: String,
    /// Operator attestation naming the (unreachable) source node. It only
    /// *enables* the fenced path; the proof is the cloud's instance status.
    pub(crate) confirm_fenced: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MoveReport {
    pub(crate) op_id: String,
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) epoch_before: u64,
    pub(crate) epoch_after: u64,
    pub(crate) served_by: String,
    pub(crate) fenced_source: bool,
    pub(crate) evidence: Value,
    /// What this report cannot promise.
    pub(crate) advice: String,
}

const MOVE_ADVICE: &str = "The target was verified serving immediately before the commit; this \
     command cannot see later failures. Run `resource status vip` to confirm.";

#[derive(Default, Debug)]
struct MoveState {
    /// A stop of the source service was attempted (it may have taken effect).
    source_stop_attempted: bool,
    source_alias_removal_attempted: bool,
    target_alias_add_attempted: bool,
    target_start_attempted: bool,
    /// A mutating phase was (or may have been, if the answer was lost)
    /// recorded at the Witness: that record never expires by itself. Set
    /// only when the record exists or may exist — never for a refusal.
    mutating_phase_written: bool,
    /// The last phase known to be recorded.
    phase: Option<Phase>,
    /// Cloud changes that are not known to have finished.
    pending: Vec<PendingChange>,
    /// Requests the cloud explicitly refused (proven, R4). Looked at once
    /// more before the lock is released.
    refused: Vec<PendingChange>,
    /// The Witness refused a phase: this command does not hold the lease.
    lost_lease: Option<String>,
    /// Stop without any rollback (for example the fencing evidence changed).
    halt: Option<String>,
    /// The target is known not to hold the alias (its add was rejected, or
    /// the rollback removed and observed it). Needed before the source may be
    /// given the alias back.
    target_vip_absent_proven: bool,
    fence_checks: Vec<Value>,
    /// Every re-check of the HA exclusion on the three hosts.
    ha_checks: Vec<Value>,
}

impl MoveState {
    fn mutated(&self) -> bool {
        self.mutating_phase_written
            || self.source_stop_attempted
            || self.source_alias_removal_attempted
            || self.target_alias_add_attempted
            || self.target_start_attempted
    }
}

struct Plan {
    op_id: String,
    /// The fencing token of this operation (sent with every service change).
    token: Token,
    source: NodeConfig,
    target: NodeConfig,
    source_target: Target,
    target_target: Target,
    witness: Target,
    source_up: bool,
    /// Whether the source service ran before the move (`None`: unreachable).
    source_was_active: Option<bool>,
    fence_evidence: Value,
    fence_id: Option<String>,
    fence_last_stop: Option<String>,
}

fn cloud_status_running(view: &NodeView) -> bool {
    view.info.status == "RUNNING"
}

pub(crate) fn move_vip(ctx: &Ctx<'_>, request: &MoveRequest) -> Res<MoveReport> {
    let target_node = ctx.node(&request.target)?.clone();
    let cidr = ctx.cfg.vip_cidr();

    // ---- 1. read-only pre-flight -------------------------------------
    let lease = lease_status(ctx)?;
    let Some(recorded_owner) = lease.state.owner.clone() else {
        return Err(Failure::Refused(
            "VIP ownership is not initialised; run `resource init vip --owner <node>`".into(),
        ));
    };
    if let Some(open) = &lease.state.op {
        // An expired lock that never mutated anything is taken over by the
        // acquire below; everything else must be resolved first.
        if open.phase.mutating() || open.expires_at > lease.now {
            return Err(Failure::Refused(format!(
                "operation {} is recorded in phase {}; resolve it first \
                 (`resource status vip`, then `resource reconcile vip`)",
                open.op_id,
                open.phase.name()
            )));
        }
    }
    // Nothing has been sent yet: an observation that fails is a refusal to
    // start, not a failed operation.
    let views = observe_all(ctx).map_err(Failure::before_any_change)?;
    let holders = owners(ctx, &views);
    let cloud_owner = match holders.as_slice() {
        [one] => one.clone(),
        [] => {
            return Err(Failure::Refused(format!(
                "the cloud shows no node holding {cidr} but the record says {recorded_owner}; \
                 inspect and run `resource reconcile vip`"
            )));
        }
        many => {
            return Err(Failure::Refused(format!(
                "the VIP is assigned to several nodes ({}); refusing",
                many.join(", ")
            )));
        }
    };
    if cloud_owner != recorded_owner {
        return Err(Failure::Refused(format!(
            "ownership conflict: the record says {recorded_owner} but the cloud shows \
             {cloud_owner}; an external change is respected and not overwritten \
             (inspect, then `resource reconcile vip`)"
        )));
    }
    if cloud_owner == target_node.name {
        return Err(Failure::Refused(format!(
            "{} already owns the VIP",
            target_node.name
        )));
    }
    let source_node = ctx.node(&cloud_owner)?.clone();
    let source_view = views
        .iter()
        .find(|v| v.node.name == source_node.name)
        .ok_or_else(|| Failure::Failed("internal: source view missing".into()))?;
    let target_view = views
        .iter()
        .find(|v| v.node.name == target_node.name)
        .ok_or_else(|| Failure::Failed("internal: target view missing".into()))?;

    // The target must be a healthy, reachable, manual-mode host *before* the
    // source is touched.
    if !cloud_status_running(target_view) {
        return Err(Failure::Refused(format!(
            "target {} is {} in the cloud, not RUNNING",
            target_node.name, target_view.info.status
        )));
    }
    let (target_target, target_reach) = reach_node(ctx, &target_node.name)?;
    match target_reach {
        Reach::Up(p) if p.ha_safe() => {
            check_fence_floor(&target_node.name, &p, &lease.state)?;
        }
        Reach::Up(p) => {
            return Err(Failure::Refused(format!(
                "target {}: HA daemon state is {}; manual control requires the exclusion to be \
                 proven (HA units masked)",
                target_node.name,
                p.ha_text()
            )));
        }
        Reach::Down(m) => {
            return Err(Failure::Refused(format!(
                "target {} is unreachable ({m}); not starting a move that cannot finish",
                target_node.name
            )));
        }
    }

    let service = ctx.cfg.service.as_str();
    let (source_target, source_reach) = reach_node(ctx, &source_node.name)?;
    let (source_up, source_was_active, fence_evidence) = match source_reach {
        Reach::Up(p) => {
            if !p.ha_safe() {
                return Err(Failure::Refused(format!(
                    "source {}: HA daemon state is {}; manual control requires the exclusion to \
                     be proven (HA units masked)",
                    source_node.name,
                    p.ha_text()
                )));
            }
            if source_view.info.status == FENCE_STATUS {
                return Err(Failure::Refused(format!(
                    "source {} answers over SSH but the cloud reports it {FENCE_STATUS}; \
                     the state is inconsistent",
                    source_node.name
                )));
            }
            check_fence_floor(&source_node.name, &p, &lease.state)?;
            // Remember whether the service ran, so that a rollback restores
            // exactly that and never starts a service that was down (C-06).
            let was_active = svc_status(ctx, &source_target, service)
                .map_err(|e| {
                    Failure::Refused(format!(
                        "cannot read {service} on source {}: {e}",
                        source_node.name
                    ))
                })?
                .active;
            (true, Some(was_active), Value::Null)
        }
        Reach::Down(message) => {
            if request.confirm_fenced.as_deref() != Some(source_node.name.as_str()) {
                return Err(Failure::Refused(format!(
                    "source {} is unreachable ({message}) and its isolation is not attested; \
                     refusing. If it is fenced, pass `--confirm-fenced {}`",
                    source_node.name, source_node.name
                )));
            }
            // The attestation only enables this path. The proof is read from
            // the cloud now, independently of anything the operator said.
            let fresh = describe_node(ctx, &source_node).map_err(Failure::before_any_change)?;
            if fresh.info.status != FENCE_STATUS {
                return Err(Failure::Refused(format!(
                    "source {} is unreachable but the cloud reports it {}, not {FENCE_STATUS}; \
                     it may still be running — fencing is not proven",
                    source_node.name, fresh.info.status
                )));
            }
            (
                false,
                None,
                json!({
                    "source_instance": fresh.info.name,
                    "source_instance_id": fresh.info.id,
                    "source_status": fresh.info.status,
                    "source_last_stop": fresh.info.last_stop,
                    "operator_attestation": source_node.name,
                }),
            )
        }
    };
    let witness = ctx.witness_target()?;
    match ping(ctx, &ctx.cfg.witness.name, &witness)? {
        Reach::Up(p) if p.ha_safe() => {}
        Reach::Up(p) => {
            return Err(Failure::Refused(format!(
                "witness {}: HA daemon state is {}; manual control requires the exclusion to be \
                 proven (HA units masked)",
                ctx.cfg.witness.name,
                p.ha_text()
            )));
        }
        Reach::Down(m) => {
            return Err(Failure::Refused(format!(
                "witness {} cannot be pinged ({m}); not starting a move that cannot be recorded",
                ctx.cfg.witness.name
            )));
        }
    }

    // ---- 2. record the intent, then acquire the operation lease -------
    // The intent is durable and survives this process. It is written before
    // the lease and before any resource change, so a crash after a mutating
    // request can never look like "nothing happened" to a later HA start.
    let op_id = format!("move-{}", proto::random_hex(6));
    let epoch_before = lease.state.epoch;
    begin_intents(
        ctx,
        &op_id,
        &source_node.name,
        &target_node.name,
        epoch_before,
        &source_target,
        &target_target,
        source_up,
    )?;
    let acquired = lease_call(
        ctx,
        op::LEASE_ACQUIRE,
        json!({
            "op_id": op_id,
            "source": source_node.name,
            "target": target_node.name,
            "ttl_s": LEASE_TTL_SECS,
            "controller": format!("mkg-v{}", env!("CARGO_PKG_VERSION")),
            "expect_epoch": epoch_before,
        }),
    );
    let token = match acquired {
        Ok(data) => match parse_lease(&data, 0)
            .ok()
            .and_then(|v| v.state.op)
            .filter(|o| o.op_id == op_id)
        {
            Some(held) => Token {
                epoch: held.epoch_at_start,
                seq: held.seq,
                op_id: op_id.clone(),
            },
            None => {
                // No resource was touched. The barrier is not needed for the
                // lease record (which expires by itself); clear it so a later
                // retry is not blocked by this attempt.
                let cleanup = resolve_intents(
                    ctx,
                    &op_id,
                    &source_node.name,
                    &target_node.name,
                    &source_target,
                    &target_target,
                    source_up,
                );
                return Err(Failure::Unknown(format!(
                    "the Witness answered the lease request in a form that does not show \
                     operation {op_id}; no VIP, alias or service was touched, but the lock may \
                     exist (a lock recorded as {op_id} expires on its own before any mutation; \
                     `resource status vip` shows it){}",
                    cleanup.err().map_or_else(String::new, |error| format!(
                        "; the manual-operation barrier could not be cleared: {error}"
                    ))
                )));
            }
        },
        Err(CallError::Refused(m)) => {
            // Nothing was changed and the lease was explicitly refused: the
            // barrier can be cleared. If it cannot, the command must not claim
            // a clean refusal while a blocking record remains.
            if let Err(error) = resolve_intents(
                ctx,
                &op_id,
                &source_node.name,
                &target_node.name,
                &source_target,
                &target_target,
                source_up,
            ) {
                return Err(Failure::Unknown(format!(
                    "the Witness refused the move ({m}), but the manual-operation \
                     barrier could not be cleared ({error}); HA will refuse to start \
                     on the affected host until `resource reconcile vip`"
                )));
            }
            return Err(Failure::Refused(format!(
                "the Witness refused the move: {m}"
            )));
        }
        // The request may have created the operation record although no clear
        // answer came back, so this is not a refusal; nothing else was
        // touched and the record cannot mutate anything by itself (R4).
        // The barrier stays: we cannot prove that the lease does not exist.
        Err(e) => {
            // No resource was touched; the barrier's async-effect job has not
            // started. Clear it so the operator can retry after the lease
            // record expires. If the cleanup fails, the barrier stays and HA
            // remains blocked (the message says so).
            let cleanup = resolve_intents(
                ctx,
                &op_id,
                &source_node.name,
                &target_node.name,
                &source_target,
                &target_target,
                source_up,
            );
            return Err(Failure::Unknown(format!(
                "the Witness lease request has no clear outcome ({e}); no VIP, alias or service \
                 was touched, but a lock recorded as {op_id} may exist and expires on its own \
                 before any mutation (`resource status vip` shows it){}",
                cleanup.err().map_or_else(String::new, |error| format!(
                    "; the manual-operation barrier could not be cleared: {error}"
                ))
            )));
        }
    };
    ctx.log.info(&format!(
        "move {op_id}: {} -> {} (epoch {epoch_before}, fencing seq {})",
        source_node.name, target_node.name, token.seq
    ));

    let plan = Plan {
        op_id,
        token,
        source: source_node,
        target: target_node,
        source_target,
        target_target,
        witness,
        source_up,
        source_was_active,
        fence_id: fence_evidence
            .get("source_instance_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        fence_last_stop: fence_evidence
            .get("source_last_stop")
            .and_then(Value::as_str)
            .map(str::to_string),
        fence_evidence,
    };
    let mut state = MoveState::default();
    match execute(ctx, &plan, &mut state, epoch_before) {
        Ok(report) => {
            // The move is committed and verified. Only now may the barrier
            // disappear. A failure to clear it is not a data loss, but it is
            // an unresolved handoff state: report UNKNOWN and keep it.
            if let Err(error) = resolve_intents(
                ctx,
                &plan.op_id,
                &plan.source.name,
                &plan.target.name,
                &plan.source_target,
                &plan.target_target,
                plan.source_up,
            ) {
                return Err(Failure::Unknown(format!(
                    "the VIP move to {} is committed, but the manual-operation barrier could \
                     not be cleared ({error}). HA will refuse to start on the affected host; \
                     run `resource reconcile vip` after the node is reachable",
                    plan.target.name
                )));
            }
            Ok(report)
        }
        Err(failure) => {
            let failure = finish_failed(ctx, &plan, &mut state, failure);
            // A refusal or a verified rollback is a known end state: the old
            // owner is back and no cloud change is pending, so the barrier can
            // go. UNKNOWN keeps it in place.
            if matches!(failure, Failure::Refused(_) | Failure::Failed(_))
                && let Err(error) = resolve_intents(
                    ctx,
                    &plan.op_id,
                    &plan.source.name,
                    &plan.target.name,
                    &plan.source_target,
                    &plan.target_target,
                    plan.source_up,
                )
            {
                return Err(Failure::Unknown(format!(
                    "{}; the manual-operation barrier could not be cleared ({error}); HA will \
                     refuse to start on the affected host until `resource reconcile vip`",
                    failure.message()
                )));
            }
            Err(failure)
        }
    }
}

/// Record `phase` before acting on it. A refusal means the lease is gone:
/// nothing may be touched any more (audit B-02). An unclear answer means the
/// record may exist, so the rollback must run.
fn record(ctx: &Ctx<'_>, plan: &Plan, state: &mut MoveState, phase: Phase) -> Res<()> {
    match record_phase(ctx, &plan.op_id, phase, None) {
        PhaseRecord::Recorded => {
            state.mutating_phase_written = true;
            state.phase = Some(phase);
            Ok(())
        }
        PhaseRecord::NotHolder(m) => {
            state.lost_lease = Some(m.clone());
            let message = format!(
                "the Witness refused phase {} ({m}): this command no longer holds the lease \
                 and has stopped without touching anything further",
                phase.name()
            );
            // Before this command changed anything (not even a phase was
            // recorded) the refusal is a plain refusal: the other holder's
            // operation is not ours to judge (R4). Afterwards it is UNKNOWN.
            Err(if state.mutated() {
                Failure::Unknown(message)
            } else {
                Failure::Refused(message)
            })
        }
        PhaseRecord::Unclear(m) => {
            state.mutating_phase_written = true;
            Err(Failure::Failed(format!(
                "cannot record phase {} at the Witness ({m}); not proceeding",
                phase.name()
            )))
        }
    }
}

/// While the source is fenced (unreachable), its cloud status must stay
/// `TERMINATED` with the same instance id and stop time that were read when
/// the move started (audit C-02). Checked before every cloud change and
/// before the commit; the time of each check is kept as evidence.
fn recheck_fence(ctx: &Ctx<'_>, plan: &Plan, state: &mut MoveState, point: &str) -> Res<()> {
    if plan.source_up {
        return Ok(());
    }
    let stop = |state: &mut MoveState, why: String| {
        state.halt = Some(why.clone());
        Failure::Unknown(format!(
            "the fencing evidence for {} could not be re-confirmed at {point}: {why}; stopping \
             without any rollback because the source may be running again",
            plan.source.name
        ))
    };
    let fresh = match describe_node(ctx, &plan.source) {
        Ok(v) => v,
        Err(e) => return Err(stop(state, e.message().to_string())),
    };
    if state.fence_checks.len() < EVIDENCE_CHANGES_MAX {
        state.fence_checks.push(json!({
            "point": point,
            "at": ctx.clock.unix_secs(),
            "status": fresh.info.status,
            "instance_id": fresh.info.id,
            "last_stop": fresh.info.last_stop,
        }));
    }
    if fresh.info.status != FENCE_STATUS {
        return Err(stop(
            state,
            format!("the cloud now reports it {}", fresh.info.status),
        ));
    }
    if plan.fence_id.as_deref() != Some(fresh.info.id.as_str())
        || plan.fence_last_stop != fresh.info.last_stop
    {
        return Err(stop(
            state,
            "its instance id or stop time changed".to_string(),
        ));
    }
    Ok(())
}

/// Re-confirm, right before something that cannot be taken back, that the
/// exclusion from the HA daemon still holds on the source (if it is
/// reachable), the target and the Witness (audit EX-03). The hosts are asked
/// again; a host that does not answer, answers as someone else, or answers
/// with anything but a proof stops the move **without any rollback**: an HA
/// daemon that has appeared anywhere may be acting, so nothing more is
/// touched (before the first change the lock is simply released). The mask is
/// what prevents a start; this check is what notices that the mask is gone.
fn ha_recheck(ctx: &Ctx<'_>, plan: &Plan, state: &mut MoveState, point: &str) -> Res<()> {
    let mut hosts: Vec<(&str, &Target)> = Vec::new();
    if plan.source_up {
        hosts.push((plan.source.name.as_str(), &plan.source_target));
    }
    hosts.push((plan.target.name.as_str(), &plan.target_target));
    hosts.push((ctx.cfg.witness.name.as_str(), &plan.witness));
    let mut seen = serde_json::Map::new();
    let mut problem: Option<String> = None;
    for (label, target) in hosts {
        let verdict = match ping(ctx, label, target) {
            Ok(Reach::Up(p)) if p.ha_safe() => p.ha_daemon.clone(),
            Ok(Reach::Up(p)) => {
                problem.get_or_insert_with(|| format!("{label}: HA daemon is {}", p.ha_text()));
                p.ha_daemon.clone()
            }
            Ok(Reach::Down(m)) => {
                problem.get_or_insert_with(|| format!("{label} does not answer ({m})"));
                "unreachable".to_string()
            }
            Err(e) => {
                problem.get_or_insert_with(|| format!("{label}: {}", e.message()));
                "unusable".to_string()
            }
        };
        seen.insert(label.to_string(), json!(verdict));
    }
    if state.ha_checks.len() < EVIDENCE_CHANGES_MAX {
        state.ha_checks.push(json!({
            "point": point,
            "at": ctx.clock.unix_secs(),
            "hosts": seen,
        }));
    }
    match problem {
        None => Ok(()),
        Some(why) => {
            let message = format!(
                "the exclusion from the HA daemon could not be re-confirmed at {point}: {why}; \
                 stopping without any rollback because an HA daemon may be acting"
            );
            // Before the first change there is nothing to protect and the
            // lock can simply be released: the move did not start and
            // nothing changed, which is a refusal exactly like the
            // pre-flight check of the same condition (R4). Afterwards
            // nothing may be undone, and the result is UNKNOWN.
            if state.mutated() {
                state.halt = Some(message.clone());
                Err(Failure::Unknown(message))
            } else {
                Err(Failure::Refused(message))
            }
        }
    }
}

fn execute(
    ctx: &Ctx<'_>,
    plan: &Plan,
    state: &mut MoveState,
    epoch_before: u64,
) -> Res<MoveReport> {
    let cidr = ctx.cfg.vip_cidr();
    let service = ctx.cfg.service.as_str();

    // ---- 3. quiesce the source ---------------------------------------
    ha_recheck(ctx, plan, state, "before_quiesce")?;
    record(ctx, plan, state, Phase::SourceQuiescing)?;
    if plan.source_up {
        state.source_stop_attempted = true;
        svc_control_fenced(ctx, &plan.source_target, service, "stop", plan).map_err(|e| {
            Failure::Failed(format!(
                "cannot stop {service} on {}: {e}",
                plan.source.name
            ))
        })?;
        match svc_status(ctx, &plan.source_target, service) {
            Ok(s) if s.is_stopped() => {}
            Ok(s) => {
                return Err(Failure::Failed(format!(
                    "{service} is still {} on {}",
                    s.active_state, plan.source.name
                )));
            }
            Err(e) => {
                return Err(Failure::Failed(format!(
                    "cannot confirm {service} stopped on {}: {e}",
                    plan.source.name
                )));
            }
        }
        confirm_nothing_answers(ctx, plan)?;
    }

    // ---- 4. release the VIP from the source --------------------------
    record(ctx, plan, state, Phase::SourceReleased)?;
    let views = observe_all(ctx)?;
    let holders = owners(ctx, &views);
    if holders.as_slice() != [plan.source.name.clone()] {
        return Err(Failure::Refused(format!(
            "the cloud now shows the VIP on [{}] instead of {} — an external change; \
             not touching the target",
            holders.join(", "),
            plan.source.name
        )));
    }
    recheck_fence(ctx, plan, state, "before_release")?;
    ha_recheck(ctx, plan, state, "before_release")?;
    let mut sent = Sent::default();
    let released = change_aliases(
        ctx,
        &plan.source,
        false,
        "release",
        &plan.op_id,
        &mut state.pending,
        &mut sent,
    );
    state.source_alias_removal_attempted |= sent.attempted;
    state.refused.extend(sent.refused.take());
    released?;

    // ---- 5. assign the VIP to the target ------------------------------
    record(ctx, plan, state, Phase::TargetAssigning)?;
    let views = observe_all(ctx)?;
    let holders = owners(ctx, &views);
    if !holders.is_empty() {
        return Err(Failure::Refused(format!(
            "the VIP reappeared on [{}] after the release; not assigning it to {}",
            holders.join(", "),
            plan.target.name
        )));
    }
    // A stale instance of the service on the target must not answer before
    // the VIP is ready.
    match svc_status(ctx, &plan.target_target, service) {
        Ok(s) if !s.is_stopped() => {
            let stopped = svc_control_fenced(ctx, &plan.target_target, service, "stop", plan)
                .map_err(|e| {
                    Failure::Failed(format!(
                        "cannot stop stale {service} on {}: {e}",
                        plan.target.name
                    ))
                })?;
            if !stopped.is_stopped() {
                return Err(Failure::Failed(format!(
                    "stale {service} on {} is still {} after the stop",
                    plan.target.name, stopped.active_state
                )));
            }
        }
        Ok(_) => {}
        Err(e) => {
            return Err(Failure::Failed(format!(
                "cannot read {service} on {}: {e}",
                plan.target.name
            )));
        }
    }
    recheck_fence(ctx, plan, state, "before_assign")?;
    ha_recheck(ctx, plan, state, "before_assign")?;
    let mut sent = Sent::default();
    let assigned = change_aliases(
        ctx,
        &plan.target,
        true,
        "assign",
        &plan.op_id,
        &mut state.pending,
        &mut sent,
    );
    state.target_alias_add_attempted |= sent.attempted;
    state.refused.extend(sent.refused.take());
    match assigned {
        Ok(()) => {}
        // Rejected, or never sent: the target does not have the alias.
        Err(Failure::Failed(m)) => {
            state.target_vip_absent_proven = true;
            return Err(Failure::Failed(m));
        }
        Err(other) => return Err(other),
    }
    record(ctx, plan, state, Phase::TargetAssigned)?;

    state.target_start_attempted = true;
    let started =
        svc_control_fenced(ctx, &plan.target_target, service, "start", plan).map_err(|e| {
            Failure::Failed(format!(
                "cannot start {service} on {}: {e}",
                plan.target.name
            ))
        })?;
    if !started.active {
        return Err(Failure::Failed(format!(
            "{service} is {} on {} after start",
            started.active_state, plan.target.name
        )));
    }

    // ---- 6. verify the VIP serves from the target ----------------------
    let served = wait_served(ctx, plan)?;
    let views = observe_all(ctx)?;
    let holders = owners(ctx, &views);
    if holders.as_slice() != [plan.target.name.clone()] {
        return Err(Failure::Unknown(format!(
            "after the move the cloud shows the VIP on [{}], expected only {}",
            holders.join(", "),
            plan.target.name
        )));
    }
    record(ctx, plan, state, Phase::TargetStarted)?;

    // ---- 7. last look, then commit ------------------------------------
    precommit_checks(ctx, plan, state)?;
    let evidence = json!({
        "served_by": served,
        "vip": cidr,
        "fence": plan.fence_evidence,
        "fence_rechecks": state.fence_checks,
        "ha_rechecks": state.ha_checks,
        "fencing_seq": plan.token.seq,
    });
    let committed = lease_call(
        ctx,
        op::LEASE_COMMIT,
        json!({"op_id": plan.op_id, "owner": plan.target.name, "evidence": evidence}),
    );
    match committed {
        Ok(data) => {
            let epoch_after = data.get("epoch").and_then(Value::as_u64).unwrap_or(0);
            if Some(epoch_after) != epoch_before.checked_add(1) {
                return Err(Failure::Unknown(format!(
                    "commit answered epoch {epoch_after}, expected {}; inspect the record",
                    epoch_before
                        .checked_add(1)
                        .map_or_else(|| "an overflow".to_string(), |e| e.to_string())
                )));
            }
            Ok(MoveReport {
                op_id: plan.op_id.clone(),
                source: plan.source.name.clone(),
                target: plan.target.name.clone(),
                epoch_before,
                epoch_after,
                served_by: served,
                fenced_source: !plan.source_up,
                evidence,
                advice: MOVE_ADVICE.to_string(),
            })
        }
        // The resources are in the target state; whether the record agrees is
        // unknown. Rolling back could split the truth, so nothing is undone.
        Err(e) => Err(Failure::Unknown(format!(
            "the VIP is on {} and serving, but the commit at the Witness did not complete ({e}); \
             operation {} stays recorded — run `resource reconcile vip`",
            plan.target.name, plan.op_id
        ))),
    }
}

/// Nothing may answer on the service port of the stopped source. A probe that
/// cannot even be performed is retried and, failing that, is a failure of the
/// step — never a silent pass (audit C-08).
fn confirm_nothing_answers(ctx: &Ctx<'_>, plan: &Plan) -> Res<()> {
    let mut last = String::new();
    for attempt in 0..PROBE_TRIES {
        match probe_refused_or_answer(ctx, &plan.source_target, "127.0.0.1", ctx.cfg.vip_port) {
            Ok(None) => return Ok(()),
            Ok(Some(body)) => {
                return Err(Failure::Failed(format!(
                    "something still answers on {} port {} ({body:?})",
                    plan.source.name, ctx.cfg.vip_port
                )));
            }
            Err(e) => last = e.to_string(),
        }
        if attempt + 1 < PROBE_TRIES {
            ctx.sleep(ALIAS_POLL);
        }
    }
    Err(Failure::Failed(format!(
        "cannot confirm that nothing answers on {} port {} ({last})",
        plan.source.name, ctx.cfg.vip_port
    )))
}

/// The last look before the commit (audit C-07, C-02): the target still runs
/// and answers on the VIP, and a fenced source is still provably fenced. A
/// failure after this point cannot be seen by this command; the report says
/// so.
fn precommit_checks(ctx: &Ctx<'_>, plan: &Plan, state: &mut MoveState) -> Res<()> {
    let service = ctx.cfg.service.as_str();
    recheck_fence(ctx, plan, state, "before_commit")?;
    ha_recheck(ctx, plan, state, "before_commit")?;
    match svc_status(ctx, &plan.target_target, service) {
        Ok(s) if s.active => {}
        Ok(s) => {
            return Err(Failure::Failed(format!(
                "{service} on {} is {} just before the commit",
                plan.target.name, s.active_state
            )));
        }
        Err(e) => {
            return Err(Failure::Failed(format!(
                "cannot re-read {service} on {} before the commit: {e}",
                plan.target.name
            )));
        }
    }
    match probe(ctx, &plan.witness, &ctx.cfg.vip, ctx.cfg.vip_port) {
        Ok(Some(body)) if body == plan.target.name => {}
        other => {
            return Err(Failure::Failed(format!(
                "the VIP does not answer as {} just before the commit ({other:?})",
                plan.target.name
            )));
        }
    }
    Ok(())
}

fn wait_served(ctx: &Ctx<'_>, plan: &Plan) -> Res<String> {
    let started = ctx.clock.now_ms();
    #[allow(unused_assignments)]
    let mut last = String::from("no answer");
    loop {
        match probe(ctx, &plan.witness, &ctx.cfg.vip, ctx.cfg.vip_port) {
            Ok(Some(body)) if body == plan.target.name => return Ok(body),
            Ok(Some(body)) => last = format!("answered {body:?}"),
            Ok(None) => last = "connection failed".to_string(),
            Err(e) => last = format!("probe unavailable: {e}"),
        }
        if ctx.clock.now_ms().saturating_sub(started) >= SERVE_TIMEOUT_MS {
            return Err(Failure::Failed(format!(
                "the VIP did not serve {} within {} s ({last})",
                plan.target.name,
                SERVE_TIMEOUT_MS / 1000
            )));
        }
        ctx.sleep(SERVE_POLL);
    }
}

// ---------------------------------------------------------------------------
// failure handling and rollback
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum RollbackOutcome {
    /// Nothing was mutated; the lock was released.
    NothingToUndo,
    /// Everything is verified back at the source; the lock was released.
    Restored,
    /// This command no longer holds the lease; it touched nothing.
    LeaseLost(String),
    /// The state is not fully restored or not provable.
    Incomplete(String),
}

/// The result when the rollback restored and verified everything. A cause
/// that was itself UNKNOWN stays UNKNOWN: a verified rollback does not turn
/// an unestablished state into a definite failure (audit C-04).
pub(crate) fn restored_failure(cause: Failure, source: &str) -> Failure {
    let text = format!(
        "{}; rolled back and verified: {source} owns the VIP again",
        cause.message()
    );
    match cause {
        Failure::Unknown(_) => Failure::Unknown(format!(
            "{text}; the cause could not be established, so the result stays UNKNOWN"
        )),
        _ => Failure::Failed(text),
    }
}

fn finish_failed(ctx: &Ctx<'_>, plan: &Plan, state: &mut MoveState, failure: Failure) -> Failure {
    // Without the lease nothing is touched, not even to undo.
    if state.lost_lease.is_some() {
        return failure;
    }
    // Evidence that a rollback would rest on has just been lost.
    if state.halt.is_some() {
        return Failure::Unknown(format!(
            "{}; operation {} remains recorded: inspect with `resource status vip`, repair, then \
             `resource reconcile vip`",
            failure.message(),
            plan.op_id
        ));
    }
    // A cloud request that may still land makes every rollback decision
    // unsafe: re-adding the alias could double it, removing it could lose it.
    if !state.pending.is_empty() {
        persist_pending(ctx, plan, state);
        return pending_failure(plan, state, &failure);
    }
    // A commit that did not complete is never rolled back (see `execute`).
    if matches!(failure, Failure::Unknown(_)) && state.target_start_attempted {
        return failure;
    }
    let outcome = rollback(ctx, plan, state, &failure);
    match outcome {
        RollbackOutcome::NothingToUndo => failure,
        RollbackOutcome::Restored => restored_failure(failure, &plan.source.name),
        RollbackOutcome::LeaseLost(why) => Failure::Unknown(format!(
            "{}; the rollback did not run because this command no longer holds the lease \
             ({why}); nothing further was touched",
            failure.message()
        )),
        RollbackOutcome::Incomplete(why) => {
            if !state.pending.is_empty() {
                persist_pending(ctx, plan, state);
                return pending_failure(plan, state, &failure);
            }
            Failure::Unknown(format!(
                "{}; rollback incomplete ({why}). Operation {} remains recorded: inspect with \
                 `resource status vip`, repair, then `resource reconcile vip`",
                failure.message(),
                plan.op_id
            ))
        }
    }
}

fn pending_failure(plan: &Plan, state: &MoveState, cause: &Failure) -> Failure {
    let list = state
        .pending
        .iter()
        .map(|p| format!("{} on {} ({})", p.action, p.node, p.why))
        .collect::<Vec<_>>()
        .join("; ");
    Failure::Unknown(format!(
        "{}; unresolved cloud change(s): {list}. They may still land, so no rollback and no \
         further change is made. Operation {} remains recorded: wait until `resource status vip` \
         shows no open cloud operation, repair what it shows, then `resource reconcile vip \
         --abandon-op {}`",
        cause.message(),
        plan.op_id,
        plan.op_id
    ))
}

/// Write the unresolved cloud changes into the lease record so that `status`
/// and `reconcile` can follow them after this command has exited.
fn persist_pending(ctx: &Ctx<'_>, plan: &Plan, state: &MoveState) {
    let Some(phase) = state.phase else {
        return;
    };
    let changes: Vec<&PendingChange> = state.pending.iter().take(EVIDENCE_CHANGES_MAX).collect();
    let evidence = json!({"cloud_changes": changes});
    match record_phase(ctx, &plan.op_id, phase, Some(evidence)) {
        PhaseRecord::Recorded => {}
        PhaseRecord::NotHolder(m) | PhaseRecord::Unclear(m) => ctx.log.info(&format!(
            "could not store the unresolved cloud changes in the lease record ({m}); they are \
             listed in this message"
        )),
    }
}

fn abort_lease(ctx: &Ctx<'_>, plan: &Plan, reason: &str) -> Result<(), String> {
    lease_call(
        ctx,
        op::LEASE_ABORT,
        json!({
            "op_id": plan.op_id,
            "restored_owner": plan.source.name,
            "reason": reason,
        }),
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// This command's operation is still the one recorded at the Witness.
/// Checked before every destructive rollback step: a controller that lost the
/// lease must not act on the resources (audit B-02).
fn still_holder(ctx: &Ctx<'_>, plan: &Plan) -> Result<(), String> {
    let view = lease_status(ctx).map_err(|e| e.message().to_string())?;
    match &view.state.op {
        Some(op) if op.op_id == plan.op_id && op.seq == plan.token.seq => Ok(()),
        Some(op) => Err(format!("operation {} holds the lease now", op.op_id)),
        None => Err("no operation is recorded any more".to_string()),
    }
}

macro_rules! hold {
    ($ctx:expr, $plan:expr) => {
        if let Err(why) = still_holder($ctx, $plan) {
            return RollbackOutcome::LeaseLost(why);
        }
    };
}

/// The last guard of a request the cloud explicitly refused (R4): nothing may
/// have appeared for it since. Called right before the rollback gives the
/// alias back to the source (the step that cannot be taken back) and right
/// before the lock is released. If an operation did appear (or the list
/// cannot be read) the request may still change the world: it is recorded as
/// an unresolved cloud change and the rollback stops.
fn recheck_refused(ctx: &Ctx<'_>, state: &mut MoveState) -> Result<(), String> {
    for refused in state.refused.clone() {
        let verdict = match ctx.gce.list_operations(&refused.instance) {
            Ok(list) => match ops_after(&list, &refused.anchor) {
                Some(new) if new.is_empty() => continue,
                Some(_) => "an operation of the instance appeared after the refusal".to_string(),
                None => "the operation list no longer shows where the request began".to_string(),
            },
            Err(e) => format!("cannot list operations: {e}"),
        };
        let why = format!(
            "the cloud had refused the {} on {} ({}), but {verdict}",
            refused.action, refused.node, refused.why
        );
        state.pending.push(PendingChange { why, ..refused });
        return Err("a refused cloud request cannot be shown to be without effect".to_string());
    }
    Ok(())
}

fn rollback(ctx: &Ctx<'_>, plan: &Plan, state: &mut MoveState, cause: &Failure) -> RollbackOutcome {
    let reason: String = cause.message().chars().take(160).collect();
    if !state.mutated() {
        return match abort_lease(ctx, plan, &reason) {
            Ok(()) => RollbackOutcome::NothingToUndo,
            // Never mutated: the lock expires on its own; nothing is unsafe.
            Err(e) => {
                ctx.log
                    .info(&format!("lock release failed ({e}); it expires by itself"));
                RollbackOutcome::NothingToUndo
            }
        };
    }
    ctx.log
        .info("rolling back (every step verified before the next)");
    let service = ctx.cfg.service.as_str();

    // The holders are established by two consecutive identical reads; a
    // single read that says "nobody" proves nothing.
    let holders = match stable_holders(ctx) {
        Ok(h) => h,
        Err(e) => return RollbackOutcome::Incomplete(format!("cannot observe the cloud: {e}")),
    };

    // Undo what this invocation did on the target — and only that.
    if holders.contains(&plan.target.name) {
        if !state.target_alias_add_attempted {
            return RollbackOutcome::Incomplete(format!(
                "{} holds the VIP but this command never assigned it (external change); \
                 left untouched",
                plan.target.name
            ));
        }
        hold!(ctx, plan);
        if let Err(e) = ha_recheck(ctx, plan, state, "rollback_remove_target") {
            return RollbackOutcome::Incomplete(e.message().to_string());
        }
        if let Err(e) = change_aliases(
            ctx,
            &plan.target,
            false,
            "rollback",
            &plan.op_id,
            &mut state.pending,
            &mut Sent::default(),
        ) {
            return RollbackOutcome::Incomplete(format!("cannot remove the target alias: {e}"));
        }
        state.target_vip_absent_proven = true;
    }
    if state.target_start_attempted || state.target_alias_add_attempted {
        hold!(ctx, plan);
        match svc_control_fenced(ctx, &plan.target_target, service, "stop", plan) {
            Ok(s) if s.is_stopped() => {}
            Ok(s) => {
                return RollbackOutcome::Incomplete(format!(
                    "{service} is {} on {} after the rollback stop",
                    s.active_state, plan.target.name
                ));
            }
            Err(e) => {
                return RollbackOutcome::Incomplete(format!(
                    "cannot stop {service} on {}: {e}",
                    plan.target.name
                ));
            }
        }
    }

    // Re-read: the VIP may be on the source, nowhere, but not elsewhere.
    let holders = match stable_holders(ctx) {
        Ok(h) => h,
        Err(e) => return RollbackOutcome::Incomplete(format!("cannot observe the cloud: {e}")),
    };
    if holders.iter().any(|h| h != &plan.source.name) {
        return RollbackOutcome::Incomplete(format!(
            "unexpected VIP holders [{}]",
            holders.join(", ")
        ));
    }
    if !plan.source_up {
        return RollbackOutcome::Incomplete(format!(
            "the source {} is fenced/unreachable and cannot be restored; the VIP is left \
             unassigned. Start the node and run `resource reconcile vip`, or move to {} again",
            plan.source.name, plan.target.name
        ));
    }
    // The source was reachable at the start; it must still be, and still be
    // a running instance, before it is given the VIP back.
    match ping(ctx, &plan.source.name, &plan.source_target) {
        Ok(Reach::Up(p)) if p.ha_safe() => {}
        Ok(_) => {
            return RollbackOutcome::Incomplete(format!(
                "{} is no longer reachable / in proven manual mode; cannot restore it",
                plan.source.name
            ));
        }
        Err(e) => return RollbackOutcome::Incomplete(format!("{e}")),
    }
    if holders.is_empty() {
        // Only give the VIP back if this command is the one that took it away;
        // an alias somebody else removed is not ours to re-create.
        if !state.source_alias_removal_attempted {
            return RollbackOutcome::Incomplete(format!(
                "the VIP is on no node although this command never removed it from {} \
                 (external change); left untouched",
                plan.source.name
            ));
        }
        // And only if the target is known not to hold it: "not visible" after
        // an add that was applied may just be a stale read (audit V3b).
        if state.target_alias_add_attempted && !state.target_vip_absent_proven {
            return RollbackOutcome::Incomplete(format!(
                "the VIP is not visible on any node, but the assignment to {} was not shown to \
                 have failed; not giving the VIP back to {} (it could end up on both)",
                plan.target.name, plan.source.name
            ));
        }
        hold!(ctx, plan);
        if let Err(why) = recheck_refused(ctx, state) {
            return RollbackOutcome::Incomplete(why);
        }
        if let Err(e) = ha_recheck(ctx, plan, state, "rollback_restore_source") {
            return RollbackOutcome::Incomplete(e.message().to_string());
        }
        if let Err(e) = change_aliases(
            ctx,
            &plan.source,
            true,
            "rollback",
            &plan.op_id,
            &mut state.pending,
            &mut Sent::default(),
        ) {
            return RollbackOutcome::Incomplete(format!("cannot restore the source alias: {e}"));
        }
    }
    // Restore exactly the service state the source had before the move.
    if plan.source_was_active == Some(true) {
        hold!(ctx, plan);
        match svc_control_fenced(ctx, &plan.source_target, service, "start", plan) {
            Ok(s) if s.active => {}
            Ok(s) => {
                return RollbackOutcome::Incomplete(format!(
                    "{service} is {} on {} after restart",
                    s.active_state, plan.source.name
                ));
            }
            Err(e) => {
                return RollbackOutcome::Incomplete(format!(
                    "cannot restart {service} on {}: {e}",
                    plan.source.name
                ));
            }
        }
    } else {
        ctx.log.info(&format!(
            "{service} on {} was not running before the move; it is left stopped",
            plan.source.name
        ));
    }
    // Final proof: only the source holds the VIP — on consecutive reads, the
    // same rule as in the forward direction — and it serves.
    match stable_holders(ctx) {
        Ok(h) if h == [plan.source.name.clone()] => {}
        Ok(_) => {
            return RollbackOutcome::Incomplete("the VIP is not held exactly by the source".into());
        }
        Err(e) => return RollbackOutcome::Incomplete(format!("cannot observe the cloud: {e}")),
    }
    if plan.source_was_active == Some(true)
        && let Err(e) = wait_served_by(ctx, plan, &plan.source.name)
    {
        return RollbackOutcome::Incomplete(format!("{e}"));
    }
    if let Err(why) = recheck_refused(ctx, state) {
        return RollbackOutcome::Incomplete(why);
    }
    match abort_lease(ctx, plan, &reason) {
        Ok(()) => RollbackOutcome::Restored,
        Err(e) => RollbackOutcome::Incomplete(format!(
            "resources are restored but the lock record could not be cleared ({e})"
        )),
    }
}

fn wait_served_by(ctx: &Ctx<'_>, plan: &Plan, expected: &str) -> Res<()> {
    let started = ctx.clock.now_ms();
    loop {
        if let Ok(Some(body)) = probe(ctx, &plan.witness, &ctx.cfg.vip, ctx.cfg.vip_port)
            && body == expected
        {
            return Ok(());
        }
        if ctx.clock.now_ms().saturating_sub(started) >= SERVE_TIMEOUT_MS {
            return Err(Failure::Failed(format!(
                "the restored VIP does not serve {expected}"
            )));
        }
        ctx.sleep(SERVE_POLL);
    }
}

// ---------------------------------------------------------------------------
// init / reconcile / status
// ---------------------------------------------------------------------------

/// The highest `(epoch, seq)` any reachable node has accepted (`(0, 0)` if
/// none). A record created or repaired now must be above it, or it would look
/// older than what a node has seen (audit B-04, B-05).
fn fence_marks(ctx: &Ctx<'_>) -> Res<(u64, u64)> {
    let (mut epoch, mut seq) = (0u64, 0u64);
    for node in &ctx.cfg.nodes {
        if let (_, Reach::Up(p)) = reach_node(ctx, &node.name)? {
            if let Some(error) = &p.fence_error {
                return Err(Failure::Refused(format!(
                    "{}: its fencing record is unusable ({error}); refusing",
                    node.name
                )));
            }
            if let Some((e, s)) = p.fence {
                epoch = epoch.max(e);
                seq = seq.max(s);
            }
        }
    }
    Ok((epoch, seq))
}

/// `(seq_floor, epoch_floor)` for the lease operations: one above the marks,
/// or zero (no constraint) if no node has a mark.
fn floors_above(marks: (u64, u64)) -> (u64, u64) {
    let (epoch, seq) = marks;
    (
        if seq > 0 { seq.saturating_add(1) } else { 0 },
        if epoch > 0 {
            epoch.saturating_add(1)
        } else {
            0
        },
    )
}

/// Evidence that `owner` is really the live owner: it holds the alias (the
/// caller checked), runs the service, answers on the VIP, and the other node
/// is provably quiet (service stopped, or terminated in the cloud).
fn verify_owner(ctx: &Ctx<'_>, views: &[NodeView], owner_name: &str) -> Res<Value> {
    let cidr = ctx.cfg.vip_cidr();
    let service = ctx.cfg.service.as_str();
    let owner = ctx.node(owner_name)?.clone();
    let other = ctx
        .cfg
        .peer_of(&owner.name)
        .ok_or_else(|| Failure::Failed("internal: peer missing".into()))?
        .clone();
    let (owner_target, owner_reach) = reach_node(ctx, &owner.name)?;
    let mut ha = serde_json::Map::new();
    match owner_reach {
        Reach::Up(p) if p.ha_safe() => {
            ha.insert(owner.name.clone(), json!(p.ha_daemon));
        }
        Reach::Up(p) => {
            return Err(Failure::Refused(format!(
                "{}: HA daemon state is {}",
                owner.name,
                p.ha_text()
            )));
        }
        Reach::Down(m) => {
            return Err(Failure::Unknown(format!(
                "the VIP holder {} is unreachable ({m}); cannot verify it",
                owner.name
            )));
        }
    }
    match svc_status(ctx, &owner_target, service) {
        Ok(s) if s.active => {}
        Ok(s) => {
            return Err(Failure::Unknown(format!(
                "{} holds the VIP but {service} is {}; repair or move, not reconcile",
                owner.name, s.active_state
            )));
        }
        Err(e) => return Err(Failure::Unknown(format!("cannot read {service}: {e}"))),
    }
    // The other node must be provably quiet: reachable with the service
    // stopped, or terminated in the cloud.
    let other_view = views
        .iter()
        .find(|v| v.node.name == other.name)
        .ok_or_else(|| Failure::Failed("internal: peer view missing".into()))?;
    let other_evidence = if other_view.info.status == FENCE_STATUS {
        json!({"node": other.name, "cloud_status": other_view.info.status})
    } else {
        let (other_target, other_reach) = reach_node(ctx, &other.name)?;
        match other_reach {
            Reach::Up(p) if !p.ha_safe() => {
                return Err(Failure::Refused(format!(
                    "{}: HA daemon state is {}",
                    other.name,
                    p.ha_text()
                )));
            }
            Reach::Up(p) => {
                ha.insert(other.name.clone(), json!(p.ha_daemon));
                match svc_status(ctx, &other_target, service) {
                    Ok(s) if s.is_stopped() => {
                        json!({"node": other.name, "service": s.active_state})
                    }
                    Ok(s) => {
                        return Err(Failure::Unknown(format!(
                            "{} runs {service} ({}) without holding the VIP",
                            other.name, s.active_state
                        )));
                    }
                    Err(e) => {
                        return Err(Failure::Unknown(format!("cannot read {service}: {e}")));
                    }
                }
            }
            Reach::Down(m) => {
                return Err(Failure::Unknown(format!(
                    "{} is unreachable ({m}) but not TERMINATED: it may still serve",
                    other.name
                )));
            }
        }
    };
    let witness = ctx.witness_target()?;
    match ping(ctx, &ctx.cfg.witness.name, &witness)? {
        Reach::Up(p) if p.ha_safe() => {
            ha.insert(ctx.cfg.witness.name.clone(), json!(p.ha_daemon));
        }
        Reach::Up(p) => {
            return Err(Failure::Refused(format!(
                "the Witness {}: HA daemon state is {}",
                ctx.cfg.witness.name,
                p.ha_text()
            )));
        }
        Reach::Down(m) => {
            return Err(Failure::Unknown(format!(
                "the Witness {} does not answer ({m})",
                ctx.cfg.witness.name
            )));
        }
    }
    match probe(ctx, &witness, &ctx.cfg.vip, ctx.cfg.vip_port) {
        Ok(Some(body)) if body == owner.name => {}
        Ok(other_body) => {
            return Err(Failure::Unknown(format!(
                "the VIP answers {other_body:?}, expected {}",
                owner.name
            )));
        }
        Err(e) => return Err(Failure::Unknown(format!("cannot probe the VIP: {e}"))),
    }
    Ok(json!({"holder": owner.name, "other": other_evidence, "vip": cidr, "ha": ha}))
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InitReport {
    pub(crate) owner: String,
    pub(crate) epoch: u64,
    pub(crate) seq: u64,
    /// What the record rests on, including the HA state of every host.
    pub(crate) evidence: Value,
}

/// Create the ownership record. It needs the same evidence as a reconcile —
/// the observed owner runs the service and answers on the VIP, the other
/// node is quiet — because a wrong first record would be trusted for ever.
/// `reinit` re-creates a record whose file is gone (audit B-05).
pub(crate) fn init_vip(ctx: &Ctx<'_>, owner: &str, reinit: bool) -> Res<InitReport> {
    let node = ctx.node(owner)?.clone();
    let views = observe_all(ctx).map_err(Failure::before_any_change)?;
    let holders = owners(ctx, &views);
    if holders.as_slice() != [node.name.clone()] {
        return Err(Failure::Refused(format!(
            "the cloud shows the VIP on [{}], not exactly on {}; refusing to record it",
            holders.join(", "),
            node.name
        )));
    }
    let evidence = verify_owner(ctx, &views, &node.name).map_err(|f| {
        Failure::Refused(format!(
            "not recording {} as the owner: {}",
            node.name,
            f.message()
        ))
    })?;
    // A cloud change that may still land makes the observed owner
    // untrustworthy (R4: this was checked by `reconcile` only). Nothing is
    // written yet, so the answer is a refusal.
    for n in &ctx.cfg.nodes {
        let list = ctx.gce.list_operations(&n.instance).map_err(|e| {
            Failure::Refused(format!(
                "not recording {} as the owner: cannot list the cloud operations of {} ({e})",
                node.name, n.name
            ))
        })?;
        if let Some(open) = list.ops.iter().find(|o| !o.is_done()) {
            return Err(Failure::Refused(format!(
                "not recording {} as the owner: cloud operation {} ({}) on {} is still {}; a \
                 change may still land",
                node.name, open.name, open.op_type, n.name, open.status
            )));
        }
    }
    let (seq_floor, epoch_floor) = floors_above(fence_marks(ctx)?);
    let data = lease_call(
        ctx,
        op::LEASE_INIT,
        json!({
            "owner": node.name,
            "reinit": reinit,
            "seq_floor": seq_floor,
            "epoch_floor": epoch_floor,
        }),
    )
    .map_err(|e| match e {
        CallError::Refused(m) => Failure::Refused(m),
        // The record may have been written although no clear answer came
        // back: only `status` can tell (R4; it used to be FAILED).
        other => Failure::Unknown(format!(
            "init: the ownership record may or may not have been written ({other}); run \
             `resource status vip` before anything else"
        )),
    })?;
    Ok(InitReport {
        owner: node.name,
        epoch: data.get("epoch").and_then(Value::as_u64).unwrap_or(0),
        seq: data.get("seq").and_then(Value::as_u64).unwrap_or(0),
        evidence,
    })
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReconcileReport {
    pub(crate) owner: String,
    pub(crate) changed: bool,
    pub(crate) epoch: u64,
    pub(crate) evidence: Value,
}

/// Cloud operations that are still open, and the changes an earlier command
/// recorded as unresolved: both must be understood before the record is
/// rewritten. Returns the evidence to store.
fn check_cloud_operations(ctx: &Ctx<'_>, lease: &LeaseState) -> Res<Value> {
    for node in &ctx.cfg.nodes {
        let list = ctx.gce.list_operations(&node.instance).map_err(|e| {
            Failure::Unknown(format!(
                "cannot list the cloud operations of {}: {e}",
                node.name
            ))
        })?;
        if let Some(open) = list.ops.iter().find(|o| !o.is_done()) {
            return Err(Failure::Unknown(format!(
                "cloud operation {} ({}) on {} is still {}; a change may still land — wait for \
                 it to finish",
                open.name, open.op_type, node.name, open.status
            )));
        }
    }
    let recorded: Vec<PendingChange> = lease
        .op
        .as_ref()
        .and_then(|op| op.evidence.get("cloud_changes"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let mut confirmed = Vec::new();
    let mut unconfirmed = Vec::new();
    for change in &recorded {
        let list = ctx.gce.list_operations(&change.instance).map_err(|e| {
            Failure::Unknown(format!(
                "cannot list the cloud operations of {}: {e}",
                change.node
            ))
        })?;
        // Confirmed only by a *successful* finished operation: a failed one
        // cannot be attributed to the recorded request (audit RA-C-01), so it
        // leaves the change unconfirmed.
        let finished = ops_after(&list, &change.anchor).is_some_and(|new| {
            new.iter()
                .any(|o| o.is_nic_update() && o.is_done() && !o.failed)
        });
        let entry = json!({"node": change.node, "action": change.action});
        if finished {
            confirmed.push(entry);
        } else {
            unconfirmed.push(entry);
        }
    }
    Ok(json!({"confirmed_cloud_changes": confirmed, "unconfirmed_cloud_changes": unconfirmed}))
}

/// Adopt the observed state as the durable truth — only when it is provable.
/// A mutating operation is cut only when the operator names it
/// (`abandon_op`) after its controller has been silent (audit B-01).
///
/// A cloud change that the interrupted operation recorded and that no finished
/// operation confirms (`unconfirmed_cloud_changes`) may still land (audit
/// RA-B-01): the reconcile then stops UNKNOWN, before it writes anything,
/// unless the operator has looked at the cloud and says so with
/// `accept_unconfirmed` (`--accept-unconfirmed-cloud-change`). The statement
/// is stored in the evidence of the record it writes.
/// After a verified reconcile, remove any durable manual-operation barrier on
/// the nodes that are running. The operator's reconcile evidence is the proof
/// that no operation is still in flight. A node that is not running cannot be
/// asked and is recorded as a warning; its barrier, if any, will block HA when
/// it comes back and can then be cleared by another reconcile. A reachable
/// node that refuses the clear is a warning too, never a reason to delete the
/// record locally.
fn clear_barriers_after_reconcile(
    ctx: &Ctx<'_>,
    views: &[NodeView],
    evidence: &mut Value,
    abandon_op: Option<&str>,
) {
    let mut cleared = Vec::new();
    let mut warnings = Vec::new();
    for node in &ctx.cfg.nodes {
        let Some(view) = views.iter().find(|view| view.node.name == node.name) else {
            warnings.push(format!("{}: no cloud observation", node.name));
            continue;
        };
        if view.info.status != "RUNNING" {
            warnings.push(format!(
                "{}: not RUNNING ({}), barrier not observable",
                node.name, view.info.status
            ));
            continue;
        }
        let target = match ctx.node_target(&node.name) {
            Ok(target) => target,
            Err(failure) => {
                warnings.push(format!("{}: {}", node.name, failure.message()));
                continue;
            }
        };
        match resolve_any_barrier(ctx, &node.name, &target, abandon_op) {
            Ok(Some(op_id)) => cleared.push(json!({"node": node.name, "op_id": op_id})),
            Ok(None) => {}
            Err(error) => warnings.push(error),
        }
    }
    if !cleared.is_empty() {
        evidence["manual_barriers_cleared"] = json!(cleared);
    }
    if !warnings.is_empty() {
        evidence["manual_barrier_warnings"] = json!(warnings);
    }
}

pub(crate) fn reconcile_vip(
    ctx: &Ctx<'_>,
    abandon_op: Option<&str>,
    accept_unconfirmed: bool,
) -> Res<ReconcileReport> {
    let lease = lease_status(ctx).map_err(|f| Failure::Unknown(f.message().to_string()))?;
    if lease.state.owner.is_none() {
        return Err(Failure::Refused(
            "ownership is not initialised; use `resource init vip`".into(),
        ));
    }
    if let Some(open) = &lease.state.op {
        if !open.phase.mutating() {
            if open.expires_at > lease.now {
                return Err(Failure::Refused(format!(
                    "operation {} is still in progress (not yet mutating); wait or let it expire",
                    open.op_id
                )));
            }
        } else {
            if abandon_op != Some(open.op_id.as_str()) {
                return Err(Failure::Refused(format!(
                    "operation {} is in phase {}: its controller may still be running. Only the \
                     operator can declare it dead: `resource reconcile vip --abandon-op {}`",
                    open.op_id,
                    open.phase.name(),
                    open.op_id
                )));
            }
            let quiet = lease.now.saturating_sub(open.last_seen);
            if quiet < ABANDON_QUIET_SECS {
                return Err(Failure::Refused(format!(
                    "operation {} was active {quiet} s ago; its controller may still be running \
                     (wait for at least {ABANDON_QUIET_SECS} s of silence)",
                    open.op_id
                )));
            }
        }
    }
    let views = observe_all(ctx).map_err(|f| Failure::Unknown(f.message().to_string()))?;
    let holders = owners(ctx, &views);
    let [owner_name] = holders.as_slice() else {
        return Err(Failure::Unknown(format!(
            "the cloud shows the VIP on [{}]; exactly one holder is required to reconcile",
            holders.join(", ")
        )));
    };
    let mut cloud = check_cloud_operations(ctx, &lease.state)?;
    let unconfirmed: Vec<String> = cloud["unconfirmed_cloud_changes"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|c| {
                    format!(
                        "{} ({})",
                        c["action"].as_str().unwrap_or("?"),
                        c["node"].as_str().unwrap_or("?")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if !unconfirmed.is_empty() {
        if !accept_unconfirmed {
            return Err(Failure::Unknown(format!(
                "the interrupted operation recorded cloud change(s) that no finished cloud \
                 operation confirms: {}. A request that was reported as lost may still land and \
                 would undo what a reconcile adopts. Nothing was written. Check both instances \
                 yourself (`gcloud compute instances describe`, `gcloud compute operations \
                 list`) and, if you accept the risk, repeat the command with \
                 --accept-unconfirmed-cloud-change",
                unconfirmed.join(", ")
            )));
        }
        cloud["unconfirmed_cloud_changes_accepted_by_operator"] = json!(true);
    }
    let mut evidence = verify_owner(ctx, &views, owner_name)?;
    evidence["cloud_operations"] = cloud;
    let marks = fence_marks(ctx)?;
    // A record that is older than what a node has served (a restored copy)
    // is repaired by the reconcile even though owner and cloud agree.
    let record_is_older = marks.1 > lease.state.seq || marks.0 > lease.state.epoch;
    if lease.state.owner.as_deref() == Some(owner_name.as_str())
        && lease.state.op.is_none()
        && !record_is_older
    {
        clear_barriers_after_reconcile(ctx, &views, &mut evidence, abandon_op);
        return Ok(ReconcileReport {
            owner: owner_name.clone(),
            changed: false,
            epoch: lease.state.epoch,
            evidence,
        });
    }
    let (seq_floor, epoch_floor) = floors_above(marks);
    let data = lease_call(
        ctx,
        op::LEASE_RECONCILE,
        json!({
            "owner": owner_name,
            "expect_epoch": lease.state.epoch,
            "expect_op_id": lease.state.op.as_ref().map(|op| op.op_id.clone()),
            "abandon_op_id": abandon_op,
            "seq_floor": seq_floor,
            "epoch_floor": epoch_floor,
            "reason": "observed state verified by reconcile",
            "evidence": evidence,
        }),
    )
    .map_err(|e| match e {
        CallError::Refused(m) => Failure::Refused(m),
        other => Failure::Unknown(format!("reconcile record not written: {other}")),
    })?;
    clear_barriers_after_reconcile(ctx, &views, &mut evidence, abandon_op);
    Ok(ReconcileReport {
        owner: owner_name.clone(),
        changed: true,
        epoch: data.get("epoch").and_then(Value::as_u64).unwrap_or(0),
        evidence,
    })
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NodeStatus {
    pub(crate) cloud_status: Option<String>,
    pub(crate) holds_vip: Option<bool>,
    pub(crate) reachable: Option<bool>,
    /// The agent's verdict over the HA daemon on this host (`masked` and
    /// `absent` are the only proofs of exclusion).
    pub(crate) ha_daemon: Option<String>,
    pub(crate) ha_detail: Vec<String>,
    /// Per HA unit: `masked`, `absent`, `loaded`, `not-found`, `active`, ...
    pub(crate) ha_units: std::collections::BTreeMap<String, String>,
    pub(crate) service_active: Option<bool>,
    pub(crate) local_id: Option<String>,
    /// Highest fencing sequence the node has accepted.
    pub(crate) fence_seq: Option<u64>,
    /// Cloud operations of the instance that are not finished.
    pub(crate) open_operations: Option<Vec<String>>,
    /// Present when the agent reports an open durable manual operation.
    pub(crate) manual_barrier: Option<Value>,
    pub(crate) errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VipStatus {
    pub(crate) resource: &'static str,
    pub(crate) vip: String,
    pub(crate) recorded_owner: Option<String>,
    pub(crate) epoch: Option<u64>,
    pub(crate) seq: Option<u64>,
    pub(crate) operation: Option<Value>,
    pub(crate) cloud_holders: Option<Vec<String>>,
    pub(crate) served_by: Option<String>,
    pub(crate) nodes: std::collections::BTreeMap<String, NodeStatus>,
    pub(crate) witness_error: Option<String>,
    /// The agent's HA verdict on the Witness host.
    pub(crate) witness_ha: Option<String>,
    /// `consistent`, `unresolved_operation`, `mismatch`, `ha_conflict` or
    /// `unknown`. `ha_conflict`: an HA daemon runs (or is queued) on a host.
    /// Nothing is `consistent` unless the exclusion is proven on every host.
    pub(crate) verdict: String,
    pub(crate) problems: Vec<String>,
    /// What may be done next and what must not be (v0.3): a function of the
    /// verdict, never of a guess.
    pub(crate) guidance: super::guidance::Guidance,
}

pub(crate) fn vip_status(ctx: &Ctx<'_>) -> VipStatus {
    let cidr = ctx.cfg.vip_cidr();
    let service = ctx.cfg.service.as_str();
    let mut problems = Vec::new();
    let mut status = VipStatus {
        resource: "vip",
        vip: ctx.cfg.vip.clone(),
        recorded_owner: None,
        epoch: None,
        seq: None,
        operation: None,
        cloud_holders: None,
        served_by: None,
        nodes: Default::default(),
        witness_error: None,
        witness_ha: None,
        verdict: "unknown".to_string(),
        problems: Vec::new(),
        guidance: Default::default(),
    };
    let mut lease_state: Option<LeaseState> = None;
    match lease_status(ctx) {
        Ok(view) => {
            status.recorded_owner = view.state.owner.clone();
            status.epoch = Some(view.state.epoch);
            status.seq = Some(view.state.seq);
            status.operation = view
                .state
                .op
                .as_ref()
                .and_then(|o| serde_json::to_value(o).ok());
            lease_state = Some(view.state);
        }
        Err(e) => {
            status.witness_error = Some(e.message().to_string());
            problems.push(format!("witness: {}", e.message()));
        }
    }
    let mut holders = Vec::new();
    let mut cloud_known = true;
    for node in &ctx.cfg.nodes {
        let mut ns = NodeStatus {
            cloud_status: None,
            holds_vip: None,
            reachable: None,
            ha_daemon: None,
            ha_detail: Vec::new(),
            ha_units: Default::default(),
            service_active: None,
            local_id: None,
            fence_seq: None,
            open_operations: None,
            manual_barrier: None,
            errors: Vec::new(),
        };
        match describe_node(ctx, node) {
            Ok(view) => {
                ns.cloud_status = Some(view.info.status.clone());
                let holds = view.info.has_alias(&cidr);
                ns.holds_vip = Some(holds);
                if holds {
                    holders.push(node.name.clone());
                }
            }
            Err(e) => {
                cloud_known = false;
                ns.errors.push(e.message().to_string());
            }
        }
        match ctx.gce.list_operations(&node.instance) {
            Ok(list) => {
                let open: Vec<String> = list
                    .ops
                    .iter()
                    .filter(|o| !o.is_done())
                    .map(|o| format!("{} ({}, {})", o.name, o.op_type, o.status))
                    .collect();
                if !open.is_empty() {
                    ns.errors.push(format!(
                        "cloud operation(s) still open: {}; a change may still land",
                        open.join(", ")
                    ));
                }
                ns.open_operations = Some(open);
            }
            Err(e) => ns.errors.push(format!("cannot list cloud operations: {e}")),
        }
        match ctx.node_target(&node.name) {
            Ok(target) => match ping(ctx, &node.name, &target) {
                Ok(Reach::Up(p)) => {
                    ns.reachable = Some(true);
                    ns.ha_daemon = Some(p.ha_daemon.clone());
                    ns.ha_detail = p.ha_detail.clone();
                    ns.ha_units = p.ha_units.clone();
                    ns.manual_barrier = p.manual_barrier.clone();
                    if p.manual_barrier
                        .as_ref()
                        .and_then(|barrier| barrier.get("present"))
                        .and_then(Value::as_bool)
                        == Some(true)
                    {
                        ns.errors.push(
                            "a durable manual-operation barrier is open; HA must not start on                              this host until it is resolved"
                                .to_string(),
                        );
                    }
                    if !p.ha_safe() {
                        ns.errors.push(format!(
                            "HA daemon exclusion is not proven: {}",
                            p.ha_text()
                        ));
                    }
                    ns.fence_seq = p.fence.map(|(_, s)| s);
                    if let Some(lease) = &lease_state
                        && let Err(f) = check_fence_floor(&node.name, &p, lease)
                    {
                        ns.errors.push(f.message().to_string());
                    }
                    match svc_status(ctx, &target, service) {
                        Ok(s) => ns.service_active = Some(s.active),
                        Err(e) => ns.errors.push(format!("service: {e}")),
                    }
                    match probe(ctx, &target, "127.0.0.1", ctx.cfg.vip_port) {
                        Ok(body) => ns.local_id = body,
                        Err(e) => ns.errors.push(format!("local probe: {e}")),
                    }
                }
                Ok(Reach::Down(m)) => {
                    ns.reachable = Some(false);
                    // A terminated instance is quiet by definition.
                    if ns.cloud_status.as_deref() != Some(FENCE_STATUS) {
                        ns.errors.push(format!("unreachable: {m}"));
                    }
                }
                Err(e) => ns.errors.push(e.message().to_string()),
            },
            Err(e) => {
                // A terminated instance has no address: that is its state,
                // not a fault of the observation.
                if ns.cloud_status.as_deref() == Some(FENCE_STATUS) {
                    ns.reachable = Some(false);
                } else {
                    ns.errors.push(e.message().to_string());
                }
            }
        }
        status.nodes.insert(node.name.clone(), ns);
    }
    if cloud_known {
        status.cloud_holders = Some(holders.clone());
    }
    if let Ok(witness) = ctx.witness_target() {
        match probe(ctx, &witness, &ctx.cfg.vip, ctx.cfg.vip_port) {
            Ok(body) => status.served_by = body,
            Err(e) => problems.push(format!("vip probe: {e}")),
        }
        match ping(ctx, &ctx.cfg.witness.name, &witness) {
            Ok(Reach::Up(p)) => {
                status.witness_ha = Some(p.ha_daemon.clone());
                if !p.ha_safe() {
                    problems.push(format!(
                        "witness: HA daemon exclusion is not proven: {}",
                        p.ha_text()
                    ));
                }
            }
            Ok(Reach::Down(m)) => problems.push(format!("witness unreachable: {m}")),
            Err(e) => problems.push(format!("witness: {}", e.message())),
        }
    }
    for (name, ns) in &status.nodes {
        for e in &ns.errors {
            problems.push(format!("{name}: {e}"));
        }
    }

    // An HA daemon that runs (or is queued) anywhere beats every other word.
    let ha_active = status
        .nodes
        .values()
        .filter_map(|n| n.ha_daemon.as_deref())
        .chain(status.witness_ha.as_deref())
        .any(|h| h == "active");
    let verdict = if ha_active {
        problems.push("an HA daemon is running on a host".to_string());
        "ha_conflict"
    } else if status.witness_error.is_some() || !cloud_known {
        "unknown"
    } else if status.operation.is_some()
        || status.nodes.values().any(|n| {
            n.manual_barrier
                .as_ref()
                .and_then(|barrier| barrier.get("present"))
                .and_then(Value::as_bool)
                == Some(true)
        })
    {
        problems.push("an operation is recorded or a manual-operation barrier is open".to_string());
        "unresolved_operation"
    } else if holders.len() != 1
        || status.recorded_owner.as_deref() != holders.first().map(String::as_str)
    {
        problems.push(format!(
            "record says {:?}, cloud shows {holders:?}",
            status.recorded_owner
        ));
        "mismatch"
    } else {
        let owner = &holders[0];
        let owner_ok = status.nodes.get(owner).is_some_and(|n| {
            n.service_active == Some(true) && n.local_id.as_deref() == Some(owner)
        });
        let others_quiet = status
            .nodes
            .iter()
            .filter(|(name, _)| *name != owner)
            .all(|(_, n)| {
                n.service_active == Some(false) || n.cloud_status.as_deref() == Some(FENCE_STATUS)
            });
        let served = status.served_by.as_deref() == Some(owner.as_str());
        if owner_ok && others_quiet && served && problems.is_empty() {
            "consistent"
        } else {
            if !served {
                problems.push(format!(
                    "the VIP answers {:?}, expected {owner}",
                    status.served_by
                ));
            }
            "unknown"
        }
    };
    status.verdict = verdict.to_string();
    status.problems = problems;
    let op_id = status
        .operation
        .as_ref()
        .and_then(|o| o["op_id"].as_str())
        .map(str::to_string);
    let op_mutating = status
        .operation
        .as_ref()
        .and_then(|o| o["phase"].as_str())
        .and_then(Phase::parse)
        .map(Phase::mutating);
    let facts = super::guidance::VipFacts {
        verdict,
        recorded_owner: status.recorded_owner.as_deref(),
        holders: &holders,
        nodes: status
            .nodes
            .iter()
            .map(|(name, n)| super::guidance::NodeFact {
                name,
                cloud_status: n.cloud_status.as_deref(),
            })
            .collect(),
        op_id: op_id.as_deref(),
        op_mutating,
    };
    status.guidance = super::guidance::for_vip(&facts);
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual::fakes::{VIP_CIDR, World};
    use crate::manual::gce::Gce;

    #[test]
    fn holders_are_only_believed_after_two_consecutive_equal_reads() {
        // The first read right after a change may still be stale.
        let w = World::new("vip-stable-holders");
        w.gce.set_lag(1);
        w.gce.set_aliases("inst-a", &[], "");
        w.gce.set_aliases("inst-b", &[Alias::plain(VIP_CIDR)], "");
        // inst-a now reads stale once (it still shows the VIP), inst-b new.
        let holders = stable_holders(&w.ctx()).unwrap();
        assert_eq!(holders, ["node-b"]);
    }

    #[test]
    fn holders_that_never_settle_are_an_error_not_a_guess() {
        let w = World::new("vip-unsettled-holders");
        w.gce.fail_describe("inst-b", true);
        assert!(stable_holders(&w.ctx()).is_err());
    }

    #[test]
    fn ra_c_a_rejected_request_needs_a_quiet_window_and_enough_readings() {
        // Mutant M07 of the second audit (REFUSAL_QUIET_READS 4 -> 1) survived:
        // under the present constants and a fast listing the time condition
        // binds first (a reading every ALIAS_POLL gives more than four
        // readings in REFUSAL_QUIET_MS); with a slow listing the count binds
        // (see the slow-readings test below). This pins
        // what a refusal costs, and that the count can never be the weaker of
        // the two conditions by accident.
        let w = World::new("ra-c-quiet-window");
        let ctx = w.ctx();
        w.gce
            .seed_op("inst-a", "updateNetworkInterface", "DONE", false);
        // The seeded operation is the anchor: nothing newer exists.
        let anchor_name = ctx.gce.list_operations("inst-a").unwrap().ops[0]
            .name
            .clone();
        let before = w.gce.inner.borrow().list_calls;
        let started = ctx.clock.now_ms();
        let settled = settle(
            &ctx,
            "inst-a",
            &Some(anchor_name),
            &ChangeReport::Rejected {
                status: 403,
                detail: "HTTPError 403".into(),
            },
        );
        let reads = w.gce.inner.borrow().list_calls - before;
        let span = ctx.clock.now_ms() - started;
        assert!(matches!(settled, Settled::Refused(_)), "{settled:?}");
        assert!(
            reads >= REFUSAL_QUIET_READS as usize,
            "only {reads} readings"
        );
        assert!(span >= REFUSAL_QUIET_MS, "only {span} ms");
        // The count is a floor that the time window reaches on its own.
        assert!(
            u64::from(REFUSAL_QUIET_READS) <= REFUSAL_QUIET_MS / ALIAS_POLL.as_millis() as u64 + 1
        );
        // One new operation at any time restarts the confirmation: a refusal
        // is never concluded while operations keep appearing.
        let w = World::new("ra-c-quiet-restart");
        let ctx = w.ctx();
        w.gce
            .seed_op("inst-a", "updateNetworkInterface", "DONE", false);
        let anchor_name = ctx.gce.list_operations("inst-a").unwrap().ops[0]
            .name
            .clone();
        w.gce.schedule_at_list(3, |inner| {
            inner.new_op("inst-a", "DONE", false);
        });
        let settled = settle(
            &ctx,
            "inst-a",
            &Some(anchor_name),
            &ChangeReport::Rejected {
                status: 403,
                detail: "HTTPError 403".into(),
            },
        );
        assert_eq!(
            settled,
            Settled::Applied,
            "a new operation is judged like any other"
        );
    }

    #[test]
    fn ra_c_slow_readings_do_not_let_the_time_alone_conclude_a_refusal() {
        // With a listing that takes 4 s (a `gcloud` call does), 10 s pass after
        // only three readings. The time window is then met, the count is not:
        // the refusal waits for the fourth reading (M07: REFUSAL_QUIET_READS
        // 4 -> 1 concludes at the third).
        let w = World::new("ra-c-slow-readings");
        let ctx = w.ctx();
        w.gce
            .seed_op("inst-a", "updateNetworkInterface", "DONE", false);
        let anchor_name = ctx.gce.list_operations("inst-a").unwrap().ops[0]
            .name
            .clone();
        let clock = w.clock.handle();
        for n in 1..=12 {
            let clock = clock.clone();
            w.gce
                .schedule_at_list(n, move |_| clock.set(clock.get() + 4_000));
        }
        let before = w.gce.inner.borrow().list_calls;
        let started = ctx.clock.now_ms();
        let settled = settle(
            &ctx,
            "inst-a",
            &Some(anchor_name),
            &ChangeReport::Rejected {
                status: 403,
                detail: "HTTPError 403".into(),
            },
        );
        let reads = w.gce.inner.borrow().list_calls - before;
        assert!(matches!(settled, Settled::Refused(_)), "{settled:?}");
        assert_eq!(reads, 4, "the count, not the time, decided");
        assert!(ctx.clock.now_ms() - started >= REFUSAL_QUIET_MS);
    }

    #[test]
    fn r8_a_failed_listing_restarts_the_count_as_well_as_the_time() {
        // Slow readings (4 s each), so that the count, not the time, is the
        // condition that binds. Two quiet readings, a FAILED one, then the
        // confirmation starts again: it needs four more quiet readings. If the
        // failed reading kept the count, the decision would come one reading
        // earlier (final R7, R-8; the reset of the time alone is pinned by the
        // refusal tests).
        let w = World::new("r8-count-reset");
        let ctx = w.ctx();
        w.gce
            .seed_op("inst-a", "updateNetworkInterface", "DONE", false);
        let anchor_name = ctx.gce.list_operations("inst-a").unwrap().ops[0]
            .name
            .clone();
        let clock = w.clock.handle();
        for n in 1..=12 {
            let clock = clock.clone();
            w.gce
                .schedule_at_list(n, move |_| clock.set(clock.get() + 4_000));
        }
        w.gce
            .schedule_at_list(3, |inner| inner.fail_list_once = true);
        let before = w.gce.inner.borrow().list_calls;
        let settled = settle(
            &ctx,
            "inst-a",
            &Some(anchor_name),
            &ChangeReport::Rejected {
                status: 403,
                detail: "HTTPError 403".into(),
            },
        );
        let reads = w.gce.inner.borrow().list_calls - before;
        assert!(matches!(settled, Settled::Refused(_)), "{settled:?}");
        assert_eq!(reads, 7, "2 quiet + 1 failed + 4 quiet readings");
    }

    #[test]
    fn ops_after_the_anchor_are_the_only_new_ones() {
        let ops = |names: &[&str]| OpList {
            ops: names
                .iter()
                .map(|n| CloudOp {
                    name: (*n).to_string(),
                    op_type: "compute.instances.updateNetworkInterface".into(),
                    status: "DONE".into(),
                    failed: false,
                })
                .collect(),
            complete: true,
        };
        let list = ops(&["op-3", "op-2", "op-1"]);
        let new = ops_after(&list, &Some("op-2".into())).unwrap();
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].name, "op-3");
        assert_eq!(ops_after(&list, &Some("op-3".into())).unwrap().len(), 0);
        assert_eq!(ops_after(&list, &None).unwrap().len(), 3);
        // An anchor that fell out of the listing: "newer" is unknowable.
        assert!(ops_after(&list, &Some("op-0".into())).is_none());
        let mut full = ops(&["op-1"]);
        full.complete = false;
        assert!(ops_after(&full, &None).is_none());
    }

    #[test]
    fn a_request_is_judged_only_by_operations_newer_than_its_anchor() {
        let op = |name: &str, status: &str, failed: bool| CloudOp {
            name: name.into(),
            op_type: "compute.instances.updateNetworkInterface".into(),
            status: status.into(),
            failed,
        };
        let list = |ops: Vec<CloudOp>| OpList {
            ops,
            complete: true,
        };
        let anchor = Some("old".to_string());
        let timed_out = ChangeReport::TimedOut;
        let waits = |j: Judged| matches!(j, Judged::Wait(_));
        let fin = Judged::Final;
        // Nothing new: unresolved (the caller keeps waiting, then stops).
        assert!(waits(judge(
            &list(vec![op("old", "DONE", false)]),
            &anchor,
            &timed_out
        )));
        // A new finished operation decides when it succeeded. A failed one is
        // NOT a proof of "not applied" (audit RA-C-01): it cannot be attributed
        // to this request, which may still land.
        let ok = list(vec![op("new", "DONE", false), op("old", "DONE", false)]);
        assert_eq!(judge(&ok, &anchor, &timed_out), fin(Settled::Applied));
        let bad = list(vec![op("new", "DONE", true), op("old", "DONE", false)]);
        assert!(matches!(
            judge(&bad, &anchor, &timed_out),
            Judged::Final(Settled::Unresolved(_))
        ));
        assert!(matches!(
            judge(&bad, &anchor, &ChangeReport::Error("x".into())),
            Judged::Final(Settled::Unresolved(_))
        ));
        // A new operation that is not finished: still waiting.
        let open = list(vec![op("new", "RUNNING", false), op("old", "DONE", false)]);
        assert!(waits(judge(&open, &anchor, &timed_out)));
        // The tool's own success needs no operation to be visible.
        let none = list(vec![op("old", "DONE", false)]);
        assert_eq!(
            judge(&none, &anchor, &ChangeReport::Done),
            fin(Settled::Reported)
        );
        // ... but it does not hide an operation that is still open.
        assert!(waits(judge(&open, &anchor, &ChangeReport::Done)));
        // Two alias operations for one request are not understood.
        let two = list(vec![
            op("n2", "DONE", false),
            op("n1", "DONE", false),
            op("old", "DONE", false),
        ]);
        assert!(matches!(
            judge(&two, &anchor, &timed_out),
            Judged::Final(Settled::Unresolved(_))
        ));
        // A lost anchor cannot be judged.
        assert!(matches!(
            judge(&ok, &Some("gone".into()), &timed_out),
            Judged::Final(Settled::Unresolved(_))
        ));
        // R4: an explicit client error. No new operation at all is only
        // "nothing yet" (the caller must see it repeatedly); any new
        // operation is judged like for every other report, so a 4xx-looking
        // report with a visible operation can never be "refused".
        let rejected = ChangeReport::Rejected {
            status: 403,
            detail: "HTTPError 403".into(),
        };
        assert_eq!(judge(&none, &anchor, &rejected), Judged::NoNewOperation);
        assert_eq!(judge(&ok, &anchor, &rejected), fin(Settled::Applied));
        assert!(matches!(
            judge(&bad, &anchor, &rejected),
            Judged::Final(Settled::Unresolved(_))
        ));
        assert!(waits(judge(&open, &anchor, &rejected)));
        assert!(matches!(
            judge(&two, &anchor, &rejected),
            Judged::Final(Settled::Unresolved(_))
        ));
        // A foreign (non alias) operation is not "no new operation" either.
        let foreign = list(vec![
            CloudOp {
                name: "other".into(),
                op_type: "compute.instances.stop".into(),
                status: "DONE".into(),
                failed: false,
            },
            op("old", "DONE", false),
        ]);
        assert!(waits(judge(&foreign, &anchor, &rejected)));
        // The other reports never become NoNewOperation.
        for report in [
            ChangeReport::Error("x".into()),
            ChangeReport::TimedOut,
            ChangeReport::Done,
        ] {
            assert_ne!(judge(&none, &anchor, &report), Judged::NoNewOperation);
        }
    }
}
