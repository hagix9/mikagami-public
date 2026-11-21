//! Node-local agent of the manual control plane (`mikagami agent`).
//!
//! The agent runs as root on each prototype host, started over SSH with a
//! fixed command line. It reads exactly one JSON request from standard input,
//! performs one bounded operation through the [`SystemOps`] boundary and
//! writes exactly one JSON response to standard output.
//!
//! Exclusive control: the manual control plane and the production HA daemon
//! must not manage the same host at the same time. What is *enforced* is
//! narrower than that sentence and is described in `exclusion.rs`: a mutating
//! operation proceeds only if the agent can positively show, at that moment,
//! that the HA units are masked (or acknowledged absent), that no job or
//! hand-started HA process exists and that no HA configuration on the host
//! names the same service or VIP. The mask itself is applied by an operator
//! (`install.sh --manual-mode`), never by the agent. Between two agent calls
//! nothing is enforced by the agent; the mask is what stops a start.
//!
//! The agent only acts on resources named in its root-owned configuration
//! file (`/etc/mikagami/agent.toml`): a unit allowlist, the chrony paths and,
//! on the Witness host only, the lease file.

use super::chrony_agent;
use super::exclusion::{self, ExclusiveProof, HaReport};
use super::fence::{FenceStore, Token};
use super::fsutil;
use super::lease::{LeaseError, LeaseStore, Phase};
use super::proto::{self, Request, Response, code, op};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const DEFAULT_AGENT_CONFIG: &str = "/etc/mikagami/agent.toml";
pub(crate) const DEFAULT_HA_UNITS: &[&str] = &["mikagami.service", "mikagami-witness.service"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentConfig {
    agent: RawAgentSection,
    #[serde(default)]
    tools: RawAgentTools,
    units: RawUnits,
    #[serde(default)]
    chrony: RawChrony,
    lease: Option<RawLease>,
    #[serde(default)]
    fence: RawFence,
    #[serde(default)]
    exclusion: RawExclusion,
    #[serde(default)]
    control: RawControl,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentSection {
    cluster: String,
    node: String,
    #[serde(default)]
    nodes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentTools {
    #[serde(default = "tool_systemctl")]
    systemctl: String,
    #[serde(default = "tool_chronyd")]
    chronyd: String,
    #[serde(default = "tool_chronyc")]
    chronyc: String,
}

impl Default for RawAgentTools {
    fn default() -> Self {
        Self {
            systemctl: tool_systemctl(),
            chronyd: tool_chronyd(),
            chronyc: tool_chronyc(),
        }
    }
}

fn tool_systemctl() -> String {
    "/usr/bin/systemctl".to_string()
}
fn tool_chronyd() -> String {
    "/usr/sbin/chronyd".to_string()
}
fn tool_chronyc() -> String {
    "/usr/bin/chronyc".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnits {
    allowed: Vec<String>,
    /// Additional HA units. They are added to the built-in ones; the
    /// built-in ones cannot be removed or replaced.
    #[serde(default)]
    ha_units: Vec<String>,
    /// The operator states that an HA unit that does not exist on this host
    /// is intended (the HA daemon is not installed here).
    #[serde(default)]
    ha_absent_ack: bool,
}

/// Detection of an HA configuration on the same host.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExclusion {
    #[serde(default = "ha_config_path")]
    ha_config: String,
    /// VIPs the manual plane moves (compared with the HA `[vip].address`).
    #[serde(default)]
    vip: Vec<String>,
    /// Acknowledge a shared service/VIP, or an unreadable HA configuration.
    #[serde(default)]
    ha_config_ack: bool,
}

impl Default for RawExclusion {
    fn default() -> Self {
        Self {
            ha_config: ha_config_path(),
            vip: Vec::new(),
            ha_config_ack: false,
        }
    }
}

fn ha_config_path() -> String {
    "/etc/mikagami/mikagami.toml".to_string()
}

/// The shared control-plane lock and durable operation barrier (v0.5).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawControl {
    lock_path: Option<String>,
    manual_barrier_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChrony {
    #[serde(default = "chrony_conf")]
    conf: String,
    #[serde(default = "chrony_unit")]
    unit: String,
    #[serde(default = "chrony_backup_dir")]
    backup_dir: String,
}

impl Default for RawChrony {
    fn default() -> Self {
        Self {
            conf: chrony_conf(),
            unit: chrony_unit(),
            backup_dir: chrony_backup_dir(),
        }
    }
}

fn chrony_conf() -> String {
    "/etc/chrony/chrony.conf".to_string()
}
fn chrony_unit() -> String {
    "chrony.service".to_string()
}
fn chrony_backup_dir() -> String {
    "/var/lib/mkg/backups".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLease {
    state: String,
}

/// Where this node keeps the highest fencing token it accepted.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFence {
    #[serde(default = "fence_state")]
    state: String,
}

impl Default for RawFence {
    fn default() -> Self {
        Self {
            state: fence_state(),
        }
    }
}

fn fence_state() -> String {
    "/var/lib/mkg/fence/fence.json".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentConfig {
    pub(crate) cluster: String,
    pub(crate) node: String,
    pub(crate) nodes: Vec<String>,
    pub(crate) systemctl: String,
    pub(crate) chronyd: String,
    pub(crate) chronyc: String,
    pub(crate) allowed_units: Vec<String>,
    pub(crate) ha_units: Vec<String>,
    pub(crate) chrony_conf: PathBuf,
    pub(crate) chrony_unit: String,
    pub(crate) backup_dir: PathBuf,
    pub(crate) lease_state: Option<PathBuf>,
    pub(crate) fence_state: PathBuf,
    pub(crate) ha_absent_ack: bool,
    pub(crate) ha_config: PathBuf,
    pub(crate) ha_config_ack: bool,
    pub(crate) manual_vips: Vec<String>,
    pub(crate) control_lock_path: PathBuf,
    pub(crate) manual_barrier_path: PathBuf,
}

fn clean_abs(path: &str) -> bool {
    let p = Path::new(path);
    p.is_absolute()
        && !path.contains("//")
        && !path.chars().any(char::is_control)
        && p.components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

impl AgentConfig {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let raw: RawAgentConfig = toml::from_str(text).map_err(|e| e.message().to_string())?;
        let mut errors = Vec::new();
        if raw.agent.cluster.is_empty() || raw.agent.cluster.len() > 64 {
            errors.push("agent.cluster is invalid".to_string());
        }
        if !super::config::is_node_name(&raw.agent.node) {
            errors.push("agent.node is invalid".to_string());
        }
        for node in &raw.agent.nodes {
            if !super::config::is_node_name(node) {
                errors.push(format!("agent.nodes entry {node:?} is invalid"));
            }
        }
        for (label, path) in [
            ("tools.systemctl", &raw.tools.systemctl),
            ("tools.chronyd", &raw.tools.chronyd),
            ("tools.chronyc", &raw.tools.chronyc),
            ("chrony.conf", &raw.chrony.conf),
            ("chrony.backup_dir", &raw.chrony.backup_dir),
            ("fence.state", &raw.fence.state),
            ("exclusion.ha_config", &raw.exclusion.ha_config),
        ] {
            if !clean_abs(path) {
                errors.push(format!("{label} must be a clean absolute path"));
            }
        }
        let control_lock_path = raw
            .control
            .lock_path
            .unwrap_or_else(|| crate::control_lock::DEFAULT_LOCK_PATH.to_string());
        let manual_barrier_path = raw
            .control
            .manual_barrier_path
            .unwrap_or_else(|| crate::manual_barrier::DEFAULT_BARRIER_PATH.to_string());
        for (label, path) in [
            ("control.lock_path", &control_lock_path),
            ("control.manual_barrier_path", &manual_barrier_path),
        ] {
            if !clean_abs(path) {
                errors.push(format!("{label} must be a clean absolute path"));
            }
        }
        if Path::new(&raw.chrony.conf).parent().is_none() {
            errors.push("chrony.conf has no directory".to_string());
        }
        for unit in raw.units.allowed.iter().chain(&raw.units.ha_units) {
            if !super::config::is_unit_name(unit) {
                errors.push(format!("unit {unit:?} is invalid"));
            }
        }
        if !super::config::is_unit_name(&raw.chrony.unit) {
            errors.push("chrony.unit is invalid".to_string());
        } else if !raw.units.allowed.contains(&raw.chrony.unit) {
            // The controller restarts the unit it is configured with through
            // the allowlist; a chrony.unit outside it would be observed but
            // never restartable (audit D-04).
            errors.push(format!(
                "chrony.unit {:?} must also be listed in units.allowed",
                raw.chrony.unit
            ));
        }
        if let Some(lease) = &raw.lease {
            if !clean_abs(&lease.state) {
                errors.push("lease.state must be a clean absolute path".to_string());
            }
            if raw.agent.nodes.len() != 2 {
                errors.push("agent.nodes must list the two nodes when [lease] is set".to_string());
            }
        }
        for vip in &raw.exclusion.vip {
            if vip.parse::<Ipv4Addr>().is_err() {
                errors.push(format!(
                    "exclusion.vip entry {vip:?} is not an IPv4 address"
                ));
            }
        }
        // The HA units are the built-in ones plus the configured ones.
        let mut ha_units: Vec<String> = DEFAULT_HA_UNITS.iter().map(|s| (*s).to_string()).collect();
        for unit in &raw.units.ha_units {
            if !ha_units.contains(unit) {
                ha_units.push(unit.clone());
            }
        }
        // A unit the agent may control must never also be an HA unit: the
        // agent would be stopping the daemon it must stay out of the way of.
        for unit in &ha_units {
            if raw.units.allowed.contains(unit) || *unit == raw.chrony.unit {
                errors.push(format!(
                    "unit {unit:?} is both an HA unit and a unit the agent may control"
                ));
            }
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok(Self {
            cluster: raw.agent.cluster,
            node: raw.agent.node,
            nodes: raw.agent.nodes,
            systemctl: raw.tools.systemctl,
            chronyd: raw.tools.chronyd,
            chronyc: raw.tools.chronyc,
            allowed_units: raw.units.allowed,
            ha_units,
            chrony_conf: PathBuf::from(raw.chrony.conf),
            chrony_unit: raw.chrony.unit,
            backup_dir: PathBuf::from(raw.chrony.backup_dir),
            lease_state: raw.lease.map(|l| PathBuf::from(l.state)),
            fence_state: PathBuf::from(raw.fence.state),
            ha_absent_ack: raw.units.ha_absent_ack,
            ha_config: PathBuf::from(raw.exclusion.ha_config),
            ha_config_ack: raw.exclusion.ha_config_ack,
            manual_vips: raw.exclusion.vip,
            control_lock_path: PathBuf::from(control_lock_path),
            manual_barrier_path: PathBuf::from(manual_barrier_path),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ServiceState {
    pub(crate) load_state: String,
    pub(crate) active_state: String,
    pub(crate) sub_state: String,
    /// `masked`, `masked-runtime`, `enabled`, ...; empty when not reported.
    pub(crate) unit_file_state: String,
    /// `MainPID`; empty when not reported. Together with `active_enter` it
    /// is the evidence that a restart really happened (audit D-04).
    pub(crate) main_pid: String,
    /// `ActiveEnterTimestampMonotonic`; empty when not reported.
    pub(crate) active_enter: String,
}

impl ServiceState {
    pub(crate) fn is_active(&self) -> bool {
        self.active_state == "active"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CheckResult {
    Valid,
    /// chronyd looked at the file and refused it.
    Rejected(String),
    /// The check itself could not run (no verdict either way).
    ToolFailure(String),
}

/// Everything the agent needs from the operating system.
pub(crate) trait SystemOps {
    fn service_state(&self, unit: &str) -> Result<ServiceState, String>;
    /// Changes a unit. The proof is the reason the argument list is longer
    /// than the call needs: there is no way to call this without the gate.
    fn service_action(
        &self,
        proof: &ExclusiveProof,
        unit: &str,
        action: &str,
    ) -> Result<(), String>;
    fn chronyd_check(&self, conf: &Path) -> CheckResult;
    fn chronyc_tracking(&self) -> Result<String, String>;
    fn probe(&self, addr: Ipv4Addr, port: u16, path: &str) -> Result<(u16, String), String>;
    fn boot_id(&self) -> String;
    /// Units with a queued systemd job. `Err` when the list cannot be read
    /// or understood (never an empty answer in that case).
    fn pending_jobs(&self) -> Result<Vec<String>, String>;
    /// Processes of this binary running `daemon run` / `witness run`.
    fn ha_processes(&self) -> Result<Vec<String>, String>;
}

pub(crate) struct AgentEnv {
    pub(crate) cfg: AgentConfig,
    pub(crate) sys: Box<dyn SystemOps>,
    /// uid that must own trusted files (0 in production).
    pub(crate) owner_uid: u32,
    pub(crate) now: Box<dyn Fn() -> u64>,
}

impl AgentEnv {
    /// Look at the HA daemon on this host now.
    pub(crate) fn ha_report(&self) -> HaReport {
        exclusion::inspect(&self.cfg, &*self.sys)
    }

    /// Take the shared control lock. This is the process-level exclusion from
    /// the HA daemon; it is not the exclusion *proof* (the proof also checks
    /// the unit state and the HA configuration).
    pub(crate) fn acquire_control_lock(&self) -> Result<crate::control_lock::ControlLock, String> {
        crate::control_lock::ControlLock::acquire(&self.cfg.control_lock_path, self.owner_uid)
            .map_err(|error| error.to_string())
    }

    /// `Err(response)` unless the exclusion from the HA daemon is proven and
    /// the shared control lock is held. The returned proof owns the lock, so
    /// a caller cannot forget to keep it for the mutation.
    #[allow(clippy::result_large_err)]
    pub(crate) fn require_exclusive(&self, id: &str) -> Result<ExclusiveProof, Response> {
        let lock = self
            .acquire_control_lock()
            .map_err(|message| Response::err(id, code::REFUSED, message))?;
        self.ha_report()
            .prove(lock)
            .map_err(|message| Response::err(id, code::REFUSED, message))
    }

    pub(crate) fn barrier_status(&self) -> serde_json::Value {
        match crate::manual_barrier::check(
            &self.cfg.manual_barrier_path,
            self.owner_uid,
            &self.cfg.cluster,
            &self.cfg.node,
        ) {
            Ok(crate::manual_barrier::BarrierState::Clear) => {
                json!({"present": false, "error": Value::Null})
            }
            Ok(crate::manual_barrier::BarrierState::Open(record)) => {
                json!({"present": true, "intent": record, "error": Value::Null})
            }
            Err(error) => json!({"present": true, "intent": Value::Null, "error": error}),
        }
    }

    pub(crate) fn lease_store(&self) -> Result<LeaseStore, String> {
        match &self.cfg.lease_state {
            Some(path) => Ok(LeaseStore::new(
                path.clone(),
                &self.cfg.cluster,
                self.cfg.nodes.clone(),
                self.owner_uid,
            )),
            None => Err("this host has no [lease] configuration".to_string()),
        }
    }

    pub(crate) fn fence_store(&self) -> FenceStore {
        FenceStore::new(
            self.cfg.fence_state.clone(),
            &self.cfg.cluster,
            &self.cfg.node,
            self.owner_uid,
        )
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string argument {key:?}"))
}

fn u64_arg(args: &Value, key: &str) -> Result<u64, String> {
    args.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing integer argument {key:?}"))
}

fn lease_response(
    id: &str,
    now: u64,
    result: Result<super::lease::LeaseState, LeaseError>,
) -> Response {
    match result {
        Ok(state) => match serde_json::to_value(&state) {
            Ok(mut value) => {
                // The Witness clock at the time of the answer.
                value["now"] = json!(now);
                Response::ok(id, value)
            }
            Err(e) => Response::err(id, code::FAILED, e.to_string()),
        },
        Err(LeaseError::Refused(message)) => Response::err(id, code::REFUSED, message),
        Err(LeaseError::Storage(message)) => {
            Response::err(id, code::FAILED, format!("lease storage: {message}"))
        }
    }
}

fn unit_checked(env: &AgentEnv, unit: &str) -> Result<(), String> {
    if env.cfg.allowed_units.iter().any(|u| u == unit) {
        Ok(())
    } else {
        Err(format!("unit {unit:?} is not in the agent allowlist"))
    }
}

fn state_json(state: &ServiceState) -> Value {
    json!({
        "active": state.is_active(),
        "active_state": state.active_state,
        "sub_state": state.sub_state,
        "load_state": state.load_state,
        "unit_file_state": state.unit_file_state,
        "main_pid": state.main_pid,
        "active_enter": state.active_enter,
    })
}

/// Dispatch one request and stamp the answer with this host's node name.
pub(crate) fn handle(env: &AgentEnv, request: &Request) -> Response {
    let mut response = dispatch(env, request);
    response.node = env.cfg.node.clone();
    response
}

/// Never panics on malformed input.
fn dispatch(env: &AgentEnv, request: &Request) -> Response {
    let id = request.id.as_str();
    if request.v != proto::PROTO_VERSION {
        return Response::err(id, code::BAD_REQUEST, "unsupported protocol version");
    }
    if !proto::valid_id(id) {
        return Response::err("invalid-id", code::BAD_REQUEST, "invalid request id");
    }
    let args = &request.args;
    let bad = |message: String| Response::err(id, code::BAD_REQUEST, message);
    match request.op.as_str() {
        op::PING => {
            // The fencing mark is read, never written, here.
            let (fence, fence_error) = match env.fence_store().current() {
                Ok(token) => (json!(token), Value::Null),
                Err(e) => (Value::Null, json!(e.to_string())),
            };
            let mut data = json!({
                "node": env.cfg.node,
                "version": env!("CARGO_PKG_VERSION"),
                "boot_id": env.sys.boot_id(),
                "fence": fence,
                "fence_error": fence_error,
                "manual_barrier": env.barrier_status(),
            });
            // `ha_daemon`, `ha_proven`, `ha_units`, `ha_detail`.
            if let (Some(map), Value::Object(ha)) =
                (data.as_object_mut(), env.ha_report().to_json())
            {
                map.extend(ha);
            }
            Response::ok(id, data)
        }
        op::SERVICE_STATUS => {
            let unit = match str_arg(args, "unit") {
                Ok(unit) => unit,
                Err(e) => return bad(e),
            };
            if let Err(e) = unit_checked(env, unit) {
                return Response::err(id, code::REFUSED, e);
            }
            match env.sys.service_state(unit) {
                Ok(state) => {
                    let mut value = state_json(&state);
                    value["unit"] = json!(unit);
                    Response::ok(id, value)
                }
                Err(e) => Response::err(id, code::FAILED, format!("cannot query unit: {e}")),
            }
        }
        op::SERVICE_CONTROL => {
            let (unit, action) = match (str_arg(args, "unit"), str_arg(args, "action")) {
                (Ok(unit), Ok(action)) => (unit, action),
                (Err(e), _) | (_, Err(e)) => return bad(e),
            };
            if !matches!(action, "start" | "stop" | "restart") {
                return bad(format!("unsupported action {action:?}"));
            }
            if let Err(e) = unit_checked(env, unit) {
                return Response::err(id, code::REFUSED, e);
            }
            let proof = match env.require_exclusive(id) {
                Ok(proof) => proof,
                Err(response) => return response,
            };
            // A controller that carries a fencing token must not be older
            // than the newest one this node has already served.
            if let Some(raw) = args.get("fence") {
                let token = match serde_json::from_value::<Token>(raw.clone()) {
                    Ok(token) => token,
                    Err(e) => return bad(format!("malformed fencing token: {e}")),
                };
                // Stale and unusable records alike: nothing is changed.
                if let Err(e) = env.fence_store().admit(&proof, &token) {
                    return Response::err(id, code::REFUSED, e.to_string());
                }
            }
            let result = env.sys.service_action(&proof, unit, action);
            let after = env.sys.service_state(unit);
            match (result, after) {
                (Ok(()), Ok(state)) => {
                    let mut value = state_json(&state);
                    value["unit"] = json!(unit);
                    value["action"] = json!(action);
                    Response::ok(id, value)
                }
                (Ok(()), Err(e)) => Response::err(
                    id,
                    code::FAILED,
                    format!("{action} ran but the unit state is unknown: {e}"),
                ),
                (Err(e), after) => Response::err(
                    id,
                    code::FAILED,
                    format!(
                        "{action} {unit} failed: {e}; state now: {}",
                        match after {
                            Ok(state) => state.active_state,
                            Err(_) => "unknown".to_string(),
                        }
                    ),
                ),
            }
        }
        op::PROBE => {
            let addr = match str_arg(args, "addr").map(str::parse::<Ipv4Addr>) {
                Ok(Ok(addr)) => addr,
                Ok(Err(_)) => return bad("addr must be an IPv4 address".to_string()),
                Err(e) => return bad(e),
            };
            let port = match u64_arg(args, "port").map(u16::try_from) {
                Ok(Ok(port)) if port != 0 => port,
                Ok(_) => return bad("port out of range".to_string()),
                Err(e) => return bad(e),
            };
            let path = match str_arg(args, "path") {
                Ok(path) => path,
                Err(e) => return bad(e),
            };
            if !(addr.is_loopback() || addr.is_private()) {
                return Response::err(
                    id,
                    code::REFUSED,
                    "probe target must be private or loopback",
                );
            }
            if !valid_probe_path(path) {
                return bad("invalid probe path".to_string());
            }
            match env.sys.probe(addr, port, path) {
                Ok((status, body)) => Response::ok(id, json!({"status": status, "body": body})),
                // The connection was refused: nothing listens. This is the one
                // failure that proves silence, and it is told apart from every
                // other one (a timeout, a half answer, a broken reply: each of
                // those means that something may have accepted the connection;
                // audit RA-C-05).
                Err(e) if e == PROBE_REFUSED => Response::ok(id, json!({"refused": true})),
                Err(e) => Response::err(id, code::FAILED, format!("probe failed: {e}")),
            }
        }
        name if name.starts_with("chrony.") => {
            // The chrony file operations are not gated on the HA unit state
            // (the HA daemon never touches chrony), but they must not race a
            // production HA process on the same host either. A read-only
            // query takes no lock; every file-changing step takes the shared
            // control lock for the duration of the agent run (OD-V04-3).
            if matches!(name, op::CHRONY_STATE | op::CHRONY_READ) {
                chrony_agent::handle(env, id, name, args)
            } else {
                match env.acquire_control_lock() {
                    Ok(lock) => {
                        let _lock = lock;
                        chrony_agent::handle(env, id, name, args)
                    }
                    Err(message) => Response::err(id, code::REFUSED, message),
                }
            }
        }
        op::CONTROL_INTENT_BEGIN | op::CONTROL_INTENT_RESOLVE | op::CONTROL_INTENT_STATUS => {
            handle_control_intent(env, id, request.op.as_str(), args)
        }
        op::LEASE_STATUS
        | op::LEASE_INIT
        | op::LEASE_ACQUIRE
        | op::LEASE_PHASE
        | op::LEASE_COMMIT
        | op::LEASE_ABORT
        | op::LEASE_RECONCILE => handle_lease(env, id, request.op.as_str(), args),
        other => bad(format!("unknown operation {other:?}")),
    }
}

fn valid_probe_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 64
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'.' | b'-'))
        && !path.contains("..")
}

/// Durable manual-operation barrier operations (v0.5).
///
/// `begin` and `resolve` take the normal exclusion proof, so the control lock
/// is held while the record is written or removed. `status` is a read-only
/// observation and is intentionally available while HA runs (the observer and
/// `resource status vip` use it).
fn handle_control_intent(env: &AgentEnv, id: &str, name: &str, args: &Value) -> Response {
    let path = &env.cfg.manual_barrier_path;
    if name == op::CONTROL_INTENT_STATUS {
        return match crate::manual_barrier::check(
            path,
            env.owner_uid,
            &env.cfg.cluster,
            &env.cfg.node,
        ) {
            Ok(crate::manual_barrier::BarrierState::Clear) => {
                Response::ok(id, json!({"present": false, "intent": Value::Null}))
            }
            Ok(crate::manual_barrier::BarrierState::Open(record)) => {
                Response::ok(id, json!({"present": true, "intent": record}))
            }
            Err(error) => Response::err(id, code::REFUSED, error),
        };
    }
    let bad = |message: String| Response::err(id, code::BAD_REQUEST, message);
    // `resolve` is cleanup of a record the controller has already verified;
    // it must not depend on the HA mask being currently applied (the HA
    // daemon may have been unmasked just as the command was refused). It
    // still takes the kernel lock, so no HA process can be running while the
    // record disappears.
    if name == op::CONTROL_INTENT_RESOLVE {
        let _lock = match env.acquire_control_lock() {
            Ok(lock) => lock,
            Err(error) => return Response::err(id, code::REFUSED, error),
        };
        return match str_arg(args, "op_id") {
            Ok(op_id) => match crate::manual_barrier::resolve(
                path,
                env.owner_uid,
                &env.cfg.cluster,
                &env.cfg.node,
                op_id,
            ) {
                Ok(()) => Response::ok(id, json!({"op_id": op_id, "present": false})),
                Err(error) => Response::err(id, code::REFUSED, error),
            },
            Err(e) => bad(e),
        };
    }
    let proof = match env.require_exclusive(id) {
        Ok(proof) => proof,
        Err(response) => return response,
    };
    // The proof owns the control lock for the rest of this call.
    let _proof = proof;
    match name {
        op::CONTROL_INTENT_BEGIN => {
            let (op_id, source, target, epoch) = match (
                str_arg(args, "op_id"),
                str_arg(args, "source"),
                str_arg(args, "target"),
                u64_arg(args, "epoch"),
            ) {
                (Ok(op_id), Ok(source), Ok(target), Ok(epoch)) => (op_id, source, target, epoch),
                (Err(e), _, _, _) | (_, Err(e), _, _) | (_, _, Err(e), _) | (_, _, _, Err(e)) => {
                    return bad(e);
                }
            };
            let controller = args
                .get("controller")
                .and_then(Value::as_str)
                .unwrap_or("mkg-controller");
            let record = crate::manual_barrier::ManualOperation {
                schema: crate::manual_barrier::SCHEMA.to_string(),
                cluster: env.cfg.cluster.clone(),
                node: env.cfg.node.clone(),
                op_id: op_id.to_string(),
                source: source.to_string(),
                target: target.to_string(),
                epoch,
                controller: controller.to_string(),
                created_at: (env.now)(),
            };
            match crate::manual_barrier::begin(path, env.owner_uid, &record) {
                Ok(()) => Response::ok(id, json!({"op_id": op_id, "present": true})),
                Err(error) => Response::err(id, code::REFUSED, error),
            }
        }
        _ => bad(format!("unsupported control intent operation {name:?}")),
    }
}

fn handle_lease(env: &AgentEnv, id: &str, name: &str, args: &Value) -> Response {
    let bad = |message: String| Response::err(id, code::BAD_REQUEST, message);
    let store = match env.lease_store() {
        Ok(store) => store,
        Err(e) => return Response::err(id, code::REFUSED, e),
    };
    let now = (env.now)();
    if name == op::LEASE_STATUS {
        return lease_response(id, now, store.status());
    }
    let proof = match env.require_exclusive(id) {
        Ok(proof) => proof,
        Err(response) => return response,
    };
    match name {
        op::LEASE_INIT => match str_arg(args, "owner") {
            Ok(owner) => lease_response(
                id,
                now,
                store.init(
                    &proof,
                    owner,
                    now,
                    args.get("reinit").and_then(Value::as_bool).unwrap_or(false),
                    args.get("seq_floor").and_then(Value::as_u64).unwrap_or(0),
                    args.get("epoch_floor").and_then(Value::as_u64).unwrap_or(0),
                ),
            ),
            Err(e) => bad(e),
        },
        op::LEASE_ACQUIRE => {
            let parsed = (|| -> Result<_, String> {
                Ok((
                    str_arg(args, "op_id")?.to_string(),
                    str_arg(args, "source")?.to_string(),
                    str_arg(args, "target")?.to_string(),
                    u64_arg(args, "ttl_s")?,
                    str_arg(args, "controller")?.to_string(),
                    u64_arg(args, "expect_epoch")?,
                ))
            })();
            match parsed {
                Ok((op_id, source, target, ttl, controller, epoch)) => {
                    if !proto::valid_id(&op_id) {
                        return bad("invalid op_id".to_string());
                    }
                    lease_response(
                        id,
                        now,
                        store.acquire(
                            &proof,
                            &op_id,
                            &source,
                            &target,
                            ttl,
                            &controller,
                            epoch,
                            now,
                        ),
                    )
                }
                Err(e) => bad(e),
            }
        }
        op::LEASE_PHASE => {
            let phase = str_arg(args, "phase").map(Phase::parse);
            match (str_arg(args, "op_id"), phase) {
                (Ok(op_id), Ok(Some(phase))) => lease_response(
                    id,
                    now,
                    store.phase(&proof, op_id, phase, args.get("evidence").cloned(), now),
                ),
                (Err(e), _) | (_, Err(e)) => bad(e),
                (_, Ok(None)) => bad("unknown phase".to_string()),
            }
        }
        op::LEASE_COMMIT => match (str_arg(args, "op_id"), str_arg(args, "owner")) {
            (Ok(op_id), Ok(owner)) => lease_response(
                id,
                now,
                store.commit(
                    &proof,
                    op_id,
                    owner,
                    args.get("evidence").cloned().unwrap_or(Value::Null),
                    now,
                ),
            ),
            (Err(e), _) | (_, Err(e)) => bad(e),
        },
        op::LEASE_ABORT => match (
            str_arg(args, "op_id"),
            str_arg(args, "restored_owner"),
            str_arg(args, "reason"),
        ) {
            (Ok(op_id), Ok(owner), Ok(reason)) => {
                lease_response(id, now, store.abort(&proof, op_id, owner, reason, now))
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => bad(e),
        },
        op::LEASE_RECONCILE => match (
            str_arg(args, "owner"),
            str_arg(args, "reason"),
            u64_arg(args, "expect_epoch"),
        ) {
            (Ok(owner), Ok(reason), Ok(epoch)) => lease_response(
                id,
                now,
                store.reconcile(
                    &proof,
                    owner,
                    epoch,
                    args.get("expect_op_id").and_then(Value::as_str),
                    args.get("abandon_op_id").and_then(Value::as_str),
                    (
                        args.get("seq_floor").and_then(Value::as_u64).unwrap_or(0),
                        args.get("epoch_floor").and_then(Value::as_u64).unwrap_or(0),
                    ),
                    reason,
                    args.get("evidence").cloned().unwrap_or(Value::Null),
                    now,
                ),
            ),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => bad(e),
        },
        other => bad(format!("unknown lease operation {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// production system boundary
// ---------------------------------------------------------------------------

const TOOL_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// The time this agent run may use in total (audit EX-07). Every external
/// tool call is clamped to what is left, so a hung `systemctl` cannot keep
/// the agent running after the controller has given up and started a
/// rollback.
#[derive(Clone, Copy)]
pub(crate) struct Budget {
    end: std::time::Instant,
}

impl Budget {
    pub(crate) fn starting_at(start: std::time::Instant, total: Duration) -> Self {
        Self { end: start + total }
    }

    pub(crate) fn remaining(&self) -> Duration {
        self.end
            .saturating_duration_since(std::time::Instant::now())
    }

    /// `timeout`, but never more than what is left; `None` when nothing is.
    pub(crate) fn clamp(&self, timeout: Duration) -> Option<Duration> {
        let left = self.remaining();
        (!left.is_zero()).then(|| timeout.min(left))
    }
}

pub(crate) struct RealSystem {
    cfg: AgentConfig,
    budget: Budget,
}

impl RealSystem {
    pub(crate) fn new(cfg: AgentConfig, budget: Budget) -> Self {
        Self { cfg, budget }
    }

    fn tool(&self, program: &str, args: &[&str], timeout: Duration) -> super::exec::ExecOutcome {
        let Some(timeout) = self.budget.clamp(timeout) else {
            return super::exec::ExecOutcome::SpawnFailed(
                "the agent's time budget is used up".to_string(),
            );
        };
        if let Err(refusal) = crate::fencing_backend::check_executable_trust(program) {
            return super::exec::ExecOutcome::SpawnFailed(format!(
                "tool {program} is not trusted: {refusal:?}"
            ));
        }
        super::exec::run(
            &super::exec::ExecCommand::new(
                program,
                args.iter().map(|a| (*a).to_string()).collect(),
                timeout,
            )
            .with_env("PATH", TOOL_PATH)
            .with_env("LANG", "C"),
        )
    }
}

/// The `systemctl show` argument vector. `--` ends the options, so a unit
/// name can never be read as one (audit D-09).
fn show_args(unit: &str) -> Vec<String> {
    vec![
        "show".to_string(),
        "--no-pager".to_string(),
        "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,ActiveEnterTimestampMonotonic"
            .to_string(),
        "--".to_string(),
        unit.to_string(),
    ]
}

/// `systemctl start|stop|restart -- <unit>`.
fn action_args(action: &str, unit: &str) -> Vec<String> {
    vec![action.to_string(), "--".to_string(), unit.to_string()]
}

/// `systemctl show --property=LoadState,ActiveState,SubState,UnitFileState`
/// output (`UnitFileState` may be empty, for example for a missing unit).
fn parse_show(text: &str) -> Result<ServiceState, String> {
    let mut state = ServiceState {
        load_state: String::new(),
        active_state: String::new(),
        sub_state: String::new(),
        unit_file_state: String::new(),
        main_pid: String::new(),
        active_enter: String::new(),
    };
    for line in text.lines() {
        match line.split_once('=') {
            Some(("LoadState", v)) => state.load_state = v.to_string(),
            Some(("ActiveState", v)) => state.active_state = v.to_string(),
            Some(("SubState", v)) => state.sub_state = v.to_string(),
            Some(("UnitFileState", v)) => state.unit_file_state = v.to_string(),
            Some(("MainPID", v)) => state.main_pid = v.to_string(),
            Some(("ActiveEnterTimestampMonotonic", v)) => state.active_enter = v.to_string(),
            _ => {}
        }
    }
    if state.load_state.is_empty() || state.active_state.is_empty() {
        Err("systemctl output not understood".to_string())
    } else {
        Ok(state)
    }
}

/// A complete `HTTP/1.x` response: status code and the start of the body.
fn parse_http(text: &str) -> Result<(u16, String), String> {
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response".to_string())?;
    let status = head
        .lines()
        .next()
        .filter(|line| line.starts_with("HTTP/1."))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "malformed HTTP status line".to_string())?;
    Ok((status, first_chars(body, 256)))
}

fn first_chars(text: &str, limit: usize) -> String {
    text.trim().chars().take(limit).collect()
}

impl SystemOps for RealSystem {
    fn service_state(&self, unit: &str) -> Result<ServiceState, String> {
        use super::exec::ExecOutcome;
        let args = show_args(unit);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        match self.tool(&self.cfg.systemctl, &args, Duration::from_secs(15)) {
            ExecOutcome::Exited {
                code: Some(0),
                stdout,
                ..
            } if !stdout.truncated => parse_show(&stdout.text()),
            ExecOutcome::Exited { code, stderr, .. } => Err(format!(
                "systemctl show exited {code:?}: {}",
                first_chars(&stderr.text(), 200)
            )),
            ExecOutcome::TimedOut { .. } => Err("systemctl show timed out".to_string()),
            ExecOutcome::SpawnFailed(e) => Err(e),
        }
    }

    fn service_action(
        &self,
        _proof: &ExclusiveProof,
        unit: &str,
        action: &str,
    ) -> Result<(), String> {
        use super::exec::ExecOutcome;
        let args = action_args(action, unit);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        match self.tool(&self.cfg.systemctl, &args, Duration::from_secs(90)) {
            ExecOutcome::Exited { code: Some(0), .. } => Ok(()),
            ExecOutcome::Exited { code, stderr, .. } => Err(format!(
                "systemctl {action} exited {code:?}: {}",
                first_chars(&stderr.text(), 200)
            )),
            ExecOutcome::TimedOut { .. } => Err(format!("systemctl {action} timed out")),
            ExecOutcome::SpawnFailed(e) => Err(e),
        }
    }

    fn chronyd_check(&self, conf: &Path) -> CheckResult {
        use super::exec::ExecOutcome;
        let Some(conf) = conf.to_str() else {
            return CheckResult::ToolFailure("non-UTF-8 path".to_string());
        };
        match self.tool(
            &self.cfg.chronyd,
            &["-p", "-f", conf],
            Duration::from_secs(20),
        ) {
            ExecOutcome::Exited { code: Some(0), .. } => CheckResult::Valid,
            ExecOutcome::Exited { stdout, stderr, .. } => {
                let mut message = stderr.text();
                if message.trim().is_empty() {
                    message = stdout.text();
                }
                CheckResult::Rejected(first_chars(&message, 400))
            }
            ExecOutcome::TimedOut { .. } => CheckResult::ToolFailure("chronyd -p timed out".into()),
            ExecOutcome::SpawnFailed(e) => CheckResult::ToolFailure(e),
        }
    }

    fn chronyc_tracking(&self) -> Result<String, String> {
        use super::exec::ExecOutcome;
        match self.tool(&self.cfg.chronyc, &["tracking"], Duration::from_secs(10)) {
            ExecOutcome::Exited {
                code: Some(0),
                stdout,
                ..
            } => Ok(first_chars(&stdout.text(), 1200)),
            ExecOutcome::Exited { code, stderr, .. } => Err(format!(
                "chronyc tracking exited {code:?}: {}",
                first_chars(&stderr.text(), 200)
            )),
            ExecOutcome::TimedOut { .. } => Err("chronyc tracking timed out".to_string()),
            ExecOutcome::SpawnFailed(e) => Err(e),
        }
    }

    fn probe(&self, addr: Ipv4Addr, port: u16, path: &str) -> Result<(u16, String), String> {
        let target = SocketAddr::from((addr, port));
        let timeout = Duration::from_secs(4);
        let mut stream = TcpStream::connect_timeout(&target, timeout).map_err(|e| {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PROBE_REFUSED.to_string()
            } else {
                e.to_string()
            }
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        let request = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        stream
            .take(16 * 1024)
            .read_to_end(&mut response)
            .map_err(|e| e.to_string())?;
        parse_http(&String::from_utf8_lossy(&response))
    }

    fn boot_id(&self) -> String {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    fn pending_jobs(&self) -> Result<Vec<String>, String> {
        use super::exec::ExecOutcome;
        match self.tool(
            &self.cfg.systemctl,
            &["list-jobs", "--no-pager", "--no-legend", "--full"],
            Duration::from_secs(10),
        ) {
            ExecOutcome::Exited {
                code: Some(0),
                stdout,
                ..
            } if !stdout.truncated => exclusion::parse_list_jobs(&stdout.text()),
            ExecOutcome::Exited { code, stderr, .. } => Err(format!(
                "systemctl list-jobs exited {code:?}: {}",
                first_chars(&stderr.text(), 200)
            )),
            ExecOutcome::TimedOut { .. } => Err("systemctl list-jobs timed out".to_string()),
            ExecOutcome::SpawnFailed(e) => Err(e),
        }
    }

    fn ha_processes(&self) -> Result<Vec<String>, String> {
        exclusion::scan_proc(Path::new("/proc"), std::process::id())
    }
}

/// The error text of a probe whose connection was refused (nothing listens).
/// The real system and the test systems report exactly this text; the agent
/// turns it into an explicit `refused` answer.
pub(crate) const PROBE_REFUSED: &str = "connection refused";

/// How long the agent waits for its request to arrive in full. The request is
/// written by the controller at once, so this is generous; it is the shortest
/// agent budget plus the margin the other backstop adds.
pub(crate) const READ_BACKSTOP: Duration = Duration::from_secs(30);

/// Read a request of at most `limit` bytes from `reader`; `on_stuck` runs (and
/// in production ends the process) if the read has not finished after `wait`.
/// The reading ends at EOF or at `limit`. Once it has finished the backstop is
/// released, so a long operation is not cut by it.
pub(crate) fn read_request<R: Read>(
    reader: R,
    limit: u64,
    wait: Duration,
    on_stuck: impl FnOnce() + Send + 'static,
) -> std::io::Result<Vec<u8>> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let finished = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&finished);
    std::thread::spawn(move || {
        std::thread::sleep(wait);
        if !flag.load(Ordering::SeqCst) {
            on_stuck();
        }
    });
    let mut input = Vec::new();
    let result = reader.take(limit).read_to_end(&mut input);
    finished.store(true, Ordering::SeqCst);
    result.map(|_| input)
}

/// Entry point of `mikagami agent`: one request in, one response out.
pub(crate) fn run_stdio(config_path: &Path) -> std::process::ExitCode {
    use std::process::ExitCode;
    let started = std::time::Instant::now();
    // SAFETY: plain syscall without arguments.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("agent: must run as root (use sudo)");
        return ExitCode::from(super::EXIT_REFUSED);
    }
    if let Err(e) = fsutil::check_trusted_file(config_path, 0) {
        eprintln!("agent: configuration {} {e}", config_path.display());
        return ExitCode::from(super::EXIT_REFUSED);
    }
    let cfg = match fsutil::read_regular_nofollow(config_path, 64 * 1024)
        .map_err(|e| e.to_string())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()))
        .and_then(|text| AgentConfig::parse(&text))
    {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("agent: invalid configuration: {e}");
            return ExitCode::from(super::EXIT_REFUSED);
        }
    };
    // The time limit starts before the request is read (audit RA-E-09): a
    // session that never sends EOF used to keep a root process for ever.
    let input = match read_request(
        std::io::stdin(),
        proto::MAX_MESSAGE as u64 + 1,
        READ_BACKSTOP,
        || {
            eprintln!("agent: no complete request arrived in time; stopping");
            std::process::exit(i32::from(super::EXIT_FAILED));
        },
    ) {
        Ok(input) if input.len() <= proto::MAX_MESSAGE => input,
        _ => {
            eprintln!("agent: request unreadable or too large");
            return ExitCode::from(super::EXIT_FAILED);
        }
    };
    let request = serde_json::from_slice::<Request>(&input);
    // One total time limit per run, by operation (see `proto::agent_budget`).
    let total = request
        .as_ref()
        .map_or(proto::AGENT_BUDGET_SHORT, |r| proto::agent_budget(&r.op));
    let budget = Budget::starting_at(started, total);
    // Backstop for anything that does not go through a tool call (file
    // operations on a hung filesystem): the run ends, whatever it is doing.
    std::thread::spawn(move || {
        std::thread::sleep(total + Duration::from_secs(5));
        eprintln!("agent: time budget exceeded; stopping");
        std::process::exit(i32::from(super::EXIT_FAILED));
    });
    let env = AgentEnv {
        sys: Box::new(RealSystem::new(cfg.clone(), budget)),
        cfg,
        owner_uid: 0,
        now: Box::new(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        }),
    };
    let response = match request {
        Ok(request) => handle(&env, &request),
        Err(e) => Response::err(
            "invalid-id",
            code::BAD_REQUEST,
            format!("malformed request: {e}"),
        ),
    };
    match serde_json::to_vec(&response) {
        Ok(mut bytes) => {
            bytes.push(b'\n');
            if std::io::stdout().write_all(&bytes).is_err() {
                return ExitCode::from(super::EXIT_FAILED);
            }
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
        Err(_) => ExitCode::from(super::EXIT_FAILED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual::testkit::{FakeSystem, agent_env, req};

    #[test]
    fn config_parses_and_rejects_bad_input() {
        let ok = r#"
[agent]
cluster = "c"
node = "node-a"
[units]
allowed = ["mkg-demo.service", "chrony.service"]
"#;
        let cfg = AgentConfig::parse(ok).unwrap();
        // chrony.unit must be a unit the agent may control (audit D-04).
        assert!(
            AgentConfig::parse(&ok.replace(", \"chrony.service\"", ""))
                .unwrap_err()
                .contains("chrony.unit")
        );
        assert_eq!(
            cfg.ha_units,
            ["mikagami.service", "mikagami-witness.service"]
        );
        assert_eq!(cfg.chrony_conf, PathBuf::from("/etc/chrony/chrony.conf"));
        assert!(cfg.lease_state.is_none());
        assert_eq!(
            cfg.fence_state,
            PathBuf::from("/var/lib/mkg/fence/fence.json")
        );
        let custom = format!("{ok}\n[fence]\nstate = \"/srv/mkg/fence.json\"\n");
        assert_eq!(
            AgentConfig::parse(&custom).unwrap().fence_state,
            PathBuf::from("/srv/mkg/fence.json")
        );
        assert!(AgentConfig::parse(&format!("{ok}\n[fence]\nstate = \"rel/fence\"\n")).is_err());
        assert!(AgentConfig::parse(&format!("{ok}\n[fence]\nother = 1\n")).is_err());
        assert!(AgentConfig::parse(&ok.replace("mkg-demo.service", "bad name")).is_err());
        assert!(AgentConfig::parse(&format!("{ok}\n[lease]\nstate = \"/x/l.json\"\n")).is_err());
        assert!(AgentConfig::parse(&format!("{ok}\n[surprise]\n")).is_err());
        // HA units are additive; the built-in ones cannot be dropped or
        // replaced, and nothing the agent may control can be an HA unit.
        let more = AgentConfig::parse(&ok.replace(
            "allowed = [\"mkg-demo.service\", \"chrony.service\"]",
            "allowed = [\"mkg-demo.service\", \"chrony.service\"]\nha_units = [\"ha-two.service\", \"mikagami.service\"]",
        ))
        .unwrap();
        assert_eq!(
            more.ha_units,
            [
                "mikagami.service",
                "mikagami-witness.service",
                "ha-two.service"
            ]
        );
        for clash in ["mkg-demo.service", "mikagami.service", "chrony.service"] {
            let text = format!(
                "[agent]\ncluster=\"c\"\nnode=\"node-a\"\n[units]\nallowed=[\"{clash}\"]\nha_units=[\"{clash}\"]\n"
            );
            assert!(AgentConfig::parse(&text).is_err(), "{clash}");
        }
        assert!(
            AgentConfig::parse(&ok.replace("mkg-demo.service", "mikagami-witness.service"))
                .is_err(),
            "a built-in HA unit cannot be allowed"
        );
        assert!(!cfg.ha_absent_ack && !cfg.ha_config_ack && cfg.manual_vips.is_empty());
        assert_eq!(
            cfg.control_lock_path,
            PathBuf::from(crate::control_lock::DEFAULT_LOCK_PATH)
        );
        assert_eq!(
            cfg.manual_barrier_path,
            PathBuf::from(crate::manual_barrier::DEFAULT_BARRIER_PATH)
        );
        let with_control = format!(
            "{ok}\n[control]\nlock_path = \"/srv/mkg/control.lock\"\nmanual_barrier_path = \"/srv/mkg/barrier.json\"\n"
        );
        let with_control = AgentConfig::parse(&with_control).unwrap();
        assert_eq!(
            with_control.control_lock_path,
            PathBuf::from("/srv/mkg/control.lock")
        );
        assert_eq!(
            with_control.manual_barrier_path,
            PathBuf::from("/srv/mkg/barrier.json")
        );
        assert!(AgentConfig::parse(&format!("{ok}\n[control]\nlock_path = \"rel\"\n")).is_err());
        assert_eq!(cfg.ha_config, PathBuf::from("/etc/mikagami/mikagami.toml"));
        let excl = format!(
            "{ok}\n[exclusion]\nvip = [\"10.0.0.130\"]\nha_config_ack = true\nha_config = \"/srv/ha.toml\"\n"
        );
        let excl = AgentConfig::parse(&excl).unwrap();
        assert!(excl.ha_config_ack);
        assert_eq!(excl.manual_vips, ["10.0.0.130"]);
        assert!(AgentConfig::parse(&format!("{ok}\n[exclusion]\nvip = [\"nope\"]\n")).is_err());
        assert!(AgentConfig::parse(&format!("{ok}\n[exclusion]\nha_config = \"rel\"\n")).is_err());
        assert!(AgentConfig::parse(&format!("{ok}\n[exclusion]\nother = 1\n")).is_err());
        assert!(
            AgentConfig::parse("[agent]\ncluster=\"c\"\nnode=\"../x\"\n[units]\nallowed=[]\n")
                .is_err()
        );
    }

    #[test]
    fn systemctl_is_called_with_an_end_of_options_marker_and_reports_restart_evidence() {
        let show = show_args("chrony.service");
        assert_eq!(&show[show.len() - 2..], ["--", "chrony.service"]);
        assert!(show.iter().any(|a| a.contains("MainPID")));
        assert_eq!(
            action_args("restart", "chrony.service"),
            ["restart", "--", "chrony.service"]
        );
        let state = parse_show(
            "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\n\
             ActiveEnterTimestampMonotonic=123456\n",
        )
        .unwrap();
        assert_eq!(
            (state.main_pid.as_str(), state.active_enter.as_str()),
            ("4242", "123456")
        );
    }

    #[test]
    fn systemctl_show_output_is_parsed_strictly() {
        let ok = parse_show("LoadState=loaded\nActiveState=active\nSubState=running\n").unwrap();
        assert!(ok.is_active() && ok.sub_state == "running");
        let missing =
            parse_show("LoadState=not-found\nActiveState=inactive\nSubState=dead\n").unwrap();
        assert_eq!(missing.load_state, "not-found");
        assert_eq!(
            missing.unit_file_state, "",
            "not reported for a missing unit"
        );
        let masked = parse_show(
            "LoadState=masked\nActiveState=inactive\nSubState=dead\nUnitFileState=masked\n",
        )
        .unwrap();
        assert_eq!(masked.unit_file_state, "masked");
        assert!(parse_show("").is_err());
        assert!(
            parse_show("ActiveState=active\n").is_err(),
            "no LoadState: not understood"
        );
        assert!(parse_show("garbage\nLoadState\n").is_err());
    }

    #[test]
    fn http_responses_are_parsed_strictly() {
        let ok = parse_http("HTTP/1.0 200 OK\r\nServer: x\r\n\r\nnode-a\n").unwrap();
        assert_eq!(ok, (200, "node-a".to_string()));
        assert_eq!(parse_http("HTTP/1.1 503 Busy\r\n\r\n").unwrap().0, 503);
        for bad in [
            "",
            "node-a",
            "HTTP/1.0 200 OK\n\nbody",
            "FTP/1.0 200\r\n\r\n",
            "HTTP/1.0 abc\r\n\r\n",
        ] {
            assert!(parse_http(bad).is_err(), "{bad:?}");
        }
        let long = format!("HTTP/1.0 200 OK\r\n\r\n{}", "x".repeat(1000));
        assert_eq!(parse_http(&long).unwrap().1.len(), 256);
    }

    #[test]
    fn unknown_operation_and_bad_version_are_rejected() {
        let (env, _dir) = agent_env("agent-unknown", FakeSystem::default());
        let response = handle(&env, &req("nonsense", json!({})));
        assert_eq!(response.error.unwrap().code, code::BAD_REQUEST);
        let mut request = req(op::PING, json!({}));
        request.v = 99;
        assert_eq!(
            handle(&env, &request).error.unwrap().code,
            code::BAD_REQUEST
        );
        let mut request = req(op::PING, json!({}));
        request.id = "bad id; rm".to_string();
        assert!(!handle(&env, &request).ok);
    }

    #[test]
    fn ping_reports_ha_daemon_state() {
        let sys = FakeSystem::default();
        let (env, _dir) = agent_env("agent-ping", sys.clone());
        let ping = || handle(&env, &req(op::PING, json!({}))).data;
        // A manual-mode host: both units masked.
        let data = ping();
        assert_eq!(data["ha_daemon"], "masked");
        assert_eq!(data["ha_proven"], true);
        assert_eq!(data["ha_units"]["mikagami.service"], "masked");
        assert_eq!(data["ha_units"]["mikagami-witness.service"], "masked");
        // Loaded but inactive is not a proof (audit EX-02).
        sys.unmask("mikagami.service");
        let data = ping();
        assert_eq!(data["ha_daemon"], "unmasked");
        assert_eq!(data["ha_proven"], false);
        assert_eq!(data["ha_units"]["mikagami.service"], "loaded");
        // Running.
        sys.set_service("mikagami.service", "active");
        assert_eq!(ping()["ha_daemon"], "active");
        // Not installed is told apart from inactive.
        sys.remove_unit("mikagami.service");
        let data = ping();
        assert_eq!(data["ha_units"]["mikagami.service"], "not-found");
        assert_eq!(data["ha_proven"], false);
        // Nothing can be established.
        sys.fail_queries(true);
        assert_eq!(ping()["ha_daemon"], "unknown");
    }

    #[test]
    fn an_absent_ha_unit_is_a_proof_only_when_acknowledged() {
        let sys = FakeSystem::default();
        sys.remove_unit("mikagami.service");
        sys.remove_unit("mikagami-witness.service");
        let (env, _dir) = agent_env("agent-absent", sys.clone());
        let r = handle(
            &env,
            &req(
                op::SERVICE_CONTROL,
                json!({"unit": "mkg-demo.service", "action": "start"}),
            ),
        );
        assert_eq!(r.error.expect("refused").code, code::REFUSED);
        assert!(sys.actions().is_empty());
        let (env, _dir) = crate::manual::testkit::agent_env_custom(
            "agent-absent-ack",
            "node-a",
            sys.clone(),
            Box::new(|| 0),
            &|c| c.ha_absent_ack = true,
        );
        let data = handle(&env, &req(op::PING, json!({}))).data;
        assert_eq!(data["ha_daemon"], "absent");
        assert_eq!(data["ha_proven"], true);
        let r = handle(
            &env,
            &req(
                op::SERVICE_CONTROL,
                json!({"unit": "mkg-demo.service", "action": "start"}),
            ),
        );
        assert!(r.ok, "{r:?}");
    }

    #[test]
    fn every_unproven_exclusion_refuses_every_mutation_with_its_own_reason() {
        type Break = Box<dyn Fn(&FakeSystem)>;
        let cases: Vec<(&str, Break, &str)> = vec![
            (
                "unmasked",
                Box::new(|s| s.unmask("mikagami.service")),
                "not proven",
            ),
            (
                "runtime mask",
                Box::new(|s| s.runtime_mask("mikagami-witness.service")),
                "not proven",
            ),
            (
                "not found",
                Box::new(|s| s.remove_unit("mikagami.service")),
                "not proven",
            ),
            (
                "running",
                Box::new(|s| s.set_service("mikagami.service", "active")),
                "running",
            ),
            (
                "activating",
                Box::new(|s| s.set_service("mikagami-witness.service", "activating")),
                "running",
            ),
            (
                "deactivating",
                Box::new(|s| s.set_service("mikagami.service", "deactivating")),
                "running",
            ),
            (
                "queued job",
                Box::new(|s| s.set_jobs(&["mikagami.service"])),
                "running",
            ),
            (
                "job list unreadable",
                Box::new(|s| s.fail_jobs(true)),
                "cannot be established",
            ),
            (
                "process scan failed",
                Box::new(|s| s.fail_processes(true)),
                "cannot be established",
            ),
            (
                "hand-started daemon",
                Box::new(|s| s.set_ha_processes(&["pid 7: mikagami daemon run"])),
                "running",
            ),
            (
                "systemctl failing",
                Box::new(|s| s.fail_queries(true)),
                "cannot be established",
            ),
        ];
        for (label, break_it, expected) in cases {
            let sys = FakeSystem::default();
            sys.set_service("mkg-demo.service", "inactive");
            let (env, _dir) = agent_env(
                &format!("agent-excl-{}", label.replace(' ', "-")),
                sys.clone(),
            );
            break_it(&sys);
            let ops: Vec<(&str, Value)> = vec![
                (
                    op::SERVICE_CONTROL,
                    json!({"unit": "mkg-demo.service", "action": "start"}),
                ),
                (op::LEASE_INIT, json!({"owner": "node-a"})),
            ];
            for (operation, args) in ops {
                let r = handle(&env, &req(operation, args));
                let error = r
                    .error
                    .unwrap_or_else(|| panic!("{label}: {operation} must be refused"));
                assert_eq!(error.code, code::REFUSED, "{label}: {operation}");
                assert!(
                    error.message.contains(expected),
                    "{label}: {operation}: {}",
                    error.message
                );
            }
            assert!(sys.actions().is_empty(), "{label}: nothing was executed");
            // Reads keep working: the controller needs them to see the problem.
            assert!(handle(&env, &req(op::PING, json!({}))).ok, "{label}");
            assert!(
                handle(&env, &req(op::LEASE_STATUS, json!({}))).ok,
                "{label}"
            );
        }
    }

    #[test]
    fn the_time_budget_clamps_every_tool_call() {
        use std::time::Instant;
        let mut cfg = crate::manual::testkit::agent_env("budget-cfg", FakeSystem::default())
            .0
            .cfg;
        cfg.systemctl = "/usr/bin/true".to_string();
        let spent = Budget::starting_at(Instant::now(), Duration::ZERO);
        let real = RealSystem::new(cfg.clone(), spent);
        let error = real.service_state("a.service").unwrap_err();
        assert!(error.contains("time budget"), "{error}");
        assert!(
            real.service_action(&ExclusiveProof::for_test(), "a.service", "start")
                .is_err()
        );
        assert!(
            real.pending_jobs().is_err(),
            "an exhausted budget is never an empty job list"
        );
        // A call is never allowed more than what is left of the budget.
        let few = Budget::starting_at(Instant::now(), Duration::from_secs(3));
        let clamped = few.clamp(Duration::from_secs(90)).expect("time left");
        assert!(clamped <= Duration::from_secs(3), "{clamped:?}");
        assert_eq!(
            few.clamp(Duration::from_millis(5)),
            Some(Duration::from_millis(5))
        );
        assert_eq!(spent.clamp(Duration::from_secs(1)), None);
        // A fresh budget lets the call through to the tool.
        let fresh = RealSystem::new(
            cfg,
            Budget::starting_at(Instant::now(), Duration::from_secs(60)),
        );
        let error = fresh.service_state("a.service").unwrap_err();
        assert!(!error.contains("time budget"), "{error}");
        // Budgets by operation.
        assert!(proto::agent_budget(op::SERVICE_CONTROL) >= Duration::from_secs(120));
        assert!(proto::agent_budget(op::LEASE_PHASE) <= Duration::from_secs(30));
    }

    #[test]
    fn service_control_is_allowlisted_and_exclusive() {
        let sys = FakeSystem::default();
        sys.set_service("mkg-demo.service", "inactive");
        let (env, _dir) = agent_env("agent-svc", sys.clone());
        let start = |unit: &str, action: &str| {
            handle(
                &env,
                &req(op::SERVICE_CONTROL, json!({"unit": unit, "action": action})),
            )
        };
        let response = start("ssh.service", "stop");
        assert_eq!(
            response.error.unwrap().code,
            code::REFUSED,
            "not in the allowlist"
        );
        assert_eq!(
            start("mkg-demo.service", "mask").error.unwrap().code,
            code::BAD_REQUEST
        );
        let response = start("mkg-demo.service", "start");
        assert!(response.ok, "{response:?}");
        assert_eq!(response.data["active"], true);
        // HA daemon active => every mutation is refused.
        sys.set_service("mikagami.service", "active");
        let response = start("mkg-demo.service", "stop");
        assert_eq!(response.error.unwrap().code, code::REFUSED);
        assert_eq!(sys.actions(), vec!["start mkg-demo.service".to_string()]);
        // Unknowable HA state is refused too.
        sys.set_service("mikagami.service", "inactive");
        sys.fail_queries(true);
        let response = start("mkg-demo.service", "stop");
        assert_eq!(response.error.unwrap().code, code::REFUSED);
    }

    #[test]
    fn failed_action_reports_failure_with_state() {
        let sys = FakeSystem::default();
        sys.set_service("mkg-demo.service", "active");
        sys.fail_action("stop");
        let (env, _dir) = agent_env("agent-fail", sys);
        let response = handle(
            &env,
            &req(
                op::SERVICE_CONTROL,
                json!({"unit": "mkg-demo.service", "action": "stop"}),
            ),
        );
        let error = response.error.unwrap();
        assert_eq!(error.code, code::FAILED);
        assert!(
            error.message.contains("state now: active"),
            "{}",
            error.message
        );
    }

    #[test]
    fn probe_is_restricted_to_private_targets_and_clean_paths() {
        let sys = FakeSystem::default();
        sys.set_probe_body("node-a");
        let (env, _dir) = agent_env("agent-probe", sys);
        let probe = |addr: &str, path: &str| {
            handle(
                &env,
                &req(op::PROBE, json!({"addr": addr, "port": 8080, "path": path})),
            )
        };
        assert!(probe("10.0.0.130", "/id").ok);
        assert!(probe("127.0.0.1", "/id").ok);
        assert_eq!(probe("8.8.8.8", "/id").error.unwrap().code, code::REFUSED);
        assert_eq!(
            probe("10.0.0.1", "/../etc/passwd").error.unwrap().code,
            code::BAD_REQUEST
        );
        assert_eq!(
            probe("not-an-ip", "/id").error.unwrap().code,
            code::BAD_REQUEST
        );
        assert_eq!(
            probe("10.0.0.1", "/id?x=1").error.unwrap().code,
            code::BAD_REQUEST
        );
    }

    #[test]
    fn lease_operations_need_lease_config_and_exclusive_mode() {
        let sys = FakeSystem::default();
        let (env, _dir) = agent_env("agent-lease", sys.clone());
        let status = handle(&env, &req(op::LEASE_STATUS, json!({})));
        assert!(status.ok, "{status:?}");
        assert!(status.data["owner"].is_null());
        let init = handle(&env, &req(op::LEASE_INIT, json!({"owner": "node-a"})));
        assert!(init.ok, "{init:?}");
        assert_eq!(init.data["epoch"], 1);
        // Mutation refused while the HA witness runs; reads still work.
        sys.set_service("mikagami-witness.service", "active");
        let refused = handle(
            &env,
            &req(
                op::LEASE_RECONCILE,
                json!({"owner": "node-b", "reason": "x", "expect_epoch": 1}),
            ),
        );
        assert_eq!(refused.error.unwrap().code, code::REFUSED);
        assert!(handle(&env, &req(op::LEASE_STATUS, json!({}))).ok);
    }

    fn control(env: &AgentEnv, action: &str, fence: Option<Value>) -> Response {
        let mut args = json!({"unit": "mkg-demo.service", "action": action});
        if let Some(fence) = fence {
            args["fence"] = fence;
        }
        handle(env, &req(op::SERVICE_CONTROL, args))
    }

    #[test]
    fn service_control_enforces_the_fencing_token_when_one_is_sent() {
        // B-01 / B-02: the node refuses a controller that was replaced.
        let sys = FakeSystem::default();
        sys.set_service("mkg-demo.service", "inactive");
        let (env, _dir) = agent_env("agent-fence", sys.clone());
        let token =
            |epoch: u64, seq: u64, op: &str| json!({"epoch": epoch, "seq": seq, "op_id": op});
        assert!(control(&env, "start", Some(token(1, 5, "op-five"))).ok);
        assert!(
            control(&env, "stop", Some(token(1, 5, "op-five"))).ok,
            "same operation"
        );
        assert!(
            control(&env, "start", Some(token(2, 7, "op-seven"))).ok,
            "newer"
        );
        let before = sys.actions().len();
        for stale in [
            token(1, 5, "op-five"),
            token(2, 6, "op-six"),
            token(1, 9, "op-nine"),
            token(2, 7, "op-forged"),
        ] {
            let r = control(&env, "stop", Some(stale.clone()));
            assert_eq!(r.error.expect("refused").code, code::REFUSED, "{stale}");
        }
        assert_eq!(
            sys.actions().len(),
            before,
            "a refused call executes nothing"
        );
        // Malformed tokens are bad requests; a missing token is not checked.
        for bad in [
            json!("x"),
            json!({"seq": 1}),
            json!({"epoch": 1, "seq": 1, "op_id": "a", "x": 1}),
        ] {
            let r = control(&env, "stop", Some(bad));
            assert_eq!(r.error.expect("bad").code, code::BAD_REQUEST);
        }
        assert!(control(&env, "stop", None).ok);
        // The mark is visible to the controller and survives the agent.
        let ping = handle(&env, &req(op::PING, json!({})));
        assert_eq!(ping.data["fence"]["seq"], 7);
        assert!(ping.data["fence_error"].is_null());
    }

    #[test]
    fn a_damaged_fencing_record_refuses_tokens_and_is_reported_by_ping() {
        let sys = FakeSystem::default();
        sys.set_service("mkg-demo.service", "inactive");
        let (env, dir) = agent_env("agent-fence-damaged", sys.clone());
        let token = json!({"epoch": 1, "seq": 1, "op_id": "op-one"});
        assert!(control(&env, "start", Some(token.clone())).ok);
        std::fs::write(dir.join("fence").join("fence.json"), "{ nope").unwrap();
        let r = control(&env, "stop", Some(token));
        assert_eq!(r.error.expect("refused").code, code::REFUSED);
        let ping = handle(&env, &req(op::PING, json!({})));
        assert!(ping.ok && ping.data["fence"].is_null());
        assert!(
            ping.data["fence_error"]
                .as_str()
                .unwrap()
                .contains("unusable")
        );
    }

    #[test]
    fn the_agent_applies_the_lease_rules_itself() {
        // B-08: the agent does not rely on the controller for them.
        let sys = FakeSystem::default();
        let (env, _dir) = agent_env("agent-lease-rules", sys);
        assert!(handle(&env, &req(op::LEASE_INIT, json!({"owner": "node-a"}))).ok);
        let acquire = json!({"op_id": "move-agent01", "source": "node-a", "target": "node-b",
            "ttl_s": 300, "controller": "x", "expect_epoch": 1});
        let r = handle(&env, &req(op::LEASE_ACQUIRE, acquire));
        assert!(r.ok, "{r:?}");
        assert_eq!(r.data["op"]["seq"], 2);
        // Skipping a phase is refused.
        let skip = handle(
            &env,
            &req(
                op::LEASE_PHASE,
                json!({"op_id": "move-agent01", "phase": "target_started"}),
            ),
        );
        assert_eq!(skip.error.unwrap().code, code::REFUSED);
        // A live, unmutated operation is not cut by a reconcile.
        let cut = handle(
            &env,
            &req(
                op::LEASE_RECONCILE,
                json!({"owner": "node-a", "reason": "x", "expect_epoch": 1,
                       "expect_op_id": "move-agent01", "abandon_op_id": "move-agent01"}),
            ),
        );
        assert_eq!(cut.error.unwrap().code, code::REFUSED);
        // A mutating one needs the operator to name it.
        assert!(
            handle(
                &env,
                &req(
                    op::LEASE_PHASE,
                    json!({"op_id": "move-agent01", "phase": "source_quiescing"})
                )
            )
            .ok
        );
        let unnamed = handle(
            &env,
            &req(
                op::LEASE_RECONCILE,
                json!({"owner": "node-a", "reason": "x", "expect_epoch": 1,
                       "expect_op_id": "move-agent01"}),
            ),
        );
        assert_eq!(unnamed.error.unwrap().code, code::REFUSED);
        // Oversized evidence is refused, and init takes its floors.
        let big = "x".repeat(super::super::lease::MAX_EVIDENCE_BYTES + 1);
        let too_big = handle(
            &env,
            &req(
                op::LEASE_PHASE,
                json!({"op_id": "move-agent01", "phase": "source_quiescing", "evidence": {"x": big}}),
            ),
        );
        assert_eq!(too_big.error.unwrap().code, code::REFUSED);
    }
}

#[cfg(test)]
mod control_intent_tests {
    use super::*;
    use crate::manual::testkit::{FakeSystem, agent_env, req};

    fn begin_args(op_id: &str) -> Value {
        json!({
            "op_id": op_id,
            "source": "node-a",
            "target": "node-b",
            "epoch": 7,
            "controller": "test-controller",
        })
    }

    #[test]
    fn a_busy_control_lock_refuses_a_service_change_before_the_action() {
        let sys = FakeSystem::default();
        let (env, dir) = agent_env("control-lock-busy", sys.clone());
        let held =
            crate::control_lock::ControlLock::acquire(&env.cfg.control_lock_path, env.owner_uid)
                .unwrap();
        let request = req(
            op::SERVICE_CONTROL,
            json!({"unit": "mkg-demo.service", "action": "start"}),
        );
        let response = handle(&env, &request);
        assert!(!response.ok);
        assert_eq!(response.error.unwrap().code, code::REFUSED);
        assert!(sys.actions().is_empty(), "no service action may run");
        drop(held);
        let response = handle(&env, &request);
        assert!(response.ok, "{response:?}");
        assert_eq!(sys.actions(), ["start mkg-demo.service"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn begin_status_resolve_round_trip_and_a_foreign_resolve_is_refused() {
        let sys = FakeSystem::default();
        let (env, dir) = agent_env("control-intent", sys);
        let begin = handle(&env, &req(op::CONTROL_INTENT_BEGIN, begin_args("move-1")));
        assert!(begin.ok, "{begin:?}");
        let state = crate::manual_barrier::check(
            &env.cfg.manual_barrier_path,
            env.owner_uid,
            &env.cfg.cluster,
            &env.cfg.node,
        )
        .unwrap();
        assert!(state.is_open());

        let status = handle(&env, &req(op::CONTROL_INTENT_STATUS, json!({})));
        assert!(status.ok);
        assert_eq!(status.data["present"], true);
        assert_eq!(status.data["intent"]["op_id"], "move-1");

        let foreign = handle(
            &env,
            &req(op::CONTROL_INTENT_RESOLVE, json!({"op_id": "move-2"})),
        );
        assert!(!foreign.ok);
        assert!(
            crate::manual_barrier::check(
                &env.cfg.manual_barrier_path,
                env.owner_uid,
                &env.cfg.cluster,
                &env.cfg.node,
            )
            .unwrap()
            .is_open()
        );

        let resolve = handle(
            &env,
            &req(op::CONTROL_INTENT_RESOLVE, json!({"op_id": "move-1"})),
        );
        assert!(resolve.ok, "{resolve:?}");
        assert_eq!(
            crate::manual_barrier::check(
                &env.cfg.manual_barrier_path,
                env.owner_uid,
                &env.cfg.cluster,
                &env.cfg.node,
            )
            .unwrap(),
            crate::manual_barrier::BarrierState::Clear
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_malformed_begin_request_changes_nothing() {
        let sys = FakeSystem::default();
        let (env, dir) = agent_env("control-intent-bad", sys);
        for args in [
            json!({"op_id": "move-1", "source": "node-a", "target": "node-b"}),
            json!({"op_id": "bad id", "source": "node-a", "target": "node-b", "epoch": 1}),
            json!({"op_id": "move-1", "source": "node-a", "target": "node-b", "epoch": 0}),
        ] {
            let response = handle(&env, &req(op::CONTROL_INTENT_BEGIN, args));
            assert!(!response.ok);
            assert!(!env.cfg.manual_barrier_path.exists());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
