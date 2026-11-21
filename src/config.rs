use serde::Deserialize;
use std::{fmt, fs, net::SocketAddr, path::Path};

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Validation(Vec<String>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "could not read configuration: {error}"),
            Self::Parse(error) => write!(f, "could not parse TOML configuration: {error}"),
            Self::Validation(errors) => {
                write!(f, "configuration validation failed: {}", errors.join("; "))
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// The location-neutral wording a configuration failure is reported with when
/// its own message would name where the shared secret lives (G6).
pub(crate) const SECRET_LOCATION_NEUTRAL: &str = "security configuration invalid";

impl ConfigError {
    /// An operator-presentable description of a configuration failure.
    ///
    /// A TOML parse error's `Display` quotes the offending configuration line,
    /// which can be the secret-bearing line, so only the parser's bare message
    /// is used. A validation message that names the secret-bearing *field*
    /// still discloses that this node's shared secret lives in a configured
    /// file, so it is reported as [`SECRET_LOCATION_NEUTRAL`] instead. Every
    /// other message is passed through unchanged.
    ///
    /// This is a presentation rule only: `Display` — and therefore every other
    /// CLI surface and the whole error taxonomy — is untouched.
    pub(crate) fn operator_summary(&self) -> String {
        match self {
            Self::Parse(parse) => {
                format!("could not parse TOML configuration: {}", parse.message())
            }
            Self::Validation(errors) => format!(
                "configuration validation failed: {}",
                errors
                    .iter()
                    .map(|message| {
                        if names_secret_field(message) {
                            SECRET_LOCATION_NEUTRAL.to_string()
                        } else {
                            message.clone()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::Io(_) => self.to_string(),
        }
    }
}

/// Whether a configuration message names the secret-bearing field. A validator
/// never interpolates a value, so the field name is the only way one of these
/// messages can disclose where the shared secret lives.
fn names_secret_field(message: &str) -> bool {
    message.to_lowercase().contains("psk")
}

/// The authority mode. v1.0 accepts no `cluster.mode` key: every node runs
/// `Conservative` (Witness lease gates on; Owner decision A-6, contract K-5),
/// so Bootstrap Admission can never run without them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Conservative,
    Availability,
}

/// The cluster topology (`cluster.topology`). Absent means `Witness`: every configuration
/// written before the two-node topology existed keeps its exact meaning.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    /// Two nodes and a third-host Witness (term / lease CAS). The v0.7 behaviour.
    #[default]
    Witness,
    /// Two nodes without a Witness (TWO_NODE_ARCHITECTURE.md). Promotion authority comes from
    /// a cooperative grant of the live peer or from a confirmed fence of the peer.
    TwoNode,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceManager {
    Systemd,
    Command,
}

/// Internal fixed values that used to be configurable but never took effect
/// (or must not vary): the heartbeat cadence, the Witness lease timing and the
/// derived node priorities. They are not configuration keys in v1.0.
pub const HEARTBEAT_INTERVAL_SEC: u64 = 1;
pub const HEARTBEAT_SUSPECT_AFTER_SEC: u64 = 3;
pub const HEARTBEAT_UNREACHABLE_AFTER_SEC: u64 = 10;
pub const HEARTBEAT_CONNECT_TIMEOUT_SEC: u64 = 2;
pub const LEASE_TTL_SEC: u64 = 10;
pub const LEASE_RENEW_INTERVAL_SEC: u64 = 3;
pub const LEASE_REQUEST_TIMEOUT_SEC: u64 = 2;
/// Derived HELLO priorities: the preferred node is 100, the other 50.
pub const PRIORITY_PREFERRED: i32 = 100;
pub const PRIORITY_STANDBY: i32 = 50;
/// Defaults for the `[fencing]` command backend (plan WU-2).
pub const DEFAULT_FENCE_TIMEOUT_SEC: u64 = 30;
pub const DEFAULT_VERIFY_TIMEOUT_SEC: u64 = 10;
pub const DEFAULT_VERIFY_POLLS: u64 = 10;

// ---- the file shape (strict; unknown keys are rejected) -------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    cluster: RawCluster,
    node: RawNode,
    peer: RawPeer,
    witness: RawWitness,
    vip: VipConfig,
    service: ServiceConfig,
    health: RawHealth,
    fencing: Option<FencingConfig>,
    route: Option<RouteConfig>,
    security: RawSecurity,
    #[serde(default)]
    state: StateConfig,
    #[serde(default)]
    failover: RawFailover,
    #[serde(default)]
    control: RawControl,
}

/// The v0.5 control-plane exclusions. Both paths are local to the host and
/// are shared with the manual agent's configuration. Defaults are the ones
/// the shipped unit/agent examples use.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawControl {
    lock_path: Option<String>,
    manual_barrier_path: Option<String>,
}

impl Default for RawControl {
    fn default() -> Self {
        Self {
            lock_path: None,
            manual_barrier_path: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    /// Shared kernel `flock` path. The HA daemon holds it for its lifetime;
    /// the manual agent holds it for one mutating request.
    pub lock_path: String,
    /// Durable record written by the manual controller before the first
    /// mutating request of a logical operation. HA refuses to start while it
    /// exists.
    pub manual_barrier_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCluster {
    id: String,
    /// Only `"witness"` reaches this struct (`Config::parse_str` routes `"two-node"` to the
    /// two-node shape first).
    #[serde(default)]
    topology: Option<String>,
}

/// The two-node file shape (strict). `[witness]`, `node.listen` and `peer.address` do not
/// exist here: the peer paths are the `[[two_node.link]]` entries.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTwoNodeConfig {
    cluster: RawCluster,
    node: RawTwoNodeNode,
    peer: RawTwoNodePeer,
    two_node: crate::two_node::config::RawTwoNode,
    vip: VipConfig,
    /// The single managed service, or
    service: Option<ServiceConfig>,
    /// the resource group (two-node only; exactly one of the two).
    group: Option<RawGroup>,
    health: RawHealth,
    fencing: Option<FencingConfig>,
    security: RawSecurity,
    #[serde(default)]
    failover: RawFailover,
    #[serde(default)]
    control: RawControl,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroup {
    #[serde(default)]
    resource: Vec<RawGroupResource>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroupResource {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    unit: Option<String>,
    start: Option<Vec<String>>,
    stop: Option<Vec<String>>,
    status: Option<Vec<String>>,
    start_timeout_sec: Option<u64>,
    stop_timeout_sec: Option<u64>,
}

/// At most this many resources in a group.
pub const GROUP_RESOURCE_LIMIT: usize = 8;

/// One resource of a group.
#[derive(Debug, Clone)]
pub enum GroupResourceKind {
    /// A service (`systemd` unit or `command` start/stop/status), started and observed
    /// exactly like the single `[service]`.
    Service(ServiceConfig),
    /// The `[vip]` address, added at this position (announced by gratuitous ARP only after
    /// every resource is up and `[health]` passed).
    Vip,
}

#[derive(Debug, Clone)]
pub struct GroupResource {
    pub name: String,
    pub kind: GroupResourceKind,
}

/// The resource group of a two-node configuration: started in order, stopped in reverse.
#[derive(Debug, Clone)]
pub struct GroupConfig {
    pub resources: Vec<GroupResource>,
}

fn group_from_raw(raw: RawGroup, errors: &mut Vec<String>) -> Option<GroupConfig> {
    let mut resources = Vec::new();
    if raw.resource.is_empty() || raw.resource.len() > GROUP_RESOURCE_LIMIT {
        errors.push(format!(
            "group.resource: between 1 and {GROUP_RESOURCE_LIMIT} resources are required"
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for (index, item) in raw.resource.into_iter().enumerate() {
        let field = format!("group.resource[{index}]");
        if item.name.is_empty()
            || !item
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            errors.push(format!(
                "{field}.name must be non-empty ASCII letters, digits, '-', '_' or '.'"
            ));
        }
        if !names.insert(item.name.clone()) {
            errors.push(format!("{field}.name {:?} is used twice", item.name));
        }
        let manager = match item.kind.as_str() {
            "systemd" => Some(ServiceManager::Systemd),
            "command" => Some(ServiceManager::Command),
            "vip" => None,
            other => {
                errors.push(format!(
                    "{field}.type must be \"systemd\", \"command\" or \"vip\" (got {other:?})"
                ));
                continue;
            }
        };
        let kind = match manager {
            Some(manager) => GroupResourceKind::Service(ServiceConfig {
                manager,
                unit: item.unit,
                start: item.start,
                stop: item.stop,
                status: item.status,
                start_timeout_sec: item
                    .start_timeout_sec
                    .unwrap_or_else(default_service_timeout),
                stop_timeout_sec: item
                    .stop_timeout_sec
                    .unwrap_or_else(default_service_timeout),
            }),
            None => {
                if item.unit.is_some()
                    || item.start.is_some()
                    || item.stop.is_some()
                    || item.status.is_some()
                    || item.start_timeout_sec.is_some()
                    || item.stop_timeout_sec.is_some()
                {
                    errors.push(format!(
                        "{field}: a vip resource takes only name and type (the address is [vip])"
                    ));
                }
                GroupResourceKind::Vip
            }
        };
        resources.push(GroupResource {
            name: item.name,
            kind,
        });
    }
    let vips = resources
        .iter()
        .filter(|r| matches!(r.kind, GroupResourceKind::Vip))
        .count();
    if vips != 1 {
        errors.push(format!(
            "group.resource: exactly one resource of type \"vip\" is required (found {vips})"
        ));
    }
    if !resources
        .iter()
        .any(|r| matches!(r.kind, GroupResourceKind::Service(_)))
    {
        errors.push("group.resource: at least one systemd or command resource is required".into());
    }
    Some(GroupConfig { resources })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTwoNodeNode {
    id: String,
    #[serde(default)]
    preferred: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTwoNodePeer {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    id: String,
    /// The fixed preferred node of the pair (at most one). Preference only
    /// orders when a cold start asks first; it is never a safety argument.
    #[serde(default)]
    preferred: bool,
    /// `ip:port` this node accepts the peer on. Required for the canonical
    /// inbound node (the higher id), rejected on the outbound node.
    listen: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    id: String,
    /// `ip:port` this node dials. Required for the canonical outbound node
    /// (the lower id), rejected on the inbound node.
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWitness {
    id: String,
    address: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHealth {
    command: Vec<String>,
    #[serde(default = "default_health_timeout")]
    timeout_sec: u64,
    #[serde(default = "default_failure_threshold")]
    failure_threshold: u32,
    #[serde(default = "default_success_threshold")]
    success_threshold: u32,
    /// What a two-node Active does when its health becomes unhealthy (default `warn`).
    #[serde(default)]
    on_failure: HealthAction,
    /// `on_failure = "restart"`: local restarts allowed per [`HEALTH_RESTART_WINDOW_SEC`].
    restart_limit: Option<u32>,
}

/// `[health] on_failure` (two-node only; the Witness topology accepts only `warn`).
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthAction {
    /// Log and show the state only (the behaviour before `on_failure` existed).
    #[default]
    Warn,
    /// Restart the services locally (the VIP stays), at most `restart_limit` times per window.
    Restart,
    /// Hand the service over to the connected peer: release first (confirmed), then the peer
    /// claims. Never by fencing, never without the peer's grant.
    Failover,
}

/// The two-node daemon runs `[health] command` in its control loop: its timeout is bounded.
pub const HEALTH_LOOP_TIMEOUT_LIMIT_SEC: u64 = 30;

/// The window of `health.restart_limit`.
pub const HEALTH_RESTART_WINDOW_SEC: u64 = 600;
const DEFAULT_HEALTH_RESTART_LIMIT: u32 = 2;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecurity {
    psk_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFailover {
    #[serde(default = "default_true")]
    auto: bool,
    #[serde(default = "default_dwell")]
    dwell_sec: u64,
    #[serde(default = "default_bootstrap_dwell")]
    bootstrap_dwell_sec: u64,
    #[serde(default = "default_bootstrap_defer")]
    bootstrap_defer_sec: u64,
    #[serde(default = "default_max_fence_actions")]
    max_fence_actions: u64,
    #[serde(default = "default_cycle_timeout")]
    cycle_timeout_sec: u64,
}

impl Default for RawFailover {
    fn default() -> Self {
        Self {
            auto: true,
            dwell_sec: default_dwell(),
            bootstrap_dwell_sec: default_bootstrap_dwell(),
            bootstrap_defer_sec: default_bootstrap_defer(),
            max_fence_actions: default_max_fence_actions(),
            cycle_timeout_sec: default_cycle_timeout(),
        }
    }
}

// ---- the validated configuration the rest of the program uses -------------

/// A validated node configuration. Built only by [`Config::parse_str`] /
/// [`Config::load`]; the `heartbeat`, `lease`, priority and bind fields are
/// derived from the v1.0 file shape, never read from it.
#[derive(Debug)]
pub struct Config {
    pub cluster: ClusterConfig,
    pub node: NodeConfig,
    pub peer: PeerConfig,
    pub heartbeat: HeartbeatConfig,
    pub witness: Option<WitnessConfig>,
    pub lease: LeaseConfig,
    pub vip: VipConfig,
    pub service: ServiceConfig,
    pub health: HealthConfig,
    pub fencing: Option<FencingConfig>,
    /// v0.7 G-2 route handoff (`G2_SAFETY_CONTRACT.md` R4.1). Absent: no route handoff.
    pub route: Option<RouteConfig>,
    pub security: SecurityConfig,
    pub state: StateConfig,
    pub failover: FailoverConfig,
    pub control: ControlPlaneConfig,
    /// `Witness` unless `cluster.topology = "two-node"`.
    pub topology: Topology,
    /// Present exactly when `topology == TwoNode`.
    pub two_node: Option<crate::two_node::config::TwoNodeConfig>,
    /// The resource group of a two-node configuration (`[[group.resource]]`); `None`: the
    /// single `[service]`.
    pub group: Option<GroupConfig>,
}

#[derive(Debug)]
pub struct ClusterConfig {
    pub id: String,
    /// Always [`Mode::Conservative`] in v1.0 (no `cluster.mode` key).
    pub mode: Mode,
    /// Derived from `node.listen` (0 on the outbound node).
    pub heartbeat_port: u16,
}

#[derive(Debug)]
pub struct NodeConfig {
    pub id: String,
    pub preferred: bool,
    pub listen: Option<String>,
    /// Derived: 100 when preferred, 50 otherwise.
    pub priority: i32,
    /// Derived from `node.listen` (the IPv4 part).
    pub bind_address: Option<String>,
}

#[derive(Debug)]
pub struct PeerConfig {
    pub id: String,
    pub address: Option<String>,
    /// Derived: the opposite of this node's own derived priority.
    pub priority: i32,
}

#[derive(Debug)]
pub struct HeartbeatConfig {
    pub interval_sec: u64,
    pub suspect_after_sec: u64,
    pub unreachable_after_sec: u64,
    pub connect_timeout_sec: u64,
}

#[derive(Debug)]
pub struct WitnessConfig {
    /// Always `Some(true)` in v1.0 (the Witness is mandatory).
    pub enabled: Option<bool>,
    pub id: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug)]
pub struct LeaseConfig {
    pub ttl_sec: u64,
    pub renew_interval_sec: u64,
    pub request_timeout_sec: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VipConfig {
    pub address: String,
    pub interface: String,
    #[serde(default = "default_arp_count")]
    pub arp_count: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub manager: ServiceManager,
    pub unit: Option<String>,
    pub start: Option<Vec<String>>,
    pub stop: Option<Vec<String>>,
    /// Required for the `command` manager (contract K-6): the strict
    /// `running` / `stopped` probe.
    pub status: Option<Vec<String>>,
    #[serde(default = "default_service_timeout")]
    pub start_timeout_sec: u64,
    #[serde(default = "default_service_timeout")]
    pub stop_timeout_sec: u64,
}

#[derive(Debug)]
pub struct HealthConfig {
    pub command: Vec<String>,
    /// Derived: health is observed on the daemon's own tick.
    pub interval_sec: u64,
    pub timeout_sec: u64,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub on_failure: HealthAction,
    pub restart_limit: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FencingBackendKind {
    None,
    Command,
}

/// Stage 14 Design Revision 5 §16.1 `[fencing]` (optional, strict). Only the
/// shape is declared here; `FencingSettings::from_config` validates it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencingConfig {
    pub backend: FencingBackendKind,
    pub fence: Option<Vec<String>>,
    pub verify: Option<Vec<String>>,
    pub fence_timeout_sec: Option<u64>,
    pub verify_timeout_sec: Option<u64>,
    pub verify_polls: Option<u64>,
}

/// v0.7 G-2 `[route]` (optional, strict): the route-handoff helper and its directory. The RH step
/// timing is not configurable (contract R4.1 §5.1).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// The helper executable (absolute; trust-checked at startup like `[fencing]` commands).
    pub helper: String,
    /// The helper's own configuration file (absolute), passed as `--config`.
    pub helper_config: String,
    /// The RH directory shared with the helper (owned by this user, mode 0700).
    pub intent_dir: String,
    /// C-4: the least time between the first and the confirming observation cycle.
    #[serde(default = "default_route_confirm_hold")]
    pub confirm_hold_sec: u64,
    /// After this, a non-confirmed route handoff is shown as `ROUTE_UNKNOWN` (no write follows).
    #[serde(default = "default_route_deadline")]
    pub deadline_sec: u64,
}

/// v0.7 G-2 `[route]` ranges (display and confirmation timing only; the RH step budget is fixed).
const ROUTE_CONFIRM_HOLD_LIMIT_SEC: u64 = 600;
const ROUTE_DEADLINE_FLOOR_SEC: u64 = 30;
const ROUTE_DEADLINE_LIMIT_SEC: u64 = 3600;

fn default_route_confirm_hold() -> u64 {
    30
}

fn default_route_deadline() -> u64 {
    300
}

#[derive(Debug)]
pub struct SecurityConfig {
    pub psk_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    #[serde(default = "default_state_path")]
    pub path: String,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            path: default_state_path(),
        }
    }
}

/// `[failover]` (all keys optional). The values order *when* a request is
/// made and bound how often; none of them is a safety argument.
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    pub auto: bool,
    pub dwell_sec: u64,
    pub bootstrap_dwell_sec: u64,
    pub bootstrap_defer_sec: u64,
    pub max_fence_actions: u64,
    pub cycle_timeout_sec: u64,
}

impl Config {
    /// Reads a configuration file. A shared two-node file (`[nodes.<id>]`) is resolved for
    /// this node through the node identity file next to it (`two_node::shared`); a missing,
    /// unsafe or foreign identity file refuses the configuration.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(ConfigError::Io)?;
        if crate::two_node::shared::is_shared_shape(&contents) {
            let identity_path = crate::two_node::shared::identity_path(path);
            let identity = crate::two_node::shared::read_identity(&identity_path)
                .map_err(|e| ConfigError::Validation(vec![e]))?;
            let config = Self::parse_shared(&contents, &identity.node)?;
            if config.cluster.id != identity.cluster {
                return Err(ConfigError::Validation(vec![format!(
                    "{} belongs to cluster {:?}, the configuration is cluster {:?}",
                    identity_path.display(),
                    identity.cluster,
                    config.cluster.id
                )]));
            }
            return Ok(config);
        }
        Self::parse_str(&contents)
    }

    /// Parses a shared two-node file for `node_id` (the registered node id).
    pub fn parse_shared(contents: &str, node_id: &str) -> Result<Self, ConfigError> {
        let derived =
            crate::two_node::shared::derive(contents, node_id).map_err(ConfigError::Validation)?;
        let per_node = toml::to_string(&derived.per_node)
            .map_err(|e| ConfigError::Validation(vec![e.to_string()]))?;
        let mut config = Self::parse_str_per_node(&per_node)?;
        match config.two_node.as_mut() {
            Some(two_node) => two_node.config_summary = Some(derived.summary),
            None => {
                return Err(ConfigError::Validation(vec![
                    "a shared configuration must be a two-node configuration".to_string(),
                ]));
            }
        }
        Ok(config)
    }

    /// Parses one node's configuration text. A shared two-node file needs the node identity
    /// and is refused here (use [`Config::load`] or [`Config::parse_shared`]).
    pub fn parse_str(contents: &str) -> Result<Self, ConfigError> {
        if crate::two_node::shared::is_shared_shape(contents) {
            return Err(ConfigError::Validation(vec![
                "a shared configuration ([nodes]) needs this node's registered id; load it \
                 from its file (mikagami node register)"
                    .to_string(),
            ]));
        }
        Self::parse_str_per_node(contents)
    }

    fn parse_str_per_node(contents: &str) -> Result<Self, ConfigError> {
        let config = match Self::probe_topology(contents)? {
            Topology::Witness => {
                let raw: RawConfig = toml::from_str(contents).map_err(ConfigError::Parse)?;
                Self::from_raw(raw)?
            }
            Topology::TwoNode => {
                let raw: RawTwoNodeConfig = toml::from_str(contents).map_err(ConfigError::Parse)?;
                Self::from_raw_two_node(raw)?
            }
        };
        config.validate()?;
        Ok(config)
    }

    /// Reads only `cluster.topology` (a string) to choose the file shape. Absent means the
    /// Witness topology, so every existing configuration parses exactly as before.
    fn probe_topology(contents: &str) -> Result<Topology, ConfigError> {
        // Only `cluster.topology` is read; every other value is ignored here, so a value the
        // typed shape accepts (for example a u64 beyond i64) never fails the probe.
        #[derive(Deserialize)]
        struct Probe {
            cluster: Option<ProbeCluster>,
        }
        #[derive(Deserialize)]
        struct ProbeCluster {
            topology: Option<toml::Value>,
        }
        let topology = match toml::from_str::<Probe>(contents) {
            Ok(probe) => probe.cluster.and_then(|cluster| cluster.topology),
            // The typed parse of the Witness shape reports the real error.
            Err(_) => return Ok(Topology::Witness),
        };
        match topology {
            None => Ok(Topology::Witness),
            Some(toml::Value::String(value)) if value == "witness" => Ok(Topology::Witness),
            Some(toml::Value::String(value)) if value == "two-node" => Ok(Topology::TwoNode),
            Some(_) => Err(ConfigError::Validation(vec![
                "cluster.topology must be \"witness\" or \"two-node\"".to_string(),
            ])),
        }
    }

    /// The two-node topology: the shared sections are validated by [`Config::validate`]
    /// exactly as for the Witness topology; the peer paths and the fence declaration by
    /// `two_node::config`.
    fn from_raw_two_node(raw: RawTwoNodeConfig) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        let (service, group) = match (raw.service, raw.group) {
            (Some(service), None) => (Some(service), None),
            (None, Some(group)) => {
                let group = group_from_raw(group, &mut errors);
                // `service` mirrors the first service of the group for the code that shows
                // one service; the two-node runtime uses the group.
                let first = group.as_ref().and_then(|g| {
                    g.resources.iter().find_map(|r| match &r.kind {
                        GroupResourceKind::Service(service) => Some(service.clone()),
                        GroupResourceKind::Vip => None,
                    })
                });
                (first, group)
            }
            (Some(_), Some(_)) => {
                errors.push("[service] and [group] exclude each other".to_string());
                (None, None)
            }
            (None, None) => {
                errors.push("a [service] or a [group] with resources is required".to_string());
                (None, None)
            }
        };
        let fencing = raw.fencing.map(fill_fencing_defaults);
        let fencing_command = fencing
            .as_ref()
            .is_some_and(|fencing| fencing.backend == FencingBackendKind::Command);
        let two_node = crate::two_node::config::validate_two_node(
            raw.two_node,
            &raw.node.id,
            &raw.peer.id,
            fencing_command,
            &mut errors,
        );
        if !errors.is_empty() {
            return Err(ConfigError::Validation(errors));
        }
        let (own_priority, peer_priority) = if raw.node.preferred {
            (PRIORITY_PREFERRED, PRIORITY_STANDBY)
        } else {
            (PRIORITY_STANDBY, PRIORITY_PREFERRED)
        };
        Ok(Self {
            cluster: ClusterConfig {
                id: raw.cluster.id,
                mode: Mode::Conservative,
                heartbeat_port: 0,
            },
            node: NodeConfig {
                id: raw.node.id,
                preferred: raw.node.preferred,
                listen: None,
                priority: own_priority,
                bind_address: None,
            },
            peer: PeerConfig {
                id: raw.peer.id,
                address: None,
                priority: peer_priority,
            },
            heartbeat: HeartbeatConfig {
                interval_sec: HEARTBEAT_INTERVAL_SEC,
                suspect_after_sec: HEARTBEAT_SUSPECT_AFTER_SEC,
                unreachable_after_sec: HEARTBEAT_UNREACHABLE_AFTER_SEC,
                connect_timeout_sec: HEARTBEAT_CONNECT_TIMEOUT_SEC,
            },
            witness: None,
            lease: LeaseConfig {
                ttl_sec: LEASE_TTL_SEC,
                renew_interval_sec: LEASE_RENEW_INTERVAL_SEC,
                request_timeout_sec: LEASE_REQUEST_TIMEOUT_SEC,
            },
            vip: raw.vip,
            service: service.ok_or_else(|| ConfigError::Validation(errors.clone()))?,
            group,
            health: HealthConfig {
                command: raw.health.command,
                interval_sec: 2,
                timeout_sec: raw.health.timeout_sec,
                failure_threshold: raw.health.failure_threshold,
                success_threshold: raw.health.success_threshold,
                on_failure: raw.health.on_failure,
                restart_limit: raw
                    .health
                    .restart_limit
                    .unwrap_or(DEFAULT_HEALTH_RESTART_LIMIT),
            },
            fencing,
            route: None,
            security: SecurityConfig {
                psk_file: raw.security.psk_file,
            },
            state: StateConfig {
                path: two_node
                    .as_ref()
                    .map(|two_node| two_node.state_path.clone())
                    .unwrap_or_else(default_state_path),
            },
            failover: raw.failover.into(),
            control: raw.control.into(),
            topology: Topology::TwoNode,
            two_node,
        })
    }

    /// Whether this node is the canonical inbound node (the higher node id).
    pub fn is_inbound(&self) -> bool {
        self.node.id.as_str() > self.peer.id.as_str()
    }

    /// Non-fatal start-up notices (ADD-10), reported once at start.
    pub fn startup_warnings(&self) -> Vec<String> {
        if let Some(two_node) = &self.two_node {
            let mut warnings = two_node.warnings(self.failover.auto, self.verify_window_ms());
            if let (Some(window), Some(fencing)) = (self.verify_window_ms(), &self.fencing) {
                let fence_ms = fencing
                    .fence_timeout_sec
                    .unwrap_or(DEFAULT_FENCE_TIMEOUT_SEC)
                    .saturating_mul(1_000);
                let cycle_ms = self.failover.cycle_timeout_sec.saturating_mul(1_000);
                if fence_ms.saturating_add(window) > cycle_ms {
                    warnings.push(format!(
                        "two-node: failover.cycle_timeout_sec ({} s) is shorter than \
                         fencing.fence_timeout_sec plus the verification window (about {} s): \
                         an automatic fence cycle ends before its last verify poll (fails \
                         safe, without promotion); raise cycle_timeout_sec",
                        self.failover.cycle_timeout_sec,
                        fence_ms.saturating_add(window) / 1000
                    ));
                }
            }
            return warnings;
        }
        let mut warnings = Vec::new();
        let command_fencing = self
            .fencing
            .as_ref()
            .is_some_and(|fencing| fencing.backend == FencingBackendKind::Command);
        if self.failover.auto && !command_fencing {
            warnings.push(
                "failover.auto is true but fencing.backend is not \"command\": automatic \
                 failover after peer loss stays disabled (cold-start Bootstrap Admission and \
                 manual SIGUSR1 promotion still work)"
                    .to_string(),
            );
        }
        warnings
    }

    fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        let same_id = raw.node.id == raw.peer.id;
        let inbound = raw.node.id.as_str() > raw.peer.id.as_str();

        // node.listen / peer.address are role-dependent (the canonical
        // direction: the lower node id dials, the higher accepts).
        let mut heartbeat_port = 0u16;
        let mut bind_address = None;
        if !same_id {
            if inbound {
                match raw.node.listen.as_deref() {
                    None => errors.push(
                        "node.listen is required on the inbound node (the higher node id)"
                            .to_string(),
                    ),
                    Some(listen) => match listen.parse::<SocketAddr>() {
                        Ok(SocketAddr::V4(address)) => {
                            heartbeat_port = address.port();
                            bind_address = Some(address.ip().to_string());
                        }
                        _ => errors.push("node.listen must be an IPv4 ip:port".to_string()),
                    },
                }
                if raw.peer.address.is_some() {
                    errors.push(
                        "peer.address is not valid on the inbound node (the peer dials this node)"
                            .to_string(),
                    );
                }
            } else {
                match raw.peer.address.as_deref() {
                    None => errors.push(
                        "peer.address is required on the outbound node (the lower node id)"
                            .to_string(),
                    ),
                    Some(address) => {
                        if address.parse::<SocketAddr>().is_err() {
                            errors.push("peer.address must be a valid socket address".to_string());
                        }
                    }
                }
                if raw.node.listen.is_some() {
                    errors.push(
                        "node.listen is not valid on the outbound node (this node dials the peer)"
                            .to_string(),
                    );
                }
            }
        }
        if !errors.is_empty() {
            return Err(ConfigError::Validation(errors));
        }

        let (own_priority, peer_priority) = if raw.node.preferred {
            (PRIORITY_PREFERRED, PRIORITY_STANDBY)
        } else {
            (PRIORITY_STANDBY, PRIORITY_PREFERRED)
        };
        if raw
            .cluster
            .topology
            .as_deref()
            .is_some_and(|topology| topology != "witness")
        {
            return Err(ConfigError::Validation(vec![
                "cluster.topology must be \"witness\" or \"two-node\"".to_string(),
            ]));
        }
        let fencing = raw.fencing.map(fill_fencing_defaults);
        let control = raw.control.into();
        Ok(Self {
            cluster: ClusterConfig {
                id: raw.cluster.id,
                mode: Mode::Conservative,
                heartbeat_port,
            },
            node: NodeConfig {
                id: raw.node.id,
                preferred: raw.node.preferred,
                listen: raw.node.listen,
                priority: own_priority,
                bind_address,
            },
            peer: PeerConfig {
                id: raw.peer.id,
                address: raw.peer.address,
                priority: peer_priority,
            },
            heartbeat: HeartbeatConfig {
                interval_sec: HEARTBEAT_INTERVAL_SEC,
                suspect_after_sec: HEARTBEAT_SUSPECT_AFTER_SEC,
                unreachable_after_sec: HEARTBEAT_UNREACHABLE_AFTER_SEC,
                connect_timeout_sec: HEARTBEAT_CONNECT_TIMEOUT_SEC,
            },
            witness: Some(WitnessConfig {
                enabled: Some(true),
                id: Some(raw.witness.id),
                address: Some(raw.witness.address),
            }),
            lease: LeaseConfig {
                ttl_sec: LEASE_TTL_SEC,
                renew_interval_sec: LEASE_RENEW_INTERVAL_SEC,
                request_timeout_sec: LEASE_REQUEST_TIMEOUT_SEC,
            },
            vip: raw.vip,
            service: raw.service,
            group: None,
            health: HealthConfig {
                command: raw.health.command,
                interval_sec: 2,
                timeout_sec: raw.health.timeout_sec,
                failure_threshold: raw.health.failure_threshold,
                success_threshold: raw.health.success_threshold,
                // Validated below: the Witness topology only warns.
                on_failure: raw.health.on_failure,
                restart_limit: raw
                    .health
                    .restart_limit
                    .unwrap_or(DEFAULT_HEALTH_RESTART_LIMIT),
            },
            fencing,
            route: raw.route,
            security: SecurityConfig {
                psk_file: raw.security.psk_file,
            },
            state: raw.state,
            failover: raw.failover.into(),
            control,
            topology: Topology::Witness,
            two_node: None,
        })
    }

    /// The approximate fence verification window (`verify_polls` polls, one every
    /// `two_node::config::VERIFY_INTERVAL_MS`), when command fencing is configured.
    pub fn verify_window_ms(&self) -> Option<u64> {
        let fencing = self.fencing.as_ref()?;
        if fencing.backend != FencingBackendKind::Command {
            return None;
        }
        Some(
            fencing
                .verify_polls
                .unwrap_or(DEFAULT_VERIFY_POLLS)
                .saturating_mul(crate::two_node::config::VERIFY_INTERVAL_MS),
        )
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        validate_id("cluster.id", &self.cluster.id, &mut errors);
        validate_id("node.id", &self.node.id, &mut errors);
        validate_id("peer.id", &self.peer.id, &mut errors);
        if self.node.id == self.peer.id {
            errors.push("node.id and peer.id must be different".to_string());
        }

        if let Err(error) = validate_ipv4_cidr(&self.vip.address) {
            errors.push(format!("vip.address: {error}"));
        }
        if self.vip.interface.trim().is_empty() {
            errors.push("vip.interface must not be empty".to_string());
        }
        if self.vip.arp_count == 0 {
            errors.push("vip.arp_count must be at least 1".to_string());
        }

        validate_service("service", &self.service, &mut errors);
        if let Some(group) = &self.group {
            for (index, resource) in group.resources.iter().enumerate() {
                if let GroupResourceKind::Service(service) = &resource.kind {
                    validate_service(&format!("group.resource[{index}]"), service, &mut errors);
                }
            }
        }

        validate_command(
            "health.command",
            &Some(self.health.command.clone()),
            &mut errors,
        );
        validate_seconds(
            "health.timeout_sec",
            Some(self.health.timeout_sec),
            &mut errors,
        );
        if self.health.failure_threshold == 0 {
            errors.push("health.failure_threshold must be at least 1".to_string());
        }
        if self.health.success_threshold == 0 {
            errors.push("health.success_threshold must be at least 1".to_string());
        }
        if self.topology == Topology::Witness && self.health.on_failure != HealthAction::Warn {
            errors
                .push("health.on_failure: the Witness topology supports only \"warn\"".to_string());
        }
        if self.topology == Topology::TwoNode
            && self.health.timeout_sec > HEALTH_LOOP_TIMEOUT_LIMIT_SEC
        {
            errors.push(format!(
                "health.timeout_sec: the two-node daemon runs the health check in its control \
                 loop; at most {HEALTH_LOOP_TIMEOUT_LIMIT_SEC} seconds"
            ));
        }
        if !(1..=10).contains(&self.health.restart_limit) {
            errors.push("health.restart_limit must be between 1 and 10".to_string());
        }

        if let Some(witness) = &self.witness {
            if let Some(id) = &witness.id {
                validate_id("witness.id", id, &mut errors);
            }
            match witness.address.as_deref() {
                None => errors.push("witness.address is required".to_string()),
                Some(address) => {
                    if address.trim().is_empty() || address.parse::<SocketAddr>().is_err() {
                        errors.push("witness.address must be a valid socket address".to_string());
                    }
                }
            }
        }

        // Stage 14 Design Revision 5 §16.1/§16.5: the one `[fencing]`
        // validator, which owns the step-timeout maxima. An absent section is
        // backend `none`.
        if let Err(fencing) =
            crate::fencing_backend::FencingSettings::from_config(self.fencing.as_ref())
        {
            errors.extend(fencing);
        }

        self.validate_failover(&mut errors);
        self.validate_route(&mut errors);

        if self.security.psk_file.trim().is_empty() {
            errors.push("security.psk_file must not be empty".to_string());
        } else if !Path::new(&self.security.psk_file).is_absolute() {
            errors.push("security.psk_file must be an absolute path".to_string());
        }
        if self.state.path.trim().is_empty() {
            errors.push("state.path must not be empty".to_string());
        } else if !Path::new(&self.state.path).is_absolute() {
            errors.push("state.path must be an absolute path".to_string());
        }
        for (field, value) in [
            ("control.lock_path", &self.control.lock_path),
            (
                "control.manual_barrier_path",
                &self.control.manual_barrier_path,
            ),
        ] {
            if value.trim().is_empty() {
                errors.push(format!("{field} must not be empty"));
            } else if !clean_abs_path(value) {
                errors.push(format!(
                    "{field} must be a clean absolute path without '..' or control characters"
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Validation(errors))
        }
    }

    /// v0.7 G-2: `[route]` needs the command fencing backend (the RH steps share its executor and
    /// its pending-reap slot) and clean absolute paths.
    fn validate_route(&self, errors: &mut Vec<String>) {
        let Some(route) = &self.route else {
            return;
        };
        let command_fencing = self
            .fencing
            .as_ref()
            .is_some_and(|fencing| fencing.backend == FencingBackendKind::Command);
        if !command_fencing {
            errors.push("route requires fencing.backend = \"command\"".to_string());
        }
        for (field, value) in [
            ("route.helper", &route.helper),
            ("route.helper_config", &route.helper_config),
            ("route.intent_dir", &route.intent_dir),
        ] {
            if !clean_abs_path(value) {
                errors.push(format!(
                    "{field} must be a clean absolute path without '..' or control characters"
                ));
            }
        }
        if !(1..=ROUTE_CONFIRM_HOLD_LIMIT_SEC).contains(&route.confirm_hold_sec) {
            errors.push(format!(
                "route.confirm_hold_sec must be between 1 and {ROUTE_CONFIRM_HOLD_LIMIT_SEC}"
            ));
        }
        if !(ROUTE_DEADLINE_FLOOR_SEC..=ROUTE_DEADLINE_LIMIT_SEC).contains(&route.deadline_sec)
            || route.deadline_sec < route.confirm_hold_sec
        {
            errors.push(format!(
                "route.deadline_sec must be between {ROUTE_DEADLINE_FLOOR_SEC} and \
                 {ROUTE_DEADLINE_LIMIT_SEC} and at least confirm_hold_sec"
            ));
        }
    }

    /// ADD-10: cross-key start-up consistency of `[failover]` and `[fencing]`.
    fn validate_failover(&self, errors: &mut Vec<String>) {
        let failover = &self.failover;
        for (field, value) in [
            ("dwell_sec", failover.dwell_sec),
            ("bootstrap_dwell_sec", failover.bootstrap_dwell_sec),
            ("bootstrap_defer_sec", failover.bootstrap_defer_sec),
            ("cycle_timeout_sec", failover.cycle_timeout_sec),
        ] {
            if value == 0 {
                errors.push(format!("failover.{field} must be at least 1 second"));
            }
        }
        if !(1..=3).contains(&failover.max_fence_actions) {
            errors.push("failover.max_fence_actions must be between 1 and 3".to_string());
        }
        if let Some(fencing) = &self.fencing
            && fencing.backend == FencingBackendKind::Command
        {
            let fence = fencing
                .fence_timeout_sec
                .unwrap_or(DEFAULT_FENCE_TIMEOUT_SEC);
            let verify = fencing
                .verify_timeout_sec
                .unwrap_or(DEFAULT_VERIFY_TIMEOUT_SEC);
            if fence.saturating_add(verify) > failover.cycle_timeout_sec {
                errors.push(
                    "fencing.fence_timeout_sec + verify_timeout_sec must fit \
                     failover.cycle_timeout_sec"
                        .to_string(),
                );
            }
        }
    }
}

fn fill_fencing_defaults(mut fencing: FencingConfig) -> FencingConfig {
    if fencing.backend == FencingBackendKind::Command {
        fencing
            .fence_timeout_sec
            .get_or_insert(DEFAULT_FENCE_TIMEOUT_SEC);
        fencing
            .verify_timeout_sec
            .get_or_insert(DEFAULT_VERIFY_TIMEOUT_SEC);
        fencing.verify_polls.get_or_insert(DEFAULT_VERIFY_POLLS);
    }
    fencing
}

impl From<RawFailover> for FailoverConfig {
    fn from(raw: RawFailover) -> Self {
        Self {
            auto: raw.auto,
            dwell_sec: raw.dwell_sec,
            bootstrap_dwell_sec: raw.bootstrap_dwell_sec,
            bootstrap_defer_sec: raw.bootstrap_defer_sec,
            max_fence_actions: raw.max_fence_actions,
            cycle_timeout_sec: raw.cycle_timeout_sec,
        }
    }
}

impl From<RawControl> for ControlPlaneConfig {
    fn from(raw: RawControl) -> Self {
        Self {
            lock_path: raw
                .lock_path
                .unwrap_or_else(|| crate::control_lock::DEFAULT_LOCK_PATH.to_string()),
            manual_barrier_path: raw
                .manual_barrier_path
                .unwrap_or_else(|| crate::manual_barrier::DEFAULT_BARRIER_PATH.to_string()),
        }
    }
}

pub(crate) fn clean_abs_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && !value.contains("..")
        && !value.contains("//")
        && !value.chars().any(char::is_control)
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn validate_id(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.is_empty() {
        errors.push(format!("{field} must not be empty"));
    } else if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        errors.push(format!(
            "{field} must not contain whitespace or control characters"
        ));
    }
}

/// Upper bound (24 hours) for one service or health command's timeout. It
/// keeps every deadline representable; a larger value is a typo, not a policy.
pub const ACTION_TIMEOUT_CEILING_SEC: u64 = 86_400;

fn validate_seconds(field: &str, value: Option<u64>, errors: &mut Vec<String>) {
    if value == Some(0) {
        errors.push(format!("{field} must be at least 1 second"));
    }
    if value.is_some_and(|seconds| seconds > ACTION_TIMEOUT_CEILING_SEC) {
        errors.push(format!(
            "{field} must not exceed {ACTION_TIMEOUT_CEILING_SEC} seconds"
        ));
    }
}

/// The `[service]` rules, for the single service (`prefix` = "service") and for every
/// service of a group (`prefix` = "group.resource[N]").
fn validate_service(prefix: &str, service: &ServiceConfig, errors: &mut Vec<String>) {
    match service.manager {
        ServiceManager::Systemd => {
            if service
                .unit
                .as_deref()
                .is_none_or(|unit| unit.trim().is_empty())
            {
                errors.push(format!("{prefix}.unit is required for systemd manager"));
            }
            if service.start.is_some() || service.stop.is_some() || service.status.is_some() {
                errors.push(format!(
                    "{prefix}.start/stop/status are not valid for systemd manager"
                ));
            }
        }
        ServiceManager::Command => {
            validate_command(&format!("{prefix}.start"), &service.start, errors);
            validate_command(&format!("{prefix}.stop"), &service.stop, errors);
            validate_command(&format!("{prefix}.status"), &service.status, errors);
            if service.unit.is_some() {
                errors.push(format!("{prefix}.unit is not valid for command manager"));
            }
        }
    }
    validate_seconds(
        &format!("{prefix}.start_timeout_sec"),
        Some(service.start_timeout_sec),
        errors,
    );
    validate_seconds(
        &format!("{prefix}.stop_timeout_sec"),
        Some(service.stop_timeout_sec),
        errors,
    );
}

fn validate_command(field: &str, command: &Option<Vec<String>>, errors: &mut Vec<String>) {
    match command {
        Some(command) => {
            if command.is_empty() || command[0].is_empty() {
                errors.push(format!("{field} must contain a program"));
            } else if !Path::new(&command[0]).is_absolute() {
                errors.push(format!("{field}[0] must be an absolute path"));
            } else if command
                .iter()
                .any(|element| element.is_empty() || element.chars().any(char::is_control))
            {
                errors.push(format!(
                    "{field} must not contain empty or control-character elements"
                ));
            }
        }
        None => errors.push(format!("{field} is required")),
    }
}

fn validate_ipv4_cidr(value: &str) -> Result<(), &'static str> {
    let (address, prefix) = value.split_once('/').ok_or("must use IPv4/prefix format")?;
    address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "must contain a valid IPv4 address")?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| "must contain a valid prefix")?;
    if prefix > 32 {
        return Err("prefix must be between 0 and 32");
    }
    Ok(())
}

fn default_true() -> bool {
    true
}
fn default_arp_count() -> u32 {
    3
}
fn default_service_timeout() -> u64 {
    30
}
fn default_health_timeout() -> u64 {
    2
}
fn default_failure_threshold() -> u32 {
    3
}
fn default_success_threshold() -> u32 {
    2
}
fn default_state_path() -> String {
    "/var/lib/mikagami/state.toml".to_string()
}
fn default_dwell() -> u64 {
    10
}
fn default_bootstrap_dwell() -> u64 {
    20
}
fn default_bootstrap_defer() -> u64 {
    15
}
fn default_max_fence_actions() -> u64 {
    2
}
fn default_cycle_timeout() -> u64 {
    120
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The outbound (lower id), preferred node of the pair.
    const VALID: &str = r#"
[cluster]
id = "example-ha"
[node]
id = "node-a"
preferred = true
[peer]
id = "node-b"
address = "192.168.100.12:7946"
[witness]
id = "witness-1"
address = "192.168.100.13:7947"
[vip]
address = "192.168.100.50/24"
interface = "eth0"
[service]
manager = "systemd"
unit = "nginx.service"
[health]
command = ["/usr/local/bin/check-nginx"]
[security]
psk_file = "/etc/mikagami/cluster.psk"
"#;

    /// The inbound (higher id), non-preferred node of the pair.
    const VALID_INBOUND: &str = r#"
[cluster]
id = "example-ha"
[node]
id = "node-b"
listen = "192.168.100.12:7946"
[peer]
id = "node-a"
[witness]
id = "witness-1"
address = "192.168.100.13:7947"
[vip]
address = "192.168.100.50/24"
interface = "eth0"
[service]
manager = "systemd"
unit = "nginx.service"
[health]
command = ["/usr/local/bin/check-nginx"]
[security]
psk_file = "/etc/mikagami/cluster.psk"
"#;

    fn validation_error(input: &str) -> String {
        match Config::parse_str(input) {
            Err(ConfigError::Validation(errors)) => errors.join("; "),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    fn parse_error(input: &str) -> String {
        match Config::parse_str(input) {
            Err(ConfigError::Parse(error)) => error.to_string(),
            other => panic!("expected parse error, got {other:?}"),
        }
    }

    /// The shipped examples are the documented starting point: they must
    /// parse with the real parser, form a consistent pair, and stay valid
    /// when their commented fencing block is enabled.
    #[test]
    fn shipped_examples_parse_and_form_a_consistent_pair() {
        let a_text = include_str!("../contrib/examples/node-a.toml");
        let b_text = include_str!("../contrib/examples/node-b.toml");
        let a = Config::parse_str(a_text).expect("node-a.toml");
        let b = Config::parse_str(b_text).expect("node-b.toml");
        assert!(!a.is_inbound() && b.is_inbound());
        assert!(a.node.preferred && !b.node.preferred);
        assert_eq!(a.cluster.id, b.cluster.id);
        let (wa, wb) = (a.witness.as_ref().unwrap(), b.witness.as_ref().unwrap());
        assert_eq!((&wa.id, &wa.address), (&wb.id, &wb.address));
        assert_eq!(a.peer.id, b.node.id);
        assert_eq!(b.peer.id, a.node.id);
        assert_eq!(a.peer.address.as_deref(), Some("192.168.100.12:7946"));
        assert_eq!(b.node.bind_address.as_deref(), Some("192.168.100.12"));
        assert_eq!(a.node.priority, b.peer.priority);
        assert_eq!(a.peer.priority, b.node.priority);
        // Without a fence command the one startup warning explains why
        // automatic takeover of a lost peer cannot act.
        assert_eq!(a.startup_warnings().len(), 1);
        for text in [a_text, b_text] {
            let enabled = text
                .lines()
                .map(|line| {
                    let keep = ["# [fencing]", "# backend", "# fence", "# verify"]
                        .iter()
                        .any(|prefix| line.starts_with(prefix));
                    if keep { &line[2..] } else { line }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let config = Config::parse_str(&enabled).expect("example with fencing enabled");
            assert!(
                config.startup_warnings().is_empty(),
                "{:?}",
                config.startup_warnings()
            );
        }
    }

    #[test]
    fn parses_outbound_preferred_node_and_derives_internal_values() {
        let config = Config::parse_str(VALID).expect("valid config should parse");
        assert_eq!(config.cluster.mode, Mode::Conservative);
        assert!(!config.is_inbound());
        assert_eq!(config.node.priority, PRIORITY_PREFERRED);
        assert_eq!(config.peer.priority, PRIORITY_STANDBY);
        assert_eq!(config.peer.address.as_deref(), Some("192.168.100.12:7946"));
        assert_eq!(config.node.bind_address, None);
        assert_eq!(config.heartbeat.interval_sec, 1);
        assert_eq!(config.heartbeat.unreachable_after_sec, 10);
        assert_eq!(config.lease.ttl_sec, 10);
        assert_eq!(config.vip.arp_count, 3);
        assert_eq!(config.health.failure_threshold, 3);
        assert_eq!(config.service.manager, ServiceManager::Systemd);
        assert_eq!(config.state.path, "/var/lib/mikagami/state.toml");
        let witness = config.witness.as_ref().unwrap();
        assert_eq!(witness.enabled, Some(true));
        assert_eq!(witness.id.as_deref(), Some("witness-1"));
        assert!(config.failover.auto);
        assert_eq!(config.failover.max_fence_actions, 2);
        assert_eq!(config.failover.cycle_timeout_sec, 120);
    }

    #[test]
    fn parses_inbound_standby_node_and_derives_listen() {
        let config = Config::parse_str(VALID_INBOUND).expect("inbound config should parse");
        assert!(config.is_inbound());
        assert_eq!(config.node.priority, PRIORITY_STANDBY);
        assert_eq!(config.peer.priority, PRIORITY_PREFERRED);
        assert_eq!(config.node.bind_address.as_deref(), Some("192.168.100.12"));
        assert_eq!(config.cluster.heartbeat_port, 7946);
        assert_eq!(config.peer.address, None);
    }

    /// Plan WU-2: the derived priorities make a both-preferred and a
    /// both-standby configuration disagree at HELLO (each side expects the
    /// opposite of its own), so the misconfiguration is refused at connect.
    #[test]
    fn derived_priorities_disagree_for_two_preferred_or_two_standby_nodes() {
        let a = Config::parse_str(VALID).unwrap();
        let b = Config::parse_str(VALID_INBOUND).unwrap();
        // a correct pair: A's own priority is what B expects of its peer.
        assert_eq!(a.node.priority, b.peer.priority);
        assert_eq!(b.node.priority, a.peer.priority);
        let b_preferred =
            Config::parse_str(&VALID_INBOUND.replace("[node]\n", "[node]\npreferred = true\n"))
                .unwrap();
        assert_ne!(a.node.priority, b_preferred.peer.priority);
        let a_standby = Config::parse_str(&VALID.replace("preferred = true\n", "")).unwrap();
        assert_ne!(a_standby.node.priority, b.peer.priority);
    }

    #[test]
    fn parses_command_service_config() {
        let input = VALID.replace(
            "manager = \"systemd\"\nunit = \"nginx.service\"",
            "manager = \"command\"\nstart = [\"/opt/app/start\", \"--foreground\"]\nstop = [\"/opt/app/stop\"]\nstatus = [\"/opt/app/status\"]",
        );
        let config = Config::parse_str(&input).expect("command config should parse");
        assert_eq!(config.service.manager, ServiceManager::Command);
        assert_eq!(config.service.unit, None);
        assert_eq!(config.service.start.as_ref().unwrap()[0], "/opt/app/start");
        assert_eq!(
            config.service.status.as_ref().unwrap()[0],
            "/opt/app/status"
        );
    }

    #[test]
    fn command_service_requires_start_stop_and_status() {
        let input = VALID.replace("manager = \"systemd\"", "manager = \"command\"");
        let error = validation_error(&input.replace("unit = \"nginx.service\"\n", ""));
        for key in ["service.start", "service.stop", "service.status"] {
            assert!(error.contains(&format!("{key} is required")), "{error}");
        }
        let with_unit = validation_error(&input);
        assert!(with_unit.contains("service.unit is not valid for command manager"));
    }

    #[test]
    fn systemd_service_rejects_command_keys() {
        let input = VALID.replace(
            "unit = \"nginx.service\"",
            "unit = \"nginx.service\"\nstatus = [\"/opt/app/status\"]",
        );
        assert!(validation_error(&input).contains("not valid for systemd manager"));
    }

    #[test]
    fn rejects_command_elements_that_are_empty_or_control_characters() {
        let input = VALID.replace(
            "[\"/usr/local/bin/check-nginx\"]",
            "[\"/usr/local/bin/check-nginx\", \"\"]",
        );
        assert!(validation_error(&input).contains("empty or control-character"));
        let input = VALID.replace(
            "[\"/usr/local/bin/check-nginx\"]",
            "[\"/usr/local/bin/check-nginx\", \"a\\u0001b\"]",
        );
        assert!(validation_error(&input).contains("empty or control-character"));
    }

    /// Plan WU-2 / Owner A-6: every key that v1.0 removed is rejected by name
    /// instead of being accepted and ignored.
    #[test]
    fn removed_keys_are_rejected_not_ignored() {
        let removed: &[(&str, &str)] = &[
            ("[cluster]\n", "mode = \"conservative\"\n"),
            ("[cluster]\n", "heartbeat_port = 7946\n"),
            ("[node]\n", "priority = 100\n"),
            ("[node]\n", "bind_address = \"0.0.0.0\"\n"),
            ("[peer]\n", "priority = 90\n"),
            ("[witness]\n", "enabled = true\n"),
            ("[vip]\n", "unknown_key = 1\n"),
            ("[health]\n", "interval_sec = 2\n"),
            ("[security]\n", "require_peer_auth = true\n"),
            ("[security]\n", "require_witness_auth = true\n"),
        ];
        for (section, line) in removed {
            let input = VALID.replace(section, &format!("{section}{line}"));
            let error = parse_error(&input);
            assert!(error.contains("unknown field"), "{line}: {error}");
        }
        for table in [
            "[heartbeat]\ninterval_sec = 1\n",
            "[lease]\nttl_sec = 10\n",
            "[hooks]\npre_promote = [\"/opt/hooks/pre\"]\n",
            "[timeouts]\npromotion_timeout_sec = 60\n",
            "[cooldown]\nrejoin_sec = 30\n",
            "[logging]\nlevel = \"debug\"\n",
        ] {
            let error = parse_error(&format!("{VALID}\n{table}"));
            assert!(error.contains("unknown field"), "{table}: {error}");
        }
    }

    #[test]
    fn rejects_toml_syntax_error() {
        assert!(matches!(
            Config::parse_str("[cluster"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn rejects_missing_required_section() {
        for section in [
            "[peer]\nid = \"node-b\"\naddress = \"192.168.100.12:7946\"\n",
            "[witness]\nid = \"witness-1\"\naddress = \"192.168.100.13:7947\"\n",
        ] {
            assert!(matches!(
                Config::parse_str(&VALID.replace(section, "")),
                Err(ConfigError::Parse(_))
            ));
        }
    }

    #[test]
    fn rejects_unknown_field() {
        let input = VALID.replace("id = \"example-ha\"", "id = \"example-ha\"\nunknown = true");
        assert!(parse_error(&input).contains("unknown"));
    }

    #[test]
    fn rejects_id_collision() {
        let input = VALID.replace("id = \"node-b\"", "id = \"node-a\"");
        let error = validation_error(&input);
        assert!(error.contains("node.id and peer.id must be different"));
    }

    #[test]
    fn role_dependent_keys_are_required_and_rejected_by_role() {
        // outbound (lower id): peer.address required, node.listen rejected
        let error = validation_error(&VALID.replace("address = \"192.168.100.12:7946\"\n", ""));
        assert!(error.contains("peer.address is required on the outbound node"));
        let error = validation_error(
            &VALID.replace("[node]\n", "[node]\nlisten = \"192.168.100.11:7946\"\n"),
        );
        assert!(error.contains("node.listen is not valid on the outbound node"));
        // inbound (higher id): node.listen required, peer.address rejected
        let error =
            validation_error(&VALID_INBOUND.replace("listen = \"192.168.100.12:7946\"\n", ""));
        assert!(error.contains("node.listen is required on the inbound node"));
        let error = validation_error(
            &VALID_INBOUND.replace("[peer]\n", "[peer]\naddress = \"192.168.100.11:7946\"\n"),
        );
        assert!(error.contains("peer.address is not valid on the inbound node"));
        // malformed values
        let error = validation_error(&VALID.replace("192.168.100.12:7946", "not-an-address"));
        assert!(error.contains("peer.address must be a valid socket address"));
        let error = validation_error(&VALID_INBOUND.replace("192.168.100.12:7946", "not-an-ip"));
        assert!(error.contains("node.listen must be an IPv4 ip:port"));
    }

    #[test]
    fn rejects_malformed_witness_and_whitespace_strings() {
        let error = validation_error(&VALID.replace("192.168.100.13:7947", "witness-host"));
        assert!(error.contains("witness.address must be a valid socket address"));
        let unit = VALID.replace("unit = \"nginx.service\"", "unit = \"   \"");
        assert!(validation_error(&unit).contains("service.unit is required"));
        let id = VALID.replace("id = \"witness-1\"", "id = \"wit ness\"");
        assert!(validation_error(&id).contains("witness.id must not contain whitespace"));
    }

    #[test]
    fn rejects_invalid_vip_and_zero_values() {
        let input = VALID.replace("192.168.100.50/24", "not-an-ip");
        assert!(validation_error(&input).contains("vip.address"));
        let input = VALID.replace(
            "[health]\n",
            "[health]\ntimeout_sec = 0\nfailure_threshold = 0\nsuccess_threshold = 0\n",
        );
        let error = validation_error(&input);
        assert!(error.contains("health.timeout_sec"));
        assert!(error.contains("health.failure_threshold"));
        assert!(error.contains("health.success_threshold"));
    }

    /// N-1: every service / health timeout has an explicit range, and a value
    /// outside it is refused (never clamped) so no deadline can overflow.
    #[test]
    fn action_timeouts_are_bounded_at_both_ends() {
        let with = |key: &str, section: &str, seconds: &str| {
            let header = format!("[{section}]\n");
            VALID.replace(&header, &format!("{header}{key} = {seconds}\n"))
        };
        let max = ACTION_TIMEOUT_CEILING_SEC.to_string();
        let over = (ACTION_TIMEOUT_CEILING_SEC + 1).to_string();
        let huge = u64::MAX.to_string();
        for (key, section) in [
            ("start_timeout_sec", "service"),
            ("stop_timeout_sec", "service"),
            ("timeout_sec", "health"),
        ] {
            let field = format!("{section}.{key}");
            for accepted in ["1", "30", max.as_str()] {
                Config::parse_str(&with(key, section, accepted))
                    .unwrap_or_else(|error| panic!("{field} = {accepted}: {error:?}"));
            }
            for refused in [over.as_str(), huge.as_str()] {
                let error = validation_error(&with(key, section, refused));
                assert!(
                    error.contains(&format!(
                        "{field} must not exceed {ACTION_TIMEOUT_CEILING_SEC}"
                    )),
                    "{field} = {refused}: {error}"
                );
            }
            assert!(validation_error(&with(key, section, "0")).contains("at least 1 second"));
        }
    }

    #[test]
    fn rejects_relative_command_and_psk_paths() {
        let input = VALID
            .replace("/usr/local/bin/check-nginx", "check-nginx")
            .replace("/etc/mikagami/cluster.psk", "cluster.psk");
        let error = validation_error(&input);
        assert!(error.contains("health.command[0]"));
        assert!(error.contains("security.psk_file"));
    }

    #[test]
    fn failover_defaults_and_cross_key_consistency() {
        let defaults = Config::parse_str(VALID).unwrap().failover;
        assert!(defaults.auto);
        assert_eq!(defaults.dwell_sec, 10);
        assert_eq!(defaults.bootstrap_dwell_sec, 20);
        assert_eq!(defaults.bootstrap_defer_sec, 15);
        // The fence-side delays of the proposal were removed (final review
        // R6/R12): they are unknown keys now.
        for removed in ["idle_dwell_sec", "standby_delay_sec"] {
            let input = format!("{VALID}\n[failover]\n{removed} = 150\n");
            assert!(parse_error(&input).contains("unknown field"), "{removed}");
        }
        let input = format!("{VALID}\n[failover]\nmax_fence_actions = 4\n");
        assert!(validation_error(&input).contains("max_fence_actions must be between 1 and 3"));
        let input = format!("{VALID}\n[failover]\ndwell_sec = 0\n");
        assert!(validation_error(&input).contains("failover.dwell_sec"));
        let input = format!("{VALID}\n[failover]\nunknown = 1\n");
        assert!(parse_error(&input).contains("unknown field"));
    }

    #[test]
    fn auto_with_fencing_none_warns_once_at_start() {
        let none = Config::parse_str(VALID).unwrap();
        assert_eq!(none.startup_warnings().len(), 1);
        let disabled = Config::parse_str(&format!("{VALID}\n[failover]\nauto = false\n")).unwrap();
        assert!(disabled.startup_warnings().is_empty());
        let command = Config::parse_str(&format!("{VALID}\n{STAGE14_7_COMMAND}")).unwrap();
        assert!(command.startup_warnings().is_empty());
    }

    #[test]
    fn fence_and_verify_timeouts_must_fit_the_cycle() {
        let input = format!(
            "{VALID}\n[failover]\ncycle_timeout_sec = 60\n\
             \n[fencing]\nbackend = \"command\"\nfence = [\"/a\"]\nverify = [\"/b\"]\n\
             fence_timeout_sec = 55\nverify_timeout_sec = 10\n"
        );
        assert!(validation_error(&input).contains("must fit failover.cycle_timeout_sec"));
    }

    /// v0.7 G-2: `[route]` needs the command fencing backend, clean absolute paths and ranges
    /// that keep the deadline at least the confirmation hold. The step budget has no key.
    #[test]
    fn g2_route_section_is_strict() {
        let route = "[route]\nhelper = \"/usr/lib/mikagami/mikagami-gce-fence\"\nhelper_config = \"/etc/mikagami/gce-fence.toml\"\nintent_dir = \"/var/lib/mikagami/route\"\n";
        let ok = Config::parse_str(&format!("{VALID}\n{STAGE14_7_COMMAND}\n{route}")).unwrap();
        let section = ok.route.as_ref().unwrap();
        assert_eq!((section.confirm_hold_sec, section.deadline_sec), (30, 300));
        assert!(
            validation_error(&format!("{VALID}\n{route}"))
                .contains("route requires fencing.backend = \"command\"")
        );
        for (line, expected) in [
            ("confirm_hold_sec = 0", "route.confirm_hold_sec"),
            ("confirm_hold_sec = 601", "route.confirm_hold_sec"),
            ("deadline_sec = 29", "route.deadline_sec"),
            ("deadline_sec = 3601", "route.deadline_sec"),
        ] {
            let input = format!("{VALID}\n{STAGE14_7_COMMAND}\n{route}{line}\n");
            assert!(validation_error(&input).contains(expected), "{line}");
        }
        let short_deadline = format!(
            "{VALID}\n{STAGE14_7_COMMAND}\n{route}confirm_hold_sec = 120\ndeadline_sec = 60\n"
        );
        assert!(validation_error(&short_deadline).contains("at least confirm_hold_sec"));
        let relative = route.replace("/var/lib/mikagami/route", "var/route");
        assert!(
            validation_error(&format!("{VALID}\n{STAGE14_7_COMMAND}\n{relative}"))
                .contains("route.intent_dir must be a clean absolute path")
        );
        for unknown in ["step_timeout_ms = 9000", "min_lease_remaining_ms = 1"] {
            assert!(
                Config::parse_str(&format!("{VALID}\n{STAGE14_7_COMMAND}\n{route}{unknown}\n"))
                    .is_err(),
                "{unknown} is not a key"
            );
        }
    }

    const STAGE14_7_COMMAND: &str = "[fencing]\nbackend = \"command\"\nfence = [\"/usr/local/libexec/mikagami/fence-peer\", \"--off\"]\nverify = [\"/usr/local/libexec/mikagami/verify-peer\"]\nfence_timeout_sec = 30\nverify_timeout_sec = 10\nverify_polls = 6\n";

    fn stage14_7_with(section: &str) -> String {
        format!("{VALID}\n{section}")
    }

    fn stage14_7_command(key: &str, line: &str) -> String {
        let section: Vec<&str> = STAGE14_7_COMMAND
            .lines()
            .filter(|existing| !existing.starts_with(&format!("{key} =")))
            .collect();
        stage14_7_with(&format!("{}\n{line}\n", section.join("\n")))
    }

    fn stage14_7_parse_error(input: &str) -> String {
        parse_error(input)
    }

    /// Revision 5 §16.1: an absent `[fencing]` section is backend `none`.
    #[test]
    fn stage14_7_absent_section_is_backend_none() {
        let config = Config::parse_str(VALID).unwrap();
        assert!(config.fencing.is_none());
        assert_eq!(
            crate::fencing_backend::FencingSettings::from_config(config.fencing.as_ref()),
            Ok(crate::fencing_backend::FencingSettings::None)
        );
    }

    #[test]
    fn stage14_7_backend_none_accepts_no_argv() {
        let config = Config::parse_str(&stage14_7_with("[fencing]\nbackend = \"none\"\n")).unwrap();
        let section = config.fencing.as_ref().unwrap();
        assert_eq!(section.backend, FencingBackendKind::None);
        assert_eq!(
            crate::fencing_backend::FencingSettings::from_config(Some(section)),
            Ok(crate::fencing_backend::FencingSettings::None)
        );
        for field in ["fence", "verify"] {
            let input = stage14_7_with(&format!(
                "[fencing]\nbackend = \"none\"\n{field} = [\"/usr/bin/true\"]\n"
            ));
            assert!(
                validation_error(&input).contains(&format!(
                    "fencing.{field} is not valid for backend \"none\""
                )),
                "{field}"
            );
        }
    }

    #[test]
    fn stage14_7_backend_command_parses_to_validated_settings() {
        let config = Config::parse_str(&stage14_7_with(STAGE14_7_COMMAND)).unwrap();
        let settings =
            crate::fencing_backend::FencingSettings::from_config(config.fencing.as_ref()).unwrap();
        let crate::fencing_backend::FencingSettings::Command(command) = settings else {
            panic!("expected command settings");
        };
        assert_eq!(
            command.fence,
            ["/usr/local/libexec/mikagami/fence-peer", "--off"]
        );
        assert_eq!(command.verify, ["/usr/local/libexec/mikagami/verify-peer"]);
        assert_eq!(command.fence_timeout.duration().as_secs(), 30);
        assert_eq!(command.verify_timeout.duration().as_secs(), 10);
        assert_eq!(command.verify_polls, 6);
    }

    /// Plan WU-2: the bounded values default to 30 / 10 / 10 when omitted.
    #[test]
    fn command_backend_bounded_values_have_defaults() {
        let section = "[fencing]\nbackend = \"command\"\nfence = [\"/usr/local/libexec/f\"]\nverify = [\"/usr/local/libexec/v\"]\n";
        let config = Config::parse_str(&stage14_7_with(section)).unwrap();
        let settings =
            crate::fencing_backend::FencingSettings::from_config(config.fencing.as_ref()).unwrap();
        let crate::fencing_backend::FencingSettings::Command(command) = settings else {
            panic!("expected command settings");
        };
        assert_eq!(command.fence_timeout.duration().as_secs(), 30);
        assert_eq!(command.verify_timeout.duration().as_secs(), 10);
        assert_eq!(command.verify_polls, 10);
    }

    /// G5: unknown backend, unknown key, missing backend and malformed argv
    /// types are strict parse failures (`deny_unknown_fields`).
    #[test]
    fn stage14_7_g5_strict_parse_failures() {
        let backend = stage14_7_command("backend", "backend = \"ipmi\"");
        assert!(stage14_7_parse_error(&backend).contains("unknown variant"));
        let key = stage14_7_command("verify_polls", "verify_polls = 6\nretries = 3");
        assert!(stage14_7_parse_error(&key).contains("unknown field"));
        let missing = stage14_7_with("[fencing]\nfence = [\"/usr/bin/true\"]\n");
        assert!(stage14_7_parse_error(&missing).contains("missing field `backend`"));
        for malformed in [
            "fence = \"/usr/bin/true\"",
            "fence = [1]",
            "fence_timeout_sec = \"30\"",
            "fence_timeout_sec = -1",
            "verify_polls = 1.5",
        ] {
            let key = malformed.split(' ').next().unwrap();
            let input = stage14_7_command(key, malformed);
            assert!(
                matches!(Config::parse_str(&input), Err(ConfigError::Parse(_))),
                "{malformed}"
            );
        }
    }

    /// G5: `command` without `fence` or `verify`, and empty or relative argv.
    #[test]
    fn stage14_7_g5_command_argv_rules() {
        for field in ["fence", "verify"] {
            let missing = stage14_7_command(field, "");
            assert!(
                validation_error(&missing).contains(&format!(
                    "fencing.{field} is required for backend \"command\""
                )),
                "{field}"
            );
            for empty in ["[]", "[\"\"]", "[\"\", \"--off\"]"] {
                let input = stage14_7_command(field, &format!("{field} = {empty}"));
                assert!(
                    validation_error(&input)
                        .contains(&format!("fencing.{field} must contain a program")),
                    "{field} = {empty}"
                );
            }
            let relative = stage14_7_command(field, &format!("{field} = [\"bin/{field}\"]"));
            assert!(
                validation_error(&relative)
                    .contains(&format!("fencing.{field}[0] must be an absolute path")),
                "{field}"
            );
        }
    }

    /// G5 / §34.17 / acceptance 35: 0, 1, max, max+1 for both timeouts and
    /// `verify_polls`, for either backend. (The cycle-fit rule needs a larger
    /// cycle for the maxima.)
    #[test]
    fn stage14_7_g5_timeout_and_poll_bounds() {
        for (key, maximum) in [
            ("fence_timeout_sec", 60),
            ("verify_timeout_sec", 30),
            ("verify_polls", 60),
        ] {
            for (value, accepted) in [(0, false), (1, true), (maximum, true), (maximum + 1, false)]
            {
                let line = format!("{key} = {value}");
                let command = stage14_7_command(key, &line);
                let none = stage14_7_with(&format!("[fencing]\nbackend = \"none\"\n{line}\n"));
                for input in [command, none] {
                    let result = Config::parse_str(&input);
                    if accepted {
                        assert!(result.is_ok(), "{line}: {result:?}");
                    } else {
                        assert!(
                            validation_error(&input).contains(&format!(
                                "fencing.{key} must be between 1 and {maximum}"
                            )),
                            "{line}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod control_path_tests {
    use super::*;

    const MINIMAL: &str = include_str!("../contrib/examples/node-a.toml");

    #[test]
    fn control_paths_default_to_the_shared_production_paths() {
        let config = Config::parse_str(MINIMAL).unwrap();
        assert_eq!(
            config.control.lock_path,
            crate::control_lock::DEFAULT_LOCK_PATH
        );
        assert_eq!(
            config.control.manual_barrier_path,
            crate::manual_barrier::DEFAULT_BARRIER_PATH
        );
    }

    #[test]
    fn control_paths_are_strict_and_clean() {
        let custom = format!(
            "{MINIMAL}\n[control]\nlock_path = \"/srv/mkg/control.lock\"\nmanual_barrier_path = \"/srv/mkg/manual-operation.json\"\n"
        );
        let config = Config::parse_str(&custom).unwrap();
        assert_eq!(config.control.lock_path, "/srv/mkg/control.lock");
        for bad in [
            "[control]\nlock_path = \"relative/lock\"\n",
            "[control]\nlock_path = \"/srv/../lock\"\n",
            "[control]\nmanual_barrier_path = \"/srv//barrier\"\n",
            "[control]\nunknown = 1\n",
        ] {
            let text = format!("{MINIMAL}\n{bad}");
            assert!(Config::parse_str(&text).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod shared_config_tests {
    use super::*;
    use crate::two_node::config::LinkEndpoint;
    use crate::two_node::shared::{NodeIdentity, write_identity};

    const SHARED: &str = include_str!("../contrib/examples/two-node-shared.toml");

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mkg-shared-{tag}-{}",
            crate::node_mutation::generate_uuid().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_shared_example_parses_for_both_nodes() {
        let a = Config::parse_shared(SHARED, "node-a").expect("node-a");
        let b = Config::parse_shared(SHARED, "node-b").expect("node-b");
        assert_eq!(
            (a.node.id.as_str(), a.peer.id.as_str()),
            ("node-a", "node-b")
        );
        assert_eq!(
            (b.node.id.as_str(), b.peer.id.as_str()),
            ("node-b", "node-a")
        );
        assert!(a.node.preferred && !b.node.preferred);
        assert_eq!(a.topology, Topology::TwoNode);
        let (ta, tb) = (a.two_node.as_ref().unwrap(), b.two_node.as_ref().unwrap());
        assert_eq!(
            ta.links[0].endpoint,
            LinkEndpoint::Dial("10.0.1.12:7946".parse().unwrap())
        );
        assert_eq!(
            tb.links[0].endpoint,
            LinkEndpoint::Listen("10.0.1.12:7946".parse().unwrap())
        );
        // Each node fences the other with the other's commands.
        let fa = a.fencing.as_ref().unwrap();
        let fb = b.fencing.as_ref().unwrap();
        assert_eq!(fa.fence.as_ref().unwrap()[1], "node-b");
        assert_eq!(fb.fence.as_ref().unwrap()[1], "node-a");
        assert_eq!(fa.verify_polls, Some(60));
        // The same summary on both nodes; the per-node files have none.
        assert!(ta.config_summary.is_some());
        assert_eq!(ta.config_summary, tb.config_summary);
        let legacy = Config::parse_str(include_str!("../contrib/examples/two-node-a.toml"))
            .expect("per-node file");
        assert_eq!(legacy.two_node.unwrap().config_summary, None);
    }

    #[test]
    fn the_shared_file_goes_through_the_per_node_validation() {
        // An error of a shared section is reported by the ordinary validation.
        let bad = SHARED.replace("verify_polls = 60", "verify_polls = 0");
        let error = Config::parse_shared(&bad, "node-a")
            .unwrap_err()
            .to_string();
        assert!(error.contains("verify_polls"), "{error}");
        let relative = SHARED.replace("\"/usr/local/sbin/fence-node\"", "\"fence-node\"");
        assert!(Config::parse_shared(&relative, "node-a").is_err());
        let unknown = SHARED.replace("[service]\n", "[service]\nextra = 1\n");
        assert!(Config::parse_shared(&unknown, "node-b").is_err());
        let listen = SHARED.replace(
            "address = { node-a = \"10.0.1.11\", node-b = \"10.0.1.12\" }",
            "address = { node-a = \"10.0.1.11\", node-b = \"not-an-ip\" }",
        );
        assert!(Config::parse_shared(&listen, "node-b").is_err());
        assert!(Config::parse_shared(&listen, "node-a").is_err());
    }

    #[test]
    fn parse_str_refuses_a_shared_file_without_an_identity() {
        let error = Config::parse_str(SHARED).unwrap_err().to_string();
        assert!(error.contains("registered id"), "{error}");
    }

    #[test]
    fn load_resolves_the_node_through_the_identity_file() {
        let dir = scratch("load");
        let path = dir.join("mikagami.toml");
        std::fs::write(&path, SHARED).unwrap();
        let missing = Config::load(&path).unwrap_err().to_string();
        assert!(missing.contains("not registered"), "{missing}");
        write_identity(
            &dir.join("node-id"),
            &NodeIdentity {
                cluster: "example-2n".into(),
                node: "node-b".into(),
            },
        )
        .unwrap();
        let config = Config::load(&path).expect("registered");
        assert_eq!(config.node.id, "node-b");
        // An identity of another cluster is refused.
        write_identity(
            &dir.join("node-id"),
            &NodeIdentity {
                cluster: "other".into(),
                node: "node-b".into(),
            },
        )
        .unwrap();
        let foreign = Config::load(&path).unwrap_err().to_string();
        assert!(foreign.contains("belongs to cluster"), "{foreign}");
        // An identity naming a node that is not in the file is refused.
        write_identity(
            &dir.join("node-id"),
            &NodeIdentity {
                cluster: "example-2n".into(),
                node: "node-c".into(),
            },
        )
        .unwrap();
        let unknown = Config::load(&path).unwrap_err().to_string();
        assert!(unknown.contains("not one of [nodes]"), "{unknown}");
        // The Witness topology and per-node files ignore the identity file.
        std::fs::write(&path, include_str!("../contrib/examples/node-a.toml")).unwrap();
        assert_eq!(Config::load(&path).unwrap().topology, Topology::Witness);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod group_config_tests {
    use super::*;

    const GROUP: &str = include_str!("../contrib/examples/two-node-group.toml");
    const SINGLE: &str = include_str!("../contrib/examples/two-node-a.toml");

    fn error(text: &str) -> String {
        Config::parse_shared(text, "node-a")
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn the_group_example_parses_in_order() {
        let config = Config::parse_shared(GROUP, "node-a").expect("group example");
        let group = config.group.as_ref().unwrap();
        let names: Vec<&str> = group.resources.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["db", "app", "vip"]);
        match &group.resources[1].kind {
            GroupResourceKind::Service(service) => {
                assert_eq!(service.manager, ServiceManager::Command);
                assert_eq!(service.start_timeout_sec, 60);
                assert_eq!(service.stop_timeout_sec, 30);
            }
            GroupResourceKind::Vip => panic!("app is a service"),
        }
        assert!(matches!(group.resources[2].kind, GroupResourceKind::Vip));
        // `service` mirrors the first service of the group.
        assert_eq!(config.service.unit.as_deref(), Some("postgresql.service"));
        // A per-node file with [service] keeps the single service.
        assert!(Config::parse_str(SINGLE).unwrap().group.is_none());
    }

    #[test]
    fn group_shape_errors_are_reported() {
        let service =
            "[service]\nmanager = \"systemd\"\nunit = \"x.service\"\n\n[[group.resource]]";
        assert!(
            error(&GROUP.replacen("[[group.resource]]", service, 1)).contains("exclude each other")
        );
        let no_vip = GROUP.replace(
            "name = \"vip\"\ntype = \"vip\"",
            "name = \"web\"\ntype = \"systemd\"\nunit = \"nginx.service\"",
        );
        assert!(error(&no_vip).contains("exactly one resource of type \"vip\""));
        let two_vips = format!("{GROUP}\n[[group.resource]]\nname = \"vip2\"\ntype = \"vip\"\n");
        assert!(error(&two_vips).contains("exactly one resource of type \"vip\""));
        let duplicate = GROUP.replace("name = \"app\"", "name = \"db\"");
        assert!(error(&duplicate).contains("is used twice"));
        let bad_type = GROUP.replace("type = \"command\"", "type = \"docker\"");
        assert!(error(&bad_type).contains("type must be"));
        let bad_name = GROUP.replace("name = \"app\"", "name = \"a pp\"");
        assert!(error(&bad_name).contains(".name must be"));
        let vip_extra = GROUP.replace("type = \"vip\"", "type = \"vip\"\nunit = \"x\"");
        assert!(error(&vip_extra).contains("a vip resource takes only"));
        let unknown = GROUP.replace("type = \"vip\"", "type = \"vip\"\nport = 1");
        assert!(error(&unknown).contains("unknown field"));
        let only_vip = GROUP
            .split("[[group.resource]]")
            .next()
            .unwrap()
            .to_string()
            + "[[group.resource]]\nname = \"vip\"\ntype = \"vip\"\n"
            + &GROUP[GROUP.find("\n[health]").unwrap()..];
        let e = error(&only_vip);
        assert!(e.contains("at least one systemd or command"), "{e}");
        let mut many = GROUP.to_string();
        for i in 0..8 {
            many.push_str(&format!(
                "\n[[group.resource]]\nname = \"s{i}\"\ntype = \"systemd\"\nunit = \"s{i}.service\"\n"
            ));
        }
        assert!(error(&many).contains("between 1 and 8"));
    }

    #[test]
    fn every_group_service_goes_through_the_service_rules() {
        let no_unit = GROUP.replace("unit = \"postgresql.service\"", "");
        assert!(error(&no_unit).contains("group.resource[0].unit is required"));
        let relative = GROUP.replace("\"/usr/local/sbin/app-start\"", "\"app-start\"");
        assert!(error(&relative).contains("group.resource[1].start[0] must be an absolute path"));
        let no_status = GROUP.replace("status = [\"/usr/local/sbin/app-status\"]", "");
        assert!(error(&no_status).contains("group.resource[1].status is required"));
        let zero = GROUP.replace("start_timeout_sec = 60", "start_timeout_sec = 0");
        assert!(error(&zero).contains("group.resource[1].start_timeout_sec"));
        let mixed = GROUP.replace(
            "unit = \"postgresql.service\"",
            "unit = \"postgresql.service\"\nstart = [\"/x\"]",
        );
        assert!(error(&mixed).contains("group.resource[0].start/stop/status are not valid"));
    }

    #[test]
    fn the_witness_topology_has_no_group() {
        let witness = format!(
            "{}\n[[group.resource]]\nname = \"vip\"\ntype = \"vip\"\n",
            include_str!("../contrib/examples/node-a.toml")
        );
        assert!(Config::parse_str(&witness).is_err());
    }

    #[test]
    fn a_change_of_the_group_is_a_configuration_mismatch() {
        let a = crate::two_node::shared::summary(GROUP).unwrap();
        let b = crate::two_node::shared::summary(
            &GROUP.replace("start_timeout_sec = 60", "start_timeout_sec = 61"),
        )
        .unwrap();
        assert_eq!(
            crate::two_node::shared::differing_sections(&a, &b),
            vec!["group".to_string()]
        );
    }
}

#[cfg(test)]
mod health_action_tests {
    use super::*;

    const TWO_NODE: &str = include_str!("../contrib/examples/two-node-a.toml");
    const WITNESS: &str = include_str!("../contrib/examples/node-a.toml");

    fn with(text: &str, extra: &str) -> String {
        text.replace("[health]\n", &format!("[health]\n{extra}\n"))
    }

    #[test]
    fn two_node_accepts_every_action_and_defaults_to_warn() {
        assert_eq!(
            Config::parse_str(TWO_NODE).unwrap().health.on_failure,
            HealthAction::Warn
        );
        for (text, action) in [
            ("on_failure = \"warn\"", HealthAction::Warn),
            ("on_failure = \"restart\"", HealthAction::Restart),
            ("on_failure = \"failover\"", HealthAction::Failover),
        ] {
            let config = Config::parse_str(&with(TWO_NODE, text)).unwrap();
            assert_eq!(config.health.on_failure, action);
            assert_eq!(config.health.restart_limit, 2);
        }
        let limit = Config::parse_str(&with(
            TWO_NODE,
            "on_failure = \"restart\"\nrestart_limit = 5",
        ))
        .unwrap();
        assert_eq!(limit.health.restart_limit, 5);
    }

    #[test]
    fn bad_actions_and_limits_are_refused() {
        assert!(Config::parse_str(&with(TWO_NODE, "on_failure = \"reboot\"")).is_err());
        for limit in ["0", "11"] {
            let error = Config::parse_str(&with(TWO_NODE, &format!("restart_limit = {limit}")))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("restart_limit must be between 1 and 10"),
                "{error}"
            );
        }
    }

    #[test]
    fn the_two_node_health_timeout_is_bounded_by_the_control_loop() {
        let error = Config::parse_str(&with(TWO_NODE, "timeout_sec = 31"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("at most 30 seconds"), "{error}");
        assert!(Config::parse_str(&with(TWO_NODE, "timeout_sec = 30")).is_ok());
        // The Witness topology keeps its own (unchanged) bound.
        assert!(Config::parse_str(&with(WITNESS, "timeout_sec = 31")).is_ok());
    }

    #[test]
    fn the_witness_topology_only_warns() {
        assert_eq!(
            Config::parse_str(&with(WITNESS, "on_failure = \"warn\""))
                .unwrap()
                .health
                .on_failure,
            HealthAction::Warn
        );
        for action in ["restart", "failover"] {
            let error = Config::parse_str(&with(WITNESS, &format!("on_failure = \"{action}\"")))
                .unwrap_err()
                .to_string();
            assert!(error.contains("supports only \"warn\""), "{error}");
        }
    }
}
