//! Two-node (witness-less) topology: the `[two_node]` section, its validation and the
//! static policy derived from it (TWO_NODE_SAFETY_MODEL.md §3).
//!
//! Two questions are evaluated **separately** and never mixed:
//!
//! * **Path redundancy** (availability): how many independent peer paths exist. It counts
//!   distinct `segment` names and, separately, distinct local `interface` names. A segment
//!   is a network, an interface is a local NIC; two segments on one NIC (VLANs) are still
//!   two segments with a shared NIC single point of failure.
//! * **Fencing capability** (safety): whether an independent fence device can stop the
//!   peer's OS and a verify can observe it stopped.
//!
//! The number of segments is never a reason to reject a configuration. A warning is only
//! a notice: accepting it never relaxes a runtime gate. The runtime gate (fencing
//! confirmed before any takeover promotion) is enforced by the controller whatever the
//! configuration says.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::net::{SocketAddr, SocketAddrV4};

/// Heartbeat period of every link (not configurable).
pub const HEARTBEAT_INTERVAL_MS: u64 = 500;
/// A link is down when no bidirectional (acknowledged) authenticated traffic was seen on
/// it for this long (not configurable).
pub const LINK_TIMEOUT_MS: u64 = 3_000;
/// The pause between verify polls of one fence attempt (not configurable).
pub const VERIFY_INTERVAL_MS: u64 = 2_000;
/// A verification window shorter than this triggers a start-up notice: a graceful OS
/// shutdown (for example an ACPI wait of 90 s) may outlast it, and the takeover then
/// fails safe (no promotion).
pub const VERIFY_WINDOW_NOTICE_MS: u64 = 120_000;
/// At most this many peer links.
pub const MAX_LINKS: usize = 4;
pub const DEFAULT_STATE_PATH: &str = "/var/lib/mikagami/two-node-state.json";
pub const DEFAULT_STATUS_PATH: &str = "/run/mikagami/two-node-status.json";
pub const DEFAULT_OPERATOR_DIR: &str = "/var/lib/mikagami/two-node-operator";
pub const DEFAULT_MAX_START_FAILURES: u32 = 3;

/// What a link carries. Descriptive: it is shown in status and warnings and never changes a
/// safety decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkRole {
    /// A dedicated HA (interconnect) network.
    Ha,
    /// The service network (the VIP's network).
    Service,
    /// One network carries both (the single-segment layout).
    Combined,
}

impl LinkRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ha => "ha",
            Self::Service => "service",
            Self::Combined => "combined",
        }
    }
}

/// The operator's declaration of the fence device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FencingDevice {
    /// `fence` acts on a power, hypervisor or cloud control plane outside the peer's OS,
    /// stops the peer's OS (not only a process), and `verify` prints `isolated` only after
    /// observing that stopped state at that control plane (for example power off or
    /// `TERMINATED`). Communication loss is never such an observation.
    Independent,
    /// No independent fence device.
    None,
}

/// Whether the fence control path shares a peer-link segment (availability only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FencingPath {
    /// The fence control path does not use any peer-link segment.
    Separate,
    /// The fence control path uses (one of) the peer-link segments.
    Shared,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLink {
    segment: String,
    role: LinkRole,
    interface: String,
    listen: Option<String>,
    peer_address: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawTwoNode {
    #[serde(default)]
    link: Vec<RawLink>,
    fencing_device: Option<FencingDevice>,
    fencing_path: Option<FencingPath>,
    state_path: Option<String>,
    status_path: Option<String>,
    operator_dir: Option<String>,
    max_start_failures: Option<u32>,
}

/// How this node reaches the peer on one link (the lower node id dials, the higher listens:
/// the same canonical direction as the Witness topology).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEndpoint {
    Listen(SocketAddrV4),
    Dial(SocketAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfig {
    pub index: u8,
    pub segment: String,
    pub role: LinkRole,
    pub interface: String,
    pub endpoint: LinkEndpoint,
}

/// The validated `[two_node]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoNodeConfig {
    pub links: Vec<LinkConfig>,
    pub fencing_device: FencingDevice,
    pub fencing_path: Option<FencingPath>,
    pub state_path: String,
    pub status_path: String,
    pub operator_dir: String,
    pub max_start_failures: u32,
    /// The configuration summary of a shared configuration file (`two_node::shared`), sent
    /// in the link `Hello`; `None` for a per-node file.
    pub config_summary: Option<String>,
}

/// Path redundancy, evaluated on its own (availability, never safety).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAssessment {
    pub segments: usize,
    pub interfaces: usize,
    pub links: usize,
}

impl PathAssessment {
    /// Two or more distinct segments on two or more distinct local interfaces.
    pub fn redundant(&self) -> bool {
        self.segments >= 2 && self.interfaces >= 2
    }
}

/// The static policy: what the runtime may *attempt*. Every attempt still passes the
/// runtime gates of the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoNodePolicy {
    pub paths: PathAssessment,
    pub fencing_device: FencingDevice,
    pub fencing_path: Option<FencingPath>,
    /// Automatic fence-then-promote after peer loss. Needs `failover.auto` and an
    /// independent fence device. Independent of the segment count.
    pub auto_takeover: bool,
    /// Automatic cooperative start (both nodes connected, both Standby with zero resources,
    /// the peer durably grants). Needs `failover.auto`; needs no fencing.
    pub auto_bootstrap: bool,
    /// An operator may request fence-then-promote (needs an independent fence device).
    pub operator_fence_takeover: bool,
    /// An operator may attest that the peer is stopped (manual failover; always allowed).
    pub operator_attested_takeover: bool,
}

pub(crate) fn validate_two_node(
    raw: RawTwoNode,
    node_id: &str,
    peer_id: &str,
    fencing_command: bool,
    errors: &mut Vec<String>,
) -> Option<TwoNodeConfig> {
    let inbound = node_id > peer_id;
    if raw.link.is_empty() {
        errors.push("two_node.link: at least one [[two_node.link]] is required".to_string());
    }
    if raw.link.len() > MAX_LINKS {
        errors.push(format!("two_node.link: at most {MAX_LINKS} links"));
    }
    let mut links = Vec::new();
    let mut endpoints = BTreeSet::new();
    for (position, link) in raw.link.into_iter().enumerate() {
        let field = format!("two_node.link[{position}]");
        let mut ok = true;
        for (key, value) in [("segment", &link.segment), ("interface", &link.interface)] {
            if value.is_empty() || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
                errors.push(format!(
                    "{field}.{key} must be non-empty without whitespace or control characters"
                ));
                ok = false;
            }
        }
        let endpoint = if inbound {
            if link.peer_address.is_some() {
                errors.push(format!(
                    "{field}.peer_address is not valid on the inbound node (the higher node id)"
                ));
                ok = false;
            }
            match link.listen.as_deref().map(str::parse::<SocketAddr>) {
                Some(Ok(SocketAddr::V4(address))) => Some(LinkEndpoint::Listen(address)),
                Some(_) => {
                    errors.push(format!("{field}.listen must be an IPv4 ip:port"));
                    None
                }
                None => {
                    errors.push(format!(
                        "{field}.listen is required on the inbound node (the higher node id)"
                    ));
                    None
                }
            }
        } else {
            if link.listen.is_some() {
                errors.push(format!(
                    "{field}.listen is not valid on the outbound node (the lower node id)"
                ));
                ok = false;
            }
            match link.peer_address.as_deref().map(str::parse::<SocketAddr>) {
                Some(Ok(address)) => Some(LinkEndpoint::Dial(address)),
                Some(Err(_)) => {
                    errors.push(format!("{field}.peer_address must be a valid ip:port"));
                    None
                }
                None => {
                    errors.push(format!(
                        "{field}.peer_address is required on the outbound node (the lower node id)"
                    ));
                    None
                }
            }
        };
        if let Some(endpoint) = &endpoint
            && !endpoints.insert(format!("{endpoint:?}"))
        {
            errors.push(format!(
                "{field}: two links use the same address (one path, not two)"
            ));
            ok = false;
        }
        if let (true, Some(endpoint)) = (ok, endpoint) {
            links.push(LinkConfig {
                index: u8::try_from(position).unwrap_or(u8::MAX),
                segment: link.segment,
                role: link.role,
                interface: link.interface,
                endpoint,
            });
        }
    }

    let fencing_device = match (fencing_command, raw.fencing_device) {
        (true, Some(FencingDevice::Independent)) => FencingDevice::Independent,
        (true, Some(FencingDevice::None)) => {
            errors.push(
                "two_node.fencing_device = \"none\" with fencing.backend = \"command\": the fence \
                 commands would never be used; remove [fencing] or declare the device"
                    .to_string(),
            );
            FencingDevice::None
        }
        (true, None) => {
            errors.push(
                "two_node.fencing_device is required with fencing.backend = \"command\" \
                 (\"independent\" only for a power/hypervisor/cloud control plane that stops \
                 the peer's OS and whose verify observes the stopped state)"
                    .to_string(),
            );
            FencingDevice::None
        }
        (false, Some(FencingDevice::Independent)) => {
            errors.push(
                "two_node.fencing_device = \"independent\" needs fencing.backend = \"command\" \
                 with fence and verify"
                    .to_string(),
            );
            FencingDevice::None
        }
        (false, _) => FencingDevice::None,
    };
    match (fencing_device, raw.fencing_path) {
        (FencingDevice::Independent, None) => errors.push(
            "two_node.fencing_path is required with an independent fence device \
             (\"separate\" or \"shared\")"
                .to_string(),
        ),
        (FencingDevice::None, Some(_)) => errors.push(
            "two_node.fencing_path is only valid with an independent fence device".to_string(),
        ),
        _ => {}
    }

    let state_path = raw
        .state_path
        .unwrap_or_else(|| DEFAULT_STATE_PATH.to_string());
    let status_path = raw
        .status_path
        .unwrap_or_else(|| DEFAULT_STATUS_PATH.to_string());
    let operator_dir = raw
        .operator_dir
        .unwrap_or_else(|| DEFAULT_OPERATOR_DIR.to_string());
    for (key, value) in [
        ("state_path", &state_path),
        ("status_path", &status_path),
        ("operator_dir", &operator_dir),
    ] {
        if !crate::config::clean_abs_path(value) {
            errors.push(format!(
                "two_node.{key} must be a clean absolute path without '..' or control characters"
            ));
        }
    }
    if state_path == status_path {
        errors.push("two_node.state_path and two_node.status_path must differ".to_string());
    }
    let max_start_failures = raw.max_start_failures.unwrap_or(DEFAULT_MAX_START_FAILURES);
    if !(1..=10).contains(&max_start_failures) {
        errors.push("two_node.max_start_failures must be between 1 and 10".to_string());
    }

    Some(TwoNodeConfig {
        links,
        fencing_device,
        fencing_path: raw.fencing_path,
        state_path,
        status_path,
        operator_dir,
        max_start_failures,
        config_summary: None,
    })
}

impl TwoNodeConfig {
    pub fn paths(&self) -> PathAssessment {
        PathAssessment {
            segments: self
                .links
                .iter()
                .map(|l| l.segment.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            interfaces: self
                .links
                .iter()
                .map(|l| l.interface.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            links: self.links.len(),
        }
    }

    pub fn policy(&self, failover_auto: bool) -> TwoNodePolicy {
        let independent = self.fencing_device == FencingDevice::Independent;
        TwoNodePolicy {
            paths: self.paths(),
            fencing_device: self.fencing_device,
            fencing_path: self.fencing_path,
            auto_takeover: failover_auto && independent,
            auto_bootstrap: failover_auto,
            operator_fence_takeover: independent,
            operator_attested_takeover: true,
        }
    }

    /// Start-up notices. They describe the configuration; none of them disables a gate.
    pub fn warnings(&self, failover_auto: bool, verify_window_ms: Option<u64>) -> Vec<String> {
        let policy = self.policy(failover_auto);
        let paths = &policy.paths;
        let mut warnings = Vec::new();
        if paths.segments < 2 {
            let mut text = "two-node: a single peer segment (recommended: two segments, \
                            service + HA); the segment is a single point of failure of the \
                            peer path"
                .to_string();
            match (policy.fencing_device, policy.fencing_path) {
                (FencingDevice::Independent, Some(FencingPath::Shared)) => text.push_str(
                    "; the fence path shares this segment, so a failure of it also blocks \
                     fencing and no automatic takeover happens then",
                ),
                (FencingDevice::Independent, _) => text.push_str(
                    "; a failure of it makes the standby fence the active node (a service \
                     interruption) and promotion still waits for the confirmed fence",
                ),
                (FencingDevice::None, _) => text.push_str(
                    "; without an independent fence device a peer loss is never taken over \
                     automatically (manual failover only)",
                ),
            }
            warnings.push(text);
        } else if paths.interfaces < 2 {
            warnings.push(format!(
                "two-node: {} segments share one local interface; the interface (NIC) is a \
                 single point of failure of the peer path",
                paths.segments
            ));
        }
        if policy.fencing_device == FencingDevice::None {
            warnings.push(
                "two-node: no independent fence device: automatic takeover after a peer loss \
                 is disabled (an operator may attest the peer stopped); a cooperative start \
                 with both nodes connected stays automatic"
                    .to_string(),
            );
        }
        if policy.fencing_device == FencingDevice::Independent
            && let Some(window) = verify_window_ms
            && window < VERIFY_WINDOW_NOTICE_MS
        {
            warnings.push(format!(
                "two-node: the fence verification window is about {} s; a graceful OS \
                 shutdown may take longer (then the takeover fails safe without promotion); \
                 consider fencing.verify_polls",
                window / 1000
            ));
        }
        if !failover_auto {
            warnings.push(
                "two-node: failover.auto = false: promotion only on an operator request"
                    .to_string(),
            );
        }
        warnings
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{Config, ConfigError, Topology};
    use crate::two_node::config::{FencingDevice, FencingPath};

    const TWO_SEG_A: &str = include_str!("../../contrib/examples/two-node-a.toml");
    const TWO_SEG_B: &str = include_str!("../../contrib/examples/two-node-b.toml");
    const ONE_SEG: &str = include_str!("../../contrib/examples/two-node-single-segment-a.toml");

    fn errors(text: &str) -> String {
        match Config::parse_str(text) {
            Err(ConfigError::Validation(errors)) => errors.join("; "),
            Err(ConfigError::Parse(error)) => format!("PARSE {}", error.message()),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn shipped_two_segment_examples_parse_with_full_policy() {
        for text in [TWO_SEG_A, TWO_SEG_B] {
            let config = Config::parse_str(text).unwrap();
            assert_eq!(config.topology, Topology::TwoNode);
            assert!(config.witness.is_none());
            let two_node = config.two_node.as_ref().unwrap();
            let policy = two_node.policy(config.failover.auto);
            assert!(policy.paths.redundant());
            assert_eq!(policy.paths.segments, 2);
            assert!(policy.auto_takeover && policy.auto_bootstrap);
            assert!(
                config.startup_warnings().is_empty(),
                "{:?}",
                config.startup_warnings()
            );
        }
    }

    #[test]
    fn single_segment_without_fencing_is_accepted_with_restricted_policy() {
        let config = Config::parse_str(ONE_SEG).unwrap();
        let policy = config
            .two_node
            .as_ref()
            .unwrap()
            .policy(config.failover.auto);
        assert_eq!(policy.paths.segments, 1);
        assert_eq!(policy.fencing_device, FencingDevice::None);
        assert!(
            !policy.auto_takeover,
            "no automatic takeover without fencing"
        );
        assert!(policy.auto_bootstrap, "cooperative start stays automatic");
        assert!(policy.operator_attested_takeover && !policy.operator_fence_takeover);
        let warnings = config.startup_warnings().join(" | ");
        assert!(warnings.contains("single peer segment"), "{warnings}");
        assert!(warnings.contains("manual failover only"), "{warnings}");
    }

    #[test]
    fn single_segment_with_independent_fencing_allows_takeover_and_warns_separately() {
        let text = ONE_SEG.replace(
            "[[two_node.link]]",
            "[two_node]\nfencing_device = \"independent\"\nfencing_path = \"shared\"\n\n[[two_node.link]]",
        ) + "\n[fencing]\nbackend = \"command\"\nfence = [\"/usr/local/sbin/f\"]\nverify = [\"/usr/local/sbin/v\"]\n";
        let config = Config::parse_str(&text).unwrap();
        let two_node = config.two_node.as_ref().unwrap();
        assert_eq!(two_node.fencing_path, Some(FencingPath::Shared));
        let policy = two_node.policy(true);
        assert!(policy.auto_takeover);
        assert!(!policy.paths.redundant());
        let warnings = config.startup_warnings().join(" | ");
        assert!(warnings.contains("single peer segment"));
        assert!(warnings.contains("fence path shares this segment"));
        assert!(
            warnings.contains("verification window"),
            "default 20 s window: {warnings}"
        );
    }

    #[test]
    fn a_fence_cycle_shorter_than_the_verify_window_is_reported() {
        let short = TWO_SEG_A.replace("cycle_timeout_sec = 180", "cycle_timeout_sec = 120");
        let config = Config::parse_str(&short).unwrap();
        let warnings = config.startup_warnings().join(" | ");
        assert!(
            warnings.contains("cycle_timeout_sec (120 s) is shorter"),
            "{warnings}"
        );
        let ok = Config::parse_str(TWO_SEG_A).unwrap();
        assert!(ok.startup_warnings().is_empty());
    }

    #[test]
    fn two_segments_on_one_interface_warn_about_the_nic_not_the_segments() {
        let text = TWO_SEG_A.replace(
            "interface = \"eth1\"\npeer_address",
            "interface = \"eth0\"\npeer_address",
        );
        let config = Config::parse_str(&text).unwrap();
        let paths = config.two_node.as_ref().unwrap().paths();
        assert_eq!((paths.segments, paths.interfaces), (2, 1));
        let warnings = config.startup_warnings().join(" | ");
        assert!(warnings.contains("share one local interface"), "{warnings}");
        assert!(!warnings.contains("single peer segment"));
    }

    #[test]
    fn link_direction_and_count_rules() {
        let no_links = TWO_SEG_A
            .split("[[two_node.link]]")
            .next()
            .unwrap()
            .to_string()
            + &TWO_SEG_A[TWO_SEG_A.find("[vip]").unwrap()..];
        assert!(errors(&no_links).contains("at least one"));
        assert!(
            errors(&TWO_SEG_A.replacen("peer_address = ", "listen = ", 1))
                .contains("listen is not valid on the outbound node")
        );
        assert!(
            errors(&TWO_SEG_B.replacen("listen = ", "peer_address = ", 1))
                .contains("peer_address is not valid on the inbound node")
        );
        let duplicate = TWO_SEG_A.replace("192.168.100.12:7946", "10.0.1.12:7946");
        assert!(errors(&duplicate).contains("same address"));
        assert!(
            errors(&TWO_SEG_A.replace(
                "peer_address = \"10.0.1.12:7946\"",
                "peer_address = \"nope\""
            ))
            .contains("valid ip:port")
        );
        assert!(
            errors(&TWO_SEG_A.replace("segment = \"ha-net\"", "segment = \"ha net\""))
                .contains("segment")
        );
        let mut five = TWO_SEG_A.to_string();
        for port in 1..4 {
            five = five.replace(
                "[vip]",
                &format!("[[two_node.link]]\nsegment = \"s{port}\"\nrole = \"ha\"\ninterface = \"e{port}\"\npeer_address = \"10.9.0.{port}:1\"\n\n[vip]"),
            );
        }
        assert!(errors(&five).contains("at most 4"));
    }

    #[test]
    fn fencing_declaration_rules() {
        assert!(
            errors(&TWO_SEG_A.replace("fencing_device = \"independent\"\n", ""))
                .contains("fencing_device is required")
        );
        assert!(
            errors(&TWO_SEG_A.replace("fencing_path = \"separate\"\n", ""))
                .contains("fencing_path is required")
        );
        assert!(
            errors(&TWO_SEG_A.replace(
                "fencing_device = \"independent\"",
                "fencing_device = \"none\""
            ))
            .contains("never be used")
        );
        let no_command = ONE_SEG.replace(
            "[[two_node.link]]",
            "[two_node]\nfencing_device = \"independent\"\nfencing_path = \"separate\"\n\n[[two_node.link]]",
        );
        assert!(errors(&no_command).contains("needs fencing.backend"));
        let path_without_device = ONE_SEG.replace(
            "[[two_node.link]]",
            "[two_node]\nfencing_path = \"separate\"\n\n[[two_node.link]]",
        );
        assert!(errors(&path_without_device).contains("only valid with an independent"));
        assert!(
            errors(&TWO_SEG_A.replace(
                "fencing_device = \"independent\"",
                "fencing_device = \"maybe\""
            ))
            .starts_with("PARSE")
        );
    }

    #[test]
    fn witness_only_keys_are_unknown_in_the_two_node_shape() {
        let with_witness = TWO_SEG_A.replace(
            "[vip]",
            "[witness]\nid = \"w\"\naddress = \"10.0.0.1:1\"\n\n[vip]",
        );
        assert!(errors(&with_witness).contains("unknown field `witness`"));
        let with_listen = TWO_SEG_A.replace(
            "preferred = true",
            "preferred = true\nlisten = \"10.0.0.1:1\"",
        );
        assert!(errors(&with_listen).contains("unknown field `listen`"));
        let with_route = TWO_SEG_A.replace(
            "[vip]",
            "[route]\nhelper = \"/x\"\nhelper_config = \"/y\"\nintent_dir = \"/z\"\n\n[vip]",
        );
        assert!(errors(&with_route).contains("unknown field `route`"));
        let bad_paths =
            TWO_SEG_A.replace("[two_node]", "[two_node]\nstate_path = \"relative/state\"");
        assert!(errors(&bad_paths).contains("two_node.state_path"));
        let bad_failures = TWO_SEG_A.replace("[two_node]", "[two_node]\nmax_start_failures = 0");
        assert!(errors(&bad_failures).contains("max_start_failures"));
    }

    #[test]
    fn topology_values_and_witness_compatibility() {
        let witness = include_str!("../../contrib/examples/node-a.toml");
        let config = Config::parse_str(witness).unwrap();
        assert_eq!(config.topology, Topology::Witness);
        assert!(config.two_node.is_none());
        assert!(config.witness.is_some());
        let explicit = witness.replacen(
            "id = \"example-ha\"",
            "id = \"example-ha\"\ntopology = \"witness\"",
            1,
        );
        assert_eq!(
            Config::parse_str(&explicit).unwrap().topology,
            Topology::Witness
        );
        let unknown = witness.replacen(
            "id = \"example-ha\"",
            "id = \"example-ha\"\ntopology = \"three-node\"",
            1,
        );
        assert!(errors(&unknown).contains("cluster.topology must be"));
        let not_string = witness.replacen(
            "id = \"example-ha\"",
            "id = \"example-ha\"\ntopology = 2",
            1,
        );
        assert!(errors(&not_string).contains("cluster.topology must be"));
        let witness_with_two_node = format!("{witness}\n[two_node]\nfencing_device = \"none\"\n");
        assert!(errors(&witness_with_two_node).contains("unknown field `two_node`"));
        // The two-node shape never needs a Witness; the Witness shape still does.
        let no_witness = witness.replace(
            "[witness]\nid = \"witness-1\"\naddress = \"192.168.100.13:7947\"\n",
            "",
        );
        assert!(matches!(
            Config::parse_str(&no_witness),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn values_beyond_i64_reach_validation_in_both_shapes() {
        let huge = u64::MAX.to_string();
        let two = TWO_SEG_A.replace(
            "[service]\n",
            &format!("[service]\nstart_timeout_sec = {huge}\n"),
        );
        assert!(
            errors(&two).contains("service.start_timeout_sec must not exceed"),
            "{}",
            errors(&two)
        );
    }

    #[test]
    fn two_node_state_path_defaults_apart_from_the_witness_state() {
        let config = Config::parse_str(ONE_SEG).unwrap();
        let two_node = config.two_node.as_ref().unwrap();
        assert_eq!(two_node.state_path, super::DEFAULT_STATE_PATH);
        assert_eq!(config.state.path, super::DEFAULT_STATE_PATH);
        assert_ne!(two_node.state_path, "/var/lib/mikagami/state.toml");
    }
}
