//! Control-host configuration of the manual control plane.
//!
//! Strict TOML (`deny_unknown_fields`). No secret is ever stored here: the
//! SSH private key is referenced by path (or the `MKG_SSH_KEY` environment
//! variable), never embedded.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub(crate) const DEFAULT_CONFIG_PATH: &str = "/etc/mikagami/prototype.toml";
/// A control configuration larger than this is refused unread (audit E-02).
pub(crate) const MAX_CONFIG_BYTES: u64 = 64 * 1024;
pub(crate) const CONFIG_ENV: &str = "MKG_CONFIG";
pub(crate) const SSH_KEY_ENV: &str = "MKG_SSH_KEY";
pub(crate) const ADDRESS_ENV: &str = "MKG_SSH_ADDRESS";

#[derive(Debug)]
pub(crate) enum ConfigError {
    Io(String),
    Parse(String),
    Invalid(Vec<String>),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(message) => write!(f, "cannot read control configuration: {message}"),
            Self::Parse(message) => write!(f, "cannot parse control configuration: {message}"),
            Self::Invalid(errors) => {
                write!(f, "control configuration invalid: {}", errors.join("; "))
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    cluster: RawCluster,
    #[serde(default)]
    ssh: RawSsh,
    #[serde(default)]
    tools: RawTools,
    #[serde(default)]
    agent: RawAgent,
    witness: RawWitness,
    #[serde(default)]
    paths: RawPaths,
    nodes: BTreeMap<String, RawNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCluster {
    #[serde(default = "default_cluster_name")]
    name: String,
    project: String,
    zone: String,
    vip: String,
    #[serde(default = "default_vip_port")]
    vip_port: u16,
    #[serde(default = "default_service")]
    service: String,
    #[serde(default = "default_chrony_unit")]
    chrony_unit: String,
}

fn default_chrony_unit() -> String {
    "chrony.service".to_string()
}

fn default_cluster_name() -> String {
    "mikagami-prototype".to_string()
}
fn default_vip_port() -> u16 {
    8080
}
fn default_service() -> String {
    "mkg-demo.service".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSsh {
    #[serde(default = "default_ssh_user")]
    user: String,
    #[serde(default)]
    key: String,
    #[serde(default = "default_ssh_timeout")]
    timeout_s: u64,
    #[serde(default = "default_address_mode")]
    address: String,
    #[serde(default)]
    known_hosts: String,
}

impl Default for RawSsh {
    fn default() -> Self {
        Self {
            user: default_ssh_user(),
            key: String::new(),
            timeout_s: default_ssh_timeout(),
            address: default_address_mode(),
            known_hosts: String::new(),
        }
    }
}

fn default_ssh_user() -> String {
    "mkg".to_string()
}
fn default_ssh_timeout() -> u64 {
    15
}
fn default_address_mode() -> String {
    "internal".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTools {
    #[serde(default = "default_ssh_tool")]
    ssh: String,
    #[serde(default = "default_gcloud_tool")]
    gcloud: String,
}

impl Default for RawTools {
    fn default() -> Self {
        Self {
            ssh: default_ssh_tool(),
            gcloud: default_gcloud_tool(),
        }
    }
}

fn default_ssh_tool() -> String {
    "/usr/bin/ssh".to_string()
}
fn default_gcloud_tool() -> String {
    "/usr/bin/gcloud".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    #[serde(default = "default_agent_binary")]
    binary: String,
    #[serde(default = "default_sudo")]
    sudo: String,
}

impl Default for RawAgent {
    fn default() -> Self {
        Self {
            binary: default_agent_binary(),
            sudo: default_sudo(),
        }
    }
}

fn default_agent_binary() -> String {
    "/usr/local/bin/mikagami".to_string()
}
fn default_sudo() -> String {
    "/usr/bin/sudo".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWitness {
    name: String,
    ip: String,
    #[serde(default)]
    instance: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPaths {
    #[serde(default)]
    state_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    instance: String,
    ip: String,
    #[serde(default = "default_priority")]
    priority: u32,
}

fn default_priority() -> u32 {
    100
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressMode {
    Internal,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeConfig {
    pub(crate) name: String,
    pub(crate) instance: String,
    pub(crate) ip: String,
    pub(crate) priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessConfig {
    pub(crate) name: String,
    /// GCE instance name of the Witness host (defaults to `name`).
    pub(crate) instance: String,
    pub(crate) ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlConfig {
    pub(crate) path: PathBuf,
    pub(crate) cluster: String,
    pub(crate) project: String,
    pub(crate) zone: String,
    pub(crate) vip: String,
    pub(crate) vip_port: u16,
    pub(crate) service: String,
    pub(crate) chrony_unit: String,
    pub(crate) ssh_user: String,
    pub(crate) ssh_key: PathBuf,
    pub(crate) ssh_timeout_s: u64,
    pub(crate) address_mode: AddressMode,
    pub(crate) known_hosts: PathBuf,
    pub(crate) ssh_tool: String,
    pub(crate) gcloud_tool: String,
    pub(crate) agent_binary: String,
    pub(crate) sudo_tool: String,
    pub(crate) witness: WitnessConfig,
    pub(crate) state_dir: PathBuf,
    /// Nodes in ascending (priority, name) order.
    pub(crate) nodes: Vec<NodeConfig>,
}

/// Syntactic checks shared by config and request validation.
pub(crate) fn is_node_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
}

pub(crate) fn is_gce_name(value: &str) -> bool {
    // RFC 1035 label as GCE instance names: 1-63 [a-z0-9-], letter first,
    // not ending in '-'.
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

pub(crate) fn is_unit_name(value: &str) -> bool {
    let Some(stem) = value.strip_suffix(".service") else {
        return false;
    };
    !stem.is_empty()
        && value.len() <= 96
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
        && !stem.starts_with('.')
        // A leading '-' would read as an option (audit D-09).
        && !stem.starts_with('-')
}

fn is_zone_or_project(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b':' | b'.')
        })
}

fn is_abs_clean(path: &str) -> bool {
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

/// Paths under `/dev` or `/proc` name devices, not files: `/dev/null` as a
/// known-hosts file would turn the host-key check into permanent first-use
/// trust, `/dev/zero` is endless (audit E-02).
fn is_device_path(path: &str) -> bool {
    ["/dev", "/proc", "/sys"]
        .iter()
        .any(|d| path == *d || path.starts_with(&format!("{d}/")))
}

/// A path that can be placed in an ssh `-o` value (possibly double-quoted).
fn is_ssh_option_safe(path: &str) -> bool {
    !path.contains('"') && !path.contains('\\') && !path.contains('\'')
}

fn is_shell_plain(path: &str) -> bool {
    path.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'.' | b'-'))
}

fn parse_ipv4(value: &str) -> Option<Ipv4Addr> {
    value.parse::<Ipv4Addr>().ok()
}

/// Per-user state directory (known hosts); `/var/lib/mkg` without a home.
fn default_state_dir() -> PathBuf {
    match std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        Some(home) => PathBuf::from(home).join(".local/state/mkg"),
        None => PathBuf::from("/var/lib/mkg"),
    }
}

impl ControlConfig {
    /// Resolve the configuration path: explicit flag, then `MKG_CONFIG`, then
    /// the default location.
    pub(crate) fn resolve_path(flag: Option<&Path>) -> PathBuf {
        if let Some(path) = flag {
            return path.to_path_buf();
        }
        match std::env::var_os(CONFIG_ENV) {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => PathBuf::from(DEFAULT_CONFIG_PATH),
        }
    }

    /// Read and check the control configuration. The file decides which
    /// programs (`tools.ssh`, `tools.gcloud`) run with the operator's rights,
    /// so it must be a regular file (no symlink) owned by root or the invoking
    /// user, not group/world writable, in directories nobody else can write,
    /// and at most [`MAX_CONFIG_BYTES`]; the two tools are held to the same
    /// standard (audit E-02).
    pub(crate) fn load(path: &Path) -> Result<Self, ConfigError> {
        // SAFETY: plain syscall without arguments.
        let euid = unsafe { libc::geteuid() };
        let bytes = crate::manual::fsutil::read_trusted_control_file(path, MAX_CONFIG_BYTES, euid)
            .map_err(|e| ConfigError::Io(format!("{} {e}", path.display())))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| ConfigError::Io(format!("{} is not valid UTF-8", path.display())))?;
        let cfg = Self::parse(
            path,
            &text,
            std::env::var(SSH_KEY_ENV).ok(),
            std::env::var(ADDRESS_ENV).ok(),
        )?;
        for (label, tool) in [
            ("tools.ssh", &cfg.ssh_tool),
            ("tools.gcloud", &cfg.gcloud_tool),
        ] {
            crate::manual::fsutil::check_tool_trust(Path::new(tool), euid)
                .map_err(|e| ConfigError::Io(format!("{label} {tool}: {e}")))?;
        }
        Ok(cfg)
    }

    pub(crate) fn parse(
        path: &Path,
        text: &str,
        key_env: Option<String>,
        address_env: Option<String>,
    ) -> Result<Self, ConfigError> {
        let raw: RawConfig =
            toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().to_string()))?;
        let mut errors = Vec::new();

        if !is_zone_or_project(&raw.cluster.project) {
            errors.push("cluster.project is not a valid project id".to_string());
        }
        if !is_zone_or_project(&raw.cluster.zone) {
            errors.push("cluster.zone is not a valid zone".to_string());
        }
        if parse_ipv4(&raw.cluster.vip).is_none() {
            errors.push("cluster.vip must be an IPv4 address".to_string());
        }
        if raw.cluster.vip_port == 0 {
            errors.push("cluster.vip_port must be non-zero".to_string());
        }
        if !is_unit_name(&raw.cluster.service) {
            errors.push("cluster.service must be a systemd .service unit name".to_string());
        }
        if !is_unit_name(&raw.cluster.chrony_unit) {
            errors.push("cluster.chrony_unit must be a systemd .service unit name".to_string());
        }
        // `chronyd service ...` carries no fencing token and no lease check
        // (the chrony unit is not a movable resource). If it named the VIP
        // service or an HA daemon unit it would be a way to start or stop
        // those without either (audit RA-B-04).
        if raw.cluster.chrony_unit == raw.cluster.service {
            errors.push(
                "cluster.chrony_unit must not be the VIP service (cluster.service): chronyd \
                 operations are not checked against the lease"
                    .to_string(),
            );
        }
        if super::agent::DEFAULT_HA_UNITS.contains(&raw.cluster.chrony_unit.as_str()) {
            errors.push(
                "cluster.chrony_unit must not be an HA daemon unit (mikagami.service, \
                 mikagami-witness.service)"
                    .to_string(),
            );
        }
        if raw.cluster.name.is_empty()
            || raw.cluster.name.len() > 64
            || raw.cluster.name.chars().any(char::is_control)
        {
            errors.push("cluster.name is invalid".to_string());
        }
        if raw.ssh.user.is_empty()
            || raw.ssh.user.starts_with('-')
            || raw.ssh.user.len() > 32
            || !raw
                .ssh
                .user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            errors.push("ssh.user is invalid".to_string());
        }
        if !(1..=120).contains(&raw.ssh.timeout_s) {
            errors.push("ssh.timeout_s must be 1..=120".to_string());
        }
        for (label, tool) in [
            ("tools.ssh", &raw.tools.ssh),
            ("tools.gcloud", &raw.tools.gcloud),
        ] {
            if !is_abs_clean(tool) {
                errors.push(format!("{label} must be a clean absolute path"));
            }
        }
        // These two become part of the command line run by the remote shell:
        // only plain path characters are accepted, so nothing can be quoted,
        // expanded or chained.
        for (label, tool) in [
            ("agent.binary", &raw.agent.binary),
            ("agent.sudo", &raw.agent.sudo),
        ] {
            if !is_abs_clean(tool) || !is_shell_plain(tool) {
                errors.push(format!(
                    "{label} must be an absolute path of [A-Za-z0-9/_.-] characters only"
                ));
            }
        }
        if !is_node_name(&raw.witness.name) {
            errors.push("witness.name is invalid".to_string());
        }
        if parse_ipv4(&raw.witness.ip).is_none() {
            errors.push("witness.ip must be an IPv4 address".to_string());
        }
        let witness_instance = if raw.witness.instance.is_empty() {
            raw.witness.name.clone()
        } else {
            raw.witness.instance.clone()
        };
        if !is_gce_name(&witness_instance) {
            errors.push("witness.instance is not a valid instance name".to_string());
        }
        let address_choice = address_env.unwrap_or_else(|| raw.ssh.address.clone());
        let address_mode = match address_choice.as_str() {
            "internal" => AddressMode::Internal,
            "external" => AddressMode::External,
            _ => {
                errors.push("ssh.address must be \"internal\" or \"external\"".to_string());
                AddressMode::Internal
            }
        };
        if raw.nodes.len() != 2 {
            errors.push(format!(
                "exactly two nodes are required, found {}",
                raw.nodes.len()
            ));
        }
        let mut nodes = Vec::new();
        for (name, node) in &raw.nodes {
            if !is_node_name(name) {
                errors.push(format!("node name {name:?} is invalid"));
            }
            if !is_gce_name(&node.instance) {
                errors.push(format!(
                    "nodes.{name}.instance is not a valid instance name"
                ));
            }
            if parse_ipv4(&node.ip).is_none() {
                errors.push(format!("nodes.{name}.ip must be an IPv4 address"));
            }
            if node.ip == raw.cluster.vip {
                errors.push(format!("nodes.{name}.ip must differ from cluster.vip"));
            }
            nodes.push(NodeConfig {
                name: name.clone(),
                instance: node.instance.clone(),
                ip: node.ip.clone(),
                priority: node.priority,
            });
        }
        nodes.sort_by(|a, b| (a.priority, &a.name).cmp(&(b.priority, &b.name)));
        if nodes.len() == 2 && nodes[0].ip == nodes[1].ip {
            errors.push("the two nodes must have different addresses".to_string());
        }
        for node in &nodes {
            if node.name == raw.witness.name
                || node.instance == witness_instance
                || node.ip == raw.witness.ip
            {
                errors.push(format!(
                    "the witness must be a third, independent host (clashes with {})",
                    node.name
                ));
            }
        }
        if raw.witness.ip == raw.cluster.vip {
            errors.push("witness.ip must differ from cluster.vip".to_string());
        }
        // The agents only probe private or loopback targets.
        if parse_ipv4(&raw.cluster.vip).is_some_and(|ip| !ip.is_private()) {
            errors.push("cluster.vip must be a private (RFC 1918) address".to_string());
        }
        if nodes.len() == 2 {
            if nodes[0].instance == nodes[1].instance {
                errors.push("the two nodes must use different instances".to_string());
            }
            if nodes[0].priority == nodes[1].priority {
                errors.push("node priorities must differ (fixed order, no scoring)".to_string());
            }
        }
        let key = match key_env.filter(|v| !v.is_empty()) {
            Some(value) => value,
            None => raw.ssh.key.clone(),
        };
        if key.is_empty() {
            errors.push(format!(
                "an SSH key path is required (ssh.key or {SSH_KEY_ENV})"
            ));
        } else if !is_abs_clean(&key) || is_device_path(&key) {
            errors.push("the SSH key path must be a clean absolute path to a file".to_string());
        }
        let state_dir = if raw.paths.state_dir.is_empty() {
            default_state_dir()
        } else if is_abs_clean(&raw.paths.state_dir)
            && is_ssh_option_safe(&raw.paths.state_dir)
            && !is_device_path(&raw.paths.state_dir)
        {
            PathBuf::from(&raw.paths.state_dir)
        } else {
            errors.push("paths.state_dir must be a clean absolute path".to_string());
            default_state_dir()
        };
        let known_hosts = if raw.ssh.known_hosts.is_empty() {
            state_dir.join("known_hosts")
        } else if is_abs_clean(&raw.ssh.known_hosts)
            && is_ssh_option_safe(&raw.ssh.known_hosts)
            && !is_device_path(&raw.ssh.known_hosts)
        {
            PathBuf::from(&raw.ssh.known_hosts)
        } else {
            errors.push(
                "ssh.known_hosts must be a clean absolute path to a file (not under /dev) without quotes or backslashes"
                    .to_string(),
            );
            state_dir.join("known_hosts")
        };
        if !errors.is_empty() {
            return Err(ConfigError::Invalid(errors));
        }
        Ok(Self {
            path: path.to_path_buf(),
            cluster: raw.cluster.name,
            project: raw.cluster.project,
            zone: raw.cluster.zone,
            vip: raw.cluster.vip,
            vip_port: raw.cluster.vip_port,
            service: raw.cluster.service,
            chrony_unit: raw.cluster.chrony_unit,
            ssh_user: raw.ssh.user,
            ssh_key: PathBuf::from(key),
            ssh_timeout_s: raw.ssh.timeout_s,
            address_mode,
            known_hosts,
            ssh_tool: raw.tools.ssh,
            gcloud_tool: raw.tools.gcloud,
            agent_binary: raw.agent.binary,
            sudo_tool: raw.agent.sudo,
            witness: WitnessConfig {
                name: raw.witness.name,
                instance: witness_instance,
                ip: raw.witness.ip,
            },
            state_dir,
            nodes,
        })
    }

    pub(crate) fn node(&self, name: &str) -> Option<&NodeConfig> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub(crate) fn node_names(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.name.clone()).collect()
    }

    /// The other node of the pair.
    pub(crate) fn peer_of(&self, name: &str) -> Option<&NodeConfig> {
        self.nodes.iter().find(|n| n.name != name)
    }

    /// `/32` form of the VIP, as GCE stores alias ranges.
    pub(crate) fn vip_cidr(&self) -> String {
        format!("{}/32", self.vip)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const SAMPLE: &str = r#"
[cluster]
name = "test-cluster"
project = "example-project"
zone = "zone-a"
vip = "10.0.0.130"
vip_port = 8080
service = "mkg-demo.service"

[ssh]
user = "mkg"
key = "/keys/id"
timeout_s = 15

[tools]
ssh = "/usr/bin/ssh"
gcloud = "/usr/local/bin/gcloud"

[witness]
name = "witness"
ip = "10.0.0.12"

[paths]
state_dir = "/var/lib/mkg"

[nodes.node-a]
instance = "inst-a"
ip = "10.0.0.10"
priority = 10

[nodes.node-b]
instance = "inst-b"
ip = "10.0.0.11"
priority = 20
"#;

    pub(crate) fn sample() -> ControlConfig {
        ControlConfig::parse(Path::new("/x.toml"), SAMPLE, None, None).unwrap()
    }

    #[test]
    fn parses_the_sample_and_orders_nodes_by_fixed_priority() {
        let cfg = sample();
        assert_eq!(cfg.node_names(), ["node-a", "node-b"]);
        assert_eq!(cfg.vip_cidr(), "10.0.0.130/32");
        assert_eq!(cfg.peer_of("node-a").unwrap().name, "node-b");
        assert_eq!(cfg.witness.instance, "witness");
        assert_eq!(cfg.address_mode, AddressMode::Internal);
        assert_eq!(cfg.known_hosts, PathBuf::from("/var/lib/mkg/known_hosts"));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = SAMPLE.replace("[paths]", "[paths]\nsurprise = 1");
        assert!(matches!(
            ControlConfig::parse(Path::new("/x"), &text, None, None),
            Err(ConfigError::Parse(_))
        ));
        let text = format!("{SAMPLE}\n[extra]\na = 1\n");
        assert!(ControlConfig::parse(Path::new("/x"), &text, None, None).is_err());
    }

    #[test]
    fn ra_b04_the_chrony_unit_may_not_be_the_vip_service_or_an_ha_unit() {
        // `chronyd service ...` carries no token and no lease check: if it named
        // the VIP service or an HA unit it would start or stop those freely.
        let with_unit = |unit: &str| {
            SAMPLE.replace(
                "service = \"mkg-demo.service\"\n",
                &format!("service = \"mkg-demo.service\"\nchrony_unit = \"{unit}\"\n"),
            )
        };
        for bad in [
            "mkg-demo.service",
            "mikagami.service",
            "mikagami-witness.service",
        ] {
            let r = ControlConfig::parse(Path::new("/x"), &with_unit(bad), None, None);
            let Err(ConfigError::Invalid(errors)) = r else {
                panic!("{bad}: expected validation errors");
            };
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("cluster.chrony_unit must not be")),
                "{bad}: {errors:?}"
            );
        }
        for good in ["chrony.service", "chronyd.service", "ntp.service"] {
            let cfg = ControlConfig::parse(Path::new("/x"), &with_unit(good), None, None)
                .unwrap_or_else(|e| panic!("{good}: {e:?}"));
            assert_eq!(cfg.chrony_unit, good);
        }
    }

    #[test]
    fn invalid_values_are_all_reported() {
        let text = SAMPLE
            .replace("vip = \"10.0.0.130\"", "vip = \"not-an-ip\"")
            .replace("gcloud = \"/usr/local/bin/gcloud\"", "gcloud = \"gcloud\"")
            .replace("priority = 20", "priority = 10");
        let Err(ConfigError::Invalid(errors)) =
            ControlConfig::parse(Path::new("/x"), &text, None, None)
        else {
            panic!("expected validation errors");
        };
        assert!(errors.iter().any(|e| e.contains("cluster.vip")));
        assert!(errors.iter().any(|e| e.contains("tools.gcloud")));
        assert!(errors.iter().any(|e| e.contains("priorities must differ")));
    }

    #[test]
    fn the_witness_must_be_independent_and_the_vip_private() {
        for (from, to) in [
            ("name = \"witness\"", "name = \"node-a\""),
            ("ip = \"10.0.0.12\"", "ip = \"10.0.0.10\""),
            ("ip = \"10.0.0.12\"", "ip = \"10.0.0.130\""),
            ("vip = \"10.0.0.130\"", "vip = \"8.8.8.8\""),
            ("ip = \"10.0.0.11\"", "ip = \"10.0.0.10\""),
        ] {
            let text = SAMPLE.replacen(from, to, 1);
            assert!(
                ControlConfig::parse(Path::new("/x"), &text, None, None).is_err(),
                "{from} -> {to}"
            );
        }
    }

    #[test]
    fn exactly_two_nodes_and_distinct_instances_are_required() {
        let one = SAMPLE.replace(
            "[nodes.node-b]\ninstance = \"inst-b\"\nip = \"10.0.0.11\"\npriority = 20\n",
            "",
        );
        assert!(ControlConfig::parse(Path::new("/x"), &one, None, None).is_err());
        let same = SAMPLE.replace("inst-b", "inst-a");
        assert!(ControlConfig::parse(Path::new("/x"), &same, None, None).is_err());
    }

    #[test]
    fn ssh_key_comes_from_env_or_file_and_is_mandatory() {
        let no_key = SAMPLE.replace("key = \"/keys/id\"", "key = \"\"");
        assert!(ControlConfig::parse(Path::new("/x"), &no_key, None, None).is_err());
        let cfg =
            ControlConfig::parse(Path::new("/x"), &no_key, Some("/env/key".into()), None).unwrap();
        assert_eq!(cfg.ssh_key, PathBuf::from("/env/key"));
        assert!(
            ControlConfig::parse(Path::new("/x"), &no_key, Some("relative".into()), None).is_err()
        );
    }

    #[test]
    fn address_mode_env_overrides_the_file() {
        let cfg = ControlConfig::parse(Path::new("/x"), SAMPLE, None, Some("external".to_string()))
            .unwrap();
        assert_eq!(cfg.address_mode, AddressMode::External);
        assert!(ControlConfig::parse(Path::new("/x"), SAMPLE, None, Some("weird".into())).is_err());
    }

    #[test]
    fn remote_command_paths_accept_only_plain_characters() {
        for bad in [
            "/usr/bin/x; reboot",
            "/usr/bin/$(id)",
            "/a b/c",
            "/a`b`",
            "/a'b",
        ] {
            let text = SAMPLE.replace(
                "[witness]",
                &format!("[agent]\nbinary = \"{bad}\"\n\n[witness]"),
            );
            assert!(
                ControlConfig::parse(Path::new("/x"), &text, None, None).is_err(),
                "{bad}"
            );
        }
        let ok = SAMPLE.replace(
            "[witness]",
            "[agent]\nbinary = \"/opt/mkg-1.0/bin/mikagami\"\n\n[witness]",
        );
        assert!(ControlConfig::parse(Path::new("/x"), &ok, None, None).is_ok());
    }

    #[test]
    fn name_validators_reject_shell_and_path_metacharacters() {
        for bad in ["", "a b", "a;b", "../x", "a/b", "A", "-a", "a$b", "a`b"] {
            assert!(!is_node_name(bad), "{bad:?}");
        }
        for bad in [
            "",
            "a b",
            "a;b",
            "x.service/../y",
            "x",
            ".x.service",
            "x y.service",
            "-x.service",
            "--version.service",
        ] {
            assert!(!is_unit_name(bad), "{bad:?}");
        }
        assert!(is_unit_name("chrony.service"));
        assert!(is_unit_name("getty@tty1.service"));
        assert!(is_gce_name("mkg-proto-node-a"));
        assert!(!is_gce_name("-bad"));
        assert!(!is_gce_name("Bad"));
    }

    #[test]
    fn dangerous_ssh_and_path_settings_are_rejected() {
        // E-02: a leading dash is an option, a device is not a known_hosts file.
        for (from, to) in [
            ("user = \"mkg\"", "user = \"-V\""),
            ("user = \"mkg\"", "user = \"-oProxyCommand=x\""),
            ("key = \"/keys/id\"", "key = \"/dev/zero\""),
            (
                "state_dir = \"/var/lib/mkg\"",
                "state_dir = \"/dev/shm/mkg\"",
            ),
        ] {
            let text = SAMPLE.replacen(from, to, 1);
            assert!(
                ControlConfig::parse(Path::new("/x"), &text, None, None).is_err(),
                "{to}"
            );
        }
        for hosts in ["/dev/null", "/dev/zero", "/proc/self/environ", "/dev"] {
            let text = SAMPLE.replacen(
                "timeout_s = 15",
                &format!("timeout_s = 15\nknown_hosts = \"{hosts}\""),
                1,
            );
            assert!(
                ControlConfig::parse(Path::new("/x"), &text, None, None).is_err(),
                "{hosts}"
            );
        }
        let ok = SAMPLE.replacen(
            "timeout_s = 15",
            "timeout_s = 15\nknown_hosts = \"/var/lib/mkg/kh\"",
            1,
        );
        assert!(ControlConfig::parse(Path::new("/x"), &ok, None, None).is_ok());
    }

    #[test]
    fn load_applies_the_trust_standard_to_the_file_and_the_tools() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::manual::fsutil::tests::temp_dir("config-load");
        let mode = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let tool = |name: &str| {
            let p = dir.join(name);
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            mode(&p, 0o755);
            p
        };
        let (ssh, gcloud) = (tool("ssh"), tool("gcloud"));
        let text = SAMPLE
            .replace(
                "ssh = \"/usr/bin/ssh\"",
                &format!("ssh = \"{}\"", ssh.display()),
            )
            .replace(
                "gcloud = \"/usr/local/bin/gcloud\"",
                &format!("gcloud = \"{}\"", gcloud.display()),
            );
        let file = dir.join("prototype.toml");
        std::fs::write(&file, &text).unwrap();
        mode(&file, 0o600);
        let load = ControlConfig::load;
        assert!(load(&file).is_ok(), "{:?}", load(&file).err());

        // The file itself.
        mode(&file, 0o666);
        let Err(ConfigError::Io(m)) = load(&file) else {
            panic!("a world-writable configuration must be refused");
        };
        assert!(m.contains("writable"), "{m}");
        mode(&file, 0o600);
        let link = dir.join("link.toml");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let Err(ConfigError::Io(m)) = load(&link) else {
            panic!("a symlink must be refused");
        };
        assert!(m.contains("symlink"), "{m}");
        let big = dir.join("big.toml");
        std::fs::write(&big, vec![b'#'; (MAX_CONFIG_BYTES + 1) as usize]).unwrap();
        mode(&big, 0o600);
        let Err(ConfigError::Io(m)) = load(&big) else {
            panic!("an oversize configuration must be refused");
        };
        assert!(m.contains("larger"), "{m}");
        for device in ["/dev/zero", "/dev/null"] {
            assert!(matches!(load(Path::new(device)), Err(ConfigError::Io(_))));
        }

        // The tools it names.
        mode(&ssh, 0o777);
        let Err(ConfigError::Io(m)) = load(&file) else {
            panic!("a writable ssh must be refused");
        };
        assert!(m.contains("tools.ssh") && m.contains("writable"), "{m}");
        mode(&ssh, 0o755);
        mode(&gcloud, 0o644);
        let Err(ConfigError::Io(m)) = load(&file) else {
            panic!("a non-executable gcloud must be refused");
        };
        assert!(m.contains("tools.gcloud"), "{m}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
