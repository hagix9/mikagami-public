//! The shared two-node configuration: one TOML file, identical on both nodes, that
//! describes both nodes under `[nodes.<id>]`. Each node knows which one it is from a small
//! node identity file (`node-id`, next to the configuration file) written once by
//! `mikagami node register`. The node id is never guessed from the host name.
//!
//! The shared file is translated into the per-node two-node shape (`[node]`, `[peer]`,
//! `[[two_node.link]]` with `listen` / `peer_address`, the peer's fence commands) and then
//! validated by exactly the same code as a hand-written per-node file. Nothing after the
//! translation knows the file was shared, so no runtime gate changes.
//!
//! Both nodes also derive a *configuration summary* (a digest per section of the values that
//! must agree) and send it in the link `Hello`. A peer whose summary differs is refused (see
//! `wire::WireError::ConfigMismatch` and the controller's `on_incompatible`).

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The node identity file name; it lives in the configuration file's directory.
pub const NODE_ID_FILE: &str = "node-id";
const MAX_NODE_ID_FILE_BYTES: u64 = 4096;

/// The sections of the summary, in the order they are sent.
const SUMMARY_SECTIONS: [&str; 9] = [
    "cluster", "nodes", "two_node", "vip", "service", "group", "health", "failover", "fencing",
];

/// `two_node` keys that are node-local paths or counters, not values both nodes must share.
const LOCAL_TWO_NODE_KEYS: [&str; 3] = ["state_path", "status_path", "operator_dir"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSharedCluster {
    id: String,
    topology: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNodeFencing {
    fence: Option<Vec<String>>,
    verify: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSharedNode {
    #[serde(default)]
    preferred: bool,
    vip_interface: Option<String>,
    fencing: Option<RawNodeFencing>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSharedLink {
    segment: String,
    role: toml::Value,
    port: u16,
    address: BTreeMap<String, String>,
    interface: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSharedTwoNode {
    #[serde(default)]
    link: Vec<RawSharedLink>,
    fencing_device: Option<toml::Value>,
    fencing_path: Option<toml::Value>,
    state_path: Option<toml::Value>,
    status_path: Option<toml::Value>,
    operator_dir: Option<toml::Value>,
    max_start_failures: Option<toml::Value>,
}

/// The shared fencing section: the backend and the timing are shared; the commands are per
/// node (`[nodes.<id>.fencing]`, "how to fence this node").
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSharedFencing {
    backend: toml::Value,
    fence_timeout_sec: Option<toml::Value>,
    verify_timeout_sec: Option<toml::Value>,
    verify_polls: Option<toml::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShared {
    cluster: RawSharedCluster,
    nodes: BTreeMap<String, RawSharedNode>,
    two_node: RawSharedTwoNode,
    vip: toml::Value,
    service: Option<toml::Value>,
    group: Option<toml::Value>,
    health: toml::Value,
    fencing: Option<RawSharedFencing>,
    security: toml::Value,
    failover: Option<toml::Value>,
    control: Option<toml::Value>,
}

/// Whether the file uses the shared shape (`[nodes]` present). Only the top-level keys are
/// read; a file that is not TOML is left to the normal parser's error.
pub fn is_shared_shape(contents: &str) -> bool {
    toml::from_str::<toml::Table>(contents).is_ok_and(|table| table.contains_key("nodes"))
}

/// The result of translating the shared file for one node.
#[derive(Debug, Clone)]
pub struct Derived {
    /// The per-node two-node file shape, ready for the normal parser.
    pub per_node: toml::Table,
    /// The configuration summary both nodes must agree on.
    pub summary: String,
    pub node_ids: Vec<String>,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && !id.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Translates the shared file for `node_id`. Every problem is reported (not only the first).
pub fn derive(contents: &str, node_id: &str) -> Result<Derived, Vec<String>> {
    let raw: RawShared = toml::from_str(contents).map_err(|e| vec![e.to_string()])?;
    let mut errors = Vec::new();
    if raw.cluster.topology != "two-node" {
        errors.push("[nodes] is only valid with cluster.topology = \"two-node\"".to_string());
    }
    let ids: Vec<String> = raw.nodes.keys().cloned().collect();
    if ids.len() != 2 {
        errors.push(format!(
            "[nodes] must describe exactly two nodes (found {})",
            ids.len()
        ));
    }
    for id in &ids {
        if !valid_id(id) {
            errors.push(format!(
                "nodes.{id:?}: a node id must be non-empty without whitespace or control characters"
            ));
        }
    }
    let preferred: Vec<&String> = raw
        .nodes
        .iter()
        .filter(|(_, node)| node.preferred)
        .map(|(id, _)| id)
        .collect();
    if preferred.len() != 1 {
        errors.push(format!(
            "exactly one node must set preferred = true (found {})",
            preferred.len()
        ));
    }
    if !raw.nodes.contains_key(node_id) {
        errors.push(format!(
            "the registered node id {node_id:?} is not one of [nodes] ({})",
            ids.join(", ")
        ));
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let peer_id = ids
        .iter()
        .find(|id| id.as_str() != node_id)
        .cloned()
        .expect("two distinct ids");
    let me = &raw.nodes[node_id];
    let peer = &raw.nodes[&peer_id];
    let inbound = node_id > peer_id.as_str();

    // Links: both nodes' address and interface on every link; the lower id dials.
    let mut links = Vec::new();
    for (position, link) in raw.two_node.link.iter().enumerate() {
        let field = format!("two_node.link[{position}]");
        for (what, map) in [("address", &link.address), ("interface", &link.interface)] {
            let keys: Vec<&String> = map.keys().collect();
            let expected: Vec<&String> = ids.iter().collect();
            if keys != expected {
                errors.push(format!(
                    "{field}.{what} must name exactly the two nodes ({}); found {}",
                    ids.join(", "),
                    keys.iter()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        if link.port == 0 {
            errors.push(format!("{field}.port must not be 0"));
        }
        let (Some(my_address), Some(peer_address), Some(my_interface)) = (
            link.address.get(node_id),
            link.address.get(&peer_id),
            link.interface.get(node_id),
        ) else {
            continue;
        };
        // Both addresses are IPv4 (the dialing node's own address is not used by the link,
        // but it is the shared description of that node and is checked the same way).
        let mine: Option<std::net::Ipv4Addr> = my_address.parse().ok();
        let theirs: Option<std::net::Ipv4Addr> = peer_address.parse().ok();
        for (id, address, ok) in [
            (node_id, my_address, mine.is_some()),
            (peer_id.as_str(), peer_address, theirs.is_some()),
        ] {
            if !ok {
                errors.push(format!(
                    "{field}.address.{id}: {address:?} is not an IPv4 address"
                ));
            }
        }
        if mine.is_some() && mine == theirs {
            errors.push(format!(
                "{field}.address: the two nodes have the same address"
            ));
        }
        let mut entry = toml::Table::new();
        entry.insert("segment".into(), link.segment.clone().into());
        entry.insert("role".into(), link.role.clone());
        entry.insert("interface".into(), my_interface.clone().into());
        if inbound {
            entry.insert(
                "listen".into(),
                format!("{my_address}:{}", link.port).into(),
            );
        } else {
            entry.insert(
                "peer_address".into(),
                format!("{peer_address}:{}", link.port).into(),
            );
        }
        links.push(toml::Value::Table(entry));
    }

    // Fencing: the shared timing plus the commands that fence the *peer*.
    let fencing = match &raw.fencing {
        None => None,
        Some(shared) => {
            let command = shared.backend.as_str() == Some("command");
            let mut table = toml::Table::new();
            table.insert("backend".into(), shared.backend.clone());
            for (key, value) in [
                ("fence_timeout_sec", &shared.fence_timeout_sec),
                ("verify_timeout_sec", &shared.verify_timeout_sec),
                ("verify_polls", &shared.verify_polls),
            ] {
                if let Some(value) = value {
                    table.insert(key.into(), value.clone());
                }
            }
            if command {
                // Both nodes must be fenceable: each node's file is the other's fence target.
                for (id, node) in &raw.nodes {
                    let ok = node
                        .fencing
                        .as_ref()
                        .is_some_and(|f| f.fence.is_some() && f.verify.is_some());
                    if !ok {
                        errors.push(format!(
                            "nodes.{id}.fencing: fence and verify (how to fence {id}) are \
                             required with fencing.backend = \"command\""
                        ));
                    }
                }
                if let Some(target) = &peer.fencing {
                    if let Some(fence) = &target.fence {
                        table.insert("fence".into(), argv(fence));
                    }
                    if let Some(verify) = &target.verify {
                        table.insert("verify".into(), argv(verify));
                    }
                }
            } else if raw.nodes.values().any(|n| n.fencing.is_some()) {
                errors.push(
                    "nodes.<id>.fencing is only valid with fencing.backend = \"command\""
                        .to_string(),
                );
            }
            Some(table)
        }
    };
    if raw.fencing.is_none() && raw.nodes.values().any(|n| n.fencing.is_some()) {
        errors.push(
            "nodes.<id>.fencing needs a [fencing] section with backend = \"command\"".to_string(),
        );
    }

    // VIP: the shared VIP with this node's interface override.
    let mut vip = raw.vip.clone();
    if let Some(interface) = &me.vip_interface {
        match vip.as_table_mut() {
            Some(table) => {
                table.insert("interface".into(), interface.clone().into());
            }
            None => errors.push("[vip] must be a table".to_string()),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut cluster = toml::Table::new();
    cluster.insert("id".into(), raw.cluster.id.clone().into());
    cluster.insert("topology".into(), "two-node".into());
    let mut node = toml::Table::new();
    node.insert("id".into(), node_id.into());
    node.insert("preferred".into(), me.preferred.into());
    let mut peer_table = toml::Table::new();
    peer_table.insert("id".into(), peer_id.clone().into());
    let mut two_node = toml::Table::new();
    two_node.insert("link".into(), toml::Value::Array(links));
    for (key, value) in [
        ("fencing_device", &raw.two_node.fencing_device),
        ("fencing_path", &raw.two_node.fencing_path),
        ("state_path", &raw.two_node.state_path),
        ("status_path", &raw.two_node.status_path),
        ("operator_dir", &raw.two_node.operator_dir),
        ("max_start_failures", &raw.two_node.max_start_failures),
    ] {
        if let Some(value) = value {
            two_node.insert(key.into(), value.clone());
        }
    }
    let mut per_node = toml::Table::new();
    per_node.insert("cluster".into(), toml::Value::Table(cluster));
    per_node.insert("node".into(), toml::Value::Table(node));
    per_node.insert("peer".into(), toml::Value::Table(peer_table));
    per_node.insert("two_node".into(), toml::Value::Table(two_node));
    per_node.insert("vip".into(), vip);
    if let Some(service) = &raw.service {
        per_node.insert("service".into(), service.clone());
    }
    if let Some(group) = &raw.group {
        per_node.insert("group".into(), group.clone());
    }
    per_node.insert("health".into(), raw.health.clone());
    per_node.insert("security".into(), raw.security.clone());
    if let Some(fencing) = fencing {
        per_node.insert("fencing".into(), toml::Value::Table(fencing));
    }
    if let Some(failover) = &raw.failover {
        per_node.insert("failover".into(), failover.clone());
    }
    if let Some(control) = &raw.control {
        per_node.insert("control".into(), control.clone());
    }
    Ok(Derived {
        per_node,
        summary: summary(contents).map_err(|e| vec![e])?,
        node_ids: ids,
    })
}

fn argv(items: &[String]) -> toml::Value {
    toml::Value::Array(items.iter().cloned().map(toml::Value::String).collect())
}

/// The configuration summary: `section=<16 hex>` for every section in [`SUMMARY_SECTIONS`],
/// comma-separated. A section is hashed from its parsed value (key order, comments and
/// formatting do not count). Node-local values (the PSK path, `[control]`, the two-node
/// state / status / operator paths) are excluded.
pub fn summary(contents: &str) -> Result<String, String> {
    let mut table: toml::Table = toml::from_str(contents).map_err(|e| e.to_string())?;
    if let Some(toml::Value::Table(two_node)) = table.get_mut("two_node") {
        for key in LOCAL_TWO_NODE_KEYS {
            two_node.remove(key);
        }
    }
    let mut parts = Vec::new();
    for section in SUMMARY_SECTIONS {
        let value = table
            .get(section)
            .map(|v| serde_json::to_value(v).map_err(|e| e.to_string()))
            .transpose()?
            .unwrap_or(serde_json::Value::Null);
        let canonical = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
        let digest = Sha256::digest(&canonical);
        let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        parts.push(format!("{section}={hex}"));
    }
    Ok(parts.join(","))
}

/// The sections whose digests differ between two summaries (all sections when a summary
/// cannot be read).
pub fn differing_sections(mine: &str, theirs: &str) -> Vec<String> {
    let parse = |s: &str| -> BTreeMap<String, String> {
        s.split(',')
            .filter_map(|part| part.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let (a, b) = (parse(mine), parse(theirs));
    let mut out: Vec<String> = SUMMARY_SECTIONS
        .iter()
        .filter(|s| a.get(**s) != b.get(**s))
        .map(|s| s.to_string())
        .collect();
    if out.is_empty() && mine != theirs {
        out.push("(unreadable summary)".to_string());
    }
    out
}

// ---- the node identity file -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentity {
    pub cluster: String,
    pub node: String,
}

/// The identity file of a configuration file: `node-id` in the same directory.
pub fn identity_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(NODE_ID_FILE)
}

/// Reads the identity file. It must be a regular file (not a symlink) owned by this
/// process's effective user, not writable by group or other, and small.
pub fn read_identity(path: &Path) -> Result<NodeIdentity, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // Opened without following a symlink; every check is made on the opened file (fstat),
    // so the file that is checked is the file that is read.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!("{} is not a regular file", path.display()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "{} does not exist: this node is not registered (run `mikagami node register \
                 --config <file> --node-id <id>` once on each node)",
                path.display()
            ));
        }
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let metadata = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{} must be owned by uid {euid} and not writable by group or other",
            path.display()
        ));
    }
    if metadata.len() > MAX_NODE_ID_FILE_BYTES {
        return Err(format!("{} is too large", path.display()));
    }
    let mut text = String::new();
    file.take(MAX_NODE_ID_FILE_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let identity: NodeIdentity =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if !valid_id(&identity.node) || identity.cluster.is_empty() {
        return Err(format!("{}: invalid node or cluster", path.display()));
    }
    Ok(identity)
}

/// Writes the identity file atomically (temporary file, fsync, rename, directory fsync),
/// mode 0600.
pub fn write_identity(path: &Path, identity: &NodeIdentity) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = dir.join(format!(".{NODE_ID_FILE}.tmp-{}", std::process::id()));
    let text = format!(
        "# Written by `mikagami node register`. The node id of this host in the shared\n\
         # configuration; do not copy this file to the other node.\n{}",
        toml::to_string(identity).map_err(|e| e.to_string())?
    );
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const SHARED: &str = r#"
[cluster]
id = "example-2n"
topology = "two-node"

[nodes.node-a]
preferred = true
[nodes.node-a.fencing]
fence = ["/usr/local/sbin/fence-node", "node-a"]
verify = ["/usr/local/sbin/verify-node-fenced", "node-a"]

[nodes.node-b]
vip_interface = "ens5"
[nodes.node-b.fencing]
fence = ["/usr/local/sbin/fence-node", "node-b"]
verify = ["/usr/local/sbin/verify-node-fenced", "node-b"]

[two_node]
fencing_device = "independent"
fencing_path = "separate"

[[two_node.link]]
segment = "ha-net"
role = "ha"
port = 7946
address = { node-a = "10.0.1.11", node-b = "10.0.1.12" }
interface = { node-a = "eth1", node-b = "eth1" }

[[two_node.link]]
segment = "service-net"
role = "service"
port = 7946
address = { node-a = "192.168.100.11", node-b = "192.168.100.12" }
interface = { node-a = "eth0", node-b = "ens5" }

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

[failover]
auto = true
cycle_timeout_sec = 180

[fencing]
backend = "command"
verify_polls = 60
"#;

    fn errors(contents: &str, node: &str) -> String {
        derive(contents, node).unwrap_err().join("\n")
    }

    #[test]
    fn detects_the_shared_shape_only_with_nodes() {
        assert!(is_shared_shape(SHARED));
        assert!(!is_shared_shape(
            "[cluster]\nid = \"x\"\n[node]\nid = \"a\"\n"
        ));
        assert!(!is_shared_shape("not toml ["));
    }

    #[test]
    fn derives_the_outbound_node_a() {
        let derived = derive(SHARED, "node-a").unwrap();
        let t = &derived.per_node;
        assert_eq!(t["node"]["id"].as_str(), Some("node-a"));
        assert_eq!(t["node"]["preferred"].as_bool(), Some(true));
        assert_eq!(t["peer"]["id"].as_str(), Some("node-b"));
        let links = t["two_node"]["link"].as_array().unwrap();
        assert_eq!(links[0]["peer_address"].as_str(), Some("10.0.1.12:7946"));
        assert!(links[0].get("listen").is_none());
        assert_eq!(links[1]["interface"].as_str(), Some("eth0"));
        assert_eq!(t["vip"]["interface"].as_str(), Some("eth0"));
        // node-a fences node-b with node-b's commands.
        assert_eq!(t["fencing"]["fence"][1].as_str(), Some("node-b"));
        assert_eq!(t["fencing"]["verify"][1].as_str(), Some("node-b"));
        assert_eq!(t["fencing"]["verify_polls"].as_integer(), Some(60));
    }

    #[test]
    fn derives_the_inbound_node_b() {
        let derived = derive(SHARED, "node-b").unwrap();
        let t = &derived.per_node;
        assert_eq!(t["node"]["preferred"].as_bool(), Some(false));
        let links = t["two_node"]["link"].as_array().unwrap();
        assert_eq!(links[0]["listen"].as_str(), Some("10.0.1.12:7946"));
        assert!(links[0].get("peer_address").is_none());
        assert_eq!(links[1]["listen"].as_str(), Some("192.168.100.12:7946"));
        assert_eq!(links[1]["interface"].as_str(), Some("ens5"));
        assert_eq!(t["vip"]["interface"].as_str(), Some("ens5"));
        assert_eq!(t["fencing"]["fence"][1].as_str(), Some("node-a"));
    }

    #[test]
    fn both_nodes_derive_the_same_summary() {
        let a = derive(SHARED, "node-a").unwrap().summary;
        let b = derive(SHARED, "node-b").unwrap().summary;
        assert_eq!(a, b);
        assert_eq!(a.split(',').count(), SUMMARY_SECTIONS.len());
    }

    #[test]
    fn summary_ignores_formatting_comments_and_local_paths() {
        let base = summary(SHARED).unwrap();
        let reformatted = SHARED
            .replace("[vip]\naddress", "# a comment\n[vip]\naddress")
            .replace(
                "psk_file = \"/etc/mikagami/cluster.psk\"",
                "psk_file = \"/srv/psk\"",
            )
            .replace(
                "fencing_path = \"separate\"",
                "fencing_path = \"separate\"\nstate_path = \"/srv/state.json\"",
            );
        assert_eq!(summary(&reformatted).unwrap(), base);
    }

    #[test]
    fn summary_names_the_differing_sections() {
        let base = summary(SHARED).unwrap();
        for (from, to, section) in [
            ("192.168.100.50/24", "192.168.100.51/24", "vip"),
            ("nginx.service", "httpd.service", "service"),
            ("verify_polls = 60", "verify_polls = 10", "fencing"),
            (
                "cycle_timeout_sec = 180",
                "cycle_timeout_sec = 120",
                "failover",
            ),
            ("10.0.1.12", "10.0.1.13", "two_node"),
            (
                "vip_interface = \"ens5\"",
                "vip_interface = \"ens6\"",
                "nodes",
            ),
        ] {
            let changed = summary(&SHARED.replace(from, to)).unwrap();
            assert_eq!(differing_sections(&base, &changed), vec![section], "{from}");
        }
        assert_eq!(differing_sections(&base, &base), Vec::<String>::new());
        assert!(!differing_sections(&base, "garbage").is_empty());
    }

    #[test]
    fn rejects_bad_node_sets() {
        let three = SHARED.replace("[two_node]\n", "[nodes.node-c]\n\n[two_node]\n");
        assert!(errors(&three, "node-a").contains("exactly two nodes"));
        let one = SHARED
            .replace("[nodes.node-b]\nvip_interface = \"ens5\"\n", "")
            .replace(
                "[nodes.node-b.fencing]\nfence = [\"/usr/local/sbin/fence-node\", \"node-b\"]\nverify = [\"/usr/local/sbin/verify-node-fenced\", \"node-b\"]\n",
                "",
            );
        assert!(errors(&one, "node-a").contains("exactly two nodes"));
        assert!(errors(SHARED, "node-z").contains("not one of [nodes]"));
        let none = SHARED.replace("preferred = true", "preferred = false");
        assert!(errors(&none, "node-a").contains("exactly one node must set preferred"));
        let both = SHARED.replace(
            "[nodes.node-b]\nvip_interface",
            "[nodes.node-b]\npreferred = true\nvip_interface",
        );
        assert!(errors(&both, "node-a").contains("exactly one node must set preferred"));
        let spaced = SHARED.replace("nodes.node-b", "nodes.\"node b\"");
        assert!(errors(&spaced, "node-a").contains("node id must be non-empty"));
        let witness = SHARED.replace("topology = \"two-node\"", "topology = \"witness\"");
        assert!(errors(&witness, "node-a").contains("only valid with cluster.topology"));
    }

    #[test]
    fn rejects_incomplete_or_conflicting_links() {
        let missing = SHARED.replace(
            "address = { node-a = \"10.0.1.11\", node-b = \"10.0.1.12\" }",
            "address = { node-a = \"10.0.1.11\" }",
        );
        assert!(errors(&missing, "node-a").contains("two_node.link[0].address must name"));
        let extra = SHARED.replace(
            "interface = { node-a = \"eth1\", node-b = \"eth1\" }",
            "interface = { node-a = \"eth1\", node-b = \"eth1\", node-c = \"eth1\" }",
        );
        assert!(errors(&extra, "node-b").contains("two_node.link[0].interface must name"));
        let garbage = SHARED.replace("node-a = \"10.0.1.11\"", "node-a = \"garbage\"");
        for node in ["node-a", "node-b"] {
            assert!(
                errors(&garbage, node).contains("address.node-a: \"garbage\" is not an IPv4"),
                "{node}"
            );
        }
        let padded = SHARED.replace("node-b = \"10.0.1.12\"", "node-b = \"10.0.1.011\"");
        assert!(derive(&padded, "node-a").is_err());
        let same = SHARED.replace("node-b = \"10.0.1.12\"", "node-b = \"10.0.1.11\"");
        assert!(errors(&same, "node-a").contains("the same address"));
        let zero = SHARED.replacen("port = 7946", "port = 0", 1);
        assert!(errors(&zero, "node-a").contains("port must not be 0"));
        let unknown = SHARED.replacen("port = 7946", "port = 7946\nlisten = \"x\"", 1);
        assert!(errors(&unknown, "node-a").contains("unknown field"));
    }

    #[test]
    fn rejects_missing_or_misplaced_fencing() {
        let no_b = SHARED.replace(
            "[nodes.node-b.fencing]\nfence = [\"/usr/local/sbin/fence-node\", \"node-b\"]\nverify = [\"/usr/local/sbin/verify-node-fenced\", \"node-b\"]\n",
            "",
        );
        // node-b's own derivation does not need node-b's commands, but the shared file must
        // make both nodes fenceable: both derivations refuse.
        assert!(errors(&no_b, "node-a").contains("nodes.node-b.fencing"));
        assert!(errors(&no_b, "node-b").contains("nodes.node-b.fencing"));
        let none_backend = SHARED.replace("backend = \"command\"", "backend = \"none\"");
        assert!(errors(&none_backend, "node-a").contains("only valid with fencing.backend"));
        let unknown = SHARED.replace("verify_polls = 60", "verify_polls = 60\nfence = [\"/x\"]");
        assert!(errors(&unknown, "node-a").contains("unknown field"));
    }

    #[test]
    fn identity_file_round_trip_and_checks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mkg-node-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("mikagami.toml");
        let path = identity_path(&config);
        assert_eq!(path, dir.join("node-id"));
        assert!(read_identity(&path).unwrap_err().contains("not registered"));
        let identity = NodeIdentity {
            cluster: "example-2n".into(),
            node: "node-a".into(),
        };
        write_identity(&path, &identity).unwrap();
        assert_eq!(read_identity(&path).unwrap(), identity);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_identity(&path).unwrap_err().contains("not writable"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            read_identity(&link)
                .unwrap_err()
                .contains("not a regular file")
        );
        std::fs::write(&path, "cluster = \"c\"\nnode = \"a b\"\n").unwrap();
        assert!(read_identity(&path).unwrap_err().contains("invalid"));
        std::fs::write(&path, "cluster = \"c\"\nnode = \"a\"\nextra = 1\n").unwrap();
        assert!(read_identity(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
