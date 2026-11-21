//! `daemon run` topology dispatch and the `two-node` subcommands.

use super::runtime::{OperatorKind, OperatorRequest, StatusView};
use super::store::{FileStore, LoadError};
use crate::cli::{NodeCommands, TwoNodeCommands};
use crate::config::{Config, Topology};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::process::ExitCode;

/// `daemon run`: a two-node configuration runs the two-node runtime; every other
/// configuration (and every configuration error) takes the unchanged Witness path.
pub(crate) fn run_daemon(config_path: &Path, arping: &Path) -> ExitCode {
    match Config::load(config_path) {
        Ok(config) if config.topology == Topology::TwoNode => {
            match super::runtime::run_daemon(config, arping) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("mikagami: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => crate::daemon_run::run_daemon(config_path, arping),
    }
}

pub(crate) fn run(command: TwoNodeCommands) -> ExitCode {
    let result = match command {
        TwoNodeCommands::Init {
            config,
            replace_corrupt,
        } => init(&config, replace_corrupt),
        TwoNodeCommands::Status { config, json } => status(&config, json),
        TwoNodeCommands::Takeover {
            config,
            attest_peer_stopped,
            fence,
        } => takeover(&config, attest_peer_stopped, fence),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mikagami: {error}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn run_node(command: NodeCommands) -> ExitCode {
    let result = match command {
        NodeCommands::Register {
            config,
            node_id,
            replace,
        } => register(&config, &node_id, replace),
        NodeCommands::Show { config } => show_node(&config),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mikagami: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `node register`: validates the shared file for `node_id`, then writes the identity file.
/// An existing identity is never silently changed; `--replace` is refused while a two-node
/// record exists (it belongs to the old id: move it aside first, never reuse it).
fn register(path: &Path, node_id: &str, replace: bool) -> Result<(), String> {
    use super::shared::{NodeIdentity, identity_path, is_shared_shape, read_identity};
    let contents = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !is_shared_shape(&contents) {
        return Err(format!(
            "{} is not a shared configuration ([nodes.<id>]); a per-node file names its node \
             in [node] and needs no registration",
            path.display()
        ));
    }
    let config = Config::parse_shared(&contents, node_id).map_err(|e| e.operator_summary())?;
    let two_node = config
        .two_node
        .as_ref()
        .ok_or("not a two-node configuration")?;
    let wanted = NodeIdentity {
        cluster: config.cluster.id.clone(),
        node: node_id.to_string(),
    };
    let target = identity_path(path);
    match std::fs::symlink_metadata(&target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", target.display())),
        Ok(_) => {
            let existing = read_identity(&target)
                .map_err(|e| format!("{e}; not overwritten (inspect and remove it yourself)"))?;
            if existing == wanted {
                println!(
                    "already registered: node {node_id} of cluster {}",
                    wanted.cluster
                );
                return Ok(());
            }
            if !replace {
                return Err(format!(
                    "{} already registers node {:?} of cluster {:?}; use --replace to change it",
                    target.display(),
                    existing.node,
                    existing.cluster
                ));
            }
            // Any entry (also a dangling symlink or an unreadable path) counts as a record.
            if std::fs::symlink_metadata(&two_node.state_path).is_ok() {
                return Err(format!(
                    "--replace refused: the two-node record {} exists and belongs to the \
                     previous registration; stop the daemon and move the record aside first \
                     (it is never reused under another node id)",
                    two_node.state_path
                ));
            }
        }
    }
    // A record of another node or cluster at the state path is never adopted.
    match FileStore::new(&two_node.state_path).load(&config.cluster.id, node_id) {
        Ok(_) | Err(LoadError::Missing) => {}
        Err(error) => {
            return Err(format!(
                "the two-node record {} cannot be used by node {node_id}: {error}; move it \
                 aside first",
                two_node.state_path
            ));
        }
    }
    super::shared::write_identity(&target, &wanted)?;
    println!(
        "registered: this host is node {node_id} (peer {}) of cluster {}; written to {}",
        config.peer.id,
        config.cluster.id,
        target.display()
    );
    Ok(())
}

fn show_node(path: &Path) -> Result<(), String> {
    let (config, two_node) = load_two_node(path)?;
    println!("node: {}  peer: {}", config.node.id, config.peer.id);
    println!("cluster: {}", config.cluster.id);
    match &two_node.config_summary {
        Some(summary) => println!("configuration summary: {summary}"),
        None => println!("configuration: per-node file (no shared summary)"),
    }
    Ok(())
}

fn load_two_node(path: &Path) -> Result<(Config, super::config::TwoNodeConfig), String> {
    let config = Config::load(path).map_err(|error| error.operator_summary())?;
    let two_node = config
        .two_node
        .clone()
        .ok_or("this is not a two-node configuration (cluster.topology = \"two-node\")")?;
    Ok((config, two_node))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn init(path: &Path, replace_corrupt: bool) -> Result<(), String> {
    let (config, two_node) = load_two_node(path)?;
    if let Some(parent) = Path::new(&two_node.state_path).parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    FileStore::new(&two_node.state_path).init(
        &config.cluster.id,
        &config.node.id,
        replace_corrupt,
        unix_now(),
    )?;
    println!("two-node record created at {}", two_node.state_path);
    Ok(())
}

fn status(path: &Path, json: bool) -> Result<(), String> {
    let (config, two_node) = load_two_node(path)?;
    let record = FileStore::new(&two_node.state_path).load(&config.cluster.id, &config.node.id);
    let live: Option<StatusView> = std::fs::read(&two_node.status_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let policy = two_node.policy(config.failover.auto);
    if json {
        let value = serde_json::json!({
            "node": config.node.id,
            "peer": config.peer.id,
            "segments": policy.paths.segments,
            "interfaces": policy.paths.interfaces,
            "fencing_device": format!("{:?}", policy.fencing_device),
            "auto_takeover": policy.auto_takeover,
            "auto_bootstrap": policy.auto_bootstrap,
            "record": match &record {
                Ok(state) => serde_json::to_value(state).unwrap_or_default(),
                Err(error) => serde_json::json!({ "error": error.to_string() }),
            },
            "daemon": live,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
        return Ok(());
    }
    println!("topology: two-node (no Witness)");
    println!("node: {}  peer: {}", config.node.id, config.peer.id);
    println!(
        "paths: {} segment(s), {} interface(s), {} link(s){}",
        policy.paths.segments,
        policy.paths.interfaces,
        policy.paths.links,
        if policy.paths.redundant() {
            ""
        } else {
            " (no path redundancy)"
        }
    );
    println!(
        "fencing: {:?}; automatic takeover after peer loss: {}; automatic cooperative start: {}",
        policy.fencing_device,
        if policy.auto_takeover {
            "yes (after a confirmed fence)"
        } else {
            "no"
        },
        if policy.auto_bootstrap { "yes" } else { "no" }
    );
    match &record {
        Ok(state) => println!(
            "record: epoch {} owner {} holding {} grant {} incident {}",
            state.epoch,
            state.owner.as_deref().unwrap_or("-"),
            state.holding,
            state.grant.as_ref().map_or("-".to_string(), |g| format!(
                "epoch {} to {}",
                g.epoch, g.grantee
            )),
            state
                .incident
                .as_ref()
                .map_or("-".to_string(), |i| format!("seq {} {:?}", i.seq, i.state)),
        ),
        Err(LoadError::Missing) => println!("record: missing (run `mikagami two-node init`)"),
        Err(error) => println!("record: {error}"),
    }
    match &live {
        Some(view) => println!(
            "daemon (as of unix {}): role {} epoch {} peer {} links {}",
            view.updated_unix,
            view.role,
            view.epoch,
            if view.peer_connected {
                "connected"
            } else {
                "not connected"
            },
            view.links
                .iter()
                .map(|l| format!(
                    "{}[{}]={}",
                    l.segment,
                    l.role,
                    if l.up { "up" } else { "down" }
                ))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        None => println!("daemon: no status file (not running, or not yet written)"),
    }
    if let Some(view) = &live
        && !view.resources.is_empty()
    {
        println!(
            "resources (as last observed, start order): {}",
            view.resources
                .iter()
                .map(|(name, state)| format!("{name}={state}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    if live
        .as_ref()
        .is_some_and(|view| view.role != "active" && view.health.is_some())
    {
        println!("health: not monitored (this node is not Active)");
    } else if let Some(health) = live.as_ref().and_then(|view| view.health.as_ref())
        && health.last_check_unix != 0
    {
        println!(
            "health (Active only): {} (failures {} successes {} in a row), on_failure {}, \
             restarts in window {}, last action {}",
            health.state,
            health.consecutive_failures,
            health.consecutive_successes,
            health.on_failure,
            health.restarts_in_window,
            health.last_action.as_deref().unwrap_or("-")
        );
    }
    if live.as_ref().is_some_and(|view| view.config_mismatch) {
        println!(
            "config mismatch: the peer is alive with another configuration; it is not \
             admitted (no fence, takeover or bootstrap) until both nodes use the same file"
        );
    }
    Ok(())
}

fn takeover(path: &Path, attest: Option<String>, fence: Option<String>) -> Result<(), String> {
    let (config, two_node) = load_two_node(path)?;
    let (kind, target) = match (attest, fence) {
        (Some(node), None) => (OperatorKind::AttestPeerStopped, node),
        (None, Some(node)) => (OperatorKind::Fence, node),
        _ => return Err("give exactly one of --attest-peer-stopped NODE or --fence NODE".into()),
    };
    if target != config.peer.id {
        return Err(format!(
            "{target} is not the configured peer ({})",
            config.peer.id
        ));
    }
    let id = crate::node_mutation::generate_uuid().ok_or("no randomness")?;
    let request = OperatorRequest {
        version: 1,
        cluster: config.cluster.id.clone(),
        target,
        kind,
        attestation_id: id.clone(),
    };
    let dir = Path::new(&two_node.operator_dir);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("create {}: {e}", dir.display()))?;
    let file = dir.join(format!("{id}.json"));
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)
        .map_err(|e| format!("write {}: {e}", file.display()))?;
    out.write_all(&serde_json::to_vec(&request).map_err(|e| e.to_string())?)
        .and_then(|()| out.sync_all())
        .map_err(|e| format!("write {}: {e}", file.display()))?;
    println!(
        "takeover request {id} recorded; send SIGUSR1 to the two-node daemon on this node \
         (it is refused while the peer is connected)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "mkg-two-node-cli-{}",
            crate::node_mutation::generate_uuid().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let text = include_str!("../../contrib/examples/two-node-single-segment-a.toml").replace(
            "[[two_node.link]]",
            &format!(
                "[two_node]\nstate_path = \"{0}/state/two-node.json\"\nstatus_path = \"{0}/status.json\"\noperator_dir = \"{0}/operator\"\n\n[[two_node.link]]",
                dir.display()
            ),
        );
        let config = dir.join("mikagami.toml");
        std::fs::write(&config, text).unwrap();
        (dir, config)
    }

    #[test]
    fn init_status_and_takeover_requests() {
        let (dir, config) = setup();
        init(&config, false).unwrap();
        assert!(init(&config, false).is_err(), "never resets a valid record");
        let state_dir = dir.join("state");
        assert_eq!(
            std::fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        status(&config, false).unwrap();
        status(&config, true).unwrap();
        assert!(takeover(&config, None, None).is_err());
        assert!(takeover(&config, Some("node-x".into()), None).is_err());
        takeover(&config, Some("node-b".into()), None).unwrap();
        let files: Vec<_> = std::fs::read_dir(dir.join("operator"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1);
        assert_eq!(
            std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let (requests, problems) = crate::two_node::runtime::take_operator_requests(
            &dir.join("operator"),
            "example-2n-single",
        );
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].kind, OperatorKind::AttestPeerStopped);
        assert!(crate::node_mutation::is_canonical_uuid_v4(
            &requests[0].attestation_id
        ));
        // A Witness configuration is not a two-node configuration.
        let witness = dir.join("witness-node.toml");
        std::fs::write(&witness, include_str!("../../contrib/examples/node-a.toml")).unwrap();
        assert!(
            init(&witness, false)
                .unwrap_err()
                .contains("not a two-node")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn shared_setup() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "mkg-two-node-shared-cli-{}",
            crate::node_mutation::generate_uuid().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let text = include_str!("../../contrib/examples/two-node-shared.toml").replace(
            "fencing_path = \"separate\"",
            &format!(
                "fencing_path = \"separate\"\nstate_path = \"{0}/state/two-node.json\"\nstatus_path = \"{0}/status.json\"\noperator_dir = \"{0}/operator\"",
                dir.display()
            ),
        );
        let config = dir.join("mikagami.toml");
        std::fs::write(&config, text).unwrap();
        (dir, config)
    }

    #[test]
    fn register_writes_the_identity_once_and_never_reuses_a_record() {
        let (dir, config) = shared_setup();
        let id_file = dir.join("node-id");
        // Unregistered: every reader refuses.
        assert!(
            load_two_node(&config)
                .unwrap_err()
                .contains("not registered")
        );
        assert!(
            register(&config, "node-z", false)
                .unwrap_err()
                .contains("not one of")
        );
        assert!(!id_file.exists(), "a refused registration writes nothing");
        register(&config, "node-a", false).unwrap();
        assert_eq!(
            std::fs::metadata(&id_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        register(&config, "node-a", false).unwrap();
        let (loaded, _) = load_two_node(&config).unwrap();
        assert_eq!(loaded.node.id, "node-a");
        show_node(&config).unwrap();
        // A different id needs --replace.
        assert!(
            register(&config, "node-b", false)
                .unwrap_err()
                .contains("--replace")
        );
        register(&config, "node-b", true).unwrap();
        assert_eq!(load_two_node(&config).unwrap().0.node.id, "node-b");
        // Once a record exists it belongs to node-b: --replace is refused.
        init(&config, false).unwrap();
        let refused = register(&config, "node-a", true).unwrap_err();
        assert!(refused.contains("move the record aside"), "{refused}");
        assert_eq!(load_two_node(&config).unwrap().0.node.id, "node-b");
        // A fresh registration never adopts another node's record.
        std::fs::remove_file(&id_file).unwrap();
        let foreign = register(&config, "node-a", false).unwrap_err();
        assert!(
            foreign.contains("cannot be used by node node-a"),
            "{foreign}"
        );
        assert!(!id_file.exists());
        // An unsafe identity file is not overwritten.
        std::fs::write(&id_file, "garbage").unwrap();
        assert!(
            register(&config, "node-b", true)
                .unwrap_err()
                .contains("not overwritten")
        );
        // A per-node file needs no registration.
        let per_node = dir.join("per-node.toml");
        std::fs::write(
            &per_node,
            include_str!("../../contrib/examples/two-node-a.toml"),
        )
        .unwrap();
        assert!(
            register(&per_node, "node-a", false)
                .unwrap_err()
                .contains("not a shared")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
