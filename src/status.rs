//! Stage 13.4 one-shot read-only status report (MKM-13.4-04).
//!
//! `mikagami status [--config <path>]` prints a truthful report assembled
//! exclusively from:
//!
//! - the configuration file (configuration-derived facts), and
//! - the persisted node mutation state (`NodeMutationStore`, read-only).
//!
//! This module intentionally imports no daemon, witness-session, peer,
//! promotion, lease, or resource-mutation machinery. It does not tick, does
//! not contact the peer or the Witness, does not mint evidence, does not
//! acquire a lease, and cannot reconstruct `Authorized` — ephemeral runtime
//! state is reported as unavailable rather than invented.
//!
//! Stage 14 Design Revision 5 §28 adds the additive fencing / activation
//! lines. They are a presentation of the persisted Node document, the
//! configuration, and (read-only) whether an attestation intent file exists.
//! They are never an input to any decision: the daemon never reads status
//! output, and nothing here mints evidence, alters fencing state, or writes
//! a file (guard `014_status_is_one_shot_read_only`).

use crate::attestation::{ROOT_UID, TrustedDir, canonical_subject, intent_dir, intent_pending};
use crate::config::{Config, ConfigError, FencingBackendKind, Mode, ServiceManager};
use crate::connection_manager::{ConnectionDirection, canonical_direction};
use crate::fencing::{FencingIncident, FencingState};
use crate::node_mutation::{NodeMutationError, NodeMutationPersistentState, NodeMutationStore};
use crate::protocol::{ClusterId, NodeId};
use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Default configuration location used when `--config` is not given.
pub(crate) const DEFAULT_CONFIG_PATH: &str = "/etc/mikagami/mikagami.toml";

/// Print the one-shot report and exit. The report itself carries any
/// degradation truthfully; producing the text always succeeds. Delivering it
/// does not: EPIPE (`status | head`) is ignored, every other write error is a
/// process failure.
pub(crate) fn run_with(
    config_path: Option<PathBuf>,
    control_config: Option<PathBuf>,
    json: bool,
) -> ExitCode {
    let path = config_path.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    let report = status_report(&path);
    // The manual control-plane overview is additive and opt-in; the HA report
    // above is produced exactly as before and never contacts a peer.
    let overview = crate::manual::run::status_wanted(control_config.as_deref(), path.is_file())
        .map(|control| crate::manual::run::status_overview(&control));
    // The process exit code, decided before anything is printed so that the
    // JSON document can state it (R4: `exit` and `result` agree with it).
    let exit = match &overview {
        None => 0,
        Some(Ok(output)) => output.exit,
        Some(Err(failure)) => failure.exit_code().max(1),
    };
    // The overview only ends 0 (consistent), 4 (not provably consistent) or
    // with a failure of its own kind (1, 3 or 4).
    let result = match (&overview, exit) {
        (Some(Err(failure)), _) => failure.label().to_lowercase(),
        (_, 0) => "ok".to_string(),
        _ => "unknown".to_string(),
    };
    let output = if json {
        let control = match &overview {
            None => serde_json::Value::Null,
            Some(Ok(output)) => output.json.clone(),
            Some(Err(failure)) => serde_json::json!({
                "ok": false,
                "result": failure.label().to_lowercase(),
                "exit": exit,
                "error": failure.message(),
            }),
        };
        // `ok` agrees with the exit code (audit E-06): the HA report always
        // succeeds; the control-plane overview, when asked for, must be
        // consistent.
        let ok = match &overview {
            None => true,
            Some(Ok(output)) => output.exit == 0,
            Some(Err(_)) => false,
        };
        let document = serde_json::json!({
            "ok": ok,
            "exit": exit,
            "result": result,
            "ha_local": {"report": report},
            "control": control,
        });
        format!(
            "{}\n",
            serde_json::to_string_pretty(&document).unwrap_or_default()
        )
    } else {
        let mut text = format!("{report}\n");
        if let Some(Ok(output)) = &overview {
            text.push_str(&output.text);
        }
        text
    };
    // EPIPE is the ordinary `status | head` case: the reader is gone and the
    // report itself was produced. Every other write error (ENOSPC, EIO, a
    // read-only stdout, ...) means the report was NOT delivered and must not
    // be reported as a success. `EBADF` from a closed descriptor is included:
    // Rust's standard streams swallow it on `print!`, but an explicit writer
    // can see it, and silently losing the report is exactly what this check
    // exists to prevent.
    match write_stdout(&output) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
        Err(error) => {
            // Status is read-only; this message is diagnostic only. A failing
            // stderr must not turn the diagnostic into a panic.
            let mut err = io::stderr().lock();
            let _ = writeln!(err, "mikagami: cannot write the status report: {error}");
            let _ = err.flush();
            return ExitCode::FAILURE;
        }
    }
    if let Some(Err(failure)) = &overview {
        // The message goes to standard error as before.
        return crate::manual::run::status_failure_exit(failure);
    }
    ExitCode::from(exit)
}

/// Write the complete report through one explicit writer. Kept separate from
/// `run_with` so the error classification can be tested without a real full
/// disk or a closed pipe.
fn write_stdout(text: &str) -> io::Result<()> {
    write_report(io::stdout().lock(), text)
}

fn write_report(mut writer: impl io::Write, text: &str) -> io::Result<()> {
    writer.write_all(text.as_bytes())?;
    writer.flush()
}

/// Build the one-shot report text. Pure read: configuration file, the
/// persisted node-mutation state, and whether an attestation intent file
/// exists in the (root-owned) state directory. No other I/O.
fn status_report(path: &Path) -> String {
    status_report_with(path, ROOT_UID)
}

/// `status_report` with the uid the attestation intent directory must belong
/// to (production: root; a test owns its private directory).
fn status_report_with(path: &Path, attestation_owner: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "config: {}", path.display());
    match Config::load(path) {
        Err(error) => {
            let _ = writeln!(out, "config.loaded: no ({})", config_load_failure(&error));
            let _ = writeln!(
                out,
                "daemon.state: unknown (configuration unavailable; no live inspection)"
            );
        }
        Ok(config) => {
            let _ = writeln!(out, "config.loaded: yes");
            write_config_facts(&mut out, &config);
            write_control_barrier_fact(&mut out, &config, attestation_owner);
            let persisted = write_persistent_facts(&mut out, &config);
            write_stage14_facts(
                &mut out,
                &config,
                path,
                &persisted,
                inspect_attestation(&config, attestation_owner),
            );
            write_route_facts(&mut out, &config);
            let _ = writeln!(
                out,
                "daemon.state: unknown (ephemeral runtime state is not reportable; \
                 no live inspection)"
            );
        }
    }
    out
}

/// v0.7 G-2: the persisted route-handoff record, read only (`route_handoff::status_lines`). The
/// node never reports the HA switchover as complete: service reachability is an external check.
fn write_route_facts(out: &mut String, config: &Config) {
    // No `[route]`: no line, so the report of a node without route handoff is unchanged.
    let Some(route) = &config.route else {
        return;
    };
    let lines = match crate::route_handoff::RhStore::open(Path::new(&route.intent_dir))
        .and_then(|store| store.latest())
    {
        Ok(record) => crate::route_handoff::status_lines(record.as_ref()),
        Err(error) => vec![format!("route.handoff: unknown ({error})")],
    };
    for line in lines {
        let _ = writeln!(out, "{line}");
    }
}

/// The durable manual-operation barrier is a read-only fact: an open record
/// means the HA daemon refuses to start on this host. The check never writes,
/// never acquires the control lock and never contacts the control host.
fn write_control_barrier_fact(out: &mut String, config: &Config, owner: u32) {
    match crate::manual_barrier::check(
        Path::new(&config.control.manual_barrier_path),
        owner,
        &config.cluster.id,
        &config.node.id,
    ) {
        Ok(crate::manual_barrier::BarrierState::Clear) => {
            let _ = writeln!(out, "control.manual_barrier: clear");
        }
        Ok(crate::manual_barrier::BarrierState::Open(record)) => {
            let _ = writeln!(
                out,
                "control.manual_barrier: open (op={} {} -> {}); daemon.start: refused",
                record.op_id, record.source, record.target
            );
        }
        Err(error) => {
            let _ = writeln!(
                out,
                "control.manual_barrier: unknown ({}); daemon.start: refused",
                error.chars().take(200).collect::<String>()
            );
        }
    }
}

/// Configuration-derived facts only. Secret material is never printed: the
/// PSK is neither shown nor located (Rev5 §34.19 G6: no PSK path beyond the
/// `state.path` line), so no `security.*` line exists.
fn write_config_facts(out: &mut String, config: &Config) {
    let _ = writeln!(out, "cluster: {}", config.cluster.id);
    let _ = writeln!(
        out,
        "cluster.mode: {}",
        match config.cluster.mode {
            Mode::Conservative => "conservative",
            Mode::Availability => "availability",
        }
    );
    let _ = writeln!(
        out,
        "node: {} (priority {})",
        config.node.id, config.node.priority
    );
    let _ = writeln!(
        out,
        "peer: {} at {} (priority {})",
        config.peer.id,
        config
            .peer
            .address
            .as_deref()
            .unwrap_or("<dials this node>"),
        config.peer.priority
    );
    match &config.witness {
        Some(witness) if witness.enabled == Some(true) => {
            let _ = writeln!(
                out,
                "witness: enabled id={} address={}",
                witness.id.as_deref().unwrap_or("<missing>"),
                witness.address.as_deref().unwrap_or("<missing>")
            );
        }
        Some(_) => {
            let _ = writeln!(out, "witness: disabled");
        }
        None => {
            let _ = writeln!(out, "witness: unconfigured");
        }
    }
    match config.service.manager {
        ServiceManager::Systemd => {
            let _ = writeln!(
                out,
                "service: systemd unit={}",
                config.service.unit.as_deref().unwrap_or("<missing>")
            );
        }
        ServiceManager::Command => {
            let _ = writeln!(out, "service: command");
        }
    }
    let _ = writeln!(out, "state.path: {}", config.state.path);
}

/// The `config.loaded: no (...)` reason (G6).
///
/// The presentation rule lives with the configuration type, which owns the
/// field names: `ConfigError::operator_summary` reports a parse failure
/// through the parser's bare message (its `Display` quotes the offending
/// configuration line) and neutralizes any validation message that names the
/// secret-bearing field. This module therefore never names, reads, or
/// compares a secret location at all, and the report stays free of one.
fn config_load_failure(error: &ConfigError) -> String {
    error.operator_summary()
}

/// What the report could read of the persisted Node document.
enum PersistedView {
    /// No Node document yet (the daemon never initialized this node).
    Absent,
    Readable(Box<NodeMutationPersistentState>),
    /// The document exists but could not be read or validated.
    Unreadable,
}

/// Persisted / recoverable facts, read-only via `NodeMutationStore`.
fn write_persistent_facts(out: &mut String, config: &Config) -> PersistedView {
    let store = NodeMutationStore::new(
        config.state.path.clone(),
        ClusterId::new(config.cluster.id.clone()),
        NodeId::new(config.node.id.clone()),
    );
    match store.load_existing() {
        Ok(state) => {
            match &state.outstanding_mutation {
                Some(outstanding) => {
                    let _ = writeln!(
                        out,
                        "node.mutation_state: outstanding({:?})",
                        outstanding.kind()
                    );
                }
                // §28: the release obligation (O) is persisted truth too. A
                // node holding O is active or releasing, so it is never
                // reported as "clean".
                None if state.release_obligation.is_some() => {
                    let _ = writeln!(
                        out,
                        "node.mutation_state: release obligation armed (see node.role)"
                    );
                }
                None => {
                    let _ = writeln!(out, "node.mutation_state: clean");
                }
            }
            PersistedView::Readable(Box::new(state))
        }
        Err(NodeMutationError::StateMissing) => {
            let _ = writeln!(out, "node.mutation_state: absent");
            PersistedView::Absent
        }
        Err(error) => {
            let _ = writeln!(out, "node.mutation_state: unreadable ({error})");
            PersistedView::Unreadable
        }
    }
}

/// Whether an attestation intent file is waiting for the daemon (§18.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttestationView {
    NonePending,
    PendingIngestion,
    /// The intent directory is not inspectable by this process (for example a
    /// non-root reader, or an untrusted directory posture).
    Unknown,
}

/// Read-only: opens the trusted intent directory object and looks up the one
/// fixed name. It creates, removes, and validates nothing.
fn inspect_attestation(config: &Config, owner: u32) -> AttestationView {
    let Some(dir) = intent_dir(Path::new(&config.state.path)) else {
        return AttestationView::Unknown;
    };
    match TrustedDir::open(dir, owner).and_then(|trusted| intent_pending(&trusted)) {
        Ok(true) => AttestationView::PendingIngestion,
        Ok(false) => AttestationView::NonePending,
        Err(_) => AttestationView::Unknown,
    }
}

/// Stage 14 §28 additive lines. Deterministic: only documented lines, no
/// UUIDs, session ids, attempt tokens, anchor terms, or loss generations.
fn write_stage14_facts(
    out: &mut String,
    config: &Config,
    config_path: &Path,
    persisted: &PersistedView,
    attestation: AttestationView,
) {
    let peer = config.peer.id.as_str();
    let incident: Option<&FencingIncident> = match persisted {
        PersistedView::Readable(state) => state.fencing_incident.as_ref(),
        PersistedView::Absent | PersistedView::Unreadable => None,
    };

    // `node.role` is derived from persisted O: activation requires a confirmed
    // ARM O, so O = None proves "not active".
    let role = match persisted {
        PersistedView::Readable(state) if state.release_obligation.is_some() => {
            "active or releasing (release obligation armed)"
        }
        PersistedView::Readable(_) | PersistedView::Absent => "not active (no release obligation)",
        PersistedView::Unreadable => "unknown (node state unreadable)",
    };
    let _ = writeln!(out, "node.role: {role}");
    let _ = writeln!(
        out,
        "node.authority: not reportable by one-shot status (runtime-only; see daemon log)"
    );

    let backend = match config.fencing.as_ref().map(|fencing| fencing.backend) {
        Some(FencingBackendKind::Command) => "command",
        Some(FencingBackendKind::None) | None => "none (operator attestation only)",
    };
    let _ = writeln!(out, "fencing.backend: {backend}");
    let _ = writeln!(
        out,
        "fencing.required: yes (any activation of this node requires {peer} to be fenced)"
    );
    let _ = writeln!(out, "fencing.target: {peer}");

    match (persisted, incident) {
        (PersistedView::Unreadable, _) => {
            let _ = writeln!(out, "fencing.incident: unknown (node state unreadable)");
            let _ = writeln!(out, "fencing.state: unknown (node state unreadable)");
            let _ = writeln!(
                out,
                "activation.blocked: yes — the node state is unreadable"
            );
            let _ = writeln!(
                out,
                "operator.action: repair or restore the node state, then run status again"
            );
        }
        (_, None) => {
            let _ = writeln!(out, "fencing.incident: none");
            let _ = writeln!(out, "fencing.state: none");
            let _ = writeln!(
                out,
                "activation.blocked: yes — {peer} is not proven fenced (no incident is open)"
            );
            let _ = writeln!(
                out,
                "operator.action: request activation (SIGUSR1 to the daemon); the daemon then opens an incident"
            );
        }
        (_, Some(incident)) => {
            let seq = incident.incident_seq;
            let _ = writeln!(out, "fencing.incident: {seq}");
            let _ = writeln!(out, "fencing.state: {}", incident.state.operator_name());
            let blocked = match &incident.state {
                FencingState::Unknown(_) => {
                    format!("yes — {peer} is not proven fenced for incident {seq}")
                }
                FencingState::Requested { .. } => {
                    format!("yes — fencing {peer} in progress for incident {seq}")
                }
                FencingState::Verifying { .. } => {
                    format!("yes — verifying {peer} isolation for incident {seq}")
                }
                FencingState::Failed { .. } => {
                    format!("yes — fencing device reports {peer} NOT isolated for incident {seq}")
                }
                FencingState::Confirmed(_) => format!(
                    "no — {peer} fenced for incident {seq}; the other activation requirements still apply"
                ),
            };
            let _ = writeln!(out, "activation.blocked: {blocked}");
            let action = match &incident.state {
                FencingState::Confirmed(_) => {
                    "request activation (SIGUSR1 to the daemon); a fresh request is required"
                        .to_string()
                }
                _ => {
                    let subject = canonical_subject(config).unwrap_or("<service>");
                    let config_flag = if config_path == Path::new(DEFAULT_CONFIG_PATH) {
                        String::new()
                    } else {
                        format!(" --config {}", config_path.display())
                    };
                    format!(
                        "fence {peer}, then: mikagami recover {subject} --confirm-fenced {peer} --incident {seq}{config_flag}"
                    )
                }
            };
            let _ = writeln!(out, "operator.action: {action}");
        }
    }

    let attestation_line = match attestation {
        AttestationView::NonePending => "none pending",
        AttestationView::PendingIngestion => "pending ingestion",
        AttestationView::Unknown => "unknown (intent directory not inspectable)",
    };
    let _ = writeln!(out, "fencing.attestation: {attestation_line}");
    if incident.is_some() {
        let _ = writeln!(
            out,
            "note: an incident opened by a previous daemon process is stale and will be retired"
        );
    }

    // §28.1: config-derived only (the canonical role follows from the two
    // node ids); no runtime read.
    match canonical_direction(
        &NodeId::new(config.node.id.clone()),
        &NodeId::new(config.peer.id.clone()),
    ) {
        Ok(ConnectionDirection::Inbound) => {
            let _ = writeln!(out, "peer.role: listens (Inbound)");
            let bind = config
                .node
                .bind_address
                .as_deref()
                .unwrap_or("<node.listen unset>");
            let _ = writeln!(
                out,
                "peer.listener_note: unexpected TCP connections to {bind}:{} block local-loss evidence; see WARN ListenerInterference",
                config.cluster.heartbeat_port
            );
        }
        Ok(ConnectionDirection::Outbound) => {
            let _ = writeln!(out, "peer.role: dials (Outbound)");
        }
        Err(_) => {
            let _ = writeln!(out, "peer.role: unknown (node and peer ids are equal)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mikagami-status-{name}-{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn valid_config(state_path: &Path, psk_path: &Path) -> String {
        format!(
            r#"
[cluster]
id = "example-ha"
[node]
id = "node-a"
preferred = true
[peer]
id = "node-b"
address = "127.0.0.1:7946"
[witness]
id = "witness-1"
address = "127.0.0.1:7947"
[vip]
address = "192.0.2.50/24"
interface = "eth0"
arp_count = 3
[service]
manager = "systemd"
unit = "nginx.service"
[health]
command = ["/usr/bin/true"]
[security]
psk_file = "{}"
[state]
path = "{}"
"#,
            psk_path.display(),
            state_path.display()
        )
    }

    /// A synthetic 64-hex PSK body (no real key) written to disk; the report must carry
    /// neither these bytes nor the file's path (Rev5 §34.19 G6).
    const TEST_PSK_HEX: &str = "5ca1ab1e5ca1ab1e0123456789abcdeffedcba98765432105ca1ab1e5ca1ab1e";

    /// G6 canary: a distinctive configured PSK path no legitimate status line
    /// can contain. Every fragment that could reveal it is forbidden anywhere
    /// in the whole report.
    const CANARY_PSK: &str = "/DO-NOT-PRINT/phase1411/secret.psk";
    const CANARY_FRAGMENTS: [&str; 6] = [
        "/DO-NOT-PRINT/phase1411/secret.psk",
        "DO-NOT-PRINT",
        "phase1411",
        "secret.psk",
        "/DO-NOT",
        "security.psk_file:",
    ];

    /// The report names no PSK location at all: not the configured file, not
    /// its directory or file name, and no `security.*` line.
    fn assert_no_psk_reference(report: &str, psk: &Path) {
        assert!(
            !report.contains(TEST_PSK_HEX),
            "raw PSK bytes in status:\n{report}"
        );
        assert!(
            !report.contains(&psk.display().to_string()),
            "PSK path in status:\n{report}"
        );
        if let Some(name) = psk.file_name().and_then(|name| name.to_str()) {
            assert!(!report.contains(name), "PSK file name in status:\n{report}");
        }
        assert!(
            !report.to_lowercase().contains("psk"),
            "a PSK reference in status:\n{report}"
        );
        assert!(
            !report.contains("security."),
            "a security.* line in status:\n{report}"
        );
    }

    #[test]
    fn report_contains_config_facts_and_absent_state() {
        let dir = temp_dir("absent");
        let state = dir.join("state.toml");
        let psk = dir.join("cluster.psk");
        let config_path = dir.join("mikagami.toml");
        fs::write(&psk, format!("{TEST_PSK_HEX}\n")).unwrap();
        fs::write(&config_path, valid_config(&state, &psk)).unwrap();

        let report = status_report(&config_path);

        assert!(report.contains("config.loaded: yes"));
        assert!(report.contains("cluster: example-ha"));
        assert!(report.contains("cluster.mode: conservative"));
        assert!(report.contains("node: node-a (priority 100)"));
        assert!(report.contains("peer: node-b at 127.0.0.1:7946 (priority 50)"));
        assert!(report.contains("witness: enabled id=witness-1 address=127.0.0.1:7947"));
        assert!(report.contains("service: systemd unit=nginx.service"));
        assert!(report.contains(&format!("state.path: {}", state.display())));
        assert_no_psk_reference(&report, &psk);
        assert!(report.contains("node.mutation_state: absent"));
        assert!(report.contains("daemon.state: unknown"));
    }

    #[test]
    fn report_shows_clean_persisted_state() {
        let dir = temp_dir("clean");
        let state = dir.join("state.toml");
        let psk = dir.join("cluster.psk");
        let config_path = dir.join("mikagami.toml");
        fs::write(&psk, format!("{TEST_PSK_HEX}\n")).unwrap();
        fs::write(&config_path, valid_config(&state, &psk)).unwrap();
        let store = NodeMutationStore::new(
            state.clone(),
            ClusterId::new("example-ha"),
            NodeId::new("node-a"),
        );
        store.initialize_new().unwrap();

        let report = status_report(&config_path);

        assert!(report.contains("node.mutation_state: clean"));
    }

    #[test]
    fn report_shows_outstanding_mutation_kind_read_only() {
        let dir = temp_dir("outstanding");
        let state = dir.join("state.toml");
        let psk = dir.join("cluster.psk");
        let config_path = dir.join("mikagami.toml");
        fs::write(&psk, format!("{TEST_PSK_HEX}\n")).unwrap();
        fs::write(&config_path, valid_config(&state, &psk)).unwrap();
        let store = NodeMutationStore::new(
            state.clone(),
            ClusterId::new("example-ha"),
            NodeId::new("node-a"),
        );
        store.initialize_new().unwrap();
        store
            .begin_lease_request(
                crate::protocol::Term(1),
                100,
                crate::protocol::DurationMs(10_000),
            )
            .unwrap();

        let report = status_report(&config_path);

        assert!(report.contains("node.mutation_state: outstanding(LeaseRequest)"));
        // Read-only guarantee: a second read still sees the same state and the
        // store was not advanced or completed.
        assert!(store.outstanding().unwrap().is_some());
    }

    #[test]
    fn report_is_truthful_when_config_is_missing() {
        let dir = temp_dir("missing");
        let report = status_report(&dir.join("does-not-exist.toml"));

        assert!(report.contains("config.loaded: no"));
        assert!(report.contains("daemon.state: unknown"));
        assert!(!report.contains("node.mutation_state: clean"));
    }

    #[test]
    fn report_never_contains_raw_psk_bytes() {
        let dir = temp_dir("rawbytes");
        let state = dir.join("state.toml");
        let psk = dir.join("cluster.psk");
        let config_path = dir.join("mikagami.toml");
        fs::write(&psk, format!("{TEST_PSK_HEX}\n")).unwrap();
        fs::write(&config_path, valid_config(&state, &psk)).unwrap();

        let report = status_report(&config_path);

        assert!(
            !report.contains(TEST_PSK_HEX),
            "status report must never contain raw PSK bytes:\n{report}"
        );
        // G6: neither the bytes nor the file's location is reported.
        assert_no_psk_reference(&report, &psk);
    }

    // ------------------------------------------------------------------
    // Stage 14 Phase 14.11: §28 status lines and §34.19 G6.
    // ------------------------------------------------------------------

    use crate::fencing::{
        ActionOutcome, AttestationId, FencingBackend, FencingEventOutcome, IncidentOpening,
    };
    use crate::protocol::{SessionId, Term};
    use std::os::unix::fs::MetadataExt;

    const SESSION_HEX: &str = "0123456789abcdef";
    const ATTESTATION_UUID: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";

    /// A canonicalized private state directory (the trusted intent directory
    /// object refuses symlinked path components, e.g. macOS `/var`).
    struct S14 {
        dir: PathBuf,
        config: PathBuf,
        state: PathBuf,
        uid: u32,
        store: NodeMutationStore,
    }

    impl Drop for S14 {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// `node`/`peer` swap the canonical role (node-a < node-b dials; node-b
    /// listens). `fencing` is an optional `[fencing]` section.
    fn s14(name: &str, node: &str, peer: &str, fencing: &str) -> S14 {
        let dir = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "mikagami-status14-{name}-{}-{}",
                std::process::id(),
                UNIQUE.fetch_add(1, Ordering::SeqCst)
            ));
        fs::create_dir_all(&dir).unwrap();
        // The trusted intent directory refuses a group- or world-writable
        // directory, so the private fixture is 0700 whatever the umask is.
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&dir).unwrap().uid();
        let state = dir.join("state.toml");
        let psk = dir.join("cluster.psk");
        let config = dir.join("mikagami.toml");
        fs::write(&psk, format!("{TEST_PSK_HEX}\n")).unwrap();
        let mut text = valid_config(&state, Path::new(CANARY_PSK))
            .replace("id = \"node-a\"", "id = \"@NODE@\"")
            .replace("id = \"node-b\"", &format!("id = \"{peer}\""))
            .replace("@NODE@", node);
        if node > peer {
            // The canonical inbound node listens (`node.listen`) and has no
            // `peer.address`; the outbound node dials.
            text = text
                .replace("address = \"127.0.0.1:7946\"\n", "")
                .replace("preferred = true\n", "listen = \"127.0.0.1:7946\"\n");
        }
        fs::write(&config, format!("{text}\n{fencing}\n")).unwrap();
        let store = NodeMutationStore::new(
            state.clone(),
            ClusterId::new("example-ha"),
            NodeId::new(node),
        );
        store.initialize_new().unwrap();
        S14 {
            dir,
            config,
            state,
            uid,
            store,
        }
    }

    fn outbound(name: &str) -> S14 {
        s14(name, "node-a", "node-b", "")
    }

    /// v0.7 G-2: the status shows the newest route-handoff record read-only and never reports
    /// the HA switchover as complete, also with a confirmed route.
    #[test]
    fn g2_status_shows_the_route_handoff_and_never_a_complete_switchover() {
        let fixture = s14(
            "g2-route",
            "node-a",
            "node-b",
            &format!(
                "{COMMAND}\n[route]\nhelper = \"/usr/lib/mikagami/mikagami-gce-fence\"\nhelper_config = \"/etc/mikagami/gce-fence.toml\"\nintent_dir = \"@ROUTE@\"\n"
            ),
        );
        let route_dir = fixture.dir.join("route");
        let text = fs::read_to_string(&fixture.config).unwrap();
        fs::write(
            &fixture.config,
            text.replace("@ROUTE@", &route_dir.display().to_string()),
        )
        .unwrap();
        // Not created yet: reported as unknown, the report itself still succeeds.
        let report = status_report_with(&fixture.config, fixture.uid);
        assert!(report.contains("route.handoff: unknown"), "{report}");
        fs::create_dir(&route_dir).unwrap();
        fs::set_permissions(
            &route_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let report = status_report_with(&fixture.config, fixture.uid);
        assert!(report.contains("route.handoff: none"), "{report}");
        let store = crate::route_handoff::RhStore::open(&route_dir).unwrap();
        let mut record = crate::route_handoff::RhRecord {
            version: crate::route_handoff::RH_RECORD_VERSION,
            cluster: "example-ha".to_string(),
            node: "node-a".to_string(),
            peer_node: "node-b".to_string(),
            term: 5,
            origin: crate::route_handoff::RhOrigin::Bootstrap,
            state: crate::route_handoff::RhState::RouteConfirmed { at_unix_ms: 1 },
            sent: false,
            checked: false,
            reason: "route confirmed by observation only".to_string(),
            updated_unix_ms: 1,
            last_observed_unix_ms: Some(2),
            last_cycle: Some("own=all peer=absent".to_string()),
            reissued: false,
            op_seen: false,
        };
        store.save(&record).unwrap();
        let report = status_report_with(&fixture.config, fixture.uid);
        assert!(
            report.contains("route.handoff: ROUTE_CONFIRMED(at=1) (not-sent) term=5"),
            "{report}"
        );
        assert!(
            report.contains("route.last_observation: at=2 own=all peer=absent"),
            "{report}"
        );
        assert!(
            report.contains("route.switchover: NOT complete"),
            "{report}"
        );
        assert!(!report.contains("switchover: complete"));
        record.term = 7;
        record.sent = true;
        record.state = crate::route_handoff::RhState::RouteUnknown;
        store.save(&record).unwrap();
        let listing = |dir: &Path| {
            let mut entries: Vec<_> = fs::read_dir(dir)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.path(), fs::read(entry.path()).unwrap())
                })
                .collect();
            entries.sort();
            entries
        };
        let before = listing(&route_dir);
        let report = status_report_with(&fixture.config, fixture.uid);
        assert!(
            report.contains("route.handoff: ROUTE_UNKNOWN (sent) term=7"),
            "{report}"
        );
        assert!(
            report.contains("route.operator_action: required"),
            "{report}"
        );
        // Read-only: the report changed no file of the RH directory.
        assert_eq!(listing(&route_dir), before);
    }

    const COMMAND: &str = "[fencing]\nbackend = \"command\"\nfence = [\"/usr/local/libexec/mikagami/fence-peer\", \"--off\"]\nverify = [\"/usr/local/libexec/mikagami/verify-peer\"]\nfence_timeout_sec = 30\nverify_timeout_sec = 10\nverify_polls = 6\n";

    fn open_incident(
        fixture: &S14,
        peer: &str,
        backend: FencingBackend,
    ) -> crate::fencing::FencingIncident {
        fixture
            .store
            .open_fencing_incident(IncidentOpening {
                target_node_id: NodeId::new(peer),
                anchor_term: Term(41),
                observer_session_id: SessionId::new(SESSION_HEX),
                observer_loss_generation: 1,
                backend,
            })
            .unwrap()
    }

    fn step(
        fixture: &S14,
        transition: crate::fencing::FencingTransition,
    ) -> crate::fencing::FencingIncident {
        fixture.store.apply_fencing_transition(transition).unwrap()
    }

    fn applied(outcome: FencingEventOutcome) -> crate::fencing::FencingTransition {
        match outcome {
            FencingEventOutcome::Transition(transition) => transition,
            FencingEventOutcome::NoOp => panic!("expected a transition"),
        }
    }

    /// UNKNOWN (B=none), REQUESTED, VERIFYING, FAILED, CONFIRMED(backend),
    /// CONFIRMED(operator).
    fn incident_in(fixture: &S14, peer: &str, which: &str) {
        match which {
            "UNKNOWN" => {
                open_incident(fixture, peer, FencingBackend::None);
            }
            "REQUESTED" => {
                open_incident(fixture, peer, FencingBackend::Command);
            }
            "VERIFYING" | "FAILED" | "CONFIRMED" | "CONFIRMED-BACKEND" => {
                let requested = open_incident(fixture, peer, FencingBackend::Command);
                let verifying = step(
                    fixture,
                    requested
                        .action_returned(1, ActionOutcome::ReportedSuccess)
                        .unwrap(),
                );
                match which {
                    "FAILED" => {
                        step(
                            fixture,
                            applied(verifying.verification_not_isolated(1).unwrap()),
                        );
                    }
                    "CONFIRMED-BACKEND" => {
                        step(
                            fixture,
                            applied(verifying.confirm_by_verification(1).unwrap()),
                        );
                    }
                    "CONFIRMED" => {
                        step(
                            fixture,
                            applied(
                                verifying
                                    .confirm_by_attestation(AttestationId::generated(
                                        ATTESTATION_UUID.into(),
                                    ))
                                    .unwrap(),
                            ),
                        );
                    }
                    _ => {}
                }
            }
            other => panic!("unknown state {other}"),
        }
    }

    /// The Stage 14 block: `node.role:` up to (not including) `daemon.state:`.
    fn stage14_block(report: &str) -> String {
        report
            .lines()
            .skip_while(|line| !line.starts_with("node.role:"))
            .take_while(|line| !line.starts_with("daemon.state:"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn report_of(fixture: &S14) -> String {
        status_report_with(&fixture.config, fixture.uid)
    }

    fn expected_block(
        fixture: &S14,
        backend: &str,
        peer: &str,
        incident: &str,
        state: &str,
        blocked: &str,
        action: &str,
        stale_note: bool,
        peer_role: &str,
    ) -> String {
        let _ = fixture;
        let mut lines = vec![
            "node.role: not active (no release obligation)".to_string(),
            "node.authority: not reportable by one-shot status (runtime-only; see daemon log)"
                .into(),
            format!("fencing.backend: {backend}"),
            format!(
                "fencing.required: yes (any activation of this node requires {peer} to be fenced)"
            ),
            format!("fencing.target: {peer}"),
            format!("fencing.incident: {incident}"),
            format!("fencing.state: {state}"),
            format!("activation.blocked: {blocked}"),
            format!("operator.action: {action}"),
            "fencing.attestation: none pending".into(),
        ];
        if stale_note {
            lines.push(
                "note: an incident opened by a previous daemon process is stale and will be retired"
                    .into(),
            );
        }
        lines.push(peer_role.into());
        lines.join("\n")
    }

    /// G6 / §28: the exact block for the no-incident case.
    #[test]
    fn stage14_11_g6_no_incident_block_is_exact() {
        let fixture = outbound("g6-none");
        let block = stage14_block(&report_of(&fixture));
        assert_eq!(
            block,
            expected_block(
                &fixture,
                "none (operator attestation only)",
                "node-b",
                "none",
                "none",
                "yes — node-b is not proven fenced (no incident is open)",
                "request activation (SIGUSR1 to the daemon); the daemon then opens an incident",
                false,
                "peer.role: dials (Outbound)",
            )
        );
    }

    /// G6 / §28: the exact block for every stored state. `operator.action`
    /// carries the exact `recover` command for the incident sequence, and
    /// `--config` because the test config is not the default path.
    #[test]
    fn stage14_11_g6_each_fencing_state_block_is_exact() {
        for (which, state, blocked, backend) in [
            (
                "UNKNOWN",
                "UNKNOWN",
                "yes — node-b is not proven fenced for incident 1",
                "none (operator attestation only)",
            ),
            (
                "REQUESTED",
                "REQUESTED",
                "yes — fencing node-b in progress for incident 1",
                "command",
            ),
            (
                "VERIFYING",
                "VERIFYING",
                "yes — verifying node-b isolation for incident 1",
                "command",
            ),
            (
                "FAILED",
                "FAILED",
                "yes — fencing device reports node-b NOT isolated for incident 1",
                "command",
            ),
        ] {
            let fencing = if backend == "command" { COMMAND } else { "" };
            let fixture = s14(&format!("g6-{which}"), "node-a", "node-b", fencing);
            incident_in(&fixture, "node-b", which);
            let action = format!(
                "fence node-b, then: mikagami recover nginx.service --confirm-fenced node-b --incident 1 --config {}",
                fixture.config.display()
            );
            assert_eq!(
                stage14_block(&report_of(&fixture)),
                expected_block(
                    &fixture,
                    backend,
                    "node-b",
                    "1",
                    state,
                    blocked,
                    &action,
                    true,
                    "peer.role: dials (Outbound)",
                ),
                "{which}"
            );
        }
        for which in ["CONFIRMED", "CONFIRMED-BACKEND"] {
            let fixture = s14(&format!("g6-{which}"), "node-a", "node-b", COMMAND);
            incident_in(&fixture, "node-b", which);
            assert_eq!(
                stage14_block(&report_of(&fixture)),
                expected_block(
                    &fixture,
                    "command",
                    "node-b",
                    "1",
                    "CONFIRMED",
                    "no — node-b fenced for incident 1; the other activation requirements still apply",
                    "request activation (SIGUSR1 to the daemon); a fresh request is required",
                    true,
                    "peer.role: dials (Outbound)",
                ),
                "{which}"
            );
        }
    }

    /// §28: the incident sequence in `fencing.incident` and in the exact
    /// recover command is the one an operator needs, and a second incident
    /// (a never-reused sequence) shows its own number.
    #[test]
    fn stage14_11_incident_sequence_is_visible_and_never_reused() {
        let fixture = outbound("seq");
        open_incident(&fixture, "node-b", FencingBackend::None);
        let first = report_of(&fixture);
        assert!(first.contains("fencing.incident: 1\n"));
        assert!(first.contains("--confirm-fenced node-b --incident 1"));
        let incident = fixture
            .store
            .load_existing()
            .unwrap()
            .fencing_incident
            .unwrap();
        fixture
            .store
            .retire_fencing_incident(&incident.incident_ref())
            .unwrap();
        assert!(report_of(&fixture).contains("fencing.incident: none\n"));
        open_incident(&fixture, "node-b", FencingBackend::None);
        let second = report_of(&fixture);
        assert!(second.contains("fencing.incident: 2\n"));
        assert!(second.contains("--confirm-fenced node-b --incident 2"));
    }

    /// §28: `node.role` is derived from the persisted release obligation, and
    /// the misleading `node.mutation_state: clean` is gone whenever O is armed
    /// (an Active node is never reported clean).
    #[test]
    fn stage14_11_obligation_semantics_are_truthful() {
        let fixture = outbound("obligation");
        let clean = report_of(&fixture);
        assert!(clean.contains("node.mutation_state: clean\n"));
        assert!(clean.contains("node.role: not active (no release obligation)\n"));
        fixture
            .store
            .arm_release_obligation(Term(42), crate::protocol::LeaseId::new("lease-42"))
            .unwrap();
        let armed = report_of(&fixture);
        assert!(armed.contains("node.role: active or releasing (release obligation armed)\n"));
        assert!(armed.contains("node.mutation_state: release obligation armed (see node.role)\n"));
        assert!(!armed.contains("node.mutation_state: clean"));
        // An outstanding mutation still reports its kind, and O still shows.
        fixture
            .store
            .begin_lease_release_for_test(
                Term(42),
                crate::protocol::LeaseId::new("lease-42"),
                "x".into(),
            )
            .unwrap();
        let releasing = report_of(&fixture);
        assert!(releasing.contains("node.mutation_state: outstanding(LeaseRelease)\n"));
        assert!(releasing.contains("node.role: active or releasing (release obligation armed)\n"));
    }

    /// §28: a document that cannot be read never shows a state, and blocks.
    #[test]
    fn stage14_11_unreadable_state_reports_unknown_and_blocks() {
        let fixture = outbound("unreadable");
        fs::write(&fixture.state, "this is not a node document").unwrap();
        let block = stage14_block(&report_of(&fixture));
        assert!(block.contains("node.role: unknown (node state unreadable)\n"));
        assert!(block.contains("fencing.incident: unknown (node state unreadable)\n"));
        assert!(block.contains("fencing.state: unknown (node state unreadable)\n"));
        assert!(block.contains("activation.blocked: yes — the node state is unreadable\n"));
        assert!(!block.contains("not active"));
    }

    /// §28: `fencing.attestation` reports a waiting intent file, read-only.
    #[test]
    fn stage14_11_attestation_pending_is_reported_read_only() {
        let fixture = outbound("attest");
        open_incident(&fixture, "node-b", FencingBackend::None);
        assert!(report_of(&fixture).contains("fencing.attestation: none pending\n"));
        let intent = fixture
            .dir
            .join(crate::attestation::ATTESTATION_INTENT_FILE);
        fs::write(&intent, b"intent").unwrap();
        let before = fs::read(&intent).unwrap();
        assert!(report_of(&fixture).contains("fencing.attestation: pending ingestion\n"));
        assert_eq!(
            fs::read(&intent).unwrap(),
            before,
            "status never removes or edits the intent"
        );
        // A reader that is not the trusted owner cannot inspect the directory.
        let stranger = status_report_with(&fixture.config, fixture.uid.wrapping_add(1));
        assert!(
            stranger.contains("fencing.attestation: unknown (intent directory not inspectable)\n")
        );
    }

    /// §28 / §28.1: `peer.role` and `peer.listener_note` come from the
    /// configured node ids only; the Inbound role also names the listener.
    #[test]
    fn stage14_11_peer_role_lines_follow_the_canonical_role() {
        let outbound = outbound("role-out");
        let report = report_of(&outbound);
        assert!(report.contains("peer.role: dials (Outbound)\n"));
        assert!(!report.contains("peer.listener_note"));
        let inbound = s14("role-in", "node-b", "node-a", "");
        let report = report_of(&inbound);
        assert!(report.contains("peer.role: listens (Inbound)\n"));
        assert!(report.contains(
            "peer.listener_note: unexpected TCP connections to 127.0.0.1:7946 block local-loss evidence; see WARN ListenerInterference\n"
        ));
    }

    /// G6: deterministic, no file writes, no identifiers. Two reports are
    /// identical, the state and directory are byte-for-byte unchanged, and no
    /// UUID, session id, attestation id, or attempt token appears.
    #[test]
    fn stage14_11_g6_status_is_deterministic_read_only_and_identifier_free() {
        let fixture = s14("g6-ro", "node-a", "node-b", COMMAND);
        incident_in(&fixture, "node-b", "VERIFYING");
        let incident = fixture
            .store
            .load_existing()
            .unwrap()
            .fencing_incident
            .unwrap();
        let listing = |dir: &Path| {
            let mut names: Vec<String> = fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        let state_before = fs::read(&fixture.state).unwrap();
        let files_before = listing(&fixture.dir);
        let first = report_of(&fixture);
        let second = report_of(&fixture);
        assert_eq!(first, second, "deterministic");
        assert_eq!(
            fs::read(&fixture.state).unwrap(),
            state_before,
            "state untouched"
        );
        assert_eq!(
            listing(&fixture.dir),
            files_before,
            "no file created or removed"
        );
        assert!(
            !first.contains(incident.incident_id.as_str()),
            "no incident UUID"
        );
        assert!(!first.contains(SESSION_HEX), "no session id");
        assert!(!first.contains(ATTESTATION_UUID), "no attestation id");
        assert!(!first.contains("attempt_token") && !first.contains("anchor"));
        assert!(!first.contains(TEST_PSK_HEX));
        // Documented lines only: every Stage 14 line starts with a documented key.
        for line in stage14_block(&first).lines() {
            assert!(
                [
                    "node.role:",
                    "node.authority:",
                    "fencing.backend:",
                    "fencing.required:",
                    "fencing.target:",
                    "fencing.incident:",
                    "fencing.state:",
                    "activation.blocked:",
                    "operator.action:",
                    "fencing.attestation:",
                    "note:",
                    "peer.role:",
                    "peer.listener_note:",
                    // v0.7 G-2 (only with `[route]`): `route_handoff::status_lines`.
                    "route.handoff:",
                    "route.reason:",
                    "route.operator_action:",
                    "route.last_observation:",
                    "route.switchover:",
                ]
                .iter()
                .any(|key| line.starts_with(key)),
                "undocumented status line: {line}"
            );
        }
        // Status contacts no daemon: it runs with no daemon anywhere.
        assert!(first.contains("daemon.state: unknown"));
    }

    /// Phase 14.11 remediation M2 (G6): with a distinctive configured PSK path,
    /// no fragment capable of revealing it appears anywhere in the WHOLE
    /// report (not just the Stage 14 block), in every state and role, and the
    /// permitted `state.path` line and the incident sequence stay available.
    #[test]
    fn stage14_11_g6_psk_path_is_absent_from_the_whole_report_in_every_state() {
        let cases: [(&str, &str, &str, Option<&str>); 9] = [
            ("none", "node-a", "node-b", None),
            ("UNKNOWN", "node-a", "node-b", Some("UNKNOWN")),
            ("REQUESTED", "node-a", "node-b", Some("REQUESTED")),
            ("VERIFYING", "node-a", "node-b", Some("VERIFYING")),
            ("FAILED", "node-a", "node-b", Some("FAILED")),
            ("CONFIRMED", "node-a", "node-b", Some("CONFIRMED")),
            (
                "CONFIRMED-BACKEND",
                "node-a",
                "node-b",
                Some("CONFIRMED-BACKEND"),
            ),
            ("inbound-UNKNOWN", "node-b", "node-a", Some("UNKNOWN")),
            ("inbound-none", "node-b", "node-a", None),
        ];
        for (name, node, peer, which) in cases {
            let fixture = s14(&format!("canary-{name}"), node, peer, COMMAND);
            if let Some(which) = which {
                incident_in(&fixture, peer, which);
            }
            let report = report_of(&fixture);
            assert!(report.contains("config.loaded: yes\n"), "{name}:\n{report}");
            for fragment in CANARY_FRAGMENTS {
                assert!(
                    !report.contains(fragment),
                    "{name}: `{fragment}` appears in the status output:\n{report}"
                );
            }
            assert!(
                !report.to_lowercase().contains("psk"),
                "{name}: a PSK reference in the status output:\n{report}"
            );
            assert!(
                report.contains(&format!("state.path: {}\n", fixture.state.display())),
                "{name}: state.path stays per Rev5:\n{report}"
            );
            if which.is_some() {
                assert!(
                    report.contains("fencing.incident: 1\n"),
                    "{name}: the incident sequence stays visible:\n{report}"
                );
            }
        }
        // Also with an armed obligation and an unreadable document.
        let armed = outbound("canary-armed");
        armed
            .store
            .arm_release_obligation(Term(42), crate::protocol::LeaseId::new("lease-42"))
            .unwrap();
        let unreadable = outbound("canary-unreadable");
        fs::write(&unreadable.state, "this is not a node document").unwrap();
        for fixture in [&armed, &unreadable] {
            let report = report_of(fixture);
            for fragment in CANARY_FRAGMENTS {
                assert!(!report.contains(fragment), "`{fragment}`:\n{report}");
            }
            assert!(!report.to_lowercase().contains("psk"), "{report}");
        }
    }

    /// Phase 14.11 remediation M2 / G6, and the second remediation: a
    /// configuration that fails to load discloses no PSK location anywhere in
    /// the whole report. Not the path, not the file name, not the directory,
    /// not the field name (`security.psk_file` or any case-insensitive `psk`),
    /// and not the secret bytes. Each failure class is exercised
    /// independently, twice, so the result is deterministic.
    #[test]
    fn stage14_11_g6_config_load_failures_never_echo_the_psk_path() {
        let fixture = outbound("canary-badcfg");
        let good = fs::read_to_string(&fixture.config).unwrap();
        let quoted = format!("psk_file = \"{CANARY_PSK}\"");
        assert!(good.contains(&quoted));
        // A validation failure unrelated to the PSK, to prove the pass-through
        // of ordinary messages is unchanged.
        let unrelated_validation = good.replace("[fencing]\n", "");
        let variants = [
            (
                "unterminated PSK value",
                good.replace(&quoted, &format!("psk_file = \"{CANARY_PSK}")),
            ),
            (
                "wrong type",
                good.replace(&quoted, &format!("psk_file = [\"{CANARY_PSK}\"]")),
            ),
            (
                "duplicate key",
                good.replace(&quoted, &format!("{quoted}\npsk_file = \"{CANARY_PSK}\"")),
            ),
            (
                "relative PSK path",
                good.replace(&quoted, "psk_file = \"DO-NOT-PRINT/phase1411/secret.psk\""),
            ),
            ("empty PSK path", good.replace(&quoted, "psk_file = \"\"")),
            (
                "garbage after the PSK line",
                good.replace(&quoted, &format!("{quoted} = {CANARY_PSK}")),
            ),
            (
                "validation failure (non-PSK field)",
                unrelated_validation.replace("arp_count = 3", "arp_count = 0"),
            ),
            (
                "parse failure (unrelated line)",
                good.replace("[cluster]\n", "[cluster\n"),
            ),
        ];
        for (name, text) in variants {
            for _ in 0..2 {
                fs::write(&fixture.config, &text).unwrap();
                let report = report_of(&fixture);
                assert!(report.contains("config.loaded: no ("), "{name}:\n{report}");
                assert!(
                    report.contains("daemon.state: unknown (configuration unavailable"),
                    "{name}:\n{report}"
                );
                // No PSK path, file name, or directory fragment.
                for fragment in CANARY_FRAGMENTS {
                    assert!(
                        !report.contains(fragment),
                        "{name}: `{fragment}` appears in the status output:\n{report}"
                    );
                }
                // G6 acceptance: no case-insensitive `psk` at all — this
                // covers the field name `security.psk_file` too.
                assert!(
                    !report.to_lowercase().contains("psk"),
                    "{name}: a PSK reference in the status output:\n{report}"
                );
                // No secret bytes and nothing derived from them.
                assert!(
                    !report.contains(TEST_PSK_HEX),
                    "{name}: raw PSK bytes in status:\n{report}"
                );
            }
        }
        // The PSK validation failures report a location-neutral reason.
        for (name, text) in [
            (
                "relative PSK path",
                good.replace(&quoted, "psk_file = \"DO-NOT-PRINT/phase1411/secret.psk\""),
            ),
            ("empty PSK path", good.replace(&quoted, "psk_file = \"\"")),
        ] {
            fs::write(&fixture.config, text).unwrap();
            let report = report_of(&fixture);
            assert!(
                report.contains("configuration validation failed: security configuration invalid"),
                "{name}:\n{report}"
            );
        }
        // An unrelated validation failure keeps its own field names: the
        // pass-through of ordinary configuration diagnostics is unchanged.
        fs::write(
            &fixture.config,
            &unrelated_validation.replace("arp_count = 3", "arp_count = 0"),
        )
        .unwrap();
        let report = report_of(&fixture);
        assert!(
            report.contains("configuration validation failed: "),
            "an unrelated validation failure is still reported:\n{report}"
        );
        assert!(
            report.contains("vip.arp_count"),
            "an unrelated validation message is unchanged:\n{report}"
        );
    }

    /// G6, second remediation: a VALID configuration still reports everything
    /// Rev5 requires — `state.path`, the incident sequence, the operator
    /// action, and the fencing state — so neutralizing the PSK reason removed
    /// nothing the operator needs.
    #[test]
    fn stage14_11_g6_neutral_reason_keeps_the_required_facts() {
        let fixture = s14("canary-neutral", "node-a", "node-b", COMMAND);
        incident_in(&fixture, "node-b", "VERIFYING");
        let report = report_of(&fixture);
        assert!(report.contains("config.loaded: yes\n"), "{report}");
        assert!(
            report.contains(&format!("state.path: {}\n", fixture.state.display())),
            "{report}"
        );
        assert!(report.contains("fencing.incident: 1\n"), "{report}");
        assert!(report.contains("fencing.state: VERIFYING\n"), "{report}");
        assert!(report.contains("node.mutation_state: clean\n"), "{report}");
        assert!(
            report.contains("operator.action: fence node-b, then: mikagami recover"),
            "{report}"
        );
        assert!(
            report.contains("--confirm-fenced node-b --incident 1"),
            "{report}"
        );
        // ... and still no PSK anything.
        assert!(!report.to_lowercase().contains("psk"), "{report}");
        assert_no_psk_reference(&report, Path::new(CANARY_PSK));
    }

    /// §28: the operator command is never printed for CONFIRMED (nothing to
    /// attest) and always names the exact incident otherwise.
    #[test]
    fn stage14_11_operator_action_is_state_specific() {
        for (which, contains_recover) in [
            ("UNKNOWN", true),
            ("REQUESTED", true),
            ("VERIFYING", true),
            ("FAILED", true),
            ("CONFIRMED", false),
        ] {
            let fixture = s14(&format!("action-{which}"), "node-a", "node-b", COMMAND);
            incident_in(&fixture, "node-b", which);
            let report = report_of(&fixture);
            assert_eq!(
                report.contains("mikagami recover nginx.service"),
                contains_recover,
                "{which}"
            );
        }
    }

    #[test]
    fn status_run_produces_a_report_and_success() {
        let dir = temp_dir("run");
        let state = dir.join("state.toml");
        let psk = dir.join("cluster.psk");
        let config_path = dir.join("mikagami.toml");
        fs::write(&psk, format!("{TEST_PSK_HEX}\n")).unwrap();
        fs::write(&config_path, valid_config(&state, &psk)).unwrap();

        assert_eq!(run_with(Some(config_path), None, false), ExitCode::SUCCESS);
    }
}

#[cfg(test)]
mod output_error_tests {
    use super::*;

    struct Failing(std::io::ErrorKind);

    impl io::Write for Failing {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn epipe_is_the_only_ignored_write_error() {
        let epipe = write_report(Failing(io::ErrorKind::BrokenPipe), "report");
        assert!(matches!(epipe, Err(e) if e.kind() == io::ErrorKind::BrokenPipe));
        for kind in [
            io::ErrorKind::StorageFull,
            io::ErrorKind::Other,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidInput,
        ] {
            let error = write_report(Failing(kind), "report").unwrap_err();
            assert_ne!(
                error.kind(),
                io::ErrorKind::BrokenPipe,
                "a non-EPIPE error must not be classified as EPIPE"
            );
        }
    }

    #[test]
    fn a_partial_write_is_an_error_not_a_short_report() {
        struct Partial;
        impl io::Write for Partial {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len().saturating_sub(1))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        // `write_all` retries and then reports WriteZero; it never returns
        // Ok for a truncated report.
        assert!(write_report(Partial, "report").is_err());
    }
}
