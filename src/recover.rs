//! Stage 14 `mikagami recover <service> --confirm-fenced <node> --incident
//! <seq>` (Design Revision 5 §18.1-§18.4; Phase 14.8, §41 step 6).
//!
//! A separate one-shot process. It reads the configuration and the Node
//! state read-only (as `status` does), prints the §18.3 statement, and
//! installs exactly one intent file. It never writes the Node store,
//! contacts the Witness or the peer, touches protected resources, opens
//! sockets, sends signals, or discovers PIDs, and it cannot confirm anything:
//! only the daemon's ingestion step can turn a valid intent into `CONFIRMED`.
//! Wording avoids the activation-command token (guards C-1).

use crate::attestation::{
    ATTESTATION_FORMAT_VERSION, ATTESTATION_STATEMENT, AttestationIntent, InstallRefusal, ROOT_UID,
    TrustedDir, canonical_subject, install_intent, intent_dir, intent_pending,
};
use crate::config::Config;
use crate::fencing::{AttestationId, FencingState};
use crate::node_mutation::NodeMutationStore;
use crate::protocol::{ClusterId, NodeId};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoverRequest {
    pub(crate) service: String,
    pub(crate) node: String,
    pub(crate) incident: u64,
    pub(crate) config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoverOutcome {
    Installed,
    AlreadyConfirmed,
}

pub(crate) fn run(request: RecoverRequest) -> ExitCode {
    match recover(&request, ROOT_UID, &mut io::stdout()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("mikagami: {message}");
            ExitCode::FAILURE
        }
    }
}

/// §18.4 CLI steps 1-8 against the configured files. `owner` is the uid the
/// intent directory and file must belong to (production: root).
fn recover(
    request: &RecoverRequest,
    owner: u32,
    out: &mut dyn Write,
) -> Result<RecoverOutcome, String> {
    // Step 1: configuration and argument syntax.
    let path = request
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(crate::status::DEFAULT_CONFIG_PATH));
    let config = Config::load(&path).map_err(|error| error.to_string())?;
    let subject = canonical_subject(&config)
        .ok_or("no canonical service subject is configured")?
        .to_string();
    if request.service != subject {
        return Err(format!(
            "service {} is not the configured subject {subject}",
            request.service
        ));
    }
    if request.node == config.node.id {
        return Err("refusing to attest the local node".into());
    }
    if request.node != config.peer.id {
        return Err(format!(
            "node {} is not the configured peer {}",
            request.node, config.peer.id
        ));
    }
    if request.incident == 0 {
        return Err("--incident must be at least 1".into());
    }

    // Step 2: the Node state, read-only.
    let store = NodeMutationStore::new(
        config.state.path.clone(),
        ClusterId::new(config.cluster.id.clone()),
        NodeId::new(config.node.id.clone()),
    );
    let state = store
        .load_existing()
        .map_err(|error| format!("could not read the Node state: {error}"))?;
    let Some(incident) = state.fencing_incident.filter(|incident| {
        incident.incident_seq == request.incident
            && incident.target_node_id.as_str() == request.node
    }) else {
        return Err(format!(
            "no open fencing incident {} for {}",
            request.incident, request.node
        ));
    };
    if matches!(incident.state, FencingState::Confirmed(_)) {
        writeln!(
            out,
            "already confirmed: incident {} for {}",
            incident.incident_seq, request.node
        )
        .map_err(|error| error.to_string())?;
        return Ok(RecoverOutcome::AlreadyConfirmed);
    }

    // Step 3: one intent at a time, checked in the one trusted directory
    // object that the install below also uses (F14.8-01).
    let dir =
        intent_dir(Path::new(&config.state.path)).ok_or("state.path has no parent directory")?;
    let trusted = TrustedDir::open(dir, owner)
        .map_err(|fault| format!("unsafe intent directory {}: {fault:?}", dir.display()))?;
    if intent_pending(&trusted)
        .map_err(|fault| format!("could not inspect the intent directory: {fault:?}"))?
    {
        return Err("an attestation is pending ingestion; wait for the daemon to ingest it".into());
    }

    // Step 5: the statement the operator accepts.
    let write = |out: &mut dyn Write, text: String| {
        writeln!(out, "{text}").map_err(|error| error.to_string())
    };
    write(
        out,
        format!(
            "I attest that node {node} is isolated: it cannot serve {subject} or its VIP to \
             clients and cannot modify shared resources. I accept responsibility that it \
             remains isolated from now until activation on this node completes (through ARM) \
             and an operator deliberately restores it. This applies to incident {seq} only.",
            node = request.node,
            seq = incident.incident_seq,
        ),
    )?;
    if matches!(incident.state, FencingState::Failed { .. }) {
        write(
            out,
            "WARNING: the fencing device reported the node NOT isolated; confirm only if you \
             isolated it by other means"
                .into(),
        )?;
    }

    // Steps 4, 6-8: install the intent file.
    let attestation_id = crate::node_mutation::generate_uuid()
        .map(AttestationId::generated)
        .ok_or("attestation identity generation failed")?;
    let intent = AttestationIntent {
        attestation_format_version: ATTESTATION_FORMAT_VERSION,
        attestation_id,
        cluster_id: config.cluster.id.clone(),
        node_id: config.node.id.clone(),
        subject,
        target_node_id: request.node.clone(),
        incident_seq: incident.incident_seq,
        incident_id: incident.incident_id.clone(),
        statement: ATTESTATION_STATEMENT.to_string(),
    };
    install_intent(&trusted, &intent).map_err(|refusal| match refusal {
        InstallRefusal::Pending => {
            "an attestation is pending ingestion; wait for the daemon to ingest it".to_string()
        }
        InstallRefusal::Concurrent => "another attestation was recorded concurrently".to_string(),
        InstallRefusal::Oversize => "the attestation exceeds the intent size limit".to_string(),
        InstallRefusal::Io(error) => format!("could not record the attestation: {error}"),
    })?;
    write(
        out,
        format!(
            "attestation recorded for incident {}; the daemon ingests it. Then request \
             activation with SIGUSR1.",
            incident.incident_seq
        ),
    )?;
    Ok(RecoverOutcome::Installed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{ATTESTATION_INTENT_FILE, IntentRead, read_intent};
    // Fixture paths are canonicalized (macOS `/var` is a symlink); the
    // trusted-directory walk refuses symlinked components by design.
    use crate::fencing::{
        ActionOutcome, FencingBackend, FencingEventOutcome, FencingIncident, IncidentOpening,
    };
    use crate::protocol::{SessionId, Term};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture {
        dir: PathBuf,
        uid: u32,
        config: PathBuf,
        store: NodeMutationStore,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// A private 0700 state directory with a config naming it and an
    /// initialized Node store.
    fn fixture(manager: &str) -> Fixture {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "mikagami-recover-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&dir).unwrap().uid();
        let state = dir.join("state.toml");
        let config = dir.join("mikagami.toml");
        fs::write(
            &config,
            format!(
                "[cluster]\nid = \"cluster\"\n\
                 [node]\nid = \"node-a\"\n\
                 [peer]\nid = \"node-b\"\naddress = \"127.0.0.1:7946\"\n\
                 [witness]\nid = \"witness-1\"\naddress = \"127.0.0.1:7947\"\n\
                 [vip]\naddress = \"192.0.2.50/24\"\ninterface = \"eth0\"\n\
                 [service]\n{manager}\n\
                 [health]\ncommand = [\"/usr/bin/true\"]\n\
                 [security]\npsk_file = \"/etc/mikagami/cluster.psk\"\n\
                 [state]\npath = \"{}\"\n",
                state.display()
            ),
        )
        .unwrap();
        let store =
            NodeMutationStore::new(&state, ClusterId::new("cluster"), NodeId::new("node-a"));
        store.initialize_new().unwrap();
        Fixture {
            dir,
            uid,
            config,
            store,
        }
    }

    fn systemd() -> Fixture {
        fixture("manager = \"systemd\"\nunit = \"nginx.service\"")
    }

    fn open(fixture: &Fixture, backend: FencingBackend) -> FencingIncident {
        fixture
            .store
            .open_fencing_incident(IncidentOpening {
                target_node_id: NodeId::new("node-b"),
                anchor_term: Term(41),
                observer_session_id: SessionId::new("0123456789abcdef"),
                observer_loss_generation: 1,
                backend,
            })
            .unwrap()
    }

    fn request(fixture: &Fixture, service: &str, node: &str, incident: u64) -> RecoverRequest {
        RecoverRequest {
            service: service.into(),
            node: node.into(),
            incident,
            config: Some(fixture.config.clone()),
        }
    }

    fn run_as_owner(
        fixture: &Fixture,
        request: &RecoverRequest,
    ) -> (Result<RecoverOutcome, String>, String) {
        let mut out = Vec::new();
        let result = recover(request, fixture.uid, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    fn state_bytes(fixture: &Fixture) -> Vec<u8> {
        fs::read(fixture.dir.join("state.toml")).unwrap()
    }

    /// §18.4: the correct command installs one intent bound to the current
    /// incident, prints the §18.3 statement, and never writes the Node state.
    #[test]
    fn stage14_8_recover_installs_one_bound_intent() {
        let fixture = systemd();
        let incident = open(&fixture, FencingBackend::None);
        let before = state_bytes(&fixture);
        let (result, out) = run_as_owner(
            &fixture,
            &request(&fixture, "nginx.service", "node-b", incident.incident_seq),
        );
        assert_eq!(result, Ok(RecoverOutcome::Installed));
        assert!(out.contains("I attest that node node-b is isolated"));
        assert!(out.contains("This applies to incident 1 only."));
        assert!(out.contains("request activation with SIGUSR1"));
        assert!(!out.contains("WARNING"));
        assert_eq!(state_bytes(&fixture), before, "the CLI never writes Node");
        let IntentRead::Intent(intent) =
            read_intent(&TrustedDir::open(&fixture.dir, fixture.uid).unwrap())
        else {
            panic!("the installed intent must be readable");
        };
        assert_eq!(
            intent.attestation_format_version,
            ATTESTATION_FORMAT_VERSION
        );
        assert!(crate::node_mutation::is_canonical_uuid_v4(
            intent.attestation_id.as_str()
        ));
        assert_eq!(intent.cluster_id, "cluster");
        assert_eq!(intent.node_id, "node-a");
        assert_eq!(intent.subject, "nginx.service");
        assert_eq!(intent.target_node_id, "node-b");
        assert_eq!(intent.incident_seq, incident.incident_seq);
        assert_eq!(intent.incident_id, incident.incident_id);
        assert_eq!(intent.statement, ATTESTATION_STATEMENT);
    }

    /// §18.1 / §18.4 steps 1-3: every argument or state mismatch refuses and
    /// installs nothing.
    #[test]
    fn stage14_8_recover_refusals_install_nothing() {
        let fixture = systemd();
        let none = request(&fixture, "nginx.service", "node-b", 1);
        let (result, _) = run_as_owner(&fixture, &none);
        assert!(result.unwrap_err().contains("no open fencing incident 1"));
        let incident = open(&fixture, FencingBackend::None);
        let before = state_bytes(&fixture);
        for (case, bad, expected) in [
            (
                "wrong service",
                request(&fixture, "other.service", "node-b", 1),
                "is not the configured subject",
            ),
            (
                "local node",
                request(&fixture, "nginx.service", "node-a", 1),
                "refusing to attest the local node",
            ),
            (
                "wrong node",
                request(&fixture, "nginx.service", "node-c", 1),
                "is not the configured peer",
            ),
            (
                "zero incident",
                request(&fixture, "nginx.service", "node-b", 0),
                "--incident must be at least 1",
            ),
            (
                "wrong incident",
                request(&fixture, "nginx.service", "node-b", 2),
                "no open fencing incident 2",
            ),
        ] {
            let (result, out) = run_as_owner(&fixture, &bad);
            assert!(result.unwrap_err().contains(expected), "{case}");
            assert!(out.is_empty(), "{case}: nothing printed before refusal");
            assert!(
                !fixture.dir.join(ATTESTATION_INTENT_FILE).exists(),
                "{case}"
            );
        }
        assert_eq!(state_bytes(&fixture), before);
        assert_eq!(incident.incident_seq, 1);
        let missing = RecoverRequest {
            config: Some(fixture.dir.join("absent.toml")),
            ..none
        };
        assert!(run_as_owner(&fixture, &missing).0.is_err());
    }

    /// §18.4 step 2: an already-`CONFIRMED` incident prints "already
    /// confirmed" and exits 0 with no write.
    #[test]
    fn stage14_8_recover_already_confirmed_is_a_no_write_success() {
        let fixture = systemd();
        let incident = open(&fixture, FencingBackend::None);
        let FencingEventOutcome::Transition(confirm) = incident
            .confirm_by_attestation(AttestationId::generated(
                crate::node_mutation::generate_uuid().unwrap(),
            ))
            .unwrap()
        else {
            panic!("expected a transition");
        };
        fixture.store.apply_fencing_transition(confirm).unwrap();
        let before = state_bytes(&fixture);
        let (result, out) =
            run_as_owner(&fixture, &request(&fixture, "nginx.service", "node-b", 1));
        assert_eq!(result, Ok(RecoverOutcome::AlreadyConfirmed));
        assert!(out.contains("already confirmed: incident 1 for node-b"));
        assert!(!fixture.dir.join(ATTESTATION_INTENT_FILE).exists());
        assert_eq!(state_bytes(&fixture), before);
    }

    /// §18.4 step 5: `FAILED` adds the device-disagreement warning.
    #[test]
    fn stage14_8_recover_warns_for_failed() {
        let fixture = systemd();
        let requested = open(&fixture, FencingBackend::Command);
        let verifying = fixture
            .store
            .apply_fencing_transition(
                requested
                    .action_returned(1, ActionOutcome::ReportedSuccess)
                    .unwrap(),
            )
            .unwrap();
        let FencingEventOutcome::Transition(failed) =
            verifying.verification_not_isolated(1).unwrap()
        else {
            panic!("expected a transition");
        };
        fixture.store.apply_fencing_transition(failed).unwrap();
        let (result, out) =
            run_as_owner(&fixture, &request(&fixture, "nginx.service", "node-b", 1));
        assert_eq!(result, Ok(RecoverOutcome::Installed));
        assert!(out.contains("WARNING: the fencing device reported the node NOT isolated"));
    }

    /// §18.4 step 3 / §34.7 duplicate: a second CLI refuses before printing.
    /// An unsafe parent refuses before any file is created. The command
    /// manager's subject is the cluster id.
    #[test]
    fn stage14_8_recover_pending_unsafe_parent_and_command_subject() {
        let fixture = systemd();
        open(&fixture, FencingBackend::None);
        let good = request(&fixture, "nginx.service", "node-b", 1);
        assert_eq!(
            run_as_owner(&fixture, &good).0,
            Ok(RecoverOutcome::Installed)
        );
        let installed = fs::read(fixture.dir.join(ATTESTATION_INTENT_FILE)).unwrap();
        let (result, out) = run_as_owner(&fixture, &good);
        assert!(result.unwrap_err().contains("pending ingestion"));
        assert!(out.is_empty());
        assert_eq!(
            fs::read(fixture.dir.join(ATTESTATION_INTENT_FILE)).unwrap(),
            installed
        );

        let unsafe_parent = systemd();
        open(&unsafe_parent, FencingBackend::None);
        fs::set_permissions(&unsafe_parent.dir, fs::Permissions::from_mode(0o777)).unwrap();
        let (result, out) = run_as_owner(
            &unsafe_parent,
            &request(&unsafe_parent, "nginx.service", "node-b", 1),
        );
        assert!(result.unwrap_err().contains("unsafe intent directory"));
        assert!(out.is_empty(), "refused before the statement is printed");
        assert!(!unsafe_parent.dir.join(ATTESTATION_INTENT_FILE).exists());

        let command = fixture_command();
        open(&command, FencingBackend::None);
        assert_eq!(
            run_as_owner(&command, &request(&command, "cluster", "node-b", 1)).0,
            Ok(RecoverOutcome::Installed)
        );
    }

    fn fixture_command() -> Fixture {
        fixture(
            "manager = \"command\"\nstart = [\"/opt/app/start\"]\nstop = [\"/opt/app/stop\"]\nstatus = [\"/opt/app/status\"]",
        )
    }

    /// The production entry requires a root-owned intent directory: as a
    /// non-root user over a user-owned tree it installs nothing.
    #[test]
    fn stage14_8_recover_production_entry_requires_root_owned_directory() {
        let fixture = systemd();
        open(&fixture, FencingBackend::None);
        let result = recover(
            &request(&fixture, "nginx.service", "node-b", 1),
            ROOT_UID,
            &mut Vec::new(),
        );
        if fixture.uid != ROOT_UID {
            assert!(result.unwrap_err().contains("ParentOwner"));
            assert!(!fixture.dir.join(ATTESTATION_INTENT_FILE).exists());
        }
    }
}
