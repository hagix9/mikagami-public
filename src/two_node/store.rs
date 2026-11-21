//! The durable two-node ownership record (TWO_NODE_SAFETY_MODEL.md §5).
//!
//! The record is **knowledge, not authority**: it orders ownership (the epoch), binds fence
//! attempts to the epoch they were opened against, keeps the grant this node gave the peer,
//! the fence history and the one-time use of every fence proof and operator attestation.
//! No promotion is ever justified by this record alone: a promotion needs a fresh grant
//! from the live peer or a fence confirmed by this process (controller). A lost, rolled
//! back or corrupt record therefore costs availability (the node stays Standby, or in
//! cleanup-only mode) and never safety.
//!
//! Format: one JSON line (the body) followed by `sha256:<hex of the body>`. Writes are
//! atomic: a fresh temporary file (create_new, 0600), fsync, rename over the record, fsync
//! of the parent directory. Only a confirmed save is a durable boundary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const STATE_VERSION: u32 = 1;
/// Bounded fence history (oldest entries are dropped; the history is diagnostics plus the
/// one-time use of recent proofs, never a safety argument by its length).
pub const HISTORY_LIMIT: usize = 64;
/// Bounded list of consumed operator attestation ids.
pub const ATTESTATION_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipState {
    pub version: u32,
    pub cluster_id: String,
    pub node_id: String,
    /// The highest ownership epoch this node knows of (its own or the peer's).
    pub epoch: u64,
    /// The node believed to own `epoch` (`None`: released or not known).
    pub owner: Option<String>,
    /// This node may hold resources: set durably before any resource acquisition, cleared
    /// only after a trusted ZeroResource observation.
    pub holding: bool,
    /// Why this node owns `epoch` (present while `owner` is this node).
    pub intent: Option<PromotionIntent>,
    /// The grant this node gave the peer and that is not yet resolved.
    pub grant: Option<Grant>,
    /// The highest epoch this node ever granted (a grant is never repeated for a lower or
    /// equal epoch).
    pub granted_high_water: u64,
    /// The highest fence incident sequence number ever used (never reused).
    pub incident_seq: u64,
    /// The open fence incident, if any.
    pub incident: Option<Incident>,
    pub history: Vec<FenceRecord>,
    pub consumed_attestations: Vec<String>,
    /// A verify reported the peer NOT stopped: no automatic fence until the peer returns
    /// authenticated (kept across restarts).
    #[serde(default)]
    pub fence_stopped: bool,
    /// Daemon starts recorded by this record (diagnostic).
    pub starts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionIntent {
    pub epoch: u64,
    pub basis: Basis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Basis {
    /// The live peer durably granted `claim_id` for this epoch.
    Grant { claim_id: String, granter: String },
    /// This process confirmed the fence `op_id` of incident `incident_seq`.
    Fence { incident_seq: u64, op_id: String },
    /// An operator attested the peer stopped.
    Operator { attestation_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub claim_id: String,
    pub epoch: u64,
    pub grantee: String,
    pub grantee_incarnation: String,
    /// The grantee's announced `state_seq` that carried the claim. A later announcement of
    /// the same incarnation (strictly greater) without the claim shows it dropped.
    pub claim_state_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub seq: u64,
    pub target: String,
    /// The epoch the incident was opened against. A confirmation is usable only while the
    /// durable epoch still equals it.
    pub base_epoch: u64,
    /// The peer process incarnation last seen before the loss.
    pub peer_incarnation: Option<String>,
    /// The current attempt (1-based) and its fresh operation id.
    pub attempt: u32,
    pub op_id: String,
    pub state: IncidentState,
    /// Opened by an operator request (not by the automatic trigger).
    pub operator: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum IncidentState {
    /// The fence action of `op_id` is about to run / running (accepted is not stopped).
    Requested,
    /// The action returned (its outcome is only an acceptance report); verify is running.
    Verifying { action: String },
    /// Verify observed the peer stopped for `op_id` (this process). Consumed by promotion.
    Confirmed,
    /// Verify observed the peer NOT stopped: never fenced again automatically.
    Failed,
    /// Not attempted or verification inconclusive; the reason is diagnostic.
    Unknown { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceRecord {
    pub seq: u64,
    pub attempt: u32,
    pub op_id: String,
    pub target: String,
    pub base_epoch: u64,
    pub outcome: String,
}

impl OwnershipState {
    pub fn fresh(cluster_id: &str, node_id: &str) -> Self {
        Self {
            version: STATE_VERSION,
            cluster_id: cluster_id.to_string(),
            node_id: node_id.to_string(),
            epoch: 0,
            owner: None,
            holding: false,
            intent: None,
            grant: None,
            granted_high_water: 0,
            incident_seq: 0,
            incident: None,
            history: Vec::new(),
            consumed_attestations: Vec::new(),
            fence_stopped: false,
            starts: 0,
        }
    }

    pub fn push_history(&mut self, record: FenceRecord) {
        self.history.push(record);
        if self.history.len() > HISTORY_LIMIT {
            let excess = self.history.len() - HISTORY_LIMIT;
            self.history.drain(..excess);
        }
    }

    /// Whether an operation id was ever recorded (used or consumed) in the history.
    pub fn op_id_recorded(&self, op_id: &str) -> bool {
        self.history.iter().any(|record| record.op_id == op_id)
    }

    pub fn consume_attestation(&mut self, id: &str) {
        self.consumed_attestations.push(id.to_string());
        if self.consumed_attestations.len() > ATTESTATION_LIMIT {
            let excess = self.consumed_attestations.len() - ATTESTATION_LIMIT;
            self.consumed_attestations.drain(..excess);
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let body = serde_json::to_string(self).map_err(|e| format!("encode: {e}"))?;
        let digest = hex(&Sha256::digest(body.as_bytes()));
        Ok(format!("{body}\nsha256:{digest}\n").into_bytes())
    }

    pub fn decode(bytes: &[u8], cluster_id: &str, node_id: &str) -> Result<Self, LoadError> {
        let text = std::str::from_utf8(bytes).map_err(|_| LoadError::Corrupt("not UTF-8"))?;
        let mut lines = text.split('\n');
        let body = lines.next().ok_or(LoadError::Corrupt("empty"))?;
        let check = lines.next().ok_or(LoadError::Corrupt("no checksum line"))?;
        if lines.next() != Some("") || lines.next().is_some() {
            return Err(LoadError::Corrupt("trailing data"));
        }
        let digest = check
            .strip_prefix("sha256:")
            .ok_or(LoadError::Corrupt("malformed checksum line"))?;
        if digest != hex(&Sha256::digest(body.as_bytes())) {
            return Err(LoadError::Corrupt("checksum mismatch"));
        }
        let state: Self =
            serde_json::from_str(body).map_err(|_| LoadError::Corrupt("malformed body"))?;
        if state.version != STATE_VERSION {
            return Err(LoadError::Corrupt("unknown version"));
        }
        if state.cluster_id != cluster_id || state.node_id != node_id {
            return Err(LoadError::IdentityMismatch);
        }
        if state.holding && state.intent.is_none() && state.owner.as_deref() == Some(node_id) {
            // Representable but inconsistent: holding self-ownership without its basis.
            return Err(LoadError::Corrupt("ownership without basis"));
        }
        Ok(state)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Missing,
    Corrupt(&'static str),
    IdentityMismatch,
    Io(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "the two-node state does not exist (run `two-node init`)"),
            Self::Corrupt(why) => write!(f, "the two-node state is corrupt ({why})"),
            Self::IdentityMismatch => {
                write!(f, "the two-node state belongs to another cluster or node")
            }
            Self::Io(error) => write!(f, "the two-node state could not be read: {error}"),
        }
    }
}

/// The persistence boundary the controller writes through. A save either completes
/// durably (`Ok`) or the caller must treat the new state as not written.
pub trait DurableStore {
    fn save(&mut self, state: &OwnershipState) -> Result<(), String>;
}

/// The production file store.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self, cluster_id: &str, node_id: &str) -> Result<OwnershipState, LoadError> {
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LoadError::Missing);
            }
            Err(error) => return Err(LoadError::Io(error.to_string())),
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(LoadError::Corrupt("not a regular file"));
            }
            Ok(_) => {}
        }
        let bytes = fs::read(&self.path).map_err(|e| LoadError::Io(e.to_string()))?;
        OwnershipState::decode(&bytes, cluster_id, node_id)
    }

    /// Creates the record once. Refuses when anything exists at the path, unless
    /// `replace_corrupt` and the existing record is corrupt (it is then moved aside, never
    /// deleted). Returns the moved-aside path, if any.
    pub fn init(
        &self,
        cluster_id: &str,
        node_id: &str,
        replace_corrupt: bool,
        unix_now: u64,
    ) -> Result<Option<PathBuf>, String> {
        let mut moved = None;
        match self.load(cluster_id, node_id) {
            Err(LoadError::Missing) => {}
            Ok(_) => {
                return Err("a valid two-node state already exists; refusing to reset it".into());
            }
            Err(LoadError::Corrupt(why)) if replace_corrupt => {
                let aside = self.path.with_extension(format!("corrupt-{unix_now}"));
                if aside.exists() {
                    return Err(format!("{} already exists", aside.display()));
                }
                fs::rename(&self.path, &aside).map_err(|e| format!("move aside: {e}"))?;
                sync_parent(&self.path).map_err(|e| format!("fsync parent: {e}"))?;
                eprintln!(
                    "mikagami: the corrupt two-node state ({why}) was moved to {}",
                    aside.display()
                );
                moved = Some(aside);
            }
            Err(error) => {
                return Err(format!(
                    "{error}; refusing to initialise (use --replace-corrupt only for a corrupt record)"
                ));
            }
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create state directory: {e}"))?;
        }
        self.write_atomic(&OwnershipState::fresh(cluster_id, node_id))?;
        Ok(moved)
    }

    fn write_atomic(&self, state: &OwnershipState) -> Result<(), String> {
        let bytes = state.encode()?;
        let suffix = crate::node_mutation::generate_uuid()
            .ok_or_else(|| "no randomness for the temporary name".to_string())?;
        let file_name = self
            .path
            .file_name()
            .ok_or_else(|| "state path has no file name".to_string())?
            .to_string_lossy()
            .into_owned();
        let temporary = self
            .path
            .with_file_name(format!(".{file_name}.tmp-{suffix}"));
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.path)?;
            sync_parent(&self.path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(|error| format!("durable save failed: {error}"))
    }
}

impl DurableStore for FileStore {
    fn save(&mut self, state: &OwnershipState) -> Result<(), String> {
        self.write_atomic(state)
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("no parent directory"))?;
    File::open(parent)?.sync_all()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "mkg-two-node-store-{tag}-{}",
            crate::node_mutation::generate_uuid().unwrap()
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn round_trip_and_checksum() {
        let mut state = OwnershipState::fresh("c", "node-a");
        state.epoch = 7;
        state.owner = Some("node-b".into());
        let bytes = state.encode().unwrap();
        assert_eq!(
            OwnershipState::decode(&bytes, "c", "node-a").unwrap(),
            state
        );
        let mut tampered = bytes.clone();
        let position = tampered.iter().position(|b| *b == b'7').unwrap();
        tampered[position] = b'8';
        assert_eq!(
            OwnershipState::decode(&tampered, "c", "node-a"),
            Err(LoadError::Corrupt("checksum mismatch"))
        );
        assert_eq!(
            OwnershipState::decode(&bytes, "c", "node-b"),
            Err(LoadError::IdentityMismatch)
        );
        assert!(matches!(
            OwnershipState::decode(&bytes[..bytes.len() - 3], "c", "node-a"),
            Err(LoadError::Corrupt(_))
        ));
        assert!(matches!(
            OwnershipState::decode(b"", "c", "node-a"),
            Err(LoadError::Corrupt(_))
        ));
    }

    #[test]
    fn unknown_fields_and_versions_are_corrupt() {
        let state = OwnershipState::fresh("c", "a");
        let body =
            serde_json::to_string(&state)
                .unwrap()
                .replacen("\"version\":1", "\"version\":2", 1);
        let bytes = format!("{body}\nsha256:{}\n", hex(&Sha256::digest(body.as_bytes())));
        assert_eq!(
            OwnershipState::decode(bytes.as_bytes(), "c", "a"),
            Err(LoadError::Corrupt("unknown version"))
        );
        let body = serde_json::to_string(&state)
            .unwrap()
            .replacen("{", "{\"extra\":1,", 1);
        let bytes = format!("{body}\nsha256:{}\n", hex(&Sha256::digest(body.as_bytes())));
        assert_eq!(
            OwnershipState::decode(bytes.as_bytes(), "c", "a"),
            Err(LoadError::Corrupt("malformed body"))
        );
    }

    #[test]
    fn self_ownership_without_basis_is_corrupt() {
        let mut state = OwnershipState::fresh("c", "a");
        state.holding = true;
        state.owner = Some("a".into());
        let bytes = state.encode().unwrap();
        assert_eq!(
            OwnershipState::decode(&bytes, "c", "a"),
            Err(LoadError::Corrupt("ownership without basis"))
        );
    }

    #[test]
    fn init_refuses_existing_and_moves_corrupt_aside_only_on_request() {
        let dir = temp_dir("init");
        let store = FileStore::new(dir.join("state.json"));
        assert_eq!(store.load("c", "a"), Err(LoadError::Missing));
        store.init("c", "a", false, 1).unwrap();
        assert_eq!(
            store.load("c", "a").unwrap(),
            OwnershipState::fresh("c", "a")
        );
        assert!(store.init("c", "a", false, 2).is_err());
        assert!(
            store.init("c", "a", true, 2).is_err(),
            "valid state is never reset"
        );
        fs::write(store.path(), b"garbage").unwrap();
        assert!(store.init("c", "a", false, 3).is_err());
        let moved = store.init("c", "a", true, 3).unwrap().unwrap();
        assert!(moved.exists());
        assert_eq!(store.load("c", "a").unwrap().epoch, 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temporary() {
        let dir = temp_dir("save");
        let mut store = FileStore::new(dir.join("state.json"));
        store.init("c", "a", false, 1).unwrap();
        let mut state = store.load("c", "a").unwrap();
        state.epoch = 3;
        store.save(&state).unwrap();
        assert_eq!(store.load("c", "a").unwrap().epoch, 3);
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["state.json".to_string()]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn history_and_attestations_are_bounded() {
        let mut state = OwnershipState::fresh("c", "a");
        for seq in 0..(HISTORY_LIMIT as u64 + 5) {
            state.push_history(FenceRecord {
                seq,
                attempt: 1,
                op_id: format!("op-{seq}"),
                target: "b".into(),
                base_epoch: 0,
                outcome: "x".into(),
            });
            state.consume_attestation(&format!("att-{seq}"));
        }
        assert_eq!(state.history.len(), HISTORY_LIMIT);
        assert_eq!(state.consumed_attestations.len(), ATTESTATION_LIMIT);
        assert_eq!(state.history[0].seq, 5);
    }
}
