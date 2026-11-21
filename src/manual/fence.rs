//! Node-side fencing high-water mark of the manual control plane.
//!
//! Every lock grant at the Witness carries a monotonically increasing `seq`
//! (see `lease.rs`). A controller attaches the token `(epoch, seq, op_id)` of
//! its operation to the mutating calls it makes on a node. The node agent
//! remembers the highest token it ever accepted and refuses smaller ones, so
//! a controller whose lock was taken over (or whose operation was cut by a
//! reconcile) cannot act on a node that already served a newer holder
//! (round-1 audit, B-01/B-02). The same record lets a controller notice a
//! Witness that was restored from an old snapshot: the Witness then shows a
//! smaller `seq`/`epoch` than a node has seen (B-04).
//!
//! Limits (documented, not hidden): a token is only enforced once the node
//! has seen a newer one; the window between a reconcile and the next
//! controller's first mutating call on that node stays open. A call without a
//! token is not checked (the same controller code always sends one).

use super::exclusion::ExclusiveProof;
use super::fsutil::{self, StoreLock};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

const SCHEMA: &str = "mkg-fence/v1";
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// The fencing token a controller sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Token {
    pub(crate) epoch: u64,
    pub(crate) seq: u64,
    pub(crate) op_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    cluster: String,
    node: String,
    epoch: u64,
    seq: u64,
    op_id: String,
    checksum: String,
}

impl Record {
    fn checksum(&self) -> String {
        let mut copy = self.clone();
        copy.checksum = String::new();
        serde_json::to_vec(&copy).map_or_else(|_| String::new(), |b| fsutil::sha256_hex(&b))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FenceError {
    /// The token is older than one this node already accepted.
    Stale(String),
    /// The record cannot be trusted or written: fail closed.
    Storage(String),
}

impl std::fmt::Display for FenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stale(m) => write!(f, "stale fencing token: {m}"),
            Self::Storage(m) => write!(f, "fencing record unusable: {m}"),
        }
    }
}

pub(crate) struct FenceStore {
    path: PathBuf,
    cluster: String,
    node: String,
    owner_uid: u32,
}

impl FenceStore {
    pub(crate) fn new(path: PathBuf, cluster: &str, node: &str, owner_uid: u32) -> Self {
        Self {
            path,
            cluster: cluster.to_string(),
            node: node.to_string(),
            owner_uid,
        }
    }

    fn load(&self) -> Result<Option<Record>, FenceError> {
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(FenceError::Storage(e.to_string())),
            Ok(_) => {}
        }
        fsutil::check_trusted_file(&self.path, self.owner_uid)
            .map_err(|e| FenceError::Storage(format!("record {e}")))?;
        let bytes = fsutil::read_regular_nofollow(&self.path, 64 * 1024)
            .map_err(|e| FenceError::Storage(e.to_string()))?;
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|e| FenceError::Storage(format!("damaged: {e}")))?;
        if record.schema != SCHEMA
            || record.cluster != self.cluster
            || record.node != self.node
            || record.checksum != record.checksum()
        {
            return Err(FenceError::Storage(
                "schema, identity or checksum does not match".to_string(),
            ));
        }
        Ok(Some(record))
    }

    /// The highest accepted token, `None` if this node never saw one.
    pub(crate) fn current(&self) -> Result<Option<Token>, FenceError> {
        Ok(self.load()?.map(|r| Token {
            epoch: r.epoch,
            seq: r.seq,
            op_id: r.op_id,
        }))
    }

    /// Accept `token` if it is not older than the recorded one, and record it.
    /// The same `seq` is accepted only for the same operation.
    pub(crate) fn admit(&self, _proof: &ExclusiveProof, token: &Token) -> Result<(), FenceError> {
        let _guard = StoreLock::acquire(&self.path, self.owner_uid, LOCK_WAIT)
            .map_err(FenceError::Storage)?;
        let current = self.load()?;
        if let Some(have) = &current {
            if token.seq < have.seq || token.epoch < have.epoch {
                return Err(FenceError::Stale(format!(
                    "token (epoch {}, seq {}) is older than the accepted (epoch {}, seq {})",
                    token.epoch, token.seq, have.epoch, have.seq
                )));
            }
            if token.seq == have.seq && token.op_id != have.op_id {
                return Err(FenceError::Stale(format!(
                    "sequence {} belongs to another operation",
                    token.seq
                )));
            }
            if token.seq == have.seq && token.epoch == have.epoch {
                return Ok(());
            }
        }
        let mut record = Record {
            schema: SCHEMA.to_string(),
            cluster: self.cluster.clone(),
            node: self.node.clone(),
            epoch: token.epoch,
            seq: token.seq,
            op_id: token.op_id.clone(),
            checksum: String::new(),
        };
        record.checksum = record.checksum();
        let mut bytes =
            serde_json::to_vec_pretty(&record).map_err(|e| FenceError::Storage(e.to_string()))?;
        bytes.push(b'\n');
        let dir = self
            .path
            .parent()
            .ok_or_else(|| FenceError::Storage("no parent directory".to_string()))?;
        let tmp = dir.join(format!(".fence-{}.tmp", super::proto::random_hex(8)));
        let write = || -> io::Result<()> {
            let mut file = fsutil::create_new(&tmp, 0o600)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            fsutil::fsync_dir(dir)
        };
        write().map_err(|e| {
            let _ = fs::remove_file(&tmp);
            FenceError::Storage(format!("cannot persist: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual::fsutil::tests::{my_uid, temp_dir};

    fn store(label: &str) -> (FenceStore, PathBuf) {
        let dir = temp_dir(label);
        (
            FenceStore::new(
                dir.join("fence").join("fence.json"),
                "c",
                "node-a",
                my_uid(),
            ),
            dir,
        )
    }

    fn token(epoch: u64, seq: u64, op: &str) -> Token {
        Token {
            epoch,
            seq,
            op_id: op.to_string(),
        }
    }

    #[test]
    fn the_mark_only_moves_forward() {
        let (store, dir) = store("fence-forward");
        assert_eq!(store.current().unwrap(), None);
        store
            .admit(&ExclusiveProof::for_test(), &token(1, 5, "op-a"))
            .unwrap();
        store
            .admit(&ExclusiveProof::for_test(), &token(1, 5, "op-a"))
            .unwrap();
        store
            .admit(&ExclusiveProof::for_test(), &token(2, 6, "op-b"))
            .unwrap();
        assert_eq!(store.current().unwrap(), Some(token(2, 6, "op-b")));
        for stale in [
            token(2, 5, "op-a"),
            token(1, 7, "op-c"),
            token(1, 4, "op-a"),
        ] {
            assert!(
                matches!(
                    store.admit(&ExclusiveProof::for_test(), &stale),
                    Err(FenceError::Stale(_))
                ),
                "{stale:?}"
            );
        }
        // The same sequence number for another operation is a forgery.
        assert!(matches!(
            store.admit(&ExclusiveProof::for_test(), &token(2, 6, "op-x")),
            Err(FenceError::Stale(_))
        ));
        assert_eq!(store.current().unwrap(), Some(token(2, 6, "op-b")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ra_b06_a_record_that_others_can_write_or_that_is_a_link_is_not_trusted() {
        // The trust check of the record file (mutant M30 of the audit removed
        // it and no test noticed): a mark that anybody can rewrite proves
        // nothing, so reading or admitting fails closed.
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (store, dir) = store("fence-untrusted");
        store
            .admit(&ExclusiveProof::for_test(), &token(1, 1, "op-a"))
            .unwrap();
        let path = dir.join("fence").join("fence.json");
        for mode in [0o666, 0o662, 0o626] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(store.current(), Err(FenceError::Storage(_))),
                "{mode:o}"
            );
            assert!(
                matches!(
                    store.admit(&ExclusiveProof::for_test(), &token(9, 9, "op-z")),
                    Err(FenceError::Storage(_))
                ),
                "{mode:o}"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.current().unwrap().is_some());
        // A symbolic link in its place is refused as well.
        let real = dir.join("fence").join("real.json");
        fs::rename(&path, &real).unwrap();
        symlink(&real, &path).unwrap();
        assert!(matches!(store.current(), Err(FenceError::Storage(_))));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_damaged_or_foreign_record_fails_closed() {
        let (store, dir) = store("fence-damaged");
        store
            .admit(&ExclusiveProof::for_test(), &token(1, 1, "op-a"))
            .unwrap();
        let path = dir.join("fence").join("fence.json");
        let good = fs::read_to_string(&path).unwrap();
        for bad in [
            "{ nope".to_string(),
            good.replace("\"seq\": 1", "\"seq\": 0"),
            good.replace("node-a", "node-b"),
        ] {
            fs::write(&path, bad).unwrap();
            assert!(matches!(store.current(), Err(FenceError::Storage(_))));
            assert!(matches!(
                store.admit(&ExclusiveProof::for_test(), &token(9, 9, "op-z")),
                Err(FenceError::Storage(_))
            ));
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
