//! Wire format between the controller and the node agent.
//!
//! One JSON request object is written to the agent's standard input and one
//! JSON response object is read from its standard output. The remote command
//! line is fixed (`<sudo> <binary> agent`), so no request data is ever parsed
//! by a remote shell.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const PROTO_VERSION: u32 = 1;
/// Largest request or response accepted by either side.
pub(crate) const MAX_MESSAGE: usize = 1 << 20;
/// Largest file content carried in a request (chrony configuration).
pub(crate) const MAX_CONTENT: usize = 256 * 1024;

pub(crate) mod op {
    pub(crate) const PING: &str = "ping";
    pub(crate) const SERVICE_STATUS: &str = "service.status";
    pub(crate) const SERVICE_CONTROL: &str = "service.control";
    pub(crate) const PROBE: &str = "probe";
    pub(crate) const CHRONY_STATE: &str = "chrony.state";
    pub(crate) const CHRONY_READ: &str = "chrony.read";
    pub(crate) const CHRONY_VALIDATE: &str = "chrony.validate";
    pub(crate) const CHRONY_BACKUP: &str = "chrony.backup";
    pub(crate) const CHRONY_STAGE: &str = "chrony.stage";
    pub(crate) const CHRONY_PUBLISH: &str = "chrony.publish";
    pub(crate) const CHRONY_RESTORE: &str = "chrony.restore";
    pub(crate) const CHRONY_CLEANUP: &str = "chrony.cleanup";
    pub(crate) const LEASE_INIT: &str = "lease.init";
    pub(crate) const LEASE_STATUS: &str = "lease.status";
    pub(crate) const LEASE_ACQUIRE: &str = "lease.acquire";
    pub(crate) const LEASE_PHASE: &str = "lease.phase";
    pub(crate) const LEASE_COMMIT: &str = "lease.commit";
    pub(crate) const LEASE_ABORT: &str = "lease.abort";
    pub(crate) const LEASE_RECONCILE: &str = "lease.reconcile";
    // v0.5: durable manual-operation barrier. `begin` and `resolve` are
    // mutating and take the exclusion proof (which owns the control lock);
    // `status` is read-only.
    pub(crate) const CONTROL_INTENT_BEGIN: &str = "control.intent.begin";
    pub(crate) const CONTROL_INTENT_RESOLVE: &str = "control.intent.resolve";
    pub(crate) const CONTROL_INTENT_STATUS: &str = "control.intent.status";
}

/// How long one agent run may take in total, by operation (audit EX-07). The
/// controller's timeouts in `remote.rs` are longer by a margin for the SSH
/// connection, so an agent never outlives the controller's wait.
pub(crate) const AGENT_BUDGET_SHORT: std::time::Duration = std::time::Duration::from_secs(25);
pub(crate) const AGENT_BUDGET_PING: std::time::Duration = std::time::Duration::from_secs(55);
pub(crate) const AGENT_BUDGET_LONG: std::time::Duration = std::time::Duration::from_secs(140);

pub(crate) fn agent_budget(operation: &str) -> std::time::Duration {
    match operation {
        op::SERVICE_CONTROL | op::CHRONY_RESTORE => AGENT_BUDGET_LONG,
        op::PING => AGENT_BUDGET_PING,
        _ => AGENT_BUDGET_SHORT,
    }
}

/// Error codes carried in-band by a response.
pub(crate) mod code {
    /// Nothing was changed; a safety rule forbids the request.
    pub(crate) const REFUSED: &str = "refused";
    /// The operation failed; it may have partly taken effect.
    pub(crate) const FAILED: &str = "failed";
    /// The request was malformed and the agent did nothing; the controller
    /// treats it like a refusal.
    pub(crate) const BAD_REQUEST: &str = "bad_request";
    /// A file operation replaced the live chrony configuration, found that
    /// somebody else had changed it inside the window, and could NOT put
    /// their version back. That version is kept on the node (the message
    /// names the file) and must not be deleted by anybody (audit RA-D-01).
    pub(crate) const DISPLACED_KEPT: &str = "displaced_kept";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) v: u32,
    pub(crate) id: String,
    pub(crate) op: String,
    #[serde(default)]
    pub(crate) args: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrorBody {
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    pub(crate) v: u32,
    pub(crate) id: String,
    pub(crate) ok: bool,
    #[serde(default)]
    pub(crate) data: Value,
    #[serde(default)]
    pub(crate) error: Option<ErrorBody>,
    /// The node name the answering agent is configured with. The controller
    /// refuses an answer from a host that is not the one it addressed.
    #[serde(default)]
    pub(crate) node: String,
}

impl Response {
    pub(crate) fn ok(id: &str, data: Value) -> Self {
        Self {
            v: PROTO_VERSION,
            id: id.to_string(),
            ok: true,
            data,
            error: None,
            node: String::new(),
        }
    }

    pub(crate) fn err(id: &str, code: &str, message: impl Into<String>) -> Self {
        Self {
            v: PROTO_VERSION,
            id: id.to_string(),
            ok: false,
            data: Value::Null,
            error: Some(ErrorBody {
                code: code.to_string(),
                message: message.into(),
            }),
            node: String::new(),
        }
    }
}

/// `true` for a request id the agent accepts: 8..=64 of `[0-9a-zA-Z-]`.
pub(crate) fn valid_id(id: &str) -> bool {
    (8..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub(crate) fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    // A CSPRNG failure must not yield a predictable id: fall back to a value
    // that is still unique within the process and obviously marked.
    if getrandom::fill(&mut buffer).is_err() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        // Mix the counter into every output byte so that even a short id
        // differs between calls in this process.
        let mixed = t.to_le_bytes();
        let counter = n.to_le_bytes();
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = mixed[i % 16]
                .wrapping_add(counter[i % 8])
                .wrapping_add(u8::try_from(i).unwrap_or(0).wrapping_mul(31));
        }
    }
    buffer.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_request_fields_are_rejected() {
        let text = r#"{"v":1,"id":"abcdefgh","op":"ping","args":{},"extra":1}"#;
        assert!(serde_json::from_str::<Request>(text).is_err());
    }

    #[test]
    fn response_round_trips() {
        let response = Response::err("abcdefgh", code::REFUSED, "no");
        let text = serde_json::to_string(&response).unwrap();
        assert_eq!(serde_json::from_str::<Response>(&text).unwrap(), response);
    }

    #[test]
    fn ids_are_restricted() {
        assert!(valid_id("abcd-1234"));
        for bad in ["short", "has space xx", "a;b;c;d;e;f", &"x".repeat(65)] {
            assert!(!valid_id(bad), "{bad:?}");
        }
        assert_eq!(random_hex(8).len(), 16);
        assert_ne!(random_hex(8), random_hex(8));
    }
}
