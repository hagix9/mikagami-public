//! Manual control plane (Prototype v0.2).
//!
//! An operator-driven orchestrator for two resources on a two-node pair:
//! the VIP (a GCE alias IP plus its service) and the chronyd configuration /
//! service. It is **not** an HA engine: there is no heartbeat, no election,
//! no scoring and no automatic movement. Every change is requested by an
//! operator command and guarded by an explicit, fail-closed safety sequence.
//!
//! Boundaries:
//!
//! * It shares no code path with the HA daemon's promotion / lease /
//!   resource-mutation layers and none of those layers can reach it
//!   (checked by `tests/architecture.rs`).
//! * It talks to the world only through two narrow interfaces: [`gce::Gce`]
//!   (cloud API) and [`remote::Remote`] (the node agent over SSH).
//! * Exclusion from the HA daemon is **enforced** only in this narrow sense:
//!   an agent operation that changes a service unit or the ownership record
//!   proceeds only if, at that moment, the agent can positively show that the
//!   HA units are persistently masked (or explicitly acknowledged absent),
//!   that no HA job or hand-started HA process exists and that no HA
//!   configuration on the host names the same service or VIP; and the
//!   controller asks the source, the target and the Witness again right before
//!   every cloud alias change and the commit. What *prevents* the HA daemon
//!   from starting in between is the mask, which an operator applies with
//!   `install.sh --manual-mode`; the agent never masks anything. Hosts where
//!   the HA daemon may run are not supported by this control plane; the
//!   switch-over is an operator procedure (QUICKSTART.md), not something the
//!   code arbitrates. Chrony file operations are not gated at all.

pub(crate) mod agent;
pub(crate) mod chrony_agent;
pub(crate) mod chrony_ctl;
pub mod cli_def;
pub(crate) mod clock;
pub(crate) mod config;
pub(crate) mod exclusion;
pub(crate) mod exec;
pub(crate) mod fence;
pub(crate) mod fsutil;
pub(crate) mod gce;
pub(crate) mod guidance;
pub(crate) mod lease;
pub(crate) mod proto;
pub(crate) mod remote;
pub(crate) mod resource;
pub(crate) mod run;
pub(crate) mod signals;
pub(crate) mod vip;

#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod exclusion_tests;
#[cfg(test)]
pub(crate) mod fakes;
#[cfg(test)]
mod integrated_tests;
#[cfg(test)]
mod r6_tests;
#[cfg(test)]
mod r7_tests;
#[cfg(test)]
mod refusal_tests;
#[cfg(test)]
mod safety_tests;
#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod v3_tests;
#[cfg(test)]
mod vip_tests;

use clock::Clock;
use config::{AddressMode, ControlConfig, NodeConfig};
use gce::Gce;
use remote::{CallError, Remote, Target};
use serde_json::Value;
use std::time::Duration;

/// Exit codes. `2` is reserved for usage errors (clap).
pub(crate) const EXIT_FAILED: u8 = 1;
pub(crate) const EXIT_REFUSED: u8 = 3;
pub(crate) const EXIT_UNKNOWN: u8 = 4;

/// Why a command did not complete. The three kinds are told apart by one
/// question: **was a request that could change a resource sent, and is the
/// outcome known?** (`CLI_REFERENCE.md`, "REFUSED, FAILED and UNKNOWN")
///
/// * `Refused` (exit 3): the command stopped before it sent any such request
///   (a configuration, authorisation, precondition or exclusion rule, an
///   observation that could not be made first), or the target of the request
///   explicitly refused it and that was proven by observation. Provably
///   nothing changed; repeating the command after removing the cause is safe.
/// * `Failed` (exit 1): a change was attempted and its outcome is *known* to
///   be "not done" or "undone" (verified rollback, verified unchanged); also
///   a read-only command that could not give its answer.
/// * `Unknown` (exit 4): a change may have been made and its outcome is not
///   established, or the state itself cannot be established. Doubt always
///   ends here; operator action is required, nothing is retried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// Nothing was changed, and that is established (see above).
    Refused(String),
    /// The operation failed with a known outcome (see above).
    Failed(String),
    /// The resulting state cannot be established. Operator action required;
    /// no automatic retry or overwrite is attempted.
    Unknown(String),
}

impl Failure {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Failed(_) => EXIT_FAILED,
            Self::Refused(_) => EXIT_REFUSED,
            Self::Unknown(_) => EXIT_UNKNOWN,
        }
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Failed(_) => "FAILED",
            Self::Refused(_) => "REFUSED",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Failed(m) | Self::Refused(m) | Self::Unknown(m) => m,
        }
    }

    /// The same failure with its message made safe for a terminal (see
    /// [`clean_for_terminal`]); the kind is kept.
    pub(crate) fn cleaned(self) -> Self {
        match self {
            Self::Failed(m) => Self::Failed(clean_for_terminal(&m)),
            Self::Refused(m) => Self::Refused(clean_for_terminal(&m)),
            Self::Unknown(m) => Self::Unknown(clean_for_terminal(&m)),
        }
    }

    /// For a step that precedes every request that could change something: a
    /// failure to *observe* or to resolve is then a refusal to start (nothing
    /// was sent), not a failed operation. `Unknown` and `Refused` are kept.
    pub(crate) fn before_any_change(self) -> Self {
        match self {
            Self::Failed(m) => Self::Refused(m),
            other => other,
        }
    }
}

/// The word that goes with an exit code in `--json` output (`result`).
pub(crate) fn result_word(exit: u8) -> &'static str {
    match exit {
        0 => "ok",
        EXIT_FAILED => "failed",
        EXIT_REFUSED => "refused",
        EXIT_UNKNOWN => "unknown",
        _ => "error",
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.label(), self.message())
    }
}

pub(crate) type Res<T> = Result<T, Failure>;

pub(crate) trait Reporter {
    /// Progress line (stderr in production).
    fn info(&self, message: &str);
}

pub(crate) struct StderrReporter;

impl Reporter for StderrReporter {
    fn info(&self, message: &str) {
        // Remote text can reach a progress line; it is cleaned like every
        // other output (audit D-06, E-04). A failed write is ignored: a
        // closed terminal must not stop a rollback (audit E-01).
        say_err(&clean_for_terminal(message));
    }
}

/// Text that came (directly or indirectly) from a remote host or the
/// operator is shown with control characters, bidirectional controls and
/// zero-width characters made visible, so it cannot drive the terminal or
/// disguise what it says. Newline and tab are kept.
pub(crate) fn clean_for_terminal(text: &str) -> String {
    text.chars()
        .map(|c| {
            let invisible = matches!(
                c,
                '\u{061c}'
                    | '\u{200b}'..='\u{200f}'
                    | '\u{2028}'..='\u{202e}'
                    | '\u{2060}'..='\u{206f}'
                    | '\u{feff}'
            );
            if (c.is_control() && c != '\n' && c != '\t') || invisible {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// [`clean_for_terminal`] applied to every string and every key of a JSON
/// value (audit RA-E-07). The JSON writer already escapes control characters;
/// bidirectional and zero-width characters stay as they are in a string, so
/// they are made visible here, like in the text output.
pub(crate) fn clean_json_for_terminal(value: &mut Value) {
    match value {
        Value::String(text) => *text = clean_for_terminal(text),
        Value::Array(items) => items.iter_mut().for_each(clean_json_for_terminal),
        Value::Object(map) => {
            let entries = std::mem::take(map);
            for (key, mut item) in entries {
                clean_json_for_terminal(&mut item);
                map.insert(clean_for_terminal(&key), item);
            }
        }
        _ => {}
    }
}

/// The first `count` characters of a hash for messages; never slices text
/// that is not a hash, never cuts inside a character.
pub(crate) fn short_digest(value: &str, count: usize) -> String {
    if fsutil::is_sha256_hex(value) {
        value.chars().take(count).collect()
    } else {
        "(malformed)".to_string()
    }
}

/// Write a line to standard error. A failure (closed pipe, full disk) is
/// ignored on purpose: no output problem may change what a command does
/// (audit E-01).
pub(crate) fn say_err(text: &str) {
    use std::io::Write as _;
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(text.as_bytes());
    let _ = err.write_all(b"\n");
    let _ = err.flush();
}

/// Write text to standard output, ignoring failures like [`say_err`].
pub(crate) fn say_out(text: &str) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

/// An address reported by the cloud becomes an ssh destination: it must be a
/// plain IPv4 address, nothing an ssh client could read as an option, a user
/// or a pattern (audit E-09).
pub(crate) fn valid_external_address(value: &str) -> Result<String, String> {
    value
        .parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.to_string())
        .ok()
        .filter(|ip| ip == value)
        .ok_or_else(|| {
            "is not a plain IPv4 address; refusing to use it as an ssh destination".to_string()
        })
}

/// Everything an orchestrated command needs.
pub(crate) struct Ctx<'a> {
    pub(crate) cfg: &'a ControlConfig,
    pub(crate) gce: &'a dyn Gce,
    pub(crate) remote: &'a dyn Remote,
    pub(crate) clock: &'a dyn Clock,
    pub(crate) log: &'a dyn Reporter,
    /// Resolved SSH targets, valid for this command only.
    targets: std::cell::RefCell<std::collections::BTreeMap<String, Target>>,
}

impl<'a> Ctx<'a> {
    pub(crate) fn new(
        cfg: &'a ControlConfig,
        gce: &'a dyn Gce,
        remote: &'a dyn Remote,
        clock: &'a dyn Clock,
        log: &'a dyn Reporter,
    ) -> Self {
        Self {
            cfg,
            gce,
            remote,
            clock,
            log,
            targets: std::cell::RefCell::new(std::collections::BTreeMap::new()),
        }
    }
}

impl Ctx<'_> {
    pub(crate) fn node(&self, name: &str) -> Res<&NodeConfig> {
        self.cfg.node(name).ok_or_else(|| {
            Failure::Refused(format!(
                "unknown node {name:?} (known: {})",
                self.cfg.node_names().join(", ")
            ))
        })
    }

    fn target_for(&self, label: &str, instance: &str, ip: &str) -> Res<Target> {
        if let Some(found) = self.targets.borrow().get(label) {
            return Ok(found.clone());
        }
        let target = self.resolve_target(label, instance, ip)?;
        self.targets
            .borrow_mut()
            .insert(label.to_string(), target.clone());
        Ok(target)
    }

    fn resolve_target(&self, label: &str, instance: &str, ip: &str) -> Res<Target> {
        let host = match self.cfg.address_mode {
            AddressMode::Internal => ip.to_string(),
            // Nothing has been sent to the host yet, so a failure to find its
            // address is a refusal to start, not a failed operation.
            AddressMode::External => {
                let info = self.gce.describe(instance).map_err(|e| {
                    Failure::Refused(format!(
                        "cannot resolve the external address of {label}: {e}"
                    ))
                })?;
                let nat = info.nat_ip.ok_or_else(|| {
                    Failure::Refused(format!("{label} has no external address (is it running?)"))
                })?;
                valid_external_address(&nat).map_err(|why| {
                    Failure::Refused(format!("the external address of {label} {why}"))
                })?
            }
        };
        Ok(Target {
            label: label.to_string(),
            host,
            host_key_alias: instance.to_string(),
        })
    }

    pub(crate) fn node_target(&self, name: &str) -> Res<Target> {
        let node = self.node(name)?;
        self.target_for(&node.name, &node.instance, &node.ip)
    }

    pub(crate) fn witness_target(&self) -> Res<Target> {
        let w = &self.cfg.witness;
        self.target_for(&w.name, &w.instance, &w.ip)
    }

    pub(crate) fn call(
        &self,
        target: &Target,
        op: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Value, CallError> {
        remote::invoke(self.remote, target, op, args, timeout)
    }

    pub(crate) fn sleep(&self, duration: Duration) {
        self.clock.sleep(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::valid_external_address;

    #[test]
    fn only_a_plain_ipv4_address_becomes_an_ssh_destination() {
        assert_eq!(
            valid_external_address("203.0.113.7").unwrap(),
            "203.0.113.7"
        );
        for bad in [
            "-oProxyCommand=x",
            "203.0.113.7;id",
            "user@203.0.113.7",
            "203.0.113.7%eth0",
            "${HOME}",
            "::1",
            "203.0.113.007",
            "203.0.113.7 ",
            "",
            "*",
        ] {
            assert!(valid_external_address(bad).is_err(), "{bad:?}");
        }
    }
}
