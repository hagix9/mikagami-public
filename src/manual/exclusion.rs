//! Exclusion between the manual control plane and the production HA daemon
//! (agent side; audit EX-01 .. EX-04).
//!
//! The agent never *creates* the exclusion. Starting the HA units is stopped
//! by `systemctl mask` (done by `install.sh --manual-mode`, a deliberate
//! operator action); the agent only **verifies, positively,** that the
//! exclusion holds before it changes anything, and says why when it does not.
//!
//! A host passes only when *all* of these are proven:
//!
//! * every HA unit is `LoadState=masked` with a persistent mask
//!   (`UnitFileState=masked`) and is not running, or is `not-found` *and* the
//!   operator acknowledged that explicitly (`units.ha_absent_ack = true`);
//! * no HA unit has a pending systemd job;
//! * no process of this binary runs `daemon run` / `witness run`;
//! * an HA configuration file on the host does not name a service unit the
//!   agent may control, nor a VIP the manual plane manages, unless that
//!   overlap is acknowledged (`exclusion.ha_config_ack = true`).
//!
//! Anything that cannot be established (a failing `systemctl`, an unreadable
//! `/proc`, an unparsable job list) is *not* a pass.

/// A value that exists only when the exclusion from the HA daemon was proven a
/// moment ago. `HaReport::prove` is the one place that makes it (nothing outside
/// this module can name its field). The operations that change a service unit
/// or the ownership record take it as an argument, so a route that reaches one
/// of them has to pass the gate. What the type cannot know is a NEW mutating
/// primitive that is written without taking one: `tests/architecture.rs` pins
/// the list of the `SystemOps` methods, the callers of `prove` and of fence
/// admission, and bans the ways to forge a value of this type
/// (final R7, R-5/R-6, audit L-1).
pub(crate) struct ExclusiveProof {
    /// The kernel lock is owned by the proof, so holding the proof means the
    /// shared control lock is held. It is released when the operation (and
    /// the proof) ends.
    _lock: crate::control_lock::ControlLock,
}

impl ExclusiveProof {
    /// For tests that exercise an operation below the gate.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            _lock: crate::control_lock::ControlLock::for_test(),
        }
    }
}

use super::agent::{AgentConfig, ServiceState, SystemOps};
use super::fsutil;
use serde_json::{Value, json};
use std::path::Path;

/// Largest HA configuration file the agent reads.
const MAX_HA_CONFIG: u64 = 256 * 1024;
/// At most this many process / detail lines are reported.
const DETAIL_MAX: usize = 8;

// ---------------------------------------------------------------------------
// classification
// ---------------------------------------------------------------------------

/// What the agent knows about one HA unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnitClass {
    /// Persistently masked and not running: it cannot be started.
    Masked,
    /// No such unit, and the operator said that is intended.
    Absent,
    /// Loaded (startable) and not running: *not* a proof of exclusion.
    Loaded,
    /// No such unit and no acknowledgement: *not* a proof either.
    NotFound,
    /// Running, starting, stopping or reloading.
    Active,
    /// A start/stop job is queued for the unit.
    Job,
    /// The state could not be established.
    Unknown,
}

impl UnitClass {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Masked => "masked",
            Self::Absent => "absent",
            Self::Loaded => "loaded",
            Self::NotFound => "not-found",
            Self::Active => "active",
            Self::Job => "job",
            Self::Unknown => "unknown",
        }
    }
}

/// The verdict over all HA units, jobs, processes and the HA configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HaState {
    /// Every HA unit is masked (units acknowledged as absent may be mixed in).
    Masked,
    /// Every HA unit is acknowledged as absent.
    Absent,
    /// A unit is loaded and could be started: not proven.
    Unmasked,
    /// The HA configuration on this host names a resource the manual plane
    /// manages.
    Conflict,
    /// An HA daemon is running, starting, queued or was started by hand.
    Active,
    /// Something could not be established.
    Unknown,
}

impl HaState {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Masked => "masked",
            Self::Absent => "absent",
            Self::Unmasked => "unmasked",
            Self::Conflict => "conflict",
            Self::Active => "active",
            Self::Unknown => "unknown",
        }
    }

    /// The only states in which a change is allowed.
    pub(crate) fn is_proven(self) -> bool {
        matches!(self, Self::Masked | Self::Absent)
    }
}

/// `unit` + what was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnitFinding {
    pub(crate) unit: String,
    pub(crate) class: UnitClass,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigFinding {
    /// No HA configuration file on this host.
    NoFile,
    /// A file exists and shares nothing with the manual plane.
    Disjoint,
    /// It shares a resource, and the operator acknowledged that.
    Acknowledged(String),
    /// It shares a resource.
    Conflict(String),
    /// It exists but cannot be read or understood (and is not acknowledged).
    Unreadable(String),
}

/// Everything the agent found out about the HA daemon on this host.
#[derive(Debug, Clone)]
pub(crate) struct HaReport {
    units: Vec<UnitFinding>,
    processes: Result<Vec<String>, String>,
    jobs: Result<Vec<String>, String>,
    config: ConfigFinding,
}

/// Classify one unit from `systemctl show` and the job list.
pub(crate) fn classify_unit(
    unit: &str,
    shown: Result<ServiceState, String>,
    jobs: &Result<Vec<String>, String>,
    absent_ack: bool,
) -> UnitFinding {
    let finding = |class: UnitClass, detail: &str| UnitFinding {
        unit: unit.to_string(),
        class,
        detail: detail.to_string(),
    };
    let state = match shown {
        Ok(state) => state,
        Err(e) => {
            return finding(
                UnitClass::Unknown,
                &format!("cannot query: {}", e.chars().take(160).collect::<String>()),
            );
        }
    };
    if let Ok(list) = jobs
        && list.iter().any(|u| u == unit)
    {
        return finding(UnitClass::Job, "a systemd job is queued for the unit");
    }
    let running = matches!(
        state.active_state.as_str(),
        "active" | "activating" | "reloading" | "deactivating" | "refreshing"
    );
    let stopped = matches!(state.active_state.as_str(), "inactive" | "failed");
    match state.load_state.as_str() {
        "not-found" => {
            if absent_ack {
                finding(UnitClass::Absent, "not installed (acknowledged)")
            } else {
                finding(
                    UnitClass::NotFound,
                    "not installed and not acknowledged (units.ha_absent_ack)",
                )
            }
        }
        "masked" => {
            if running {
                finding(UnitClass::Active, "masked but still running")
            } else if !stopped {
                finding(UnitClass::Unknown, "masked, unexpected ActiveState")
            } else if state.unit_file_state == "masked" {
                finding(UnitClass::Masked, "masked")
            } else {
                // `mask --runtime` (or an unreadable UnitFileState) does not
                // survive a reboot, which would let the HA unit start.
                finding(
                    UnitClass::Loaded,
                    "masked only until reboot or mask kind not established",
                )
            }
        }
        "loaded" => {
            if running {
                finding(UnitClass::Active, "running")
            } else if stopped {
                finding(UnitClass::Loaded, "loaded and startable, not masked")
            } else {
                finding(UnitClass::Unknown, "unexpected ActiveState")
            }
        }
        other => finding(
            UnitClass::Unknown,
            &format!(
                "unexpected LoadState {:?}",
                other.chars().take(40).collect::<String>()
            ),
        ),
    }
}

impl HaReport {
    pub(crate) fn state(&self) -> HaState {
        let process_hit = matches!(&self.processes, Ok(list) if !list.is_empty());
        if process_hit
            || self
                .units
                .iter()
                .any(|u| matches!(u.class, UnitClass::Active | UnitClass::Job))
        {
            return HaState::Active;
        }
        if self.units.iter().any(|u| u.class == UnitClass::Unknown)
            || self.processes.is_err()
            || self.jobs.is_err()
            || matches!(self.config, ConfigFinding::Unreadable(_))
        {
            return HaState::Unknown;
        }
        if matches!(self.config, ConfigFinding::Conflict(_)) {
            return HaState::Conflict;
        }
        if self
            .units
            .iter()
            .any(|u| matches!(u.class, UnitClass::Loaded | UnitClass::NotFound))
        {
            return HaState::Unmasked;
        }
        if self.units.iter().all(|u| u.class == UnitClass::Absent) {
            HaState::Absent
        } else {
            HaState::Masked
        }
    }

    /// Short human lines for the ping answer and the refusal.
    pub(crate) fn details(&self) -> Vec<String> {
        let mut out = Vec::new();
        for u in &self.units {
            if !matches!(u.class, UnitClass::Masked | UnitClass::Absent) {
                out.push(format!("{}: {} ({})", u.unit, u.class.name(), u.detail));
            }
        }
        match &self.processes {
            Ok(list) => out.extend(list.iter().map(|p| format!("process: {p}"))),
            Err(e) => out.push(format!("process scan failed: {e}")),
        }
        if let Err(e) = &self.jobs {
            out.push(format!("job list failed: {e}"));
        }
        match &self.config {
            ConfigFinding::Conflict(m) | ConfigFinding::Unreadable(m) => {
                out.push(format!("HA configuration: {m}"));
            }
            ConfigFinding::NoFile | ConfigFinding::Disjoint | ConfigFinding::Acknowledged(_) => {}
        }
        out.truncate(DETAIL_MAX);
        out
    }

    pub(crate) fn to_json(&self) -> Value {
        let units: serde_json::Map<String, Value> = self
            .units
            .iter()
            .map(|u| (u.unit.clone(), json!(u.class.name())))
            .collect();
        let state = self.state();
        json!({
            "ha_daemon": state.name(),
            "ha_proven": state.is_proven(),
            "ha_units": units,
            "ha_detail": self.details(),
        })
    }

    /// The proof of the exclusion, or the reason why there is none. This is the
    /// only place that builds an [`ExclusiveProof`]: nothing outside this
    /// module can name its field, so safe code cannot make one. Code that uses
    /// `unsafe` to conjure a reference to this zero-sized type is outside what
    /// the compiler stops; the architecture tests ban that in the manual plane
    /// (v0.3, audit B LOW-2).
    pub(crate) fn prove(
        &self,
        lock: crate::control_lock::ControlLock,
    ) -> Result<ExclusiveProof, String> {
        match self.refusal() {
            None => Ok(ExclusiveProof { _lock: lock }),
            Some(reason) => Err(reason),
        }
    }

    /// `None` when the exclusion is proven; otherwise the reason, worded for
    /// what is actually wrong (audit EX-06: no misleading "HA is active").
    pub(crate) fn refusal(&self) -> Option<String> {
        let detail = self.details().join("; ");
        match self.state() {
            HaState::Masked | HaState::Absent => None,
            HaState::Active => Some(format!(
                "a Mikagami HA daemon is running, starting or queued on this host ({detail}); the \
                 manual control plane refuses to change anything (exclusive-mode rule)"
            )),
            HaState::Unmasked => Some(format!(
                "exclusion from the Mikagami HA daemon is not proven: {detail}. The HA units must \
                 be masked on a manual-mode host (`install.sh --manual-mode`); an inactive but \
                 startable unit is not a proof"
            )),
            HaState::Conflict => Some(format!(
                "this host carries an HA configuration for a resource the manual plane manages \
                 ({detail}); refusing unless `exclusion.ha_config_ack = true`"
            )),
            HaState::Unknown => Some(format!(
                "the state of the Mikagami HA daemon cannot be established ({detail}); refusing"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// the HA configuration file
// ---------------------------------------------------------------------------

fn bare_address(address: &str) -> &str {
    address.split('/').next().unwrap_or(address).trim()
}

/// Compare the HA daemon's configuration (when present) with what the manual
/// plane manages. Only the two keys that matter are read.
pub(crate) fn inspect_ha_config(cfg: &AgentConfig) -> ConfigFinding {
    let path: &Path = &cfg.ha_config;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ConfigFinding::NoFile,
        Err(e) => {
            return unreadable(cfg, format!("{} cannot be inspected: {e}", path.display()));
        }
    }
    let parsed = fsutil::read_regular_nofollow(path, MAX_HA_CONFIG)
        .map_err(|e| e.to_string())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()))
        .and_then(|text| toml::from_str::<toml::Value>(&text).map_err(|e| e.message().to_string()));
    let value = match parsed {
        Ok(value) => value,
        Err(e) => {
            return unreadable(
                cfg,
                format!("{} cannot be read or understood ({e})", path.display()),
            );
        }
    };
    let mut overlaps = Vec::new();
    if let Some(unit) = value
        .get("service")
        .and_then(|s| s.get("unit"))
        .and_then(toml::Value::as_str)
        && (cfg.allowed_units.iter().any(|u| u == unit) || cfg.chrony_unit == unit)
    {
        overlaps.push(format!(
            "its [service].unit {unit:?} is a unit the agent may control"
        ));
    }
    if let Some(address) = value
        .get("vip")
        .and_then(|s| s.get("address"))
        .and_then(toml::Value::as_str)
    {
        let bare = bare_address(address);
        if cfg.manual_vips.iter().any(|v| bare_address(v) == bare) {
            overlaps.push(format!(
                "its [vip].address {bare:?} is a VIP the manual plane moves"
            ));
        }
    }
    if overlaps.is_empty() {
        return ConfigFinding::Disjoint;
    }
    let message = format!("{}: {}", path.display(), overlaps.join("; "));
    if cfg.ha_config_ack {
        ConfigFinding::Acknowledged(message)
    } else {
        ConfigFinding::Conflict(message)
    }
}

fn unreadable(cfg: &AgentConfig, message: String) -> ConfigFinding {
    if cfg.ha_config_ack {
        ConfigFinding::Acknowledged(message)
    } else {
        ConfigFinding::Unreadable(message)
    }
}

// ---------------------------------------------------------------------------
// the report
// ---------------------------------------------------------------------------

/// Look at the host now.
pub(crate) fn inspect(cfg: &AgentConfig, sys: &dyn SystemOps) -> HaReport {
    let jobs = sys.pending_jobs();
    let units = cfg
        .ha_units
        .iter()
        .map(|unit| classify_unit(unit, sys.service_state(unit), &jobs, cfg.ha_absent_ack))
        .collect();
    HaReport {
        units,
        processes: sys.ha_processes(),
        jobs,
        config: inspect_ha_config(cfg),
    }
}

// ---------------------------------------------------------------------------
// systemctl list-jobs
// ---------------------------------------------------------------------------

const JOB_TYPES: &[&str] = &[
    "start",
    "stop",
    "restart",
    "reload",
    "reload-or-restart",
    "try-restart",
    "try-reload-or-restart",
    "reload-or-try-restart",
    "verify-active",
    "nop",
];

/// The unit types a `list-jobs` line may name (audit RA-A-02). A job is queued
/// for any unit, not only for services (`session-3.scope`, `user.slice`,
/// `home.mount`, `apt-daily.timer`, `systemd-fsck@dev-sda1.service` ...).
const UNIT_TYPES: &[&str] = &[
    "service",
    "socket",
    "target",
    "device",
    "mount",
    "automount",
    "swap",
    "path",
    "timer",
    "slice",
    "scope",
    "snapshot",
];

/// `name.type` as `systemctl list-jobs --full` prints it: a non-empty name of
/// the characters systemd allows in a unit name (escapes such as `\x2d`
/// included) and one of [`UNIT_TYPES`]. Whether the unit is an HA unit is
/// decided elsewhere, by the exact name; this only decides that the token has
/// the shape of a unit.
fn is_job_unit_token(token: &str) -> bool {
    let Some((stem, kind)) = token.rsplit_once('.') else {
        return false;
    };
    UNIT_TYPES.contains(&kind)
        && !stem.is_empty()
        && token.len() <= 256
        && !stem.starts_with('-')
        && stem.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b':' | b'\\')
        })
}

/// Unit names that have a queued job, from `systemctl list-jobs --no-legend
/// --full`. The exact output on a real host is not verified (NV-1), so the
/// parser is strict about the *shape*: an empty output or `No jobs running.`
/// is "no jobs"; a line of the shape `<id> <unit> <type> <state>` names one
/// unit; anything else is an error, which the caller treats as "not proven".
/// The unit may be of any type (audit RA-A-02: a queued job of a scope, a
/// slice or a mount used to make the whole answer "not understood", and a
/// move that had already changed something stopped UNKNOWN for no reason);
/// whether it is an HA unit is still decided by the exact name.
pub(crate) fn parse_list_jobs(text: &str) -> Result<Vec<String>, String> {
    let mut units = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line == "No jobs running." {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let [id, unit, kind, ..] = tokens.as_slice() else {
            return Err("a list-jobs line is not understood".to_string());
        };
        if !id.bytes().all(|b| b.is_ascii_digit())
            || id.is_empty()
            || !is_job_unit_token(unit)
            || !JOB_TYPES.contains(kind)
        {
            return Err("a list-jobs line is not understood".to_string());
        }
        units.push((*unit).to_string());
    }
    Ok(units)
}

// ---------------------------------------------------------------------------
// /proc scan
// ---------------------------------------------------------------------------

fn base_name(arg: &[u8]) -> &[u8] {
    arg.rsplit(|b| *b == b'/').next().unwrap_or(arg)
}

/// `true` when `args` (a NUL-split command line) starts the HA daemon or the
/// Witness: a `daemon` or `witness` word followed later by `run`.
pub(crate) fn is_ha_command_line(args: &[&[u8]]) -> bool {
    let Some((_, rest)) = args.split_first() else {
        return false;
    };
    let Some(at) = rest
        .iter()
        .position(|a| *a == b"daemon" || *a == b"witness")
    else {
        return false;
    };
    rest[at + 1..].iter().any(|a| *a == b"run")
}

fn exe_of(proc_dir: &Path) -> Option<std::path::PathBuf> {
    let link = std::fs::read_link(proc_dir.join("exe")).ok()?;
    let text = link.to_string_lossy();
    Some(std::path::PathBuf::from(
        text.strip_suffix(" (deleted)").unwrap_or(&text).to_string(),
    ))
}

/// Processes under `proc_root` that run this binary as an HA daemon or
/// Witness. A process counts as "this binary" when its executable is the
/// agent's own, or when it was started under the name `mikagami` / `mkg`.
/// Unreadable entries that vanished during the scan are skipped; a
/// `proc_root` that cannot be listed is an error.
pub(crate) fn scan_proc(proc_root: &Path, own_pid: u32) -> Result<Vec<String>, String> {
    scan_proc_with(proc_root, own_pid, &|dir| {
        std::fs::read(dir.join("cmdline"))
    })
}

/// `true` for the errors that mean "this process is gone": it ended between
/// the listing of `/proc` and the read of its command line. `ENOENT` is the
/// usual form, `ESRCH` ("No such process") the other one the kernel uses for
/// a task that exits during the read (audit RA-A-03). Everything else
/// (`EACCES`, `EIO`, ...) is a real failure of the scan and stays an error.
fn process_vanished(error: &std::io::Error) -> bool {
    /// `ESRCH` is 3 on Linux and on the BSDs; named here so that this file
    /// needs no entry in the allow list of `libc` items.
    const ESRCH: i32 = 3;
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(ESRCH)
}

/// [`scan_proc`] with the way a command line is read supplied (tests make a
/// process vanish or an entry unreadable).
fn scan_proc_with(
    proc_root: &Path,
    own_pid: u32,
    read_cmdline: &dyn Fn(&Path) -> std::io::Result<Vec<u8>>,
) -> Result<Vec<String>, String> {
    let own_exe =
        exe_of(&proc_root.join("self")).or_else(|| exe_of(&proc_root.join(own_pid.to_string())));
    let entries = std::fs::read_dir(proc_root).map_err(|e| format!("cannot list /proc: {e}"))?;
    let mut hits = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot list /proc: {e}"))?;
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        let dir = entry.path();
        let raw = match read_cmdline(&dir) {
            Ok(raw) => raw,
            Err(e) if process_vanished(&e) => continue,
            Err(e) => return Err(format!("cannot read the command line of pid {pid}: {e}")),
        };
        if raw.is_empty() {
            continue;
        }
        let args: Vec<&[u8]> = raw.split(|b| *b == 0).filter(|a| !a.is_empty()).collect();
        let named = args
            .first()
            .is_some_and(|a0| matches!(base_name(a0), b"mikagami" | b"mkg"));
        let same_binary = match (&own_exe, exe_of(&dir)) {
            (Some(own), Some(other)) => *own == other,
            _ => false,
        };
        if (named || same_binary) && is_ha_command_line(&args) {
            let shown: String = args
                .iter()
                .take(4)
                .map(|a| {
                    String::from_utf8_lossy(a)
                        .chars()
                        .take(40)
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join(" ");
            hits.push(format!("pid {pid}: {shown}"));
        }
    }
    hits.sort();
    hits.truncate(DETAIL_MAX);
    Ok(hits)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual::fsutil::tests::temp_dir;
    use crate::manual::testkit::{FakeSystem, agent_env_custom};

    fn state(load: &str, active: &str, file: &str) -> Result<ServiceState, String> {
        Ok(ServiceState {
            load_state: load.to_string(),
            active_state: active.to_string(),
            sub_state: "x".to_string(),
            unit_file_state: file.to_string(),
            ..ServiceState::default()
        })
    }

    fn class(shown: Result<ServiceState, String>, ack: bool) -> UnitClass {
        classify_unit("mikagami.service", shown, &Ok(vec![]), ack).class
    }

    #[test]
    fn a_unit_is_proven_only_by_a_persistent_mask_or_an_acknowledged_absence() {
        assert_eq!(
            class(state("masked", "inactive", "masked"), false),
            UnitClass::Masked
        );
        assert_eq!(
            class(state("masked", "failed", "masked"), false),
            UnitClass::Masked
        );
        assert_eq!(
            class(state("not-found", "inactive", ""), true),
            UnitClass::Absent
        );
        // Not proofs.
        assert_eq!(
            class(state("not-found", "inactive", ""), false),
            UnitClass::NotFound
        );
        assert_eq!(
            class(state("loaded", "inactive", "enabled"), true),
            UnitClass::Loaded
        );
        assert_eq!(
            class(state("loaded", "failed", "disabled"), true),
            UnitClass::Loaded
        );
        assert_eq!(
            class(state("masked", "inactive", "masked-runtime"), false),
            UnitClass::Loaded,
            "a runtime mask does not survive a reboot"
        );
        assert_eq!(
            class(state("masked", "inactive", ""), false),
            UnitClass::Loaded
        );
        // Running in any form.
        for active in ["active", "activating", "reloading", "deactivating"] {
            assert_eq!(
                class(state("loaded", active, "enabled"), false),
                UnitClass::Active,
                "{active}"
            );
            assert_eq!(
                class(state("masked", active, "masked"), false),
                UnitClass::Active,
                "{active}"
            );
        }
        // Not understood.
        assert_eq!(
            class(state("loaded", "weird", "enabled"), false),
            UnitClass::Unknown
        );
        assert_eq!(
            class(state("error", "inactive", ""), false),
            UnitClass::Unknown
        );
        assert_eq!(
            class(state("masked", "weird", "masked"), false),
            UnitClass::Unknown
        );
        assert_eq!(class(Err("boom".to_string()), true), UnitClass::Unknown);
    }

    #[test]
    fn a_queued_job_beats_every_other_finding() {
        let jobs = Ok(vec!["mikagami.service".to_string()]);
        for shown in [
            state("masked", "inactive", "masked"),
            state("loaded", "inactive", "enabled"),
            state("not-found", "inactive", ""),
        ] {
            assert_eq!(
                classify_unit("mikagami.service", shown, &jobs, true).class,
                UnitClass::Job
            );
        }
        assert_eq!(
            classify_unit(
                "mikagami-witness.service",
                state("masked", "inactive", "masked"),
                &jobs,
                false
            )
            .class,
            UnitClass::Masked,
            "a job of another unit says nothing about this one"
        );
    }

    #[test]
    fn list_jobs_is_parsed_strictly() {
        assert_eq!(parse_list_jobs("").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_list_jobs("No jobs running.\n").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_list_jobs("  42 mikagami.service start running\n 43 ssh.service stop waiting\n")
                .unwrap(),
            ["mikagami.service", "ssh.service"]
        );
        // Round R6 (RA-A-02): a queued job of any unit type is understood; the
        // HA decision stays with the exact name.
        assert_eq!(
            parse_list_jobs(
                "  3 session-4.scope stop running\n 4 user.slice start waiting\n\
                 5 home.mount start running\n 6 apt-daily.timer start waiting\n\
                 7 systemd-fsck@dev-sda1.service start running\n\
                 8 dev-disk-by\\x2duuid-1234.device start running\n\
                 9 mikagami.service start running\n"
            )
            .unwrap(),
            [
                "session-4.scope",
                "user.slice",
                "home.mount",
                "apt-daily.timer",
                "systemd-fsck@dev-sda1.service",
                "dev-disk-by\\x2duuid-1234.device",
                "mikagami.service"
            ]
        );
        for bad in [
            "garbage",
            "x mikagami.service start running",
            // Still not a unit: no known type, empty stem, an option-like
            // stem, characters a unit name cannot hold.
            "42 mikagami.unknowntype start running",
            "42 .service start running",
            "42 -x.service start running",
            "42 foo/bar.service start running",
            "42 foo$bar.scope start running",
            "42 user.slice frobnicate running",
            "-1 user.slice start running",
            "42 mikagami.service",
            "42 mikagami.service frobnicate running",
            "42 mikagami… start running",
            "42 nothing-a-unit start running",
            "JOB UNIT TYPE STATE",
        ] {
            assert!(parse_list_jobs(bad).is_err(), "{bad:?}");
        }
    }

    fn report(sys: &FakeSystem, tweak: impl Fn(&mut AgentConfig)) -> HaReport {
        let (env, _dir) =
            agent_env_custom("excl-report", "node-a", sys.clone(), Box::new(|| 0), &tweak);
        inspect(&env.cfg, &*env.sys)
    }

    #[test]
    fn the_verdict_follows_the_worst_finding() {
        let sys = FakeSystem::default();
        assert_eq!(report(&sys, |_| {}).state(), HaState::Masked);
        // Failing probes are never a pass.
        sys.fail_jobs(true);
        assert_eq!(report(&sys, |_| {}).state(), HaState::Unknown);
        sys.fail_jobs(false);
        sys.fail_processes(true);
        assert_eq!(report(&sys, |_| {}).state(), HaState::Unknown);
        sys.fail_processes(false);
        sys.fail_queries(true);
        assert_eq!(report(&sys, |_| {}).state(), HaState::Unknown);
        sys.fail_queries(false);
        // Unmasked, then running: running wins.
        sys.unmask("mikagami.service");
        assert_eq!(report(&sys, |_| {}).state(), HaState::Unmasked);
        sys.set_jobs(&["mikagami.service"]);
        assert_eq!(report(&sys, |_| {}).state(), HaState::Active);
        sys.set_jobs(&[]);
        sys.set_service("mikagami.service", "activating");
        assert_eq!(report(&sys, |_| {}).state(), HaState::Active);
        // Absent units: only with the acknowledgement.
        let gone = FakeSystem::default();
        gone.remove_unit("mikagami.service");
        gone.remove_unit("mikagami-witness.service");
        assert_eq!(report(&gone, |_| {}).state(), HaState::Unmasked);
        assert_eq!(
            report(&gone, |c| c.ha_absent_ack = true).state(),
            HaState::Absent
        );
        gone.mask("mikagami.service");
        assert_eq!(
            report(&gone, |c| c.ha_absent_ack = true).state(),
            HaState::Masked
        );
        // A hand-started daemon.
        let hand = FakeSystem::default();
        hand.set_ha_processes(&["pid 7: mikagami daemon run"]);
        let r = report(&hand, |_| {});
        assert_eq!(r.state(), HaState::Active);
        assert!(r.refusal().unwrap().contains("running"));
    }

    #[test]
    fn the_refusal_names_the_real_cause() {
        let sys = FakeSystem::default();
        assert!(report(&sys, |_| {}).refusal().is_none());
        sys.unmask("mikagami.service");
        let message = report(&sys, |_| {}).refusal().unwrap();
        assert!(
            message.contains("not proven") && message.contains("--manual-mode"),
            "{message}"
        );
        assert!(
            !message.contains("is active"),
            "an inactive unit must not be reported as active: {message}"
        );
        sys.fail_queries(true);
        let message = report(&sys, |_| {}).refusal().unwrap();
        assert!(message.contains("cannot be established"), "{message}");
    }

    fn write_ha_config(dir: &Path, text: &str) -> std::path::PathBuf {
        let path = dir.join("ha.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn an_ha_configuration_for_the_same_service_or_vip_is_refused_unless_acknowledged() {
        let dir = temp_dir("excl-haconf");
        let sys = FakeSystem::default();
        let with = |text: &str, ack: bool| {
            let path = write_ha_config(&dir, text);
            report(&sys, move |c| {
                c.ha_config = path.clone();
                c.ha_config_ack = ack;
            })
        };
        // No file at all.
        assert_eq!(
            report(&sys, |c| c.ha_config = dir.join("absent.toml")).state(),
            HaState::Masked
        );
        // A file about other resources.
        let other = "[service]\nunit = \"nginx.service\"\n[vip]\naddress = \"10.9.9.9/32\"\n";
        assert_eq!(with(other, false).state(), HaState::Masked);
        // Same unit, same VIP (with and without a prefix length).
        for text in [
            "[service]\nunit = \"mkg-demo.service\"\n",
            "[service]\nunit = \"chrony.service\"\n",
            "[vip]\naddress = \"10.0.0.130/32\"\n",
            "[vip]\naddress = \"10.0.0.130\"\n",
        ] {
            let r = with(text, false);
            assert_eq!(r.state(), HaState::Conflict, "{text}");
            assert!(r.refusal().unwrap().contains("ha_config_ack"));
            assert_eq!(
                with(text, true).state(),
                HaState::Masked,
                "acknowledged: {text}"
            );
        }
        // Damaged: not understood is not a pass, unless acknowledged.
        assert_eq!(with("this is = not [toml", false).state(), HaState::Unknown);
        assert_eq!(with("this is = not [toml", true).state(), HaState::Masked);
        let huge = "#".repeat(300 * 1024);
        assert_eq!(with(&huge, false).state(), HaState::Unknown);
        // A symlink in place of the file is not followed.
        let target = write_ha_config(&dir, "[vip]\naddress = \"10.0.0.130\"\n");
        let link = dir.join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let r = report(&sys, |c| c.ha_config = link.clone());
        assert_eq!(r.state(), HaState::Unknown);
    }

    // ---- /proc ---------------------------------------------------------

    fn fake_proc(dir: &Path, pid: u32, args: &[&str], exe: Option<&str>) {
        let p = dir.join(pid.to_string());
        std::fs::create_dir_all(&p).unwrap();
        let mut raw = Vec::new();
        for a in args {
            raw.extend_from_slice(a.as_bytes());
            raw.push(0);
        }
        std::fs::write(p.join("cmdline"), raw).unwrap();
        if let Some(exe) = exe {
            std::os::unix::fs::symlink(exe, p.join("exe")).unwrap();
        }
    }

    #[test]
    fn a_hand_started_daemon_or_witness_is_found_in_proc() {
        let dir = temp_dir("excl-proc");
        fake_proc(
            &dir,
            10,
            &["/usr/local/bin/mikagami", "daemon", "run", "--config", "/x"],
            None,
        );
        fake_proc(&dir, 11, &["mkg", "witness", "run", "--config", "/y"], None);
        fake_proc(&dir, 12, &["/usr/local/bin/mikagami", "agent"], None);
        fake_proc(
            &dir,
            13,
            &["/usr/local/bin/mikagami", "witness", "init"],
            None,
        );
        fake_proc(&dir, 14, &["vim", "daemon", "run"], None);
        // Renamed binary, found by its executable.
        fake_proc(
            &dir,
            15,
            &["innocent", "daemon", "run"],
            Some("/opt/own/mikagami (deleted)"),
        );
        // Global option before the subcommand.
        fake_proc(&dir, 16, &["mikagami", "--quiet", "daemon", "run"], None);
        // Kernel thread / empty command line, and a non-numeric entry.
        fake_proc(&dir, 17, &[], None);
        std::fs::create_dir_all(dir.join("sys")).unwrap();
        // A process that vanished: directory without cmdline.
        std::fs::create_dir_all(dir.join("18")).unwrap();
        let own_dir = dir.join("999");
        std::fs::create_dir_all(&own_dir).unwrap();
        std::os::unix::fs::symlink("/opt/own/mikagami", own_dir.join("exe")).unwrap();
        let hits = scan_proc(&dir, 999).unwrap();
        let pids: Vec<&str> = hits.iter().map(|h| h.split(':').next().unwrap()).collect();
        assert_eq!(pids, ["pid 10", "pid 11", "pid 15", "pid 16"], "{hits:?}");
        // The agent's own pid is never a hit.
        fake_proc(&dir, 999, &["mikagami", "daemon", "run"], None);
        assert_eq!(scan_proc(&dir, 999).unwrap().len(), 4);
        // An unlistable /proc is an error, never an empty answer.
        assert!(scan_proc(&dir.join("missing"), 1).is_err());
    }

    #[test]
    fn ra_a03_a_process_that_exits_during_the_scan_is_skipped_but_a_real_failure_is_not() {
        let dir = temp_dir("excl-proc-vanish");
        fake_proc(&dir, 10, &["mikagami", "daemon", "run"], None);
        fake_proc(&dir, 20, &["mikagami", "agent"], None);
        fake_proc(&dir, 30, &["mikagami", "witness", "run"], None);
        let read_with = |failing: i32, kind: Option<std::io::ErrorKind>| {
            move |proc_dir: &Path| -> std::io::Result<Vec<u8>> {
                if proc_dir.ends_with("20") {
                    return Err(match kind {
                        Some(k) => std::io::Error::from(k),
                        None => std::io::Error::from_raw_os_error(failing),
                    });
                }
                std::fs::read(proc_dir.join("cmdline"))
            }
        };
        // ESRCH (3): the process is gone; the others are still found.
        let hits = scan_proc_with(&dir, 999, &read_with(3, None)).unwrap();
        let pids: Vec<&str> = hits.iter().map(|h| h.split(':').next().unwrap()).collect();
        assert_eq!(pids, ["pid 10", "pid 30"]);
        // ENOENT (2) keeps working.
        assert_eq!(
            scan_proc_with(&dir, 999, &read_with(2, None))
                .unwrap()
                .len(),
            2
        );
        // Real failures stay errors (fail closed): EACCES (13), EIO (5), and a
        // permission-denied kind, so a scan that cannot see a process is not a
        // quiet answer.
        for failing in [13, 5, 1, 4] {
            let r = scan_proc_with(&dir, 999, &read_with(failing, None));
            assert!(
                matches!(&r, Err(m) if m.contains("pid 20")),
                "errno {failing}: {r:?}"
            );
        }
        let r = scan_proc_with(
            &dir,
            999,
            &read_with(0, Some(std::io::ErrorKind::PermissionDenied)),
        );
        assert!(r.is_err());
        assert!(process_vanished(&std::io::Error::from_raw_os_error(3)));
        assert!(!process_vanished(&std::io::Error::from_raw_os_error(13)));
    }

    #[test]
    fn command_lines_are_matched_conservatively() {
        let args =
            |v: &[&'static str]| -> Vec<&'static [u8]> { v.iter().map(|s| s.as_bytes()).collect() };
        assert!(is_ha_command_line(&args(&["m", "daemon", "run"])));
        assert!(is_ha_command_line(&args(&[
            "m", "witness", "run", "--config", "c"
        ])));
        assert!(is_ha_command_line(&args(&[
            "m", "-v", "daemon", "--x", "run"
        ])));
        assert!(!is_ha_command_line(&args(&["m", "agent"])));
        assert!(!is_ha_command_line(&args(&["m", "run", "daemon"])));
        assert!(!is_ha_command_line(&args(&["m", "witness", "init"])));
        assert!(!is_ha_command_line(&args(&[])));
        assert!(!is_ha_command_line(&args(&["daemon", "run"]))); // argv[0] only
    }
}
