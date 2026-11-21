//! Controller-side chrony configuration management.
//!
//! `apply` sequence: observe → validate → diff → backup → stage → publish
//! (compare-and-swap) → restart → verify (service active, live hash equals
//! the requested hash, `chronyc tracking` answers, the process really
//! restarted) → clean up. Any failure after the publish triggers a *verified*
//! rollback; any answer lost in transit is resolved by re-reading the remote
//! hash, never by assuming. A publish whose answer was lost is first
//! **fenced** (the staged file is removed under the node's lock) so that a
//! late-running agent cannot publish behind the controller's back (audit
//! D-01). A state that cannot be established is reported as UNKNOWN.
//!
//! What a successful apply proves: the live file is the requested one, the
//! configured unit is active and was restarted (its process or start time
//! changed), and `chronyc tracking` answers. It does **not** prove that the
//! clock is synchronised (audit D-05): chronyd needs time to select a source.

use super::chrony_agent::{backup_id_ok, stage_id_ok};
use super::fsutil;
use super::proto::{MAX_CONTENT, op};
use super::remote::{CallError, LONG, SHORT, Target};
use super::vip::{Reach, ping, svc_control, svc_status};
use super::{Ctx, Failure, Res};
use serde::Serialize;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

const VERIFY_TIMEOUT_MS: u64 = 45_000;
const VERIFY_POLL: Duration = Duration::from_secs(2);
const REREAD_ATTEMPTS: u32 = 4;
const MAX_DIFF_LINES: usize = 4000;

// ---------------------------------------------------------------------------
// local input
// ---------------------------------------------------------------------------

/// Read the operator's candidate file: a regular file (no symlink), bounded,
/// valid UTF-8, without NUL.
pub(crate) fn read_candidate(path: &std::path::Path) -> Res<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Failure::Refused(format!("cannot open {}: {e}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|e| Failure::Refused(format!("cannot inspect {}: {e}", path.display())))?;
    if !metadata.is_file() {
        return Err(Failure::Refused(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_CONTENT as u64 {
        return Err(Failure::Refused(format!(
            "{} is larger than {MAX_CONTENT} bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(file, MAX_CONTENT as u64 + 1),
        &mut bytes,
    )
    .map_err(|e| Failure::Refused(format!("cannot read {}: {e}", path.display())))?;
    if bytes.len() > MAX_CONTENT {
        return Err(Failure::Refused(format!(
            "{} grew while reading",
            path.display()
        )));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| Failure::Refused(format!("{} is not valid UTF-8", path.display())))?;
    if text.contains('\0') {
        return Err(Failure::Refused(format!(
            "{} contains a NUL byte",
            path.display()
        )));
    }
    Ok(text)
}

fn failure_for(context: &str, error: CallError) -> Failure {
    match error {
        CallError::Refused(m) => Failure::Refused(format!("{context}: {m}")),
        other => Failure::Failed(format!("{context}: {other}")),
    }
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ShowReport {
    pub(crate) node: String,
    pub(crate) conf_path: String,
    pub(crate) conf_sha256: Option<String>,
    pub(crate) conf_trusted: bool,
    /// The agent observes the unit this controller restarts (audit D-04).
    pub(crate) unit_matches: bool,
    pub(crate) unit_active: Option<bool>,
    pub(crate) unit_state: Option<String>,
    pub(crate) tracking_ok: bool,
    pub(crate) tracking: Option<String>,
    pub(crate) problems: Vec<String>,
}

struct RemoteState {
    /// The unit the agent restarts and observes (its `chrony.unit`).
    unit_name: Option<String>,
    sha: Option<String>,
    trusted: bool,
    active: Option<bool>,
    unit_state: Option<String>,
    tracking_ok: bool,
    tracking: Option<String>,
    conf_path: String,
    problems: Vec<String>,
    /// Versions written by somebody else that the agent keeps (`.mkg-displaced-*`):
    /// their number and the first names (final R7, R-3).
    displaced_count: u64,
    /// The agent sent the field but it cannot be relied on (audit L-4).
    displaced_unknown: bool,
    displaced_names: Vec<String>,
}

fn remote_state(ctx: &Ctx<'_>, target: &Target) -> Result<RemoteState, CallError> {
    let data = ctx.call(target, op::CHRONY_STATE, json!({}), SHORT)?;
    let mut problems = Vec::new();
    let conf = &data["conf"];
    let trusted = conf["trusted"].as_bool().unwrap_or(false);
    if let Some(p) = conf["problem"].as_str() {
        problems.push(format!("configuration: {p}"));
    }
    let unit = &data["unit"];
    if let Some(p) = unit["problem"].as_str() {
        problems.push(format!("unit: {p}"));
    }
    let tracking = &data["tracking"];
    let tracking_ok = tracking["ok"].as_bool().unwrap_or(false);
    if let Some(p) = tracking["problem"].as_str() {
        problems.push(format!("tracking: {p}"));
    }
    // A hash that is not a SHA-256 is not a hash (it is also never sliced).
    let sha = conf["sha256"]
        .as_str()
        .filter(|s| fsutil::is_sha256_hex(s))
        .map(str::to_string);
    if conf["sha256"].is_string() && sha.is_none() {
        problems.push("configuration: the agent returned a malformed hash".to_string());
    }
    // An agent without the field has no kept versions to report (an older
    // agent). A field that is there but unreadable, or a count that is not a
    // number, is NOT "none": nobody can say, so the next apply refuses (audit L-4).
    let displaced = &data["displaced"];
    // An agent that sends no field at all is older than this controller: it
    // neither protects a displaced version nor reports one, so nothing can be
    // said about kept versions and the next apply refuses (both sides have to
    // be upgraded together; audit A2 LOW-2).
    // (A field that is missing has no numeric `count`, so the last clause
    // covers the older agent as well as a count that is not a number.)
    let displaced_unknown =
        displaced["readable"].as_bool() == Some(false) || displaced["count"].as_u64().is_none();
    if displaced_unknown {
        problems.push(
            "the agent cannot say whether kept versions of a configuration exist in the chrony \
             directory (it is older than this controller, the listing is unreadable or the \
             answer is not understood)"
                .to_string(),
        );
    }
    let displaced_count = displaced["count"].as_u64().unwrap_or(0);
    let displaced_names: Vec<String> = data["displaced"]["names"]
        .as_array()
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .take(8)
                .map(clean_text)
                .collect()
        })
        .unwrap_or_default();
    if displaced_count > 0 {
        problems.push(displaced_text(displaced_count, &displaced_names));
    }
    Ok(RemoteState {
        unit_name: unit["name"].as_str().map(str::to_string),
        sha,
        trusted,
        active: unit["active"].as_bool(),
        unit_state: unit["active_state"].as_str().map(str::to_string),
        tracking_ok,
        tracking: tracking["text"].as_str().map(str::to_string),
        conf_path: data["conf_path"].as_str().unwrap_or("").to_string(),
        problems,
        displaced_count,
        displaced_unknown,
        displaced_names,
    })
}

fn displaced_text(count: u64, names: &[String]) -> String {
    format!(
        "{count} kept version(s) of a configuration that somebody else wrote (or a name left by \
         an interrupted replacement) are in the chrony directory ({}); look at them and delete \
         them yourself when they are no longer needed (QUICKSTART section 11)",
        names.join(", ")
    )
}

/// The unit this controller restarts must be the unit the agent observes and
/// reports on (audit D-04); otherwise a restart and its verification would
/// concern different services.
fn unit_mismatch(ctx: &Ctx<'_>, node: &str, state: &RemoteState) -> Option<String> {
    match state.unit_name.as_deref() {
        Some(name) if name == ctx.cfg.chrony_unit => None,
        Some(name) => Some(format!(
            "{node}: the controller restarts {:?} but the agent's chrony.unit is {:?}; fix \
             cluster.chrony_unit or the agent configuration",
            ctx.cfg.chrony_unit,
            clean_text(name)
        )),
        None => Some(format!(
            "{node}: the agent did not report which unit it observes (chrony.unit); it is \
             older than this controller or damaged"
        )),
    }
}

/// Text from a node, shortened by characters (never bytes) and with control
/// and bidirectional characters made visible.
fn clean_text(text: &str) -> String {
    super::clean_for_terminal(&text.chars().take(120).collect::<String>())
}

/// Like [`clean_text`] for the one agent message that carries a file name the
/// operator needs in full (audit RA-D-01).
fn clean_long_text(text: &str) -> String {
    super::clean_for_terminal(&text.chars().take(400).collect::<String>())
}

pub(crate) fn show(ctx: &Ctx<'_>, node: &str) -> Res<ShowReport> {
    let node = ctx.node(node)?.clone();
    let target = ctx.node_target(&node.name)?;
    let mut state = remote_state(ctx, &target)
        .map_err(|e| failure_for(&format!("cannot read chrony state of {}", node.name), e))?;
    if let Some(problem) = unit_mismatch(ctx, &node.name, &state) {
        state.problems.push(problem);
    }
    Ok(ShowReport {
        node: node.name,
        conf_path: state.conf_path,
        conf_sha256: state.sha,
        conf_trusted: state.trusted,
        unit_matches: state.unit_name.as_deref() == Some(ctx.cfg.chrony_unit.as_str()),
        unit_active: state.active,
        unit_state: state.unit_state,
        tracking_ok: state.tracking_ok,
        tracking: state.tracking,
        problems: state.problems,
    })
}

// ---------------------------------------------------------------------------
// validate / diff
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ValidateReport {
    pub(crate) node: String,
    pub(crate) valid: bool,
    pub(crate) sha256: String,
    pub(crate) message: Option<String>,
}

fn validate_remote(ctx: &Ctx<'_>, target: &Target, content: &str) -> Res<(bool, Option<String>)> {
    let data = ctx
        .call(
            target,
            op::CHRONY_VALIDATE,
            json!({"content": content}),
            SHORT,
        )
        .map_err(|e| failure_for("validation could not run", e))?;
    let valid = data["valid"]
        .as_bool()
        .ok_or_else(|| Failure::Failed("validation answer not understood".into()))?;
    Ok((valid, data["message"].as_str().map(str::to_string)))
}

pub(crate) fn validate(ctx: &Ctx<'_>, node: &str, content: &str) -> Res<ValidateReport> {
    let node = ctx.node(node)?.clone();
    let target = ctx.node_target(&node.name)?;
    let (valid, message) = validate_remote(ctx, &target, content)?;
    Ok(ValidateReport {
        node: node.name,
        valid,
        sha256: fsutil::sha256_hex(content.as_bytes()),
        message,
    })
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiffReport {
    pub(crate) node: String,
    pub(crate) identical: bool,
    pub(crate) remote_sha256: String,
    pub(crate) local_sha256: String,
    pub(crate) unified: String,
}

fn read_remote(ctx: &Ctx<'_>, target: &Target) -> Res<(String, String)> {
    let data = ctx
        .call(target, op::CHRONY_READ, json!({}), SHORT)
        .map_err(|e| failure_for("cannot read the live configuration", e))?;
    let content = data["content"].as_str().map(str::to_string);
    let sha = data["sha256"].as_str().map(str::to_string);
    match (content, sha) {
        (Some(c), Some(s)) if fsutil::sha256_hex(c.as_bytes()) == s => Ok((c, s)),
        _ => Err(Failure::Failed(
            "the live configuration did not arrive intact".into(),
        )),
    }
}

pub(crate) fn diff(ctx: &Ctx<'_>, node: &str, local: &str) -> Res<DiffReport> {
    let node = ctx.node(node)?.clone();
    let target = ctx.node_target(&node.name)?;
    let (remote, remote_sha) = read_remote(ctx, &target)?;
    let local_sha = fsutil::sha256_hex(local.as_bytes());
    let identical = remote_sha == local_sha;
    let unified = if identical {
        String::new()
    } else {
        unified_diff(
            &format!("{}:{}", node.name, "chrony.conf"),
            "candidate",
            &remote,
            local,
        )
    };
    Ok(DiffReport {
        node: node.name,
        identical,
        remote_sha256: remote_sha,
        local_sha256: local_sha,
        unified,
    })
}

/// A compact unified diff based on the longest common subsequence of lines.
pub(crate) fn unified_diff(from_name: &str, to_name: &str, from: &str, to: &str) -> String {
    let a: Vec<&str> = from.split_inclusive('\n').collect();
    let b: Vec<&str> = to.split_inclusive('\n').collect();
    if a.len() > MAX_DIFF_LINES || b.len() > MAX_DIFF_LINES {
        return format!(
            "--- {from_name}\n+++ {to_name}\n(files differ; {} vs {} lines is too large to diff)\n",
            a.len(),
            b.len()
        );
    }
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = format!("--- {from_name}\n+++ {to_name}\n");
    let (mut i, mut j) = (0, 0);
    let mut lines: Vec<String> = Vec::new();
    let line = |tag: char, text: &str| {
        if text.ends_with('\n') {
            format!("{tag}{text}")
        } else {
            format!("{tag}{text}\n\\ No newline at end of file\n")
        }
    };
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            lines.push(line(' ', a[i]));
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            lines.push(line('+', b[j]));
            j += 1;
        } else {
            lines.push(line('-', a[i]));
            i += 1;
        }
    }
    out.push_str(&format!("@@ -1,{n} +1,{m} @@\n"));
    for l in lines {
        out.push_str(&l);
    }
    out
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ApplyReport {
    pub(crate) node: String,
    pub(crate) changed: bool,
    pub(crate) dry_run: bool,
    pub(crate) old_sha256: String,
    pub(crate) new_sha256: String,
    pub(crate) backup_id: Option<String>,
    pub(crate) tracking: Option<String>,
    pub(crate) diff: String,
}

#[derive(Debug)]
enum RestoreOutcome {
    Verified,
    Failed(String),
    Unknown(String),
    /// The previous file is back; the rollback's own restart or what was
    /// checked after it did not succeed. `restart` says what is known about
    /// that second restart.
    RestoredVerifyFailed {
        detail: String,
        restart: SecondRestart,
    },
    /// The previous file is back, but the agent refused the restart (the
    /// exclusion from the HA daemon is no longer proven). The running
    /// chronyd was not restarted by this command.
    RestoredNotRestarted(String),
}

/// What is known about the restart that the rollback itself asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecondRestart {
    /// It failed before a request was sent.
    NotRequested,
    /// A request was sent; it failed or its answer was lost.
    Unconfirmed,
    /// It was carried out; the verification after it failed.
    Done,
}

impl SecondRestart {
    fn note(self) -> &'static str {
        match self {
            Self::NotRequested => {
                "The rollback did not request a restart of its own (it failed before it could send \
                 one), so chronyd was not restarted by the rollback"
            }
            Self::Unconfirmed => {
                "The rollback ALSO requested a restart, but it failed or its answer was lost, so it \
                 is not known whether chronyd was restarted a second time"
            }
            Self::Done => {
                "The rollback ALSO requested a restart and it was carried out, so chronyd was \
                 restarted by this command at least twice"
            }
        }
    }
}

/// Why a restart-and-verify did not succeed.
#[derive(Debug)]
enum VerifyError {
    /// The agent refused the request: nothing was restarted.
    Refused(String),
    /// It failed **before** any restart request was sent (the state read that
    /// comes first): this command did not restart chronyd (audit v0.3 MEDIUM-1).
    NotRequested(String),
    /// A restart request was sent and it failed or its answer was lost: whether
    /// chronyd was restarted is not known.
    Unconfirmed(String),
    /// The restart was carried out (the agent answered it) and what was
    /// checked afterwards did not hold.
    Failed(String),
}

impl VerifyError {
    fn message(&self) -> &str {
        match self {
            Self::Refused(m) | Self::NotRequested(m) | Self::Unconfirmed(m) | Self::Failed(m) => m,
        }
    }

    /// What the report may say about the restart this failure belongs to.
    fn restart_note(&self) -> &'static str {
        match self {
            Self::Refused(_) => {
                "The first restart after the publish was refused, so this command did not \
                 restart chronyd and it should still run the previous configuration."
            }
            Self::NotRequested(_) => {
                "No restart was requested after the publish (the command failed before it \
                 could send one), so this command did not restart chronyd and it should still \
                 run the previous configuration."
            }
            Self::Unconfirmed(_) => {
                "A restart was REQUESTED after the publish but it failed or its answer was \
                 lost, so it is not known whether chronyd was restarted: it may be running the \
                 CANDIDATE configuration although the previous file is back on disk."
            }
            Self::Failed(_) => {
                "A restart WAS requested after the publish before this failure, so chronyd may \
                 be running the CANDIDATE configuration although the previous file is back on \
                 disk."
            }
        }
    }
}

/// The first characters of a hash for messages; never slices a string that
/// is not a hash.
pub(crate) fn short_hash(sha: &str) -> String {
    super::short_digest(sha, 12)
}

/// Remove the staged file under the node's lock, so that no publish of it can
/// run any more (audit D-01). `Err` when that cannot be shown.
///
/// `Ok(Some(text))` when the staged name held a file that is not what was staged
/// (a version written by somebody else): the agent keeps it instead of deleting
/// it (final R7, audit H-2) and `text` names where.
fn fence_stage(ctx: &Ctx<'_>, target: &Target, stage_id: &str) -> Result<Option<String>, String> {
    let mut last = String::from("no attempt");
    for attempt in 0..REREAD_ATTEMPTS {
        match ctx.call(
            target,
            op::CHRONY_CLEANUP,
            json!({"stage_id": stage_id}),
            SHORT,
        ) {
            Ok(data) => return Ok(kept_note(&data)),
            Err(CallError::Transport(t)) => last = t.to_string(),
            Err(other) => return Err(other.to_string()),
        }
        if attempt + 1 < REREAD_ATTEMPTS {
            ctx.sleep(Duration::from_secs(1));
        }
    }
    Err(last)
}

/// Tell the operator what the replacement carried over, and that the window
/// before the swap was not closed when the platform could not exchange files.
fn note_publish(ctx: &Ctx<'_>, node: &str, data: &Value) {
    if let Some(mode) = data["mode"].as_str()
        && mode != "0644"
    {
        ctx.log.info(&format!(
            "{node}: the live file's mode {} and owner {}:{} were kept ({} extended attribute(s))",
            clean_text(mode),
            data["uid"],
            data["gid"],
            data["xattrs"]
        ));
    }
    if data["exchange"].as_bool() == Some(false) {
        ctx.log.info(&format!(
            "{node}: the file system or platform cannot exchange files atomically; an edit \
             made by somebody else within a few milliseconds of this publish would be lost \
             (LIMITATIONS 19)"
        ));
    }
}

/// What the agent says about a staged file it did not delete (see [`fence_stage`]).
fn kept_note(data: &Value) -> Option<String> {
    data["kept"].as_str().map(|path| {
        format!(
            "the staged file held a version that is not the one that was staged and it is kept \
             as {} ({})",
            clean_long_text(path),
            data["note"]
                .as_str()
                .map(clean_long_text)
                .unwrap_or_default()
        )
    })
}

/// The remote hash and the kept versions, read together.
struct Reread {
    sha: String,
    /// Kept versions on the node (`.mkg-displaced-*`), an unreadable listing
    /// counting as one: either way somebody has to look (audit H-1).
    kept: u64,
    names: Vec<String>,
}

/// Re-read the remote state a few times. `None` when the hash cannot be established.
fn reread(ctx: &Ctx<'_>, target: &Target) -> Option<Reread> {
    for attempt in 0..REREAD_ATTEMPTS {
        if let Ok(state) = remote_state(ctx, target)
            && let Some(sha) = state.sha
        {
            return Some(Reread {
                sha,
                kept: state.displaced_count + u64::from(state.displaced_unknown),
                names: state.displaced_names,
            });
        }
        if attempt + 1 < REREAD_ATTEMPTS {
            ctx.sleep(Duration::from_secs(1));
        }
    }
    None
}

/// The text of an UNKNOWN that is decided by a kept version, whatever the live
/// hash looks like: the live file may have been taken off the path of somebody's
/// edit, so no restart, no rollback and no clean-up follows (audit H-1).
fn kept_after_loss(what: &str, r: &Reread, node: &str, backup_id: &str) -> String {
    format!(
        "{what}; {} kept version(s) of a configuration that somebody else wrote exist in the \
         chrony directory of {node} ({}). The live file may be the candidate and the edit of \
         somebody else is NOT live; chronyd was NOT restarted and nothing was deleted or \
         restored. Backup {backup_id} holds the file observed before this command; compare the \
         files (QUICKSTART section 11) before doing anything else",
        r.kept,
        r.names.join(", ")
    )
}

/// The same for the rollback (audit A2 MEDIUM-2): the restore may have happened,
/// so the text must not say that nothing was restarted or restored. What is known
/// about the restarts is the sentence of the apply report that follows (audit
/// v0.3 MEDIUM-1: this text used to claim that the first restart had happened).
fn kept_after_restore_loss(what: &str, r: &Reread, node: &str, backup_id: &str) -> String {
    format!(
        "{what}; {} kept version(s) of a configuration that somebody else wrote exist in the \
         chrony directory of {node} ({}). The restore of the previous file may or may not have \
         taken effect, and the edit of somebody else is NOT live. Nothing further was \
         restarted, deleted or restored by this command after that. Backup {backup_id} holds the file observed \
         before this command; compare the files (QUICKSTART section 11) before doing anything else",
        r.kept,
        r.names.join(", ")
    )
}

fn restart_and_verify(
    ctx: &Ctx<'_>,
    target: &Target,
    expected_sha: &str,
) -> Result<Option<String>, VerifyError> {
    let unit = ctx.cfg.chrony_unit.as_str();
    // The state before the restart: the proof that chronyd was restarted (and
    // so read the file) is that its process or start time changed (D-04).
    let before = match svc_status(ctx, target, unit) {
        Ok(state) => state,
        Err(CallError::Refused(m)) => {
            return Err(VerifyError::Refused(format!("status refused: {m}")));
        }
        Err(e) => {
            return Err(VerifyError::NotRequested(format!(
                "cannot read {unit} before the restart: {e}"
            )));
        }
    };
    match svc_control(ctx, target, unit, "restart") {
        Ok(s) if s.active => {
            let proven = (!s.main_pid.is_empty() || !s.active_enter.is_empty())
                && (s.main_pid != before.main_pid || s.active_enter != before.active_enter);
            if !proven {
                return Err(VerifyError::Failed(format!(
                    "{unit} answered the restart but its process and start time did not change \
                     (MainPID {:?} -> {:?}); chronyd cannot be shown to have read the file",
                    clean_text(&before.main_pid),
                    clean_text(&s.main_pid)
                )));
            }
        }
        Ok(s) => {
            return Err(VerifyError::Failed(format!(
                "{unit} is {} after restart",
                clean_text(&s.active_state)
            )));
        }
        Err(CallError::Refused(m)) => {
            return Err(VerifyError::Refused(format!("restart refused: {m}")));
        }
        Err(e) => return Err(VerifyError::Unconfirmed(format!("restart failed: {e}"))),
    }
    let started = ctx.clock.now_ms();
    #[allow(unused_assignments)]
    let mut last = String::from("no observation");
    loop {
        match remote_state(ctx, target) {
            Ok(state) => {
                let hash_ok = state.sha.as_deref() == Some(expected_sha);
                let active = state.active == Some(true);
                if hash_ok && active && state.tracking_ok {
                    return Ok(state.tracking);
                }
                last = format!(
                    "hash {} / unit {} / tracking {}",
                    if hash_ok { "ok" } else { "MISMATCH" },
                    state.unit_state.unwrap_or_else(|| "unknown".into()),
                    if state.tracking_ok {
                        "ok"
                    } else {
                        "not answering"
                    }
                );
                if !hash_ok {
                    // A different file is live: waiting will not change that.
                    return Err(VerifyError::Failed(format!(
                        "live configuration hash differs ({last})"
                    )));
                }
            }
            Err(e) => last = format!("state unreadable: {e}"),
        }
        if ctx.clock.now_ms().saturating_sub(started) >= VERIFY_TIMEOUT_MS {
            return Err(VerifyError::Failed(format!(
                "verification did not succeed in time ({last})"
            )));
        }
        ctx.sleep(VERIFY_POLL);
    }
}

fn restore_backup(
    ctx: &Ctx<'_>,
    target: &Target,
    backup_id: &str,
    old_sha: &str,
    new_sha: &str,
) -> RestoreOutcome {
    let restored = ctx.call(
        target,
        op::CHRONY_RESTORE,
        json!({"backup_id": backup_id, "expect_backup": old_sha, "expect_current": new_sha}),
        LONG,
    );
    match restored {
        Ok(_) => {}
        Err(CallError::Refused(m)) => {
            return RestoreOutcome::Unknown(format!(
                "the live configuration is no longer ours ({m}); left untouched"
            ));
        }
        Err(CallError::Failed(m)) => return RestoreOutcome::Failed(m),
        // The previous file is back, but a version written by somebody else
        // inside the window was set aside and kept (audit RA-D-01).
        Err(CallError::DisplacedKept(m)) => {
            return RestoreOutcome::Unknown(format!(
                "a version written by somebody else during the restore could not be put back: {}",
                clean_long_text(&m)
            ));
        }
        Err(CallError::Transport(t)) => {
            // The answer was lost; the remote hash tells what happened.
            match reread(ctx, target).map(|r| (r.sha.clone(), r)) {
                Some((_, r)) if r.kept > 0 => {
                    return RestoreOutcome::Unknown(kept_after_restore_loss(
                        &format!("restore answer lost ({t})"),
                        &r,
                        "the node",
                        backup_id,
                    ));
                }
                Some((sha, _)) if sha == old_sha => {}
                Some((sha, _)) if sha == new_sha => {
                    // The restore may still be queued or running on the node
                    // and land after this look: the outcome is open.
                    return RestoreOutcome::Unknown(format!(
                        "restore answer lost ({t}) and the live file still shows the new \
                         configuration; the restore may yet land"
                    ));
                }
                Some(_) => {
                    return RestoreOutcome::Unknown(
                        "the live configuration is neither the old nor the new one".into(),
                    );
                }
                None => {
                    return RestoreOutcome::Unknown(format!(
                        "restore answer lost ({t}) and the remote hash is unreadable"
                    ));
                }
            }
        }
    }
    match restart_and_verify(ctx, target, old_sha) {
        Ok(_) => RestoreOutcome::Verified,
        Err(VerifyError::Refused(m)) => RestoreOutcome::RestoredNotRestarted(m),
        Err(e) => {
            let restart = match &e {
                VerifyError::NotRequested(_) => SecondRestart::NotRequested,
                VerifyError::Unconfirmed(_) => SecondRestart::Unconfirmed,
                _ => SecondRestart::Done,
            };
            RestoreOutcome::RestoredVerifyFailed {
                detail: format!("restored file but verification failed: {}", e.message()),
                restart,
            }
        }
    }
}

pub(crate) fn apply(ctx: &Ctx<'_>, node: &str, content: &str, dry_run: bool) -> Res<ApplyReport> {
    let node = ctx.node(node)?.clone();
    let target = ctx.node_target(&node.name)?;
    let new_sha = fsutil::sha256_hex(content.as_bytes());

    // 0. The restart at the end is gated by the exclusion from the HA daemon.
    // Prove it now, once, so that an apply is never started that cannot be
    // finished (audit EX-06). Everything else in an apply is file work the HA
    // daemon cannot touch, and it runs through to the rollback regardless.
    if !dry_run {
        match ping(ctx, &node.name, &target) {
            Ok(Reach::Up(p)) if p.ha_safe() => {}
            Ok(Reach::Up(p)) => {
                return Err(Failure::Refused(format!(
                    "{}: the exclusion from the HA daemon is not proven ({}); the restart that \
                     ends an apply would be refused, so nothing is changed",
                    node.name,
                    p.ha_text()
                )));
            }
            // Nothing has been sent that could change the node: a refusal to
            // start (R4; it used to be FAILED).
            Ok(Reach::Down(m)) => {
                return Err(Failure::Refused(format!(
                    "cannot reach {} to check the HA exclusion: {m}; nothing was changed",
                    node.name
                )));
            }
            Err(f) => return Err(f),
        }
    }

    // 1-2. observe the live state and its hash. Everything up to the backup
    // is reading: a failure here changed nothing and is a refusal to start.
    let state = remote_state(ctx, &target)
        .map_err(|e| failure_for(&format!("cannot observe {}", node.name), e))
        .map_err(Failure::before_any_change)?;
    if !dry_run && let Some(problem) = unit_mismatch(ctx, &node.name, &state) {
        return Err(Failure::Refused(format!("{problem}; nothing is changed")));
    }
    // A kept version of somebody else's edit is evidence that an operator has
    // not looked at yet: a new change would bury it under another one.
    if !dry_run && (state.displaced_count > 0 || state.displaced_unknown) {
        return Err(Failure::Refused(format!(
            "{}: {}; nothing is changed",
            node.name,
            if state.displaced_unknown {
                "the agent cannot say whether kept versions of a configuration exist in the \
                 chrony directory"
                    .to_string()
            } else {
                displaced_text(state.displaced_count, &state.displaced_names)
            }
        )));
    }
    let Some(old_sha) = state.sha.clone().filter(|_| state.trusted) else {
        return Err(Failure::Refused(format!(
            "the live configuration on {} is missing or untrusted ({}); not touching it",
            node.name,
            state.problems.join("; ")
        )));
    };
    // 3. validate the candidate with the real chronyd on the target.
    let (valid, message) =
        validate_remote(ctx, &target, content).map_err(Failure::before_any_change)?;
    if !valid {
        return Err(Failure::Refused(format!(
            "chronyd rejected the candidate: {}",
            message.unwrap_or_default()
        )));
    }
    // 4. show the difference.
    let (remote_text, remote_sha) =
        read_remote(ctx, &target).map_err(Failure::before_any_change)?;
    if remote_sha != old_sha {
        return Err(Failure::Refused(
            "the live configuration changed while it was being read; retry".into(),
        ));
    }
    let diff_text = unified_diff(
        &format!("{}:chrony.conf", node.name),
        "candidate",
        &remote_text,
        content,
    );
    if old_sha == new_sha {
        // The file already matches, but "nothing to do" is only a success if
        // chrony actually runs it: an earlier interrupted apply may have left
        // this exact file behind with the service down.
        if state.active != Some(true) || !state.tracking_ok {
            return Err(Failure::Unknown(format!(
                "{} already holds this configuration but chrony is not healthy (unit {}, \
                 tracking {}); use `resource restart chronyd --node {}` and re-check",
                node.name,
                state.unit_state.as_deref().unwrap_or("unknown"),
                if state.tracking_ok {
                    "ok"
                } else {
                    "not answering"
                },
                node.name
            )));
        }
        return Ok(ApplyReport {
            node: node.name,
            changed: false,
            dry_run,
            old_sha256: old_sha,
            new_sha256: new_sha,
            backup_id: None,
            tracking: state.tracking,
            diff: String::new(),
        });
    }
    if dry_run {
        return Ok(ApplyReport {
            node: node.name,
            changed: false,
            dry_run: true,
            old_sha256: old_sha,
            new_sha256: new_sha,
            backup_id: None,
            tracking: state.tracking,
            diff: diff_text,
        });
    }

    // 5. unique, verified backup of exactly the observed file.
    let backup = ctx
        .call(
            &target,
            op::CHRONY_BACKUP,
            json!({"expect_sha256": old_sha}),
            SHORT,
        )
        .map_err(|e| failure_for("backup failed", e));
    let backup = match backup {
        Ok(data) => data,
        Err(f) => {
            // A lost answer may still have created a (harmless) backup file.
            return Err(f);
        }
    };
    let backup_id = backup["backup_id"]
        .as_str()
        .filter(|id| backup_id_ok(id))
        .map(str::to_string);
    // The sweep found a leftover whose content was not what its name promised
    // and moved it to a protected name: a kept version appeared during this
    // command. Nothing of the configuration was changed; stop before staging
    // (audit A2 LOW-1).
    if let Some(list) = backup["quarantined"].as_array().filter(|l| !l.is_empty()) {
        let names: Vec<String> = list
            .iter()
            .filter_map(Value::as_str)
            .take(8)
            .map(clean_text)
            .collect();
        return Err(Failure::Refused(format!(
            "{}: the sweep of earlier leftovers kept {} file(s) whose content is not what their \
             name promised ({}); look at them (QUICKSTART section 11) and delete them yourself \
             before the next apply. The configuration was not changed",
            node.name,
            list.len(),
            names.join(", ")
        )));
    }
    if let Some(swept) = backup["swept"].as_u64().filter(|n| *n > 0) {
        ctx.log.info(&format!(
            "removed {swept} stale temporary file(s) of earlier interrupted runs on {}",
            node.name
        ));
    }
    let backup_sha = backup["sha256"].as_str().map(str::to_string);
    let (Some(backup_id), Some(backup_sha)) = (backup_id, backup_sha) else {
        return Err(Failure::Failed("backup answer not understood".into()));
    };
    if backup_sha != old_sha {
        return Err(Failure::Failed(
            "the backup hash does not match the observed file".into(),
        ));
    }
    ctx.log
        .info(&format!("backup {backup_id} ({})", short_hash(&old_sha)));

    // 6. stage the candidate beside the live file.
    let staged = ctx
        .call(
            &target,
            op::CHRONY_STAGE,
            json!({"content": content, "sha256": new_sha}),
            SHORT,
        )
        .map_err(|e| failure_for("staging failed", e))?;
    let Some(stage_id) = staged["stage_id"]
        .as_str()
        .filter(|id| stage_id_ok(id))
        .map(str::to_string)
    else {
        return Err(Failure::Failed("stage answer not understood".into()));
    };
    let cleanup = |ctx: &Ctx<'_>| {
        if let Ok(data) = ctx.call(
            &target,
            op::CHRONY_CLEANUP,
            json!({"stage_id": stage_id}),
            SHORT,
        ) && let Some(text) = kept_note(&data)
        {
            ctx.log.info(&format!("{}: {text}", node.name));
        }
    };

    // 7. atomic publish (compare-and-swap on the observed hash).
    let published = ctx.call(
        &target,
        op::CHRONY_PUBLISH,
        json!({"stage_id": stage_id, "expect_current": old_sha, "expect_new": new_sha}),
        SHORT,
    );
    let published_ok = match published {
        Ok(data) => {
            note_publish(ctx, &node.name, &data);
            true
        }
        Err(CallError::Refused(m)) => {
            cleanup(ctx);
            return Err(Failure::Refused(format!("publish refused: {m}")));
        }
        // Somebody else edited the file inside the replacement window and
        // their version could not be put back (audit RA-D-01). The live file
        // is the candidate; their version is kept on the node. Nothing is
        // cleaned up, restarted or restored: every one of those steps would
        // either delete their version or act on a file nobody has decided
        // about.
        Err(CallError::DisplacedKept(m)) => {
            return Err(Failure::Unknown(format!(
                "publish: the configuration was edited by somebody else while it was being \
                 replaced, and that version could not be put back. {} The live file on {} is now \
                 the candidate; chronyd was NOT restarted and nothing was deleted or restored. \
                 Backup {backup_id} holds the file observed before this command. Compare the \
                 three files before doing anything else",
                clean_long_text(&m),
                node.name
            )));
        }
        Err(CallError::Failed(m)) => {
            // The agent may have renamed before failing; the hash decides,
            // unless a kept version exists (audit H-1).
            match reread(ctx, &target).map(|r| (r.sha.clone(), r)) {
                Some((_, r)) if r.kept > 0 => {
                    return Err(Failure::Unknown(kept_after_loss(
                        &format!("publish failed ({m})"),
                        &r,
                        &node.name,
                        &backup_id,
                    )));
                }
                Some((sha, _)) if sha == old_sha => {
                    cleanup(ctx);
                    return Err(Failure::Failed(format!(
                        "publish failed, nothing changed: {m}"
                    )));
                }
                Some((sha, _)) if sha == new_sha => true,
                _ => {
                    return Err(Failure::Unknown(format!(
                        "publish failed ({m}) and the live configuration cannot be classified; \
                         backup {backup_id} is on the node"
                    )));
                }
            }
        }
        Err(CallError::Transport(t)) => {
            // The publish may still be running or queued on the node. Remove
            // its staged file under the node's lock first: afterwards it has
            // either finished (the hash shows it) or can no longer succeed.
            match fence_stage(ctx, &target, &stage_id) {
                Ok(None) => {}
                Ok(Some(text)) => {
                    return Err(Failure::Unknown(format!(
                        "publish answer lost ({t}); {text}. The live file may be the candidate \
                         and the edit of somebody else is NOT live; chronyd was NOT restarted \
                         and nothing was restored. Backup {backup_id} holds the file observed \
                         before this command; compare the files (QUICKSTART section 11) before \
                         doing anything else"
                    )));
                }
                Err(why) => {
                    return Err(Failure::Unknown(format!(
                        "publish answer lost ({t}) and the staged file could not be removed under \
                     the node's lock ({why}); a late publish may still land. Check \
                     `chronyd show --node {}` before anything else; backup {backup_id} is on the \
                     node",
                        node.name
                    )));
                }
            }
            match reread(ctx, &target).map(|r| (r.sha.clone(), r)) {
                // A kept version decides first, whatever the hash looks like: the
                // live file may be the candidate with somebody's edit taken off
                // its path (audit H-1).
                Some((_, r)) if r.kept > 0 => {
                    return Err(Failure::Unknown(kept_after_loss(
                        &format!("publish answer lost ({t})"),
                        &r,
                        &node.name,
                        &backup_id,
                    )));
                }
                Some((sha, _)) if sha == old_sha => {
                    return Err(Failure::Failed(format!(
                        "publish answer lost ({t}); the staged file was removed under the node's \
                     lock and the live file is unchanged"
                    )));
                }
                Some((sha, _)) if sha == new_sha => true,
                Some(_) => {
                    return Err(Failure::Unknown(format!(
                        "publish answer lost ({t}) and the live file is neither the old nor the \
                     new one; backup {backup_id} is on the node"
                    )));
                }
                None => {
                    return Err(Failure::Unknown(format!(
                        "publish answer lost ({t}) and the remote hash is unreadable; \
                     backup {backup_id} is on the node"
                    )));
                }
            }
        }
    };
    debug_assert!(published_ok);

    // 8-9. restart and prove the requested configuration is live.
    match restart_and_verify(ctx, &target, &new_sha) {
        Ok(tracking) => {
            cleanup(ctx);
            Ok(ApplyReport {
                node: node.name,
                changed: true,
                dry_run: false,
                old_sha256: old_sha,
                new_sha256: new_sha,
                backup_id: Some(backup_id),
                tracking,
                diff: diff_text,
            })
        }
        Err(failure) => {
            let why = failure.message().to_string();
            // Whether a restart was requested, and with what result, decides what the
            // report may say about the running chronyd (audit RA-D-02, v0.3 MEDIUM-1):
            // it is read from the kind of the failure, which records whether a
            // request was sent at all.
            let restart_note = failure.restart_note();
            ctx.log
                .info(&format!("apply failed after publish ({why}); rolling back"));
            let outcome = restore_backup(ctx, &target, &backup_id, &old_sha, &new_sha);
            cleanup(ctx);
            match outcome {
                RestoreOutcome::Verified => Err(Failure::Failed(format!(
                    "{why}; rolled back to the previous configuration and verified (backup {backup_id})"
                ))),
                // Every arm that is not verified says what is known about the
                // restarts (audit B, LOW-1; CLI_REFERENCE promise RA-D-02).
                RestoreOutcome::Failed(m) => Err(Failure::Unknown(format!(
                    "{why}; ROLLBACK FAILED ({m}). The previous file is backup {backup_id} on {}. \
                     {restart_note} The rollback itself did not restart chronyd",
                    node.name
                ))),
                RestoreOutcome::Unknown(m) => Err(Failure::Unknown(format!(
                    "{why}; rollback could not be established ({m}). Backup {backup_id} on {}. \
                     {restart_note} The rollback did not get as far as a restart of its own",
                    node.name
                ))),
                RestoreOutcome::RestoredVerifyFailed { detail, restart } => {
                    Err(Failure::Unknown(format!(
                        "{why}; ROLLBACK FAILED ({detail}). The previous file is back (backup \
                         {backup_id}) on {}. {restart_note} {}; confirm with \
                         `resource status chronyd`",
                        node.name,
                        restart.note()
                    )))
                }
                RestoreOutcome::RestoredNotRestarted(m) => Err(Failure::Unknown(format!(
                    "{why}; the previous file is back (backup {backup_id}) but chronyd could not \
                     be restarted ({m}). {} Confirm with `resource status chronyd` before \
                     anything else",
                    restart_note
                ))),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// service operations on chronyd
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ServiceReport {
    pub(crate) node: String,
    pub(crate) unit: String,
    pub(crate) action: String,
    pub(crate) active: bool,
    pub(crate) active_state: String,
}

pub(crate) fn service_action(ctx: &Ctx<'_>, node: &str, action: &str) -> Res<ServiceReport> {
    let node = ctx.node(node)?.clone();
    let target = ctx.node_target(&node.name)?;
    let unit = ctx.cfg.chrony_unit.clone();
    let state = svc_control(ctx, &target, &unit, action).map_err(|e| match e {
        CallError::Refused(m) => Failure::Refused(format!("{action} {unit} on {}: {m}", node.name)),
        // The agent ran `systemctl` and reports that it failed: the unit may
        // have changed state on the way (a stop that half worked, a start
        // that failed after a restart began). Not a known outcome, so the
        // state is read back and the result is UNKNOWN (R4; it used to be
        // FAILED without a look).
        CallError::Failed(m) | CallError::DisplacedKept(m) => {
            let now = svc_status(ctx, &target, &unit)
                .map(|s| s.active_state)
                .unwrap_or_else(|_| "unknown".into());
            Failure::Unknown(format!(
                "{action} {unit} on {}: the agent reports a failure ({m}); the unit may have \
                 changed state, unit state now: {now}",
                node.name
            ))
        }
        CallError::Transport(t) => {
            // Re-observe: the unit may have changed state anyway.
            let now = svc_status(ctx, &target, &unit)
                .map(|s| s.active_state)
                .unwrap_or_else(|_| "unknown".into());
            Failure::Unknown(format!(
                "{action} {unit} on {}: no answer ({t}); unit state now: {now}",
                node.name
            ))
        }
    })?;
    let expected_active = action != "stop";
    if state.active != expected_active {
        return Err(Failure::Failed(format!(
            "{unit} on {} is {} after {action}",
            node.name, state.active_state
        )));
    }
    Ok(ServiceReport {
        node: node.name,
        unit,
        action: action.to_string(),
        active: state.active,
        active_state: state.active_state,
    })
}

pub(crate) fn status_value(ctx: &Ctx<'_>, node: &str) -> Value {
    match show(ctx, node) {
        Ok(report) => serde_json::to_value(report).unwrap_or(Value::Null),
        Err(f) => json!({"node": node, "error": f.message()}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual::fakes::{Fault, World};
    use crate::manual::proto::op;
    use std::os::unix::fs::PermissionsExt;

    const OLD: &str = "pool 2.pool.ntp.org iburst\n";
    const NEW: &str = "pool time.example.invalid iburst\nmakestep 1 3\n";

    fn live(w: &World, node: &str) -> String {
        fs::read_to_string(&w.remote.host(node).env.cfg.chrony_conf).unwrap()
    }

    fn sha(s: &str) -> String {
        fsutil::sha256_hex(s.as_bytes())
    }

    #[test]
    fn unified_diff_marks_added_removed_and_unchanged_lines() {
        let d = unified_diff("a", "b", "x\ny\nz\n", "x\nw\nz\n");
        assert!(d.contains("\n x\n"));
        assert!(d.contains("\n-y\n"));
        assert!(d.contains("\n+w\n"));
        assert!(d.contains("\n z\n"));
        let d = unified_diff("a", "b", "a", "a\n");
        assert!(d.contains("No newline"));
        let big = "l\n".repeat(MAX_DIFF_LINES + 1);
        assert!(unified_diff("a", "b", &big, "x\n").contains("too large"));
    }

    #[test]
    fn candidate_reader_rejects_symlinks_binary_and_oversize() {
        let dir = crate::manual::fsutil::tests::temp_dir("cand");
        let good = dir.join("good.conf");
        fs::write(&good, OLD).unwrap();
        assert_eq!(read_candidate(&good).unwrap(), OLD);
        let link = dir.join("link.conf");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(matches!(read_candidate(&link), Err(Failure::Refused(_))));
        let bin = dir.join("bin.conf");
        fs::write(&bin, [0xff, 0xfe]).unwrap();
        assert!(matches!(read_candidate(&bin), Err(Failure::Refused(_))));
        let nul = dir.join("nul.conf");
        fs::write(&nul, "a\0b").unwrap();
        assert!(matches!(read_candidate(&nul), Err(Failure::Refused(_))));
        let big = dir.join("big.conf");
        fs::write(&big, "x".repeat(MAX_CONTENT + 1)).unwrap();
        assert!(matches!(read_candidate(&big), Err(Failure::Refused(_))));
        assert!(matches!(read_candidate(&dir), Err(Failure::Refused(_))));
        assert!(matches!(
            read_candidate(&dir.join("missing")),
            Err(Failure::Refused(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn show_validate_and_diff_report_the_remote_truth() {
        let w = World::new("chrony-show");
        let ctx = w.ctx();
        let shown = show(&ctx, "node-a").unwrap();
        assert_eq!(shown.conf_sha256.as_deref(), Some(sha(OLD).as_str()));
        assert_eq!(shown.unit_active, Some(true));
        assert!(shown.tracking_ok);
        let ok = validate(&ctx, "node-a", NEW).unwrap();
        assert!(ok.valid);
        w.remote.host("node-a").sys.reject_config("bogus");
        let bad = validate(&ctx, "node-a", "bogus line\n").unwrap();
        assert!(!bad.valid);
        let d = diff(&ctx, "node-a", NEW).unwrap();
        assert!(!d.identical);
        assert!(d.unified.contains("+makestep 1 3"));
        assert!(diff(&ctx, "node-a", OLD).unwrap().identical);
        assert!(matches!(show(&ctx, "nope"), Err(Failure::Refused(_))));
        assert_eq!(live(&w, "node-a"), OLD, "read-only commands change nothing");
    }

    #[test]
    fn show_of_an_unreachable_node_fails_and_does_not_invent_state() {
        let w = World::new("chrony-show-down");
        w.remote.host("node-b").reachable.set(false);
        let r = show(&w.ctx(), "node-b");
        assert!(matches!(r, Err(Failure::Failed(m)) if m.contains("unreachable")));
    }

    #[test]
    fn apply_success_publishes_restarts_and_verifies() {
        let w = World::new("chrony-ok");
        let report = apply(&w.ctx(), "node-a", NEW, false).unwrap();
        assert!(report.changed);
        assert_eq!(report.new_sha256, sha(NEW));
        assert_eq!(live(&w, "node-a"), NEW);
        assert!(report.backup_id.is_some());
        assert_eq!(
            w.remote.host("node-a").sys.actions(),
            vec!["restart chrony.service"]
        );
        // Stage files are gone; the backup remains for audit.
        let conf_dir = w
            .remote
            .host("node-a")
            .env
            .cfg
            .chrony_conf
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(fs::read_dir(conf_dir).unwrap().all(|e| {
            let n = e.unwrap().file_name().to_string_lossy().into_owned();
            n == "chrony.conf"
        }));
        // Applying the same file again is a no-op and does not restart.
        let again = apply(&w.ctx(), "node-a", NEW, false).unwrap();
        assert!(!again.changed);
        assert_eq!(w.remote.host("node-a").sys.actions().len(), 1);
    }

    #[test]
    fn identical_content_is_not_success_while_chrony_is_unhealthy() {
        let w = World::new("chrony-noop-unhealthy");
        w.remote
            .host("node-a")
            .sys
            .set_service("chrony.service", "failed");
        let r = apply(&w.ctx(), "node-a", OLD, false);
        assert!(
            matches!(&r, Err(Failure::Unknown(m)) if m.contains("not healthy")),
            "{r:?}"
        );
        w.remote
            .host("node-a")
            .sys
            .set_service("chrony.service", "active");
        w.remote.host("node-a").sys.fail_tracking(true);
        assert!(matches!(
            apply(&w.ctx(), "node-a", OLD, false),
            Err(Failure::Unknown(_))
        ));
        w.remote.host("node-a").sys.fail_tracking(false);
        assert!(apply(&w.ctx(), "node-a", OLD, false).is_ok());
    }

    #[test]
    fn dry_run_and_rejected_candidates_change_nothing() {
        let w = World::new("chrony-dry");
        let dry = apply(&w.ctx(), "node-a", NEW, true).unwrap();
        assert!(dry.dry_run && !dry.changed);
        assert!(dry.diff.contains("+makestep"));
        assert_eq!(live(&w, "node-a"), OLD);
        w.remote.host("node-a").sys.reject_config("bogus");
        let rejected = apply(&w.ctx(), "node-a", "bogus\n", false);
        assert!(matches!(rejected, Err(Failure::Refused(m)) if m.contains("rejected")));
        assert_eq!(live(&w, "node-a"), OLD);
        assert!(w.remote.host("node-a").sys.actions().is_empty());
        assert_eq!(
            w.remote.count("node-a", op::CHRONY_BACKUP),
            0,
            "no backup before validation"
        );
    }

    #[test]
    fn restart_failure_after_publish_rolls_back_and_verifies() {
        let w = World::new("chrony-reload-fail");
        // The first restart (after publish) fails; the rollback restart works.
        w.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("restart"),
            0,
            1,
            Fault::FailBefore("injected".into()),
        );
        let r = apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Failed(m)) = r else {
            panic!("{r:?}")
        };
        assert!(m.contains("rolled back"), "{m}");
        assert_eq!(live(&w, "node-a"), OLD);
        assert_eq!(
            w.remote
                .host("node-a")
                .sys
                .service("chrony.service")
                .as_deref(),
            Some("active")
        );
    }

    #[test]
    fn verification_failures_roll_back() {
        // tracking never answers after the restart => rollback to OLD, and
        // since tracking still fails the rollback cannot be verified either.
        let w = World::new("chrony-track-fail");
        w.remote.host("node-a").sys.fail_tracking(true);
        let r = apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(m)) = r else {
            panic!("{r:?}")
        };
        assert!(
            m.contains("ROLLBACK FAILED") || m.contains("rollback"),
            "{m}"
        );
        assert_eq!(live(&w, "node-a"), OLD, "the file itself was restored");
    }

    #[test]
    fn inactive_unit_after_restart_rolls_back() {
        let w = World::new("chrony-inactive");
        w.remote.host("node-a").sys.fail_action("restart");
        let r = apply(&w.ctx(), "node-a", NEW, false);
        // Both the apply restart and the rollback restart fail: the file was
        // restored but the service state cannot be proven good => UNKNOWN.
        let Err(Failure::Unknown(m)) = r else {
            panic!("{r:?}")
        };
        assert!(m.contains("ROLLBACK FAILED"), "{m}");
        assert_eq!(live(&w, "node-a"), OLD);
    }

    #[test]
    fn lost_publish_answer_is_resolved_by_rereading_the_hash() {
        // The publish executed but the answer was lost: treated as published,
        // then verified and completed.
        let w = World::new("chrony-lost-after");
        w.remote
            .inject("node-a", op::CHRONY_PUBLISH, Fault::DropAfter);
        let r = apply(&w.ctx(), "node-a", NEW, false).unwrap();
        assert!(r.changed);
        assert_eq!(live(&w, "node-a"), NEW);

        // The publish never arrived: unchanged, reported as a failure, the
        // stage file is cleaned up.
        let w = World::new("chrony-lost-before");
        w.remote
            .inject("node-a", op::CHRONY_PUBLISH, Fault::DropBefore);
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(matches!(r, Err(Failure::Failed(m)) if m.contains("unchanged")));
        assert_eq!(live(&w, "node-a"), OLD);
        let dir = w
            .remote
            .host("node-a")
            .env
            .cfg
            .chrony_conf
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(fs::read_dir(dir).unwrap().count(), 1, "stage file removed");
    }

    #[test]
    fn publish_answer_lost_and_hash_unreadable_is_unknown() {
        let w = World::new("chrony-unknown");
        w.remote
            .inject("node-a", op::CHRONY_PUBLISH, Fault::DropAfter);
        // After the lost answer every state read also fails.
        w.remote
            .inject_when("node-a", op::CHRONY_STATE, None, 1, 8, Fault::DropBefore);
        let r = apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(m)) = r else {
            panic!("{r:?}")
        };
        assert!(m.contains("unreadable"), "{m}");
    }

    #[test]
    fn external_change_between_observation_and_publish_is_not_overwritten() {
        let w = World::new("chrony-race");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let stranger = "server other.example.invalid\n";
        // Somebody else edits the file right before our publish is handled.
        let tamper = conf.clone();
        w.remote.inject(
            "node-a",
            op::CHRONY_PUBLISH,
            Fault::Hook(std::rc::Rc::new(move || {
                fs::write(&tamper, stranger).unwrap()
            })),
        );
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(
            matches!(&r, Err(Failure::Refused(m)) if m.contains("not overwriting")),
            "{r:?}"
        );
        assert_eq!(live(&w, "node-a"), stranger, "the foreign edit survives");
        assert!(
            w.remote.host("node-a").sys.actions().is_empty(),
            "no restart happened"
        );
        let dir = conf.parent().unwrap().to_path_buf();
        assert_eq!(
            fs::read_dir(dir).unwrap().count(),
            1,
            "the stage file was cleaned up"
        );
    }

    #[test]
    fn rollback_never_overwrites_a_file_that_is_no_longer_ours() {
        let w = World::new("chrony-rollback-race");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        let stranger = "server other.example.invalid\n";
        // The restart fails; before the rollback restore runs, somebody
        // replaced our published file with their own.
        w.remote.inject_when(
            "node-a",
            op::SERVICE_CONTROL,
            Some("restart"),
            0,
            1,
            Fault::FailBefore("injected".into()),
        );
        let tamper = conf.clone();
        w.remote.inject(
            "node-a",
            op::CHRONY_RESTORE,
            Fault::Hook(std::rc::Rc::new(move || {
                fs::write(&tamper, stranger).unwrap()
            })),
        );
        let r = apply(&w.ctx(), "node-a", NEW, false);
        let Err(Failure::Unknown(m)) = &r else {
            panic!("{r:?}")
        };
        assert!(
            m.contains("no longer ours") || m.contains("rollback could not be established"),
            "{m}"
        );
        assert_eq!(
            live(&w, "node-a"),
            stranger,
            "the foreign file is left alone"
        );
    }

    #[test]
    fn untrusted_live_file_is_never_touched() {
        let w = World::new("chrony-untrusted");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        fs::set_permissions(&conf, fs::Permissions::from_mode(0o666)).unwrap();
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(matches!(r, Err(Failure::Refused(m)) if m.contains("untrusted")));
        assert_eq!(live(&w, "node-a"), OLD);
    }

    #[test]
    fn exclusive_mode_blocks_apply_before_any_change() {
        let w = World::new("chrony-ha");
        w.remote
            .host("node-a")
            .sys
            .set_service("mikagami.service", "active");
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(matches!(r, Err(Failure::Refused(_))), "{r:?}");
        assert_eq!(live(&w, "node-a"), OLD);
        assert!(w.remote.host("node-a").sys.actions().is_empty());
    }

    #[test]
    fn service_actions_are_verified() {
        let w = World::new("chrony-svc");
        let stop = service_action(&w.ctx(), "node-b", "stop").unwrap();
        assert!(!stop.active);
        let start = service_action(&w.ctx(), "node-b", "start").unwrap();
        assert!(start.active);
        // R4: the agent says the restart failed; the unit may have changed
        // state on the way, so the result is UNKNOWN with the state read back
        // (it used to be FAILED without a look).
        w.remote.host("node-b").sys.fail_action("restart");
        assert!(matches!(
            service_action(&w.ctx(), "node-b", "restart"),
            Err(Failure::Unknown(m)) if m.contains("unit state now:")
        ));
        // A lost answer is reported as UNKNOWN with the observed state.
        w.remote.host("node-b").sys.clear_failures();
        w.remote
            .inject("node-b", op::SERVICE_CONTROL, Fault::DropAfter);
        let r = service_action(&w.ctx(), "node-b", "stop");
        assert!(matches!(r, Err(Failure::Unknown(m)) if m.contains("unit state now: inactive")));
    }

    // ------------------------------------------------------------------
    // Round-1 audit, work package 4 (D-01 .. D-10)
    // ------------------------------------------------------------------

    fn conf_dir_of(w: &World, node: &str) -> std::path::PathBuf {
        w.remote
            .host(node)
            .env
            .cfg
            .chrony_conf
            .parent()
            .unwrap()
            .to_path_buf()
    }

    /// The `chrony.publish` arguments the controller sent last (what a late
    /// agent would still execute).
    fn last_publish_args(calls: &std::cell::RefCell<Vec<String>>) -> Value {
        let calls = calls.borrow();
        let line = calls
            .iter()
            .rev()
            .find(|c| c.starts_with(&format!("node-a {}", op::CHRONY_PUBLISH)))
            .expect("a publish was sent")
            .clone();
        serde_json::from_str(line.splitn(3, ' ').nth(2).unwrap()).unwrap()
    }

    fn late_agent(
        env: &crate::manual::agent::AgentEnv,
        args: Value,
    ) -> crate::manual::proto::Response {
        use crate::manual::proto::{PROTO_VERSION, Request, random_hex};
        crate::manual::agent::handle(
            env,
            &Request {
                v: PROTO_VERSION,
                id: random_hex(8),
                op: op::CHRONY_PUBLISH.into(),
                args,
            },
        )
    }

    #[test]
    fn d01_a_publish_that_arrives_after_the_fence_cannot_change_the_file() {
        let w = World::new("d01-after-fence");
        w.remote
            .inject("node-a", op::CHRONY_PUBLISH, Fault::DropBefore);
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(
            matches!(&r, Err(Failure::Failed(m)) if m.contains("removed under the node's lock")),
            "{r:?}"
        );
        // The agent that outlived the ssh timeout finally runs the request.
        let late = late_agent(
            &w.remote.host("node-a").env,
            last_publish_args(&w.remote.calls),
        );
        assert!(!late.ok, "the late publish must fail: {late:?}");
        assert_eq!(live(&w, "node-a"), OLD, "'unchanged' stays true");
        assert!(w.remote.host("node-a").sys.actions().is_empty());
    }

    #[test]
    fn d01_a_publish_that_wins_the_race_with_the_fence_is_seen_in_the_hash() {
        // The audit's interleaving: the publish runs after the controller
        // concluded nothing happened and just before its clean-up reaches
        // the node. With the fence the clean-up takes the lock and the
        // controller looks again.
        let w = World::new("d01-before-fence");
        w.remote
            .inject("node-a", op::CHRONY_PUBLISH, Fault::DropBefore);
        let hosts = w.remote.hosts.clone();
        let calls = w.remote.calls.clone();
        w.remote.inject(
            "node-a",
            op::CHRONY_CLEANUP,
            Fault::Hook(std::rc::Rc::new(move || {
                let late = late_agent(&hosts["node-a"].env, last_publish_args(&calls));
                assert!(late.ok, "{late:?}");
            })),
        );
        let r = apply(&w.ctx(), "node-a", NEW, false);
        // Never "unchanged": the new file is live, so the apply went on to
        // restart chronyd and verify it.
        let report = r.expect("the late publish was observed and the apply completed");
        assert!(report.changed);
        assert_eq!(live(&w, "node-a"), NEW);
        assert_eq!(
            w.remote.host("node-a").sys.actions(),
            vec!["restart chrony.service"]
        );
    }

    #[test]
    fn d01_a_lost_publish_that_cannot_be_fenced_is_unknown() {
        let w = World::new("d01-unfenced");
        w.remote
            .inject("node-a", op::CHRONY_PUBLISH, Fault::DropBefore);
        w.remote.inject_when(
            "node-a",
            op::CHRONY_CLEANUP,
            None,
            0,
            100,
            Fault::DropBefore,
        );
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(
            matches!(&r, Err(Failure::Unknown(m)) if m.contains("late publish may still land")),
            "{r:?}"
        );
        // The stage file is still there: the fence did not happen.
        assert!(
            fs::read_dir(conf_dir_of(&w, "node-a"))
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(".mkg-stage-"))
        );
    }

    #[test]
    fn d01_a_fence_that_the_agent_refuses_is_unknown_too() {
        let w = World::new("d01-fence-refused");
        w.remote
            .inject("node-a", op::CHRONY_PUBLISH, Fault::TimeoutAfter);
        w.remote.inject_when(
            "node-a",
            op::CHRONY_CLEANUP,
            None,
            0,
            1,
            Fault::FailBefore("another chrony operation holds the lock".into()),
        );
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(matches!(&r, Err(Failure::Unknown(_))), "{r:?}");
    }

    #[test]
    fn d01_a_lost_restore_answer_with_the_new_file_still_live_is_unknown() {
        let w = World::new("d01-restore");
        w.remote
            .inject("node-a", op::CHRONY_RESTORE, Fault::DropBefore);
        w.remote.host("node-a").sys.fail_action("restart");
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(
            matches!(&r, Err(Failure::Unknown(m)) if m.contains("may yet land")),
            "{r:?}"
        );
    }

    #[test]
    fn d03_the_mode_and_group_of_the_live_file_survive_apply_and_rollback() {
        use std::os::unix::fs::MetadataExt;
        let w = World::new("d03-mode");
        let conf = w.remote.host("node-a").env.cfg.chrony_conf.clone();
        fs::set_permissions(&conf, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&conf).unwrap();
        apply(&w.ctx(), "node-a", NEW, false).unwrap();
        let after = fs::metadata(&conf).unwrap();
        assert_eq!(after.mode() & 0o7777, 0o640, "apply keeps the mode");
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert!(
            w.log.lines().iter().any(|l| l.contains("mode 0640")),
            "a mode other than 0644 is reported: {:?}",
            w.log.lines()
        );
        // Roll back (the restart's answer is lost): the old file returns with
        // the mode of the live file it replaced.
        let w2 = World::new("d03-mode-rollback");
        let conf2 = w2.remote.host("node-a").env.cfg.chrony_conf.clone();
        fs::set_permissions(&conf2, fs::Permissions::from_mode(0o600)).unwrap();
        w2.remote
            .inject_when("node-a", op::SERVICE_CONTROL, None, 0, 1, Fault::DropAfter);
        let r = apply(&w2.ctx(), "node-a", NEW, false);
        assert!(r.is_err(), "{r:?}");
        assert_eq!(live(&w2, "node-a"), OLD);
        assert_eq!(
            fs::metadata(&conf2).unwrap().mode() & 0o7777,
            0o600,
            "the restored file has the mode of the live file it replaced"
        );
    }

    #[test]
    fn d04_a_controller_and_agent_that_disagree_on_the_unit_change_nothing() {
        // (a) the audit's case: the controller restarts a unit the agent does
        // not even know.
        let mut w = World::new("d04-a");
        w.cfg.chrony_unit = "chronyd.service".to_string();
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(
            matches!(&r, Err(Failure::Refused(m)) if m.contains("chronyd.service")),
            "{r:?}"
        );
        assert_eq!(live(&w, "node-a"), OLD);
        // (b) a different but allowed unit: the old test showed a false
        // success after restarting the wrong service.
        let mut w = World::new("d04-b");
        w.cfg.chrony_unit = "mkg-demo.service".to_string();
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(matches!(&r, Err(Failure::Refused(_))), "{r:?}");
        assert!(w.remote.host("node-a").sys.actions().is_empty());
        assert_eq!(live(&w, "node-a"), OLD);
        // The status shows the mismatch instead of "healthy".
        let shown = show(&w.ctx(), "node-a").unwrap();
        assert!(!shown.unit_matches);
        assert!(shown.problems.iter().any(|p| p.contains("chrony.unit")));
    }

    #[test]
    fn d04_a_restart_that_changes_nothing_is_not_a_proven_restart() {
        let w = World::new("d04-noop");
        w.remote
            .host("node-a")
            .sys
            .restart_does_nothing("chrony.service");
        let r = apply(&w.ctx(), "node-a", NEW, false);
        // The new file was published, the restart proved nothing, the
        // rollback's restart proves nothing either: the end state is open.
        assert!(
            matches!(&r, Err(Failure::Unknown(m)) if m.contains("did not change")),
            "{r:?}"
        );
    }

    #[test]
    fn d06_d07_remote_strings_are_validated_and_never_sliced() {
        use std::rc::Rc;
        // A short, non-ASCII "hash" from a hostile agent: no panic, no use.
        let w = World::new("d07-sha");
        w.remote.inject_when(
            "node-a",
            op::CHRONY_STATE,
            None,
            0,
            100,
            Fault::Rewrite(Rc::new(|data| {
                data["conf"]["sha256"] = json!("a\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}");
            })),
        );
        let shown = show(&w.ctx(), "node-a").unwrap();
        assert_eq!(shown.conf_sha256, None);
        assert!(shown.problems.iter().any(|p| p.contains("malformed hash")));
        assert!(matches!(
            apply(&w.ctx(), "node-a", NEW, false),
            Err(Failure::Refused(_))
        ));
        assert_eq!(short_hash("a\u{e9}"), "(malformed)");
        assert_eq!(short_hash(&sha(OLD)).len(), 12);
        // A backup id that is not one of ours is not accepted.
        let w = World::new("d07-backup-id");
        w.remote.inject(
            "node-a",
            op::CHRONY_BACKUP,
            Fault::Rewrite(Rc::new(|data| {
                data["backup_id"] = json!("../../etc/passwd\u{1b}[31m");
            })),
        );
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(
            matches!(&r, Err(Failure::Failed(m)) if m.contains("backup answer")),
            "{r:?}"
        );
        assert_eq!(live(&w, "node-a"), OLD);
    }

    #[test]
    fn d07_a_stage_id_that_is_not_ours_is_never_sent_back_to_the_node() {
        use std::rc::Rc;
        let w = World::new("d07-stage-id");
        w.remote.inject(
            "node-a",
            op::CHRONY_STAGE,
            Fault::Rewrite(Rc::new(|data| {
                data["stage_id"] = json!("../../etc/cron.d/x");
            })),
        );
        let r = apply(&w.ctx(), "node-a", NEW, false);
        assert!(
            matches!(&r, Err(Failure::Failed(m)) if m.contains("stage answer")),
            "{r:?}"
        );
        assert_eq!(live(&w, "node-a"), OLD);
        assert_eq!(w.remote.count("node-a", op::CHRONY_PUBLISH), 0);
    }
}
