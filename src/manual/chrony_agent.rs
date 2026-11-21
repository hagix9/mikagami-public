//! Node-side chrony configuration operations.
//!
//! None of these file operations is gated on the HA daemon (audit EX-06): the
//! HA daemon never reads or writes the chrony configuration, so the gate
//! protected nothing here and, when the HA daemon appeared in the middle of an
//! `apply`, it stopped the rollback's file restore and left the live file and
//! the running chronyd disagreeing. The only gated chrony step is the
//! `service.control` restart (in `agent.rs`), and the controller checks the
//! exclusion once, before it starts an `apply`.
//!
//! Each operation is small, idempotent where possible, and serialised by one
//! lock (the controller's stage clean-up takes it too, which is what lets it
//! fence a publish whose answer was lost, audit D-01). The publish step is a
//! compare-and-swap on the SHA-256 of the live configuration, so a
//! configuration changed by anybody else between the controller's observation
//! and the publish is never overwritten. The last window (between the hash
//! check and the replacement) is closed where the platform allows it: the
//! staged file is *exchanged* with the live one (`renameat2`
//! `RENAME_EXCHANGE`, Linux), the displaced file is hashed, and a difference
//! puts it back (audit D-02). Without the exchange the window remains and is
//! reported (`exchange: false`). The staged file first receives the owner,
//! mode and extended attributes (ACL, SELinux label) of the live file (audit
//! D-03).
//!
//! File discipline: the live file, its directory and the backup directory
//! must be root-owned (or owned by the configured trust uid), not group/world
//! writable and not symlinks. Staged files are created exclusively with
//! `O_NOFOLLOW` inside the configuration directory (the AppArmor profile of
//! chronyd only reads there) and are published with an atomic `rename`.

use super::agent::{AgentEnv, CheckResult};
use super::fsutil::{self, TrustError};
use super::proto::{MAX_CONTENT, Response, code, op};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(test)]
thread_local! {
    /// Test hook: runs after the hash check and the attribute copy, right
    /// before the live file is replaced.
    pub(crate) static PRE_SWAP: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Stage/validate/restore leftovers older than this are removed by a backup.
const STALE_TEMP_SECS: u64 = 3600;

const LOCK_WAIT: Duration = Duration::from_secs(20);

#[cfg(test)]
thread_local! {
    pub(crate) static LOCK_WAIT_TEST: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

fn lock_wait() -> Duration {
    #[cfg(test)]
    if let Some(wait) = LOCK_WAIT_TEST.with(std::cell::Cell::get) {
        return wait;
    }
    LOCK_WAIT
}
const MAX_CONF_READ: u64 = 1 << 20;
const STAGE_PREFIX: &str = ".mkg-stage-";
const VALIDATE_PREFIX: &str = ".mkg-validate-";
const RESTORE_PREFIX: &str = ".mkg-restore-";
/// A version of the configuration that somebody else wrote inside the window
/// of a replacement and that could not be put back. Nothing in this module
/// deletes such a file: it is not matched by the clean-up of a staged file or
/// by [`sweep_stale_temporaries`] (audit RA-D-01).
const DISPLACED_PREFIX: &str = ".mkg-displaced-";

struct Guard(File);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn conf_dir(env: &AgentEnv) -> Result<PathBuf, String> {
    env.cfg
        .chrony_conf
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "chrony.conf has no directory".to_string())
}

fn trust_message(what: &str, error: TrustError) -> String {
    format!("{what} {error}")
}

/// The directory, the live file and (when present) the backup directory must
/// be trustworthy before anything is read from or written into them.
fn check_trust(env: &AgentEnv) -> Result<(), String> {
    let dir = conf_dir(env)?;
    fsutil::check_trusted_dir(&dir, env.owner_uid)
        .map_err(|e| trust_message("chrony configuration directory", e))?;
    fsutil::check_trusted_file(&env.cfg.chrony_conf, env.owner_uid)
        .map_err(|e| trust_message("chrony configuration file", e))?;
    Ok(())
}

fn lock(env: &AgentEnv) -> Result<Guard, String> {
    fsutil::ensure_private_dir(&env.cfg.backup_dir, env.owner_uid)
        .map_err(|e| trust_message("backup directory", e))?;
    let path = env.cfg.backup_dir.join(".chrony.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("lock file: {e}"))?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Guard(file)),
            Err(fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= lock_wait() {
                    return Err("another chrony operation holds the lock".to_string());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(fs::TryLockError::Error(e)) => return Err(format!("lock: {e}")),
        }
    }
}

fn read_conf(env: &AgentEnv) -> Result<(Vec<u8>, String), String> {
    check_trust(env)?;
    let bytes = fsutil::read_regular_nofollow(&env.cfg.chrony_conf, MAX_CONF_READ)
        .map_err(|e| format!("cannot read the live configuration: {e}"))?;
    let sha = fsutil::sha256_hex(&bytes);
    Ok((bytes, sha))
}

fn valid_content(content: &str) -> Result<(), String> {
    if content.len() > MAX_CONTENT {
        return Err(format!("configuration larger than {MAX_CONTENT} bytes"));
    }
    if content.contains('\0') {
        return Err("configuration contains a NUL byte".to_string());
    }
    Ok(())
}

/// A stage id is 16 hex digits (older controllers and agents) or 32: 16 random
/// ones followed by the first 16 of the content hash.
pub(crate) fn stage_id_ok(value: &str) -> bool {
    matches!(value.len(), 16 | 32)
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The 16 hex digits of the content hash in a 32-digit id (`None` for the
/// older 16-digit form, which says nothing about the content).
fn id_hash16(stage_id: &str) -> Option<&str> {
    (stage_id.len() == 32).then(|| &stage_id[16..])
}

/// Whether the file at `path` is a regular file whose content hash starts with
/// `hash16`.
fn content_has_hash16(path: &Path, hash16: &str) -> bool {
    matches!(
        fsutil::read_regular_nofollow(path, MAX_CONF_READ),
        Ok(bytes) if fsutil::sha256_hex(&bytes).starts_with(hash16)
    )
}

/// For a name `.mkg-stage-<32 hex>.conf` / `.mkg-restore-<32 hex>.conf`: the
/// hash digits that the name promises about the content.
fn name_hash16(name: &str) -> Option<String> {
    let rest = name
        .strip_prefix(STAGE_PREFIX)
        .or_else(|| name.strip_prefix(RESTORE_PREFIX))?;
    let id = rest.strip_suffix(".conf")?;
    (stage_id_ok(id) && id.len() == 32).then(|| id[16..].to_string())
}

pub(crate) fn backup_id_ok(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("chrony-") else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(".conf") else {
        return false;
    };
    let Some((secs, rand)) = rest.split_once('-') else {
        return false;
    };
    (1..=12).contains(&secs.len())
        && secs.bytes().all(|b| b.is_ascii_digit())
        && rand.len() == 8
        && rand.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn fail(id: &str, message: impl Into<String>) -> Response {
    Response::err(id, code::FAILED, message)
}

fn refuse(id: &str, message: impl Into<String>) -> Response {
    Response::err(id, code::REFUSED, message)
}

fn arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string argument {key:?}"))
}

pub(crate) fn handle(env: &AgentEnv, id: &str, name: &str, args: &Value) -> Response {
    let bad = |message: String| Response::err(id, code::BAD_REQUEST, message);
    match name {
        op::CHRONY_STATE => state(env, id),
        op::CHRONY_READ => read(env, id),
        op::CHRONY_VALIDATE => match arg(args, "content") {
            Ok(content) => validate(env, id, content),
            Err(e) => bad(e),
        },
        op::CHRONY_BACKUP => match arg(args, "expect_sha256") {
            Ok(sha) if fsutil::is_sha256_hex(sha) => backup(env, id, sha),
            Ok(_) => bad("expect_sha256 is not a SHA-256".to_string()),
            Err(e) => bad(e),
        },
        op::CHRONY_STAGE => match (arg(args, "content"), arg(args, "sha256")) {
            (Ok(content), Ok(sha)) if fsutil::is_sha256_hex(sha) => stage(env, id, content, sha),
            (Ok(_), Ok(_)) => bad("sha256 is not a SHA-256".to_string()),
            (Err(e), _) | (_, Err(e)) => bad(e),
        },
        op::CHRONY_PUBLISH => match (
            arg(args, "stage_id"),
            arg(args, "expect_current"),
            arg(args, "expect_new"),
        ) {
            (Ok(stage_id), Ok(current), Ok(new))
                if stage_id_ok(stage_id)
                    && fsutil::is_sha256_hex(current)
                    && fsutil::is_sha256_hex(new) =>
            {
                publish(env, id, stage_id, current, new)
            }
            (Ok(_), Ok(_), Ok(_)) => bad("malformed identifier or hash".to_string()),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => bad(e),
        },
        op::CHRONY_RESTORE => match (
            arg(args, "backup_id"),
            arg(args, "expect_backup"),
            arg(args, "expect_current"),
        ) {
            (Ok(backup_id), Ok(backup), Ok(current))
                if backup_id_ok(backup_id)
                    && fsutil::is_sha256_hex(backup)
                    && fsutil::is_sha256_hex(current) =>
            {
                restore(env, id, backup_id, backup, current)
            }
            (Ok(_), Ok(_), Ok(_)) => bad("malformed identifier or hash".to_string()),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => bad(e),
        },
        op::CHRONY_CLEANUP => match arg(args, "stage_id") {
            Ok(stage_id) if stage_id_ok(stage_id) => cleanup(env, id, stage_id),
            Ok(_) => bad("malformed stage id".to_string()),
            Err(e) => bad(e),
        },
        other => bad(format!("unknown chrony operation {other:?}")),
    }
}

fn state(env: &AgentEnv, id: &str) -> Response {
    let conf = match read_conf(env) {
        Ok((_, sha)) => json!({"sha256": sha, "trusted": true}),
        Err(e) => json!({"sha256": Value::Null, "trusted": false, "problem": e}),
    };
    let unit = match env.sys.service_state(&env.cfg.chrony_unit) {
        Ok(state) => json!({
            "name": env.cfg.chrony_unit,
            "active": state.is_active(),
            "active_state": state.active_state,
            "sub_state": state.sub_state,
        }),
        Err(e) => json!({"name": env.cfg.chrony_unit, "active": Value::Null, "problem": e}),
    };
    let tracking = match env.sys.chronyc_tracking() {
        Ok(text) => json!({"ok": true, "text": text}),
        Err(e) => json!({"ok": false, "problem": e}),
    };
    Response::ok(
        id,
        json!({
            "conf_path": env.cfg.chrony_conf.display().to_string(),
            "conf": conf,
            "unit": unit,
            "tracking": tracking,
            "displaced": displaced_report(env),
        }),
    )
}

/// The versions of the configuration that somebody else wrote and that this
/// module keeps (`.mkg-displaced-*`): how many, and the first names, so that
/// an operator sees them in `chronyd show` and an apply can refuse to bury
/// them (final R7, R-3). Nothing here deletes anything.
fn displaced_report(env: &AgentEnv) -> Value {
    const NAMES_LISTED: usize = 16;
    let Ok(dir) = conf_dir(env) else {
        return json!({"count": 0, "names": [], "readable": false});
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return json!({"count": 0, "names": [], "readable": false});
    };
    // The kept versions, and the leftovers (`.mkg-stage-*`, `.mkg-restore-*`)
    // whose content is not what their name promises: those hold somebody's
    // version too (an agent that died inside `swap_in`) and the controller must
    // see them before it decides anything (audit A2 MEDIUM-1). A leftover of
    // ours has the content its name promises and is not listed.
    let mut names: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(DISPLACED_PREFIX) {
            names.extend([name]);
        } else if let Some(hash16) = name_hash16(&name)
            && fs::symlink_metadata(entry.path()).is_ok_and(|m| m.is_file())
            && !content_has_hash16(&entry.path(), &hash16)
            // Already kept under a displaced name (a second name of the same
            // file): that name is listed, this one is not counted twice.
            && existing_displaced_name_of(&entry.path()).is_none()
        {
            names.extend([name]);
        }
    }
    names.sort();
    let count = names.len();
    names.truncate(NAMES_LISTED);
    json!({"count": count, "names": names, "readable": true})
}

fn read(env: &AgentEnv, id: &str) -> Response {
    match read_conf(env) {
        Ok((bytes, sha)) => match String::from_utf8(bytes) {
            Ok(text) => Response::ok(id, json!({"content": text, "sha256": sha})),
            Err(_) => fail(id, "the live configuration is not valid UTF-8"),
        },
        Err(e) => fail(id, e),
    }
}

fn validate(env: &AgentEnv, id: &str, content: &str) -> Response {
    if let Err(e) = valid_content(content) {
        return refuse(id, e);
    }
    let dir = match conf_dir(env) {
        Ok(dir) => dir,
        Err(e) => return fail(id, e),
    };
    if let Err(e) = fsutil::check_trusted_dir(&dir, env.owner_uid) {
        return refuse(id, trust_message("chrony configuration directory", e));
    }
    let path = dir.join(format!(
        "{VALIDATE_PREFIX}{}.conf",
        super::proto::random_hex(8)
    ));
    if let Err(e) = fsutil::write_new_durable(&path, content.as_bytes(), 0o644) {
        return fail(id, format!("cannot stage the validation copy: {e}"));
    }
    let verdict = env.sys.chronyd_check(&path);
    let removal = fs::remove_file(&path);
    if let Err(e) = removal {
        return fail(id, format!("validation copy could not be removed: {e}"));
    }
    match verdict {
        CheckResult::Valid => Response::ok(id, json!({"valid": true})),
        CheckResult::Rejected(message) => {
            Response::ok(id, json!({"valid": false, "message": message}))
        }
        CheckResult::ToolFailure(message) => {
            fail(id, format!("chronyd could not check the file: {message}"))
        }
    }
}

fn backup(env: &AgentEnv, id: &str, expect_sha: &str) -> Response {
    let _guard = match lock(env) {
        Ok(guard) => guard,
        Err(e) => return fail(id, e),
    };
    let (bytes, sha) = match read_conf(env) {
        Ok(read) => read,
        Err(e) => return fail(id, e),
    };
    if sha != expect_sha {
        return refuse(id, "the live configuration changed since it was observed");
    }
    let (swept, quarantined) = sweep_stale_temporaries(env);
    let backup_id = format!(
        "chrony-{}-{}.conf",
        (env.now)(),
        super::proto::random_hex(4)
    );
    let path = env.cfg.backup_dir.join(&backup_id);
    if let Err(e) = fsutil::write_new_durable(&path, &bytes, 0o600) {
        return fail(id, format!("cannot write the backup: {e}"));
    }
    match fsutil::read_regular_nofollow(&path, MAX_CONF_READ) {
        Ok(copy) if fsutil::sha256_hex(&copy) == sha => Response::ok(
            id,
            json!({"backup_id": backup_id, "sha256": sha, "swept": swept, "quarantined": quarantined}),
        ),
        _ => {
            let _ = fs::remove_file(&path);
            fail(id, "the backup does not match the live configuration")
        }
    }
}

/// Remove leftovers of interrupted operations (`.mkg-stage-*`,
/// `.mkg-validate-*`, `.mkg-restore-*`) that are regular files older than
/// [`STALE_TEMP_SECS`] (audit D-08). Called under the lock, from `backup`, so
/// it never races a stage that is about to be published. Backups are not
/// removed (retention is the operator's decision; see LIMITATIONS).
fn sweep_stale_temporaries(env: &AgentEnv) -> (usize, Vec<String>) {
    let Ok(dir) = conf_dir(env) else {
        return (0, Vec::new());
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return (0, Vec::new());
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0;
    let mut quarantined = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if ![STAGE_PREFIX, VALIDATE_PREFIX, RESTORE_PREFIX]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let old = meta
            .modified()
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age.as_secs() >= STALE_TEMP_SECS);
        if !(meta.is_file() && old) {
            continue;
        }
        // A leftover whose content is not what its name promises is somebody's
        // version: it is kept under a protected name, not deleted (audit H-2).
        if let Some(hash16) = name_hash16(&name)
            && !content_has_hash16(&entry.path(), &hash16)
        {
            let (kept, _) = quarantine(&entry.path());
            quarantined.extend([kept.display().to_string()]);
            continue;
        }
        if fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    (removed, quarantined)
}

enum SwapError {
    /// The live file was not the one that was observed; it is back in place.
    Refused(String),
    Failed(String),
    /// The live file was not the one that was observed and it could NOT be put
    /// back: the live path holds the new content and the other version is
    /// kept (the text says where). Callers must not delete it.
    NotPutBack(String),
}

/// The name under which a displaced version is kept: the staged file's name
/// with the prefix of this kind of file; `n` > 0 gives the next free name
/// when that one is taken (`-1`, `-2`, ...).
fn displaced_path_n(staged: &Path, n: u32) -> PathBuf {
    let name = staged
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = name.trim_start_matches('.');
    if n == 0 {
        staged.with_file_name(format!("{DISPLACED_PREFIX}{stem}"))
    } else {
        staged.with_file_name(format!("{DISPLACED_PREFIX}{stem}-{n}"))
    }
}

/// How many names are tried for one displaced version.
const DISPLACED_NAME_TRIES: u32 = 16;

fn already_exists(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::AlreadyExists
}

/// A second name (hard link) for the file at `staged` under the first free
/// displaced name. Creating a link never replaces anything: a taken name
/// (file, directory, link) moves on to the next one.
fn keep_by_link(staged: &Path) -> Result<PathBuf, std::io::Error> {
    let mut last = std::io::Error::from(std::io::ErrorKind::AlreadyExists);
    for n in 0..DISPLACED_NAME_TRIES {
        let keep = displaced_path_n(staged, n);
        match fsutil::link_new(staged, &keep) {
            Ok(()) => return Ok(keep),
            Err(e) if already_exists(&e) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Move the file at `staged` to the first free displaced name without
/// replacing anything (needs no support for hard links). With a kernel that
/// cannot refuse to replace, a plain rename to a name that is absent at the
/// moment is the last resort.
fn keep_by_move(staged: &Path) -> Result<PathBuf, std::io::Error> {
    let mut last = std::io::Error::from(std::io::ErrorKind::AlreadyExists);
    for n in 0..DISPLACED_NAME_TRIES {
        let keep = displaced_path_n(staged, n);
        let moved = match fsutil::rename_noreplace(staged, &keep) {
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                fsutil::rename_to_absent_name(staged, &keep)
            }
            other => other,
        };
        match moved {
            Ok(()) => return Ok(keep),
            Err(e) if already_exists(&e) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

const FATE_PROTECTED: &str = "nothing deletes it";
const FATE_MOVED: &str = "nothing deletes it (no second name could be made, so the file was MOVED there; the staged name no longer exists)";
const FATE_UNPROTECTED: &str = "NO protected name could be made (no link, no move), so it stays under this staged name: the clean-up of this stage id and the sweep leave a file whose content is not the staged content alone, but no other name protects it; copy it away NOW";

/// Keep the file at `staged` (a version nobody asked us to write) under a name
/// that no clean-up and no sweep acts on: a hard link under the first free
/// displaced name, else a move without replacing; only when both are refused
/// does it stay under the staged name, made to look fresh, and the text says
/// that this name is not protected (final R7, R-3). Returns the name and what
/// happens to it.
fn protect_displaced(staged: &Path) -> (PathBuf, &'static str) {
    if let Ok(keep) = keep_by_link(staged) {
        let _ = fs::remove_file(staged);
        return (keep, FATE_PROTECTED);
    }
    if let Ok(keep) = keep_by_move(staged) {
        return (keep, FATE_MOVED);
    }
    // Make it look fresh so that the sweep of stale temporaries (which goes by
    // age) leaves it alone for a while.
    if let Ok(file) = fs::OpenOptions::new().append(true).open(staged) {
        let _ = file.set_modified(std::time::SystemTime::now());
    }
    (staged.to_path_buf(), FATE_UNPROTECTED)
}

/// The name under which `staged` (a hard link or the very file) is already
/// kept, if any: a displaced name of the same inode.
fn existing_displaced_name_of(staged: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(staged).ok()?;
    let dir = staged.parent()?;
    for entry in fs::read_dir(dir).ok()?.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(DISPLACED_PREFIX)
        {
            continue;
        }
        if let Ok(other) = fs::symlink_metadata(entry.path())
            && other.dev() == meta.dev()
            && other.ino() == meta.ino()
        {
            return Some(entry.path());
        }
    }
    None
}

/// A staged or restore file whose content is not what its name promises (the
/// name is that of a leftover of ours, the content is somebody's version: the
/// agent died inside `swap_in`, or a third version came back). A clean-up or a
/// sweep must not delete it; it gets a protected name instead, and the staged
/// name goes away only when the data has another name (final R7, audit H-2).
/// Returns the name that now holds it and what is true of that name.
fn quarantine(staged: &Path) -> (PathBuf, &'static str) {
    if let Some(existing) = existing_displaced_name_of(staged) {
        let _ = fs::remove_file(staged);
        return (existing, FATE_PROTECTED);
    }
    if let Ok(keep) = keep_by_move(staged) {
        return (keep, FATE_MOVED);
    }
    if let Ok(keep) = keep_by_link(staged) {
        let _ = fs::remove_file(staged);
        return (keep, FATE_PROTECTED);
    }
    if let Ok(file) = fs::OpenOptions::new().append(true).open(staged) {
        let _ = file.set_modified(std::time::SystemTime::now());
    }
    (staged.to_path_buf(), FATE_UNPROTECTED)
}

#[cfg(test)]
thread_local! {
    /// Test hook: runs between the two exchanges of [`swap_in`] (after the
    /// displaced file has been kept, before it is put back).
    pub(crate) static MID_SWAP: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
    /// Test hook: the agent "dies" (a panic that nothing catches inside the
    /// module) at this point of [`swap_in`]: 1 after the first exchange, 2
    /// after the second name was made, 3 after the put-back.
    pub(crate) static CRASH_AT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn crash_point(point: u8) {
    if CRASH_AT.with(std::cell::Cell::get) == point {
        panic!("simulated agent crash at point {point}");
    }
}

/// Put `staged` in the place of `live`. Returns whether the atomic exchange
/// was used. With the exchange, the file that was displaced is hashed and must
/// be the one the compare-and-swap observed; otherwise the exchange is undone
/// (audit D-02). `ours` is the hash of the content of `staged`: after the
/// undo, the file that comes back to `staged` must have that content; if it
/// does not, somebody wrote a third version inside the window and that one is
/// kept too (final R7, R-10). Without the exchange (platform or filesystem), a
/// plain rename is the fallback and the small window between the hash check
/// and the rename stays.
fn swap_in(
    staged: &Path,
    live: &Path,
    expect_current: &str,
    ours: &str,
) -> Result<bool, SwapError> {
    match fsutil::exchange(staged, live) {
        Ok(()) => {
            #[cfg(test)]
            crash_point(1);
            // The other file is now at `staged`. Before anything else is read
            // or decided, give it a second name that nothing deletes, so that
            // a failure or a death of this process from here on cannot lose it
            // (audit RA-D-01; the order is final R7, R-4). A failure to make
            // the name is not an error yet: the ordinary case needs no name.
            let held = keep_by_link(staged).ok();
            #[cfg(test)]
            crash_point(2);
            let displaced = fsutil::read_regular_nofollow(staged, MAX_CONF_READ);
            if matches!(&displaced, Ok(bytes) if fsutil::sha256_hex(bytes) == expect_current) {
                if let Some(name) = &held {
                    let _ = fs::remove_file(name);
                }
                let _ = fs::remove_file(staged);
                return Ok(true);
            }
            #[cfg(test)]
            MID_SWAP.with(|hook| {
                if let Some(f) = hook.borrow().as_ref() {
                    f();
                }
            });
            match fsutil::exchange(staged, live) {
                Ok(()) => {
                    #[cfg(test)]
                    crash_point(3);
                    let back_is_ours = matches!(
                        fsutil::read_regular_nofollow(staged, MAX_CONF_READ),
                        Ok(bytes) if fsutil::sha256_hex(&bytes) == ours
                    );
                    if back_is_ours {
                        // The version is back at the live path (the second
                        // name is just another name of that file).
                        if let Some(name) = &held {
                            let _ = fs::remove_file(name);
                        }
                        return Err(SwapError::Refused(
                            "the live configuration was changed while it was being replaced; the \
                             change was put back, nothing was overwritten"
                                .to_string(),
                        ));
                    }
                    // The file that came back is neither ours nor the one we
                    // displaced: a third version was written inside the window.
                    // The first foreign version is live again; keep the third.
                    if let Some(name) = &held {
                        let _ = fs::remove_file(name);
                    }
                    let (kept, fate) = protect_displaced(staged);
                    Err(SwapError::NotPutBack(format!(
                        "A newer version written by somebody else appeared while the first one was \
                         being put back. The live configuration is again the first version that \
                         somebody else wrote; the newest one is kept as {}; {fate}. Compare them \
                         before you decide anything",
                        kept.display()
                    )))
                }
                Err(e) => {
                    let (kept, fate) = match held {
                        // The data has its protected name: the staged name goes,
                        // so that exactly one name is left to look at.
                        Some(name) => {
                            let _ = fs::remove_file(staged);
                            (name, FATE_PROTECTED)
                        }
                        None => protect_displaced(staged),
                    };
                    Err(SwapError::NotPutBack(format!(
                        "The version written by somebody else is kept as {}; {fate}. \
                         The live configuration was changed while it was being replaced and \
                         could NOT be put back ({e}); the live file now holds the content being put in \
                         (candidate or backup)",
                        kept.display()
                    )))
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => fs::rename(staged, live)
            .map(|()| false)
            .map_err(|e| SwapError::Failed(format!("atomic publish failed: {e}"))),
        Err(e) => Err(SwapError::Failed(format!("atomic exchange failed: {e}"))),
    }
}

fn attributes_json(attributes: &fsutil::Attributes, exchanged: bool) -> Value {
    json!({
        "mode": attributes.mode_text(),
        "uid": attributes.uid,
        "gid": attributes.gid,
        "xattrs": attributes.xattrs,
        "xattrs_supported": attributes.xattrs_supported,
        "exchange": exchanged,
    })
}

fn stage(env: &AgentEnv, id: &str, content: &str, expect_sha: &str) -> Response {
    if let Err(e) = valid_content(content) {
        return refuse(id, e);
    }
    if fsutil::sha256_hex(content.as_bytes()) != expect_sha {
        return fail(id, "the received content does not match its hash");
    }
    let dir = match conf_dir(env) {
        Ok(dir) => dir,
        Err(e) => return fail(id, e),
    };
    if let Err(e) = fsutil::check_trusted_dir(&dir, env.owner_uid) {
        return refuse(id, trust_message("chrony configuration directory", e));
    }
    // The id carries the first 16 hex digits of the content hash: a clean-up or
    // a sweep that finds anything else under this name knows that the file is
    // not the one that was staged and keeps it (final R7, audit H-2).
    let stage_id = format!("{}{}", super::proto::random_hex(8), &expect_sha[..16]);
    let path = dir.join(format!("{STAGE_PREFIX}{stage_id}.conf"));
    if let Err(e) = fsutil::write_new_durable(&path, content.as_bytes(), 0o644) {
        return fail(id, format!("cannot write the staged file: {e}"));
    }
    Response::ok(id, json!({"stage_id": stage_id}))
}

fn publish(
    env: &AgentEnv,
    id: &str,
    stage_id: &str,
    expect_current: &str,
    expect_new: &str,
) -> Response {
    let _guard = match lock(env) {
        Ok(guard) => guard,
        Err(e) => return fail(id, e),
    };
    let dir = match conf_dir(env) {
        Ok(dir) => dir,
        Err(e) => return fail(id, e),
    };
    let (_, current) = match read_conf(env) {
        Ok(read) => read,
        Err(e) => return fail(id, e),
    };
    if current != expect_current {
        // Already published by a retried request of ours?
        if current == expect_new {
            return Response::ok(id, json!({"sha256": current, "already": true}));
        }
        return refuse(
            id,
            "the live configuration changed since it was observed; not overwriting",
        );
    }
    let staged = dir.join(format!("{STAGE_PREFIX}{stage_id}.conf"));
    if fsutil::check_trusted_file(&staged, env.owner_uid).is_err() {
        return fail(id, "the staged file is missing or untrusted");
    }
    match fsutil::read_regular_nofollow(&staged, MAX_CONF_READ) {
        Ok(bytes) if fsutil::sha256_hex(&bytes) == expect_new => {}
        _ => return fail(id, "the staged file does not match the expected hash"),
    }
    let attributes = match fsutil::copy_attributes(&env.cfg.chrony_conf, &staged) {
        Ok(attributes) => attributes,
        Err(e) => {
            return fail(
                id,
                format!("cannot give the staged file the attributes of the live file: {e}"),
            );
        }
    };
    #[cfg(test)]
    PRE_SWAP.with(|hook| {
        if let Some(f) = hook.borrow().as_ref() {
            f();
        }
    });
    let exchanged = match swap_in(&staged, &env.cfg.chrony_conf, expect_current, expect_new) {
        Ok(exchanged) => exchanged,
        Err(SwapError::Refused(m)) => return refuse(id, m),
        Err(SwapError::Failed(m)) => return fail(id, m),
        Err(SwapError::NotPutBack(m)) => return Response::err(id, code::DISPLACED_KEPT, m),
    };
    if let Err(e) = fsutil::fsync_dir(&dir) {
        return fail(id, format!("publish could not be made durable: {e}"));
    }
    match read_conf(env) {
        Ok((_, sha)) if sha == expect_new => {
            let mut data = attributes_json(&attributes, exchanged);
            data["sha256"] = json!(sha);
            Response::ok(id, data)
        }
        Ok((_, sha)) => fail(id, format!("published file hash differs ({sha})")),
        Err(e) => fail(id, e),
    }
}

fn restore(
    env: &AgentEnv,
    id: &str,
    backup_id: &str,
    expect_backup: &str,
    expect_current: &str,
) -> Response {
    let _guard = match lock(env) {
        Ok(guard) => guard,
        Err(e) => return fail(id, e),
    };
    let dir = match conf_dir(env) {
        Ok(dir) => dir,
        Err(e) => return fail(id, e),
    };
    let backup_path = env.cfg.backup_dir.join(backup_id);
    if let Err(e) = fsutil::check_trusted_file(&backup_path, env.owner_uid) {
        return fail(id, trust_message("backup file", e));
    }
    let bytes = match fsutil::read_regular_nofollow(&backup_path, MAX_CONF_READ) {
        Ok(bytes) => bytes,
        Err(e) => return fail(id, format!("cannot read the backup: {e}")),
    };
    if fsutil::sha256_hex(&bytes) != expect_backup {
        return fail(id, "the backup does not match its recorded hash");
    }
    let (_, current) = match read_conf(env) {
        Ok(read) => read,
        Err(e) => return fail(id, e),
    };
    if current == expect_backup {
        return Response::ok(id, json!({"sha256": current, "already": true}));
    }
    if current != expect_current {
        return refuse(
            id,
            "the live configuration is neither ours nor the backup; not overwriting",
        );
    }
    let staged = dir.join(format!(
        "{RESTORE_PREFIX}{}{}.conf",
        super::proto::random_hex(8),
        &expect_backup[..16]
    ));
    if let Err(e) = fsutil::write_new_durable(&staged, &bytes, 0o644) {
        return fail(id, format!("cannot stage the restore copy: {e}"));
    }
    let attributes = match fsutil::copy_attributes(&env.cfg.chrony_conf, &staged) {
        Ok(attributes) => attributes,
        Err(e) => {
            let _ = fs::remove_file(&staged);
            return fail(
                id,
                format!("cannot give the restore copy the attributes of the live file: {e}"),
            );
        }
    };
    #[cfg(test)]
    PRE_SWAP.with(|hook| {
        if let Some(f) = hook.borrow().as_ref() {
            f();
        }
    });
    let exchanged = match swap_in(&staged, &env.cfg.chrony_conf, expect_current, expect_backup) {
        Ok(exchanged) => exchanged,
        Err(SwapError::Refused(m)) => {
            let _ = fs::remove_file(&staged);
            return refuse(id, m);
        }
        Err(SwapError::Failed(m)) => {
            let _ = fs::remove_file(&staged);
            return fail(id, m);
        }
        // The staged path may hold the version somebody else wrote: it is
        // kept, never removed here (audit RA-D-01).
        Err(SwapError::NotPutBack(m)) => return Response::err(id, code::DISPLACED_KEPT, m),
    };
    if let Err(e) = fsutil::fsync_dir(&dir) {
        return fail(id, format!("restore could not be made durable: {e}"));
    }
    match read_conf(env) {
        Ok((_, sha)) if sha == expect_backup => {
            let mut data = attributes_json(&attributes, exchanged);
            data["sha256"] = json!(sha);
            Response::ok(id, data)
        }
        Ok((_, sha)) => fail(id, format!("restored file hash differs ({sha})")),
        Err(e) => fail(id, e),
    }
}

/// Remove a staged file **under the lock**. Besides tidying up, this is the
/// fence of the controller (audit D-01): when the answer to a publish was
/// lost, the publish may still be running or queued on the node. Once this
/// call has returned, any such publish has either finished (the live hash
/// shows it) or can no longer find its staged file and fails.
fn cleanup(env: &AgentEnv, id: &str, stage_id: &str) -> Response {
    let _guard = match lock(env) {
        Ok(guard) => guard,
        Err(e) => return fail(id, e),
    };
    let dir = match conf_dir(env) {
        Ok(dir) => dir,
        Err(e) => return fail(id, e),
    };
    let path = dir.join(format!("{STAGE_PREFIX}{stage_id}.conf"));
    // A 32-digit id promises the content: anything else under the name is a
    // version somebody else wrote (the agent died inside `swap_in`, or a third
    // version came back) and is kept, not deleted (final R7, audit H-2). The
    // 16-digit form of older controllers makes no promise and is removed as before.
    if let Some(hash16) = id_hash16(stage_id) {
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Response::ok(id, json!({"removed": false}));
            }
            Err(e) => return fail(id, format!("cannot look at the staged file: {e}")),
            Ok(meta) if !meta.is_file() => {
                return Response::ok(
                    id,
                    json!({
                        "removed": false,
                        "kept": path.display().to_string(),
                        "note": "not a regular file; left untouched",
                    }),
                );
            }
            Ok(_) if !content_has_hash16(&path, hash16) => {
                let (kept, fate) = quarantine(&path);
                return Response::ok(
                    id,
                    json!({
                        "removed": false,
                        "kept": kept.display().to_string(),
                        "note": fate,
                    }),
                );
            }
            Ok(_) => {}
        }
    }
    match fs::remove_file(&path) {
        Ok(()) => Response::ok(id, json!({"removed": true})),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Response::ok(id, json!({"removed": false}))
        }
        Err(e) => fail(id, format!("cannot remove the staged file: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual::testkit::{FakeSystem, agent_env, req};
    use std::os::unix::fs::{PermissionsExt, symlink};

    const OLD: &str = "pool 2.pool.ntp.org iburst\n";
    const NEW: &str = "pool time.example.invalid iburst\n";

    fn setup(label: &str) -> (AgentEnv, FakeSystem, PathBuf) {
        let sys = FakeSystem::default();
        let (env, dir) = agent_env(label, sys.clone());
        fs::write(&env.cfg.chrony_conf, OLD).unwrap();
        fs::set_permissions(&env.cfg.chrony_conf, fs::Permissions::from_mode(0o644)).unwrap();
        (env, sys, dir)
    }

    fn call(env: &AgentEnv, name: &str, args: Value) -> Response {
        crate::manual::agent::handle(env, &req(name, args))
    }

    fn sha(text: &str) -> String {
        fsutil::sha256_hex(text.as_bytes())
    }

    #[test]
    fn state_and_read_report_the_live_hash() {
        let (env, _sys, dir) = setup("chrony-state");
        let state = call(&env, op::CHRONY_STATE, json!({}));
        assert_eq!(state.data["conf"]["sha256"], sha(OLD));
        assert_eq!(state.data["unit"]["active"], true);
        let read = call(&env, op::CHRONY_READ, json!({}));
        assert_eq!(read.data["content"], OLD);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn state_flags_an_untrusted_or_symlinked_configuration() {
        let (env, _sys, dir) = setup("chrony-untrusted");
        fs::set_permissions(&env.cfg.chrony_conf, fs::Permissions::from_mode(0o666)).unwrap();
        let state = call(&env, op::CHRONY_STATE, json!({}));
        assert_eq!(state.data["conf"]["trusted"], false);
        assert!(!call(&env, op::CHRONY_READ, json!({})).ok);
        fs::set_permissions(&env.cfg.chrony_conf, fs::Permissions::from_mode(0o644)).unwrap();
        let real = dir.join("real.conf");
        fs::rename(&env.cfg.chrony_conf, &real).unwrap();
        symlink(&real, &env.cfg.chrony_conf).unwrap();
        let state = call(&env, op::CHRONY_STATE, json!({}));
        assert_eq!(state.data["conf"]["trusted"], false);
        let backup = call(&env, op::CHRONY_BACKUP, json!({"expect_sha256": sha(OLD)}));
        assert!(!backup.ok, "no backup of an untrusted file");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn validate_reports_accept_and_reject_and_leaves_no_residue() {
        let (env, sys, dir) = setup("chrony-validate");
        let conf_dir = env.cfg.chrony_conf.parent().unwrap().to_path_buf();
        let entries = || fs::read_dir(&conf_dir).unwrap().count();
        let before = entries();
        let ok = call(&env, op::CHRONY_VALIDATE, json!({"content": NEW}));
        assert_eq!(ok.data["valid"], true);
        sys.reject_config("bogus");
        let rejected = call(
            &env,
            op::CHRONY_VALIDATE,
            json!({"content": "bogus directive\n"}),
        );
        assert!(rejected.ok);
        assert_eq!(rejected.data["valid"], false);
        assert!(
            rejected.data["message"]
                .as_str()
                .unwrap()
                .contains("rejected")
        );
        let nul = call(&env, op::CHRONY_VALIDATE, json!({"content": "a\u{0}b"}));
        assert_eq!(nul.error.unwrap().code, code::REFUSED);
        let huge = call(
            &env,
            op::CHRONY_VALIDATE,
            json!({"content": "x".repeat(MAX_CONTENT + 1)}),
        );
        assert_eq!(huge.error.unwrap().code, code::REFUSED);
        sys.fail_check();
        assert!(!call(&env, op::CHRONY_VALIDATE, json!({"content": NEW})).ok);
        assert_eq!(entries(), before, "validation copies are always removed");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn file_operations_run_while_an_ha_daemon_runs() {
        // Audit EX-06: the HA daemon cannot touch these files, so its
        // presence must not stop a publish half way or the rollback restore.
        let (env, sys, dir) = setup("chrony-ha-running");
        sys.unmask("mikagami.service");
        sys.set_service("mikagami.service", "active");
        sys.set_ha_processes(&["pid 9: mikagami daemon run"]);
        let backup = call(&env, op::CHRONY_BACKUP, json!({"expect_sha256": sha(OLD)}));
        assert!(backup.ok, "{backup:?}");
        let stage = call(
            &env,
            op::CHRONY_STAGE,
            json!({"content": NEW, "sha256": sha(NEW)}),
        );
        assert!(stage.ok, "{stage:?}");
        let publish = call(
            &env,
            op::CHRONY_PUBLISH,
            json!({"stage_id": stage.data["stage_id"], "expect_current": sha(OLD), "expect_new": sha(NEW)}),
        );
        assert!(publish.ok, "{publish:?}");
        let restore = call(
            &env,
            op::CHRONY_RESTORE,
            json!({"backup_id": backup.data["backup_id"], "expect_backup": sha(OLD), "expect_current": sha(NEW)}),
        );
        assert!(restore.ok, "{restore:?}");
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), OLD);
        // The restart of the unit is the one gated step, and it says why.
        let restart = call(
            &env,
            op::SERVICE_CONTROL,
            json!({"unit": "chrony.service", "action": "restart"}),
        );
        let error = restart.error.expect("refused");
        assert_eq!(error.code, code::REFUSED);
        assert!(error.message.contains("running"), "{}", error.message);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn full_publish_flow_is_compare_and_swap() {
        let (env, _sys, dir) = setup("chrony-publish");
        let backup = call(&env, op::CHRONY_BACKUP, json!({"expect_sha256": sha(OLD)}));
        assert!(backup.ok, "{backup:?}");
        let backup_id = backup.data["backup_id"].as_str().unwrap().to_string();
        assert_eq!(backup.data["sha256"], sha(OLD));
        let stage = call(
            &env,
            op::CHRONY_STAGE,
            json!({"content": NEW, "sha256": sha(NEW)}),
        );
        let stage_id = stage.data["stage_id"].as_str().unwrap().to_string();
        let publish = |current: &str| {
            call(
                &env,
                op::CHRONY_PUBLISH,
                json!({"stage_id": stage_id, "expect_current": current, "expect_new": sha(NEW)}),
            )
        };
        // Somebody else changed the file after our observation.
        fs::write(&env.cfg.chrony_conf, "server other.example.invalid\n").unwrap();
        let refused = publish(&sha(OLD));
        assert_eq!(refused.error.unwrap().code, code::REFUSED);
        assert_eq!(
            fs::read_to_string(&env.cfg.chrony_conf).unwrap(),
            "server other.example.invalid\n"
        );
        fs::write(&env.cfg.chrony_conf, OLD).unwrap();
        let done = publish(&sha(OLD));
        assert!(done.ok, "{done:?}");
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), NEW);
        let mode = fs::metadata(&env.cfg.chrony_conf)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
        // A retried publish after success is recognised, not an error.
        assert!(
            call(
                &env,
                op::CHRONY_PUBLISH,
                json!({"stage_id": stage_id, "expect_current": sha(OLD), "expect_new": sha(NEW)}),
            )
            .data["already"]
                .as_bool()
                .unwrap()
        );
        // Restore only when the live file is ours.
        let restore = |current: &str| {
            call(
                &env,
                op::CHRONY_RESTORE,
                json!({"backup_id": backup_id, "expect_backup": sha(OLD), "expect_current": current}),
            )
        };
        let stranger = restore(&sha("something else\n"));
        assert_eq!(stranger.error.unwrap().code, code::REFUSED);
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), NEW);
        assert!(restore(&sha(NEW)).ok);
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), OLD);
        // Restoring again is idempotent.
        assert!(restore(&sha(NEW)).data["already"].as_bool().unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn backup_requires_the_observed_hash_and_is_private() {
        let (env, _sys, dir) = setup("chrony-backup");
        let stale = call(
            &env,
            op::CHRONY_BACKUP,
            json!({"expect_sha256": sha("other")}),
        );
        assert_eq!(stale.error.unwrap().code, code::REFUSED);
        let backup = call(&env, op::CHRONY_BACKUP, json!({"expect_sha256": sha(OLD)}));
        let path = env
            .cfg
            .backup_dir
            .join(backup.data["backup_id"].as_str().unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), OLD);
        let second = call(&env, op::CHRONY_BACKUP, json!({"expect_sha256": sha(OLD)}));
        assert_ne!(
            second.data["backup_id"], backup.data["backup_id"],
            "unique backups"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stage_checks_hash_size_and_does_not_depend_on_the_ha_daemon() {
        let (env, sys, dir) = setup("chrony-stage");
        let wrong = call(
            &env,
            op::CHRONY_STAGE,
            json!({"content": NEW, "sha256": sha("zzz")}),
        );
        assert!(!wrong.ok);
        let conf_dir = env.cfg.chrony_conf.parent().unwrap().to_path_buf();
        assert!(fs::read_dir(&conf_dir).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(STAGE_PREFIX)
        }));
        // File work is not gated on the HA daemon (audit EX-06).
        sys.set_service("mikagami.service", "active");
        let staged = call(
            &env,
            op::CHRONY_STAGE,
            json!({"content": NEW, "sha256": sha(NEW)}),
        );
        assert!(staged.ok, "{staged:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn identifiers_from_the_controller_cannot_escape_the_directories() {
        let (env, _sys, dir) = setup("chrony-ids");
        for bad in ["../../etc/passwd", "chrony-1-../x.conf", "x", ""] {
            let r = call(
                &env,
                op::CHRONY_RESTORE,
                json!({"backup_id": bad, "expect_backup": sha(OLD), "expect_current": sha(OLD)}),
            );
            assert_eq!(r.error.unwrap().code, code::BAD_REQUEST, "{bad:?}");
        }
        for bad in ["../../x", "short", "ZZZZZZZZZZZZZZZZ", "0123456789abcde/"] {
            let r = call(&env, op::CHRONY_CLEANUP, json!({"stage_id": bad}));
            assert_eq!(r.error.unwrap().code, code::BAD_REQUEST, "{bad:?}");
        }
        assert!(backup_id_ok("chrony-1700000000-0123abcd.conf"));
        assert!(!backup_id_ok("chrony-1700000000-0123abcd.conf.x"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cleanup_is_idempotent_and_never_follows_symlinks() {
        let (env, _sys, dir) = setup("chrony-cleanup");
        let conf_dir = env.cfg.chrony_conf.parent().unwrap().to_path_buf();
        let victim = dir.join("victim");
        fs::write(&victim, "keep").unwrap();
        let id = "0123456789abcdef";
        symlink(&victim, conf_dir.join(format!("{STAGE_PREFIX}{id}.conf"))).unwrap();
        assert!(call(&env, op::CHRONY_CLEANUP, json!({"stage_id": id})).ok);
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(
            call(&env, op::CHRONY_CLEANUP, json!({"stage_id": id})).data["removed"],
            false
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn publish_refuses_a_tampered_stage_file() {
        let (env, _sys, dir) = setup("chrony-tamper");
        let stage = call(
            &env,
            op::CHRONY_STAGE,
            json!({"content": NEW, "sha256": sha(NEW)}),
        );
        let stage_id = stage.data["stage_id"].as_str().unwrap().to_string();
        let conf_dir = env.cfg.chrony_conf.parent().unwrap().to_path_buf();
        fs::write(
            conf_dir.join(format!("{STAGE_PREFIX}{stage_id}.conf")),
            "evil\n",
        )
        .unwrap();
        let r = call(
            &env,
            op::CHRONY_PUBLISH,
            json!({"stage_id": stage_id, "expect_current": sha(OLD), "expect_new": sha(NEW)}),
        );
        assert!(!r.ok);
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), OLD);
        fs::remove_dir_all(dir).unwrap();
    }

    // ------------------------------------------------------------------
    // Round-1 audit, work package 4
    // ------------------------------------------------------------------

    fn stage_for(env: &AgentEnv, content: &str) -> String {
        let r = call(
            env,
            op::CHRONY_STAGE,
            json!({"content": content, "sha256": sha(content)}),
        );
        assert!(r.ok, "{r:?}");
        r.data["stage_id"].as_str().unwrap().to_string()
    }

    fn publish_args(stage_id: &str, current: &str, new: &str) -> Value {
        json!({"stage_id": stage_id, "expect_current": sha(current), "expect_new": sha(new)})
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".mkg-"))
            .collect()
    }

    #[test]
    fn d02_the_exchange_publishes_and_leaves_no_staged_file() {
        let (env, _sys, dir) = setup("d02-ok");
        let stage = stage_for(&env, NEW);
        let r = call(&env, op::CHRONY_PUBLISH, publish_args(&stage, OLD, NEW));
        assert!(r.ok, "{r:?}");
        assert_eq!(r.data["exchange"], true);
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), NEW);
        let conf_dir = env.cfg.chrony_conf.parent().unwrap();
        assert!(leftovers(conf_dir).is_empty(), "{:?}", leftovers(conf_dir));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn d02_an_edit_inside_the_compare_window_is_put_back_and_the_publish_refused() {
        // The audit's reproduction: somebody edits the file between the hash
        // check and the replacement. Before: the edit vanished and the apply
        // reported success. Now: the displaced file is hashed, found to differ,
        // and put back.
        let (env, _sys, dir) = setup("d02-window");
        let stage = stage_for(&env, NEW);
        let conf = env.cfg.chrony_conf.clone();
        let edited = "server admin-edit.example.invalid\n";
        PRE_SWAP.with(|h| {
            *h.borrow_mut() = Some(Box::new({
                let conf = conf.clone();
                move || fs::write(&conf, edited).unwrap()
            }))
        });
        let r = call(&env, op::CHRONY_PUBLISH, publish_args(&stage, OLD, NEW));
        PRE_SWAP.with(|h| *h.borrow_mut() = None);
        assert!(!r.ok, "{r:?}");
        assert_eq!(r.error.as_ref().unwrap().code, code::REFUSED);
        assert_eq!(
            fs::read_to_string(&conf).unwrap(),
            edited,
            "the foreign edit is still the live file"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn d02_without_an_atomic_exchange_the_plain_rename_is_used_and_said_so() {
        let (env, _sys, dir) = setup("d02-fallback");
        let stage = stage_for(&env, NEW);
        fsutil::EXCHANGE_UNSUPPORTED.with(|f| f.set(true));
        let r = call(&env, op::CHRONY_PUBLISH, publish_args(&stage, OLD, NEW));
        fsutil::EXCHANGE_UNSUPPORTED.with(|f| f.set(false));
        assert!(r.ok, "{r:?}");
        assert_eq!(r.data["exchange"], false);
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), NEW);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn d03_publish_and_restore_keep_the_mode_of_the_live_file() {
        use std::os::unix::fs::MetadataExt;
        let (env, _sys, dir) = setup("d03-attrs");
        fs::set_permissions(&env.cfg.chrony_conf, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&env.cfg.chrony_conf).unwrap();
        let backup = call(&env, op::CHRONY_BACKUP, json!({"expect_sha256": sha(OLD)}));
        assert!(backup.ok);
        let stage = stage_for(&env, NEW);
        let r = call(&env, op::CHRONY_PUBLISH, publish_args(&stage, OLD, NEW));
        assert!(r.ok, "{r:?}");
        assert_eq!(r.data["mode"], "0640");
        let after = fs::metadata(&env.cfg.chrony_conf).unwrap();
        assert_eq!(after.mode() & 0o7777, 0o640);
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        let restored = call(
            &env,
            op::CHRONY_RESTORE,
            json!({
                "backup_id": backup.data["backup_id"],
                "expect_backup": sha(OLD),
                "expect_current": sha(NEW),
            }),
        );
        assert!(restored.ok, "{restored:?}");
        assert_eq!(restored.data["mode"], "0640");
        assert_eq!(
            fs::metadata(&env.cfg.chrony_conf).unwrap().mode() & 0o7777,
            0o640
        );
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), OLD);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn d03_a_file_that_cannot_get_the_attributes_is_not_published() {
        // A set-id bit survives only if the owner is right; a target that is
        // not a regular file at all is refused rather than guessed at.
        let (env, _sys, dir) = setup("d03-refuse");
        let stage = stage_for(&env, NEW);
        let conf_dir = env.cfg.chrony_conf.parent().unwrap().to_path_buf();
        let path = conf_dir.join(format!("{STAGE_PREFIX}{stage}.conf"));
        fs::remove_file(&path).unwrap();
        symlink(&env.cfg.chrony_conf, &path).unwrap();
        let r = call(&env, op::CHRONY_PUBLISH, publish_args(&stage, OLD, NEW));
        assert!(!r.ok, "a symlinked stage is never published: {r:?}");
        assert_eq!(fs::read_to_string(&env.cfg.chrony_conf).unwrap(), OLD);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn d01_cleanup_takes_the_lock_so_it_can_fence_a_running_publish() {
        let (env, _sys, dir) = setup("d01-lock");
        let stage = stage_for(&env, NEW);
        // Another operation holds the lock: the clean-up must not slip past.
        let held = lock(&env).unwrap();
        LOCK_WAIT_TEST.with(|w| w.set(Some(Duration::from_millis(100))));
        let r = call(&env, op::CHRONY_CLEANUP, json!({"stage_id": stage}));
        assert!(!r.ok, "{r:?}");
        let conf_dir = env.cfg.chrony_conf.parent().unwrap();
        assert_eq!(leftovers(conf_dir).len(), 1, "the staged file is untouched");
        drop(held);
        let r = call(&env, op::CHRONY_CLEANUP, json!({"stage_id": stage}));
        LOCK_WAIT_TEST.with(|w| w.set(None));
        assert!(r.ok, "{r:?}");
        assert_eq!(r.data["removed"], true);
        assert!(leftovers(conf_dir).is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn d08_stale_temporaries_are_swept_by_a_backup_and_fresh_ones_are_not() {
        let (env, _sys, dir) = setup("d08-sweep");
        let conf_dir = env.cfg.chrony_conf.parent().unwrap().to_path_buf();
        let old = conf_dir.join(".mkg-stage-00000000000000aa.conf");
        let old_v = conf_dir.join(".mkg-validate-00000000000000bb.conf");
        let fresh = conf_dir.join(".mkg-stage-00000000000000cc.conf");
        let other = conf_dir.join("not-ours.conf");
        for p in [&old, &old_v, &fresh, &other] {
            fs::write(p, "x").unwrap();
        }
        let two_hours_ago = std::time::SystemTime::now() - Duration::from_secs(7200);
        for p in [&old, &old_v, &other] {
            fs::File::options()
                .write(true)
                .open(p)
                .unwrap()
                .set_modified(two_hours_ago)
                .unwrap();
        }
        let r = call(&env, op::CHRONY_BACKUP, json!({"expect_sha256": sha(OLD)}));
        assert!(r.ok, "{r:?}");
        assert_eq!(r.data["swept"], 2);
        assert!(!old.exists() && !old_v.exists());
        assert!(
            fresh.exists(),
            "a fresh staged file may belong to a running apply"
        );
        assert!(other.exists(), "only our own prefixes are ever removed");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn d04_state_names_the_unit_it_observes() {
        let (env, _sys, dir) = setup("d04-name");
        let state = call(&env, op::CHRONY_STATE, json!({}));
        assert_eq!(state.data["unit"]["name"], "chrony.service");
        fs::remove_dir_all(dir).unwrap();
    }
}
