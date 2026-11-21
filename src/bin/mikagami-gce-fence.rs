//! Phase 1-J25 candidate: `mikagami-gce-fence`, the GCE fence action and verify helper of the
//! Stage 14 command backend (cargo feature `j25-gce-fence`; never a default feature, so the
//! production build does not build it).
//!
//! ```text
//! [fencing]
//! backend = "command"
//! fence  = ["/usr/lib/mikagami/mikagami-gce-fence", "fence",  "--config", "/etc/mikagami/gce-fence.toml"]
//! verify = ["/usr/lib/mikagami/mikagami-gce-fence", "verify", "--config", "/etc/mikagami/gce-fence.toml"]
//! ```
//!
//! The daemon passes the attempt identity in `MIKAGAMI_CLUSTER`, `MIKAGAMI_FENCE_TARGET`,
//! `MIKAGAMI_FENCE_INCIDENT` and `MIKAGAMI_FENCE_ATTEMPT`; the decisions are those of
//! `gce_fence_backend` (included below). `verify` prints exactly `isolated` or `not-isolated` and
//! exits 0, or exits non-zero with no output when the result is unknown.
//!
//! v0.7 G-2 route handoff (`G2_SAFETY_CONTRACT.md` R4.1 §3.1): `route-check`, `route-observe
//! --part own|peer|op` and `route-assign` are the daemon's RH steps (one Compute API call at most,
//! millisecond HTTP limits, inside the RH deadline set), each with `--intent <file>` naming the
//! daemon's durable binding in `[route] intent_dir`. `operator-assign --operator-request <uuid>` is
//! the operator's single bound update. The former bare `assign` is removed: it sent with a random
//! request id, no intent and no binding, and reported a sent request as success.
//!
//! I/O: the Compute API and the token endpoint are reached through `curl` (the configured absolute
//! path), with the request configuration, including the bearer token, on curl's standard input, so
//! the token is never in an argument list, a file or a log. Records are written atomically (write,
//! fsync, rename, directory fsync) under the configured state directory, which must be owned by the
//! effective user with mode 0700; one flock per state directory serializes concurrent helpers.

#[path = "../gce_fence_backend.rs"]
mod gce_fence_backend;

use gce_fence_backend::*;
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

const USAGE: &str = "usage: mikagami-gce-fence fence|verify --config <file>\n       mikagami-gce-fence route-check|route-assign|route-reissue --config <file> --intent <file>\n       mikagami-gce-fence route-observe --config <file> --intent <file> --part own|peer|op\n       mikagami-gce-fence operator-assign --config <file> --operator-request <uuid>";
const LOCK_WAIT: Duration = Duration::from_secs(5);
/// G-2: a route step must finish inside the RH execution time (2.0 s), so it waits briefly only.
const ROUTE_LOCK_WAIT: Duration = Duration::from_millis(100);
/// G-2 (contract R4.1 §3.1): curl `--max-time` of the token request and of the one API call of a
/// route step (together under the 2.0 s RH execution time).
const ROUTE_TOKEN_TIMEOUT: &str = "0.5";
const ROUTE_API_TIMEOUT: &str = "1.2";
/// The largest intent file read.
const ROUTE_INTENT_MAX_BYTES: u64 = 16 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const STATUS_MARK: &str = "\n__mikagami_http_status__:";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AliasConfig {
    nic: String,
    ranges: Vec<String>,
    inventory_complete: bool,
    propagation_hold_sec: u64,
    /// J26 audit N-1: the longest gap between two absent observations of one hold (default: the
    /// smaller of 15 s and the hold).
    max_observation_gap_sec: Option<u64>,
    /// J26 audit N-4: run once per protected range, with every `{range}` argument replaced.
    probe: Option<Vec<String>>,
}

/// G-2 `[route]`: this node's own instance (the plan's target is the peer) and the directory the
/// daemon writes its intents to. The configured identity is authoritative: an intent can never
/// change it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteConfig {
    own_instance: String,
    own_instance_id: String,
    /// The own instance's zone, when it differs from the peer's.
    own_zone: Option<String>,
    intent_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestConfig {
    /// Honoured only by a `j25-fault-injection` build (a production build refuses the whole
    /// section, so it never reads the field).
    #[cfg_attr(not(feature = "j25-fault-injection"), allow(dead_code))]
    fault_file: Option<String>,
    /// J26 audit N-2: accept a propagation hold below the production minimum (a test build only).
    allow_short_hold: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperConfig {
    cluster: String,
    target_node: String,
    project: String,
    zone: String,
    instance: String,
    instance_id: String,
    methods: Vec<FenceMethod>,
    combine: Combine,
    api_base: String,
    token_url: String,
    curl: String,
    state_dir: String,
    http_timeout_sec: u64,
    alias: Option<AliasConfig>,
    route: Option<RouteConfig>,
    test: Option<TestConfig>,
}

impl HelperConfig {
    fn plan(&self) -> Result<FencePlan, String> {
        let plan = FencePlan {
            cluster: self.cluster.clone(),
            target_node: self.target_node.clone(),
            target: InstanceIdentity {
                project: self.project.clone(),
                zone: self.zone.clone(),
                name: self.instance.clone(),
                instance_id: self.instance_id.clone(),
            },
            methods: self.methods.clone(),
            combine: self.combine,
            alias: self.alias.as_ref().map(|alias| AliasPolicy {
                nic: alias.nic.clone(),
                ranges: alias.ranges.clone(),
                inventory_complete: alias.inventory_complete,
                propagation_hold_ms: alias.propagation_hold_sec.saturating_mul(1_000),
                max_observation_gap_ms: alias
                    .max_observation_gap_sec
                    .unwrap_or(alias.propagation_hold_sec.clamp(1, 15))
                    .saturating_mul(1_000),
                probe_required: alias.probe.is_some(),
                short_hold_for_test: cfg!(feature = "j25-fault-injection")
                    && self.test.as_ref().and_then(|test| test.allow_short_hold) == Some(true),
            }),
        };
        plan.validate()?;
        if !(1..=30).contains(&self.http_timeout_sec) {
            return Err("http_timeout_sec must be 1..=30".to_string());
        }
        // J25 audit N-2: the bearer token is sent to api_base, so it must be https. Plain http is
        // accepted only for a loopback test endpoint; the token endpoint may also be the GCE
        // metadata server, which is plain http by design and never leaves the host.
        let loopback = |url: &str| {
            [
                "http://127.0.0.1:",
                "http://127.0.0.1/",
                "http://[::1]:",
                "http://localhost:",
            ]
            .iter()
            .any(|prefix| url.starts_with(prefix))
        };
        let metadata = |url: &str| {
            url.starts_with("http://metadata.google.internal/")
                || url.starts_with("http://169.254.169.254/")
        };
        for (name, url, extra) in [
            ("api_base", &self.api_base, false),
            ("token_url", &self.token_url, true),
        ] {
            let allowed = url.starts_with("https://") || loopback(url) || (extra && metadata(url));
            if !allowed || url.contains('"') || url.contains(char::is_whitespace) {
                return Err(format!(
                    "{name} must be an https URL (plain http only for loopback{})",
                    if extra { " or the metadata server" } else { "" }
                ));
            }
        }
        if !Path::new(&self.curl).is_absolute() {
            return Err("curl must be an absolute path".to_string());
        }
        if let Some(probe) = self.alias.as_ref().and_then(|alias| alias.probe.as_ref())
            && probe
                .first()
                .is_none_or(|program| !Path::new(program).is_absolute())
        {
            return Err("alias.probe must start with an absolute path".to_string());
        }
        if let Some(probe) = self.alias.as_ref().and_then(|alias| alias.probe.as_ref())
            && !probe
                .iter()
                .skip(1)
                .any(|argument| argument.contains("{range}"))
        {
            return Err("alias.probe must name the probed range as {range}".to_string());
        }
        Ok(plan)
    }
}

/// The file must be a regular file owned by the effective user and not group/world-writable: it
/// names the VM that will be stopped.
fn check_owned(path: &Path, directory: bool) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let kind_ok = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !kind_ok || metadata.uid() != euid || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is not a trusted {}",
            path.display(),
            if directory { "directory" } else { "file" }
        ));
    }
    if directory && metadata.mode() & 0o077 != 0 {
        return Err(format!("{} must have mode 0700", path.display()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// curl transport
// ---------------------------------------------------------------------------------------------

fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => {}
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// One curl exchange. `config` is curl's `-K -` configuration (it carries the URL, the headers and
/// the body); the status code is appended by `--write-out` after a marker. `max_time` is curl's
/// `--max-time` value (whole or decimal seconds).
fn curl_exchange(curl: &str, method: &str, max_time: &str, config: &str) -> HttpOutcome {
    let spawned = Command::new(curl)
        .args([
            // J25 audit N-2: -q (first) ignores any .curlrc; --globoff keeps []{} literal.
            "-q",
            "--globoff",
            "-sS",
            "--max-time",
            max_time,
            "-X",
            method,
            "-K",
            "-",
            "-o",
            "-",
            "--write-out",
        ])
        .arg(format!("{STATUS_MARK}%{{http_code}}"))
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return HttpOutcome::NotSent(format!("curl could not start: {error}")),
    };
    if let Some(mut stdin) = child.stdin.take()
        && stdin.write_all(config.as_bytes()).is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return HttpOutcome::NotSent("the curl configuration could not be written".to_string());
    }
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => return HttpOutcome::Transport(format!("curl did not finish: {error}")),
    };
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    match output.status.code() {
        Some(0) => {
            let Some((body, status)) = stdout.rsplit_once(STATUS_MARK) else {
                return HttpOutcome::Transport("curl gave no status".to_string());
            };
            match status.trim().parse::<u16>() {
                Ok(0) | Err(_) => HttpOutcome::Transport("curl gave no HTTP status".to_string()),
                Ok(status) => HttpOutcome::Response {
                    status,
                    body: body.to_string(),
                },
            }
        }
        // Could not resolve host / could not connect: nothing was sent.
        Some(6 | 7) => {
            HttpOutcome::NotSent(format!("curl exit {}", output.status.code().unwrap_or(-1)))
        }
        Some(28) => HttpOutcome::Timeout,
        code => HttpOutcome::Transport(format!("curl exit {code:?}")),
    }
}

struct CurlTransport {
    curl: String,
    api_base: String,
    max_time: String,
    token: String,
}

impl CurlTransport {
    fn connect(config: &HelperConfig) -> Result<Self, String> {
        let max_time = config.http_timeout_sec.to_string();
        Self::connect_with(config, &max_time, &max_time)
    }

    /// G-2 route steps: the millisecond limits of contract R4.1 §3.1.
    fn connect_route(config: &HelperConfig) -> Result<Self, String> {
        Self::connect_with(config, ROUTE_TOKEN_TIMEOUT, ROUTE_API_TIMEOUT)
    }

    fn connect_with(
        config: &HelperConfig,
        auth_max_time: &str,
        api_time: &str,
    ) -> Result<Self, String> {
        let request = format!(
            "url = {}\nheader = {}\n",
            quote(&config.token_url),
            quote("Metadata-Flavor: Google")
        );
        let token = match curl_exchange(&config.curl, "GET", auth_max_time, &request) {
            HttpOutcome::Response { status: 200, body } => {
                serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("access_token")
                            .and_then(|token| token.as_str())
                            .map(str::to_string)
                    })
                    .filter(|token| {
                        !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic())
                    })
                    .ok_or("the token answer has no usable access_token".to_string())?
            }
            HttpOutcome::Response { status, .. } => {
                return Err(format!("the token endpoint answered HTTP {status}"));
            }
            other => {
                return Err(format!(
                    "the token endpoint failed: {}",
                    describe_outcome(&other)
                ));
            }
        };
        Ok(Self {
            curl: config.curl.clone(),
            api_base: config.api_base.trim_end_matches('/').to_string(),
            max_time: api_time.to_string(),
            token,
        })
    }
}

fn describe_outcome(outcome: &HttpOutcome) -> String {
    match outcome {
        HttpOutcome::Response { status, .. } => format!("HTTP {status}"),
        HttpOutcome::NotSent(detail) => format!("not sent ({detail})"),
        HttpOutcome::Timeout => "timeout".to_string(),
        HttpOutcome::Transport(detail) => format!("transport ({detail})"),
    }
}

impl ComputeTransport for CurlTransport {
    fn call(&mut self, method: HttpMethod, path: &str, body: Option<&str>) -> HttpOutcome {
        let mut request = format!(
            "url = {}\nheader = {}\n",
            quote(&format!("{}/{}", self.api_base, path)),
            quote(&format!("Authorization: Bearer {}", self.token))
        );
        if let Some(body) = body {
            request.push_str(&format!(
                "header = {}\ndata-binary = {}\n",
                quote("Content-Type: application/json"),
                quote(body)
            ));
        } else if method != HttpMethod::Get {
            request.push_str(&format!("data-binary = {}\n", quote("")));
        }
        curl_exchange(&self.curl, method.as_str(), &self.max_time, &request)
    }
}

// ---------------------------------------------------------------------------------------------
// Durable record store and lock
// ---------------------------------------------------------------------------------------------

struct FileStore {
    records: PathBuf,
}

impl FileStore {
    fn open(state_dir: &Path) -> Result<Self, String> {
        check_owned(state_dir, true)?;
        let records = state_dir.join("records");
        match fs::create_dir(&records) {
            Ok(()) => {
                fs::set_permissions(
                    &records,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )
                .map_err(|error| format!("records: {error}"))?;
                sync_dir(state_dir).map_err(|error| format!("state dir sync: {error}"))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("records: {error}")),
        }
        check_owned(&records, true)?;
        Ok(Self { records })
    }

    fn path(&self, binding: &AttemptBinding, method: FenceMethod) -> PathBuf {
        self.records.join(format!(
            "{}-{}-{}.json",
            binding.incident_id,
            binding.attempt_token,
            method.as_str()
        ))
    }
}

fn sync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

impl FileStore {
    fn route_path(&self, key: &str, kind: &str) -> Result<PathBuf, StoreError> {
        if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StoreError::Io("bad route key".to_string()));
        }
        Ok(self.records.join(format!("route-{key}-{kind}.json")))
    }

    fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, StoreError> {
        let mut text = String::new();
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(mut file) => file
                .read_to_string(&mut text)
                .map_err(|error| StoreError::Io(error.to_string()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::Io(error.to_string())),
        };
        serde_json::from_str::<T>(&text)
            .map(Some)
            .map_err(|error| StoreError::Foreign(format!("unreadable record: {error}")))
    }

    fn save_json<T: serde::Serialize>(&self, path: &Path, value: &T) -> Result<(), StoreError> {
        let io = |error: std::io::Error| StoreError::Io(error.to_string());
        let text = serde_json::to_string_pretty(value)
            .map_err(|error| StoreError::Io(error.to_string()))?;
        let temporary = self
            .records
            .join(format!(".tmp-route-{}", std::process::id()));
        let _ = fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(io)?;
        file.write_all(text.as_bytes()).map_err(io)?;
        file.write_all(b"\n").map_err(io)?;
        file.sync_all().map_err(io)?;
        drop(file);
        fs::rename(&temporary, path).map_err(io)?;
        sync_dir(&self.records).map_err(io)
    }
}

impl RouteStore for FileStore {
    fn load_observation(&mut self, key: &str) -> Result<Option<RouteObservation>, StoreError> {
        Self::load_json(&self.route_path(key, "observation")?)
    }
    fn save_observation(&mut self, record: &RouteObservation) -> Result<(), StoreError> {
        self.save_json(&self.route_path(&record.key, "observation")?, record)
    }
    fn load_assign(&mut self, key: &str) -> Result<Option<RouteAssignRecord>, StoreError> {
        Self::load_json(&self.route_path(key, "assign")?)
    }
    fn save_assign(&mut self, record: &RouteAssignRecord) -> Result<(), StoreError> {
        #[cfg(feature = "j25-fault-injection")]
        if faults::fire_io("route-record-write") {
            return Err(StoreError::Io(
                "G-2 test-only fault: route record write".to_string(),
            ));
        }
        self.save_json(&self.route_path(&record.key, "assign")?, record)
    }
    fn load_reissue(&mut self, key: &str) -> Result<Option<RouteAssignRecord>, StoreError> {
        Self::load_json(&self.route_path(key, "reissue")?)
    }
    fn save_reissue(&mut self, record: &RouteAssignRecord) -> Result<(), StoreError> {
        #[cfg(feature = "j25-fault-injection")]
        if faults::fire_io("route-record-write") {
            return Err(StoreError::Io(
                "G-2 test-only fault: route record write".to_string(),
            ));
        }
        self.save_json(&self.route_path(&record.key, "reissue")?, record)
    }
    /// r17 R-9: another `route-*-assign.json` / `route-*-reissue.json` modified after this key's
    /// assign record. Any unreadable entry or time is `Err` (the re-issue is then refused).
    fn newer_route_records(&mut self, key: &str) -> Result<bool, StoreError> {
        let io = |error: std::io::Error| StoreError::Io(error.to_string());
        let own = self.route_path(key, "assign")?;
        let own_time = fs::symlink_metadata(&own)
            .and_then(|metadata| metadata.modified())
            .map_err(io)?;
        let own_name = own.file_name().map(|name| name.to_os_string());
        for entry in fs::read_dir(&self.records).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry.file_name();
            let Some(text) = name.to_str() else {
                return Err(StoreError::Io("a record name is not UTF-8".to_string()));
            };
            let route_record = text.starts_with("route-")
                && (text.ends_with("-assign.json") || text.ends_with("-reissue.json"));
            if !route_record
                || Some(&name) == own_name.as_ref()
                || text == format!("route-{key}-reissue.json")
            {
                continue;
            }
            let time = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .map_err(io)?;
            if time >= own_time {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl RecordStore for FileStore {
    fn load(
        &mut self,
        binding: &AttemptBinding,
        method: FenceMethod,
    ) -> Result<Option<ActionRecord>, StoreError> {
        let path = self.path(binding, method);
        let mut text = String::new();
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(mut file) => file
                .read_to_string(&mut text)
                .map_err(|error| StoreError::Io(error.to_string()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::Io(error.to_string())),
        };
        serde_json::from_str::<ActionRecord>(&text)
            .map(Some)
            .map_err(|error| StoreError::Foreign(format!("unreadable record: {error}")))
    }

    fn save(&mut self, record: &ActionRecord) -> Result<(), StoreError> {
        let path = self.path(&record.binding, record.method);
        let temporary = self.records.join(format!(".tmp-{}", std::process::id()));
        let io = |error: std::io::Error| StoreError::Io(error.to_string());
        let text = serde_json::to_string_pretty(record)
            .map_err(|error| StoreError::Io(error.to_string()))?;
        #[cfg(feature = "j25-fault-injection")]
        if faults::fire_io("record-write") {
            return Err(StoreError::Io(
                "J25 test-only fault: record write".to_string(),
            ));
        }
        let _ = fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(io)?;
        file.write_all(text.as_bytes()).map_err(io)?;
        file.write_all(b"\n").map_err(io)?;
        file.sync_all().map_err(io)?;
        drop(file);
        fs::rename(&temporary, &path).map_err(io)?;
        sync_dir(&self.records).map_err(io)
    }
}

/// An exclusive flock on `<state_dir>/lock`, held until the process exits.
fn lock(state_dir: &Path, wait: Duration) -> Result<File, String> {
    let path = state_dir.join("lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| format!("lock: {error}"))?;
    let started = Instant::now();
    loop {
        // SAFETY: the descriptor is open for the whole call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        if started.elapsed() >= wait {
            return Err("another helper holds the state directory".to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------------------------
// Clock, probe, log, faults
// ---------------------------------------------------------------------------------------------

/// Milliseconds of `CLOCK_BOOTTIME` (Linux; counts suspend) or `CLOCK_MONOTONIC` elsewhere.
fn now_ms() -> Option<u64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    #[cfg(target_os = "linux")]
    let clock = libc::CLOCK_BOOTTIME;
    #[cfg(not(target_os = "linux"))]
    let clock = libc::CLOCK_MONOTONIC;
    // SAFETY: `now` is a valid, writable timespec.
    if unsafe { libc::clock_gettime(clock, &mut now) } != 0 {
        return None;
    }
    u64::try_from(now.tv_sec)
        .ok()?
        .checked_mul(1_000)?
        .checked_add(u64::try_from(now.tv_nsec).ok()? / 1_000_000)
}

struct CommandProbe(Vec<String>);

impl DataPlaneProbe for CommandProbe {
    fn probe(&mut self, range: &str) -> ProbeResult {
        let Some((program, rest)) = self.0.split_first() else {
            return ProbeResult::Unknown;
        };
        let args: Vec<String> = rest
            .iter()
            .map(|argument| argument.replace("{range}", range))
            .collect();
        let child = Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            return ProbeResult::Unknown;
        };
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut out = String::new();
                    if let Some(mut stdout) = child.stdout.take() {
                        let _ = stdout.read_to_string(&mut out);
                    }
                    return match (status.code(), out.trim()) {
                        (Some(0), "absent") => ProbeResult::Absent,
                        (Some(0), "present") => ProbeResult::Present,
                        _ => ProbeResult::Unknown,
                    };
                }
                Ok(None) if started.elapsed() < PROBE_TIMEOUT => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ProbeResult::Unknown;
                }
            }
        }
    }
}

struct Log {
    file: Option<File>,
}

impl Log {
    fn open(state_dir: &Path) -> Self {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(state_dir.join("helper.log"))
            .ok();
        Self { file }
    }

    /// One line: never a token, a body or a header.
    fn line(&mut self, text: &str) {
        let stamp = now_ms().unwrap_or(0);
        let line = format!("boottime_ms={stamp} pid={} {text}\n", std::process::id());
        if let Some(file) = &mut self.file {
            let _ = file.write_all(line.as_bytes());
        }
        eprint!("mikagami-gce-fence: {line}");
    }
}

#[cfg(feature = "j25-fault-injection")]
mod faults {
    //! J25 TEST-ONLY crash points of the helper (feature `j25-fault-injection`). A point fires
    //! when the configured fault file holds `<point> <count>` with a positive count; it then logs
    //! `J25_HELPER_FAULT_FIRED`, kills the parent (the daemon, which systemd restarts) with SIGKILL
    //! and waits to be killed with it: a crash of the promoting node at exactly that point.
    use std::fs;
    use std::sync::OnceLock;

    pub static FILE: OnceLock<String> = OnceLock::new();

    fn take(point: &str) -> bool {
        let Some(path) = FILE.get() else {
            return false;
        };
        let Ok(text) = fs::read_to_string(path) else {
            return false;
        };
        let mut words = text.split_whitespace();
        let (Some(armed), Some(count), None) = (words.next(), words.next(), words.next()) else {
            return false;
        };
        let Ok(count) = count.parse::<u64>() else {
            return false;
        };
        if armed != point
            || count == 0
            || fs::write(path, format!("{point} {}\n", count - 1)).is_err()
        {
            return false;
        }
        eprintln!(
            "J25_HELPER_FAULT_FIRED point={point} remaining={}",
            count - 1
        );
        true
    }

    pub fn crash(point: &str) {
        if take(point) {
            // SAFETY: getppid and kill have no memory preconditions.
            unsafe { libc::kill(libc::getppid(), libc::SIGKILL) };
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }

    pub fn fire_io(point: &str) -> bool {
        take(point)
    }
}

struct Hooks;

impl FaultHook for Hooks {
    fn at(&mut self, _point: FencePoint) {
        #[cfg(feature = "j25-fault-injection")]
        faults::crash(_point.as_str());
    }
}

// ---------------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------------

struct Args {
    command: String,
    config: PathBuf,
    intent: Option<PathBuf>,
    part: Option<String>,
    operator_request: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or(USAGE)?;
    let mut config = None;
    let mut intent = None;
    let mut part = None;
    let mut operator_request = None;
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(USAGE)?;
        let slot = match flag.as_str() {
            "--config" => {
                config = Some(PathBuf::from(value));
                continue;
            }
            "--intent" => &mut intent,
            "--part" => &mut part,
            "--operator-request" => &mut operator_request,
            _ => return Err(USAGE.to_string()),
        };
        if slot.replace(value).is_some() {
            return Err(USAGE.to_string());
        }
    }
    Ok(Args {
        command,
        config: config.ok_or(USAGE)?,
        intent: intent.map(PathBuf::from),
        part,
        operator_request,
    })
}

fn load_config(path: &Path) -> Result<HelperConfig, String> {
    check_owned(path, false)?;
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    toml::from_str::<HelperConfig>(&text).map_err(|error| format!("{}: {error}", path.display()))
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let failure_code = if args.command == "verify" {
        VERIFY_INCONCLUSIVE_EXIT as u8
    } else {
        2
    };
    match run(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("mikagami-gce-fence: {error}");
            ExitCode::from(failure_code)
        }
    }
}

fn run(args: &Args) -> Result<ExitCode, String> {
    let config = load_config(&args.config)?;
    let plan = config.plan()?;
    #[cfg(feature = "j25-fault-injection")]
    if let Some(file) = config
        .test
        .as_ref()
        .and_then(|test| test.fault_file.clone())
    {
        let _ = faults::FILE.set(file);
    }
    // J26: a production build refuses the whole [test] section (fault_file, allow_short_hold).
    #[cfg(not(feature = "j25-fault-injection"))]
    if config.test.is_some() {
        return Err("[test] needs a j25-fault-injection build".to_string());
    }
    let state_dir = PathBuf::from(&config.state_dir);
    let mut store = FileStore::open(&state_dir)?;
    let mut log = Log::open(&state_dir);
    let route_command = matches!(
        args.command.as_str(),
        "route-check" | "route-observe" | "route-assign" | "route-reissue" | "operator-assign"
    );
    let _lock = lock(
        &state_dir,
        if route_command {
            ROUTE_LOCK_WAIT
        } else {
            LOCK_WAIT
        },
    )?;
    match args.command.as_str() {
        "fence" | "verify" => {}
        "route-check" | "route-observe" | "route-assign" | "route-reissue" => {
            return route_step(args, &config, &plan, &mut store, &mut log);
        }
        "operator-assign" => return operator(args, &config, &plan, &mut store, &mut log),
        _ => return Err(USAGE.to_string()),
    }
    let binding = AttemptBinding::from_step(
        &plan,
        env("MIKAGAMI_CLUSTER").as_deref(),
        env("MIKAGAMI_FENCE_TARGET").as_deref(),
        env("MIKAGAMI_FENCE_INCIDENT").as_deref(),
        env("MIKAGAMI_FENCE_ATTEMPT").as_deref(),
    )
    .map_err(|error| error.to_string())?;
    let attempt = format!(
        "incident={} attempt={}",
        binding.incident_id, binding.attempt_token
    );
    let mut api = CurlTransport::connect(&config).map_err(|error| {
        log.line(&format!(
            "{} {attempt} token unavailable: {error}",
            args.command
        ));
        error
    })?;
    if args.command == "fence" {
        let reports = fence(&mut ActionContext {
            plan: &plan,
            binding: &binding,
            api: &mut api,
            store: &mut store,
            hooks: &mut Hooks,
        });
        let mut ok = true;
        for (method, report) in &reports {
            ok &= report.is_success();
            log.line(&format!(
                "fence {attempt} method={} result={report}",
                method.as_str()
            ));
        }
        return Ok(if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }
    let mut clock = now_ms;
    let mut probe: Box<dyn DataPlaneProbe> =
        match config.alias.as_ref().and_then(|alias| alias.probe.clone()) {
            Some(argv) => Box::new(CommandProbe(argv)),
            None => Box::new(NoProbe),
        };
    let (verdicts, verdict) = verify(&mut VerifyContext {
        plan: &plan,
        binding: &binding,
        api: &mut api,
        store: &mut store,
        hooks: &mut Hooks,
        probe: probe.as_mut(),
        clock: &mut clock,
    });
    for (method, method_verdict) in &verdicts {
        log.line(&format!(
            "verify {attempt} method={} verdict={method_verdict:?}",
            method.as_str()
        ));
    }
    let (code, stdout) = verify_output(&verdict);
    log.line(&format!("verify {attempt} final={verdict:?} exit={code}"));
    print!("{stdout}");
    let _ = std::io::stdout().flush();
    Ok(ExitCode::from(code as u8))
}

/// G-2: the own instance of `[route]` (same project; its own zone when configured).
fn own_instance(config: &HelperConfig) -> Result<(InstanceIdentity, &RouteConfig), String> {
    let route = config.route.as_ref().ok_or("route commands need [route]")?;
    let own = InstanceIdentity {
        project: config.project.clone(),
        zone: route
            .own_zone
            .clone()
            .unwrap_or_else(|| config.zone.clone()),
        name: route.own_instance.clone(),
        instance_id: route.own_instance_id.clone(),
    };
    own.validate()?;
    Ok((own, route))
}

/// G-2 (contract L-R3-2): the intent must be a private regular file directly inside the
/// configured `intent_dir` (itself owned by this user, mode 0700), not a symlink, bounded in size,
/// and in the exact intent format.
fn read_intent(path: &Path, route: &RouteConfig) -> Result<RouteIntent, String> {
    let dir = Path::new(&route.intent_dir);
    if !dir.is_absolute() || !path.is_absolute() || path.parent() != Some(dir) {
        return Err("the intent is not directly inside route.intent_dir".to_string());
    }
    check_owned(dir, true)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("intent: {error}"))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != euid
        || metadata.mode() & 0o077 != 0
        || metadata.len() > ROUTE_INTENT_MAX_BYTES
    {
        return Err("the intent is not a private regular file of this user".to_string());
    }
    let mut text = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|file| file.take(ROUTE_INTENT_MAX_BYTES).read_to_string(&mut text))
        .map_err(|error| format!("intent: {error}"))?;
    serde_json::from_str::<RouteIntent>(&text).map_err(|error| format!("intent: {error}"))
}

/// One RH step. Prints exactly one answer line of the fixed grammar and exits 0; any other
/// outcome exits non-zero with no output (the daemon reads it as inconclusive).
fn route_step(
    args: &Args,
    config: &HelperConfig,
    plan: &FencePlan,
    store: &mut FileStore,
    log: &mut Log,
) -> Result<ExitCode, String> {
    let (own, route) = own_instance(config)?;
    let intent = read_intent(args.intent.as_deref().ok_or(USAGE)?, route)?;
    let binding = RouteBinding::from_intent(
        plan,
        &own,
        &intent,
        env("MIKAGAMI_FENCE_INCIDENT").as_deref(),
        env("MIKAGAMI_FENCE_ATTEMPT").as_deref(),
    )?;
    let answer: String = match (args.command.as_str(), args.part.as_deref()) {
        ("route-check", None) => match route_check(plan, &binding, store) {
            Ok(()) => "ok".to_string(),
            Err(reason) => {
                log.line(&format!(
                    "route-check term={} refused: {reason}",
                    binding.term
                ));
                "refused".to_string()
            }
        },
        ("route-observe", Some(part)) => {
            let mut api = CurlTransport::connect_route(config)?;
            match part {
                "own" => observe_own(&mut api, &binding, store)?,
                "peer" => observe_peer(&mut api, &binding)?,
                "op" => observe_op(&mut api, &binding, store)?,
                _ => return Err(USAGE.to_string()),
            }
            .to_string()
        }
        ("route-assign", None) => {
            // The fence records are re-checked before anything is sent (G-A3, second check).
            let mut fence_store = FileStore {
                records: store.records.clone(),
            };
            let mut api = CurlTransport::connect_route(config)?;
            route_assign(&mut api, plan, &binding, &mut fence_store, store)
        }
        ("route-reissue", None) => {
            // r17: the same G-A3 re-check, then at most the term's one re-issue of the identical
            // request (`route_reissue` refuses everything else before any API call).
            let mut fence_store = FileStore {
                records: store.records.clone(),
            };
            let mut api = CurlTransport::connect_route(config)?;
            route_reissue(&mut api, plan, &binding, &mut fence_store, store)
        }
        _ => return Err(USAGE.to_string()),
    };
    log.line(&format!(
        "{} term={} answer={answer}",
        args.command, binding.term
    ));
    println!("{answer}");
    let _ = std::io::stdout().flush();
    Ok(ExitCode::SUCCESS)
}

/// The operator's single bound alias update (contract §5.2); never run by the daemon.
fn operator(
    args: &Args,
    config: &HelperConfig,
    plan: &FencePlan,
    store: &mut FileStore,
    log: &mut Log,
) -> Result<ExitCode, String> {
    let (own, _) = own_instance(config)?;
    let request = args.operator_request.as_deref().ok_or(USAGE)?;
    let mut api = CurlTransport::connect(config)?;
    let answer = operator_assign(&mut api, plan, &own, request, store);
    log.line(&format!("operator-assign answer={answer}"));
    println!("{answer}");
    Ok(if answer == "accepted" || answer == "not-needed" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// v0.7 G-2 (audit M-2): the intent file validation of `read_intent` (contract §3.1, L-R3-2).
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("g2-intent-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn route(dir: &Path) -> RouteConfig {
        RouteConfig {
            own_instance: "vm-b".to_string(),
            own_instance_id: "2002".to_string(),
            own_zone: None,
            intent_dir: dir.display().to_string(),
        }
    }

    const INTENT: &str = r#"{"version":1,"cluster":"c1","node":"node-b","peer_node":"node-a","term":8,"origin":{"kind":"bootstrap"}}"#;

    fn write_private(path: &Path, text: &str) {
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn g2_intent_file_is_read_only_when_private_and_inside_the_directory() {
        let dir = private_dir("ok");
        let path = dir.join("rh-8.intent.json");
        write_private(&path, INTENT);
        let intent = read_intent(&path, &route(&dir)).unwrap();
        assert_eq!(intent.term, 8);
        assert!(matches!(intent.origin, RouteOrigin::Bootstrap));
    }

    #[test]
    fn g2_intent_file_refusals() {
        let dir = private_dir("refusals");
        let config = route(&dir);
        // Group/world readable.
        let open = dir.join("open.json");
        write_private(&open, INTENT);
        fs::set_permissions(&open, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_intent(&open, &config).is_err());
        // A symlink to a valid private file.
        let target = dir.join("target.json");
        write_private(&target, INTENT);
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_intent(&link, &config).is_err());
        // Over the size bound.
        let big = dir.join("big.json");
        write_private(&big, &" ".repeat(ROUTE_INTENT_MAX_BYTES as usize + 1));
        assert!(read_intent(&big, &config).is_err());
        // Outside the configured directory (a sub-directory counts as outside).
        let nested = dir.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        let inner = nested.join("rh-8.intent.json");
        write_private(&inner, INTENT);
        assert!(read_intent(&inner, &config).is_err());
        let elsewhere = private_dir("elsewhere").join("rh-8.intent.json");
        write_private(&elsewhere, INTENT);
        assert!(read_intent(&elsewhere, &config).is_err());
        // A relative path, unknown fields, another format.
        assert!(read_intent(Path::new("rh-8.intent.json"), &config).is_err());
        let extra = dir.join("extra.json");
        write_private(
            &extra,
            &INTENT.replace("\"term\":8", "\"term\":8,\"own_instance_id\":\"9\""),
        );
        assert!(read_intent(&extra, &config).is_err());
        let garbage = dir.join("garbage.json");
        write_private(&garbage, "not json");
        assert!(read_intent(&garbage, &config).is_err());
        // The directory itself must be private (mode 0700).
        let valid = dir.join("valid.json");
        write_private(&valid, INTENT);
        assert!(read_intent(&valid, &config).is_ok());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(read_intent(&valid, &config).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(read_intent(&valid, &config).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
