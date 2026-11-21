//! Controller-to-agent transport (SSH) and the in-band result mapping.

use super::config::ControlConfig;
use super::exec::{self, ExecCommand, ExecOutcome};
use super::proto::{self, PROTO_VERSION, Request, Response, code};
use serde_json::Value;
use std::time::Duration;

/// Where to reach one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// Node or witness label, used in messages.
    pub(crate) label: String,
    /// SSH address (internal IP or resolved external IP).
    pub(crate) host: String,
    /// Stable host-key identity, independent of the address.
    pub(crate) host_key_alias: String,
}

/// Why a call produced no usable agent answer. In every case the requested
/// operation may or may not have taken effect: callers must re-observe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TransportError {
    Unreachable(String),
    Timeout(String),
    Protocol(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(m) => write!(f, "unreachable: {m}"),
            Self::Timeout(m) => write!(f, "timed out: {m}"),
            Self::Protocol(m) => write!(f, "protocol error: {m}"),
        }
    }
}

pub(crate) trait Remote {
    fn call(
        &self,
        target: &Target,
        op: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Response, TransportError>;
}

/// Outcome of one agent call after mapping the in-band error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallError {
    /// No answer; the effect (if any) is unknown.
    Transport(TransportError),
    /// The agent refused: nothing was changed.
    Refused(String),
    /// The agent attempted the operation and it failed (may be partial).
    Failed(String),
    /// A file replacement displaced a version of the file that somebody else
    /// had written meanwhile and could not put it back; the agent kept it and
    /// the text names where (audit RA-D-01). The caller must stop, leave
    /// every staged file alone and report UNKNOWN.
    DisplacedKept(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{e}"),
            Self::Refused(m) => write!(f, "refused by agent: {m}"),
            Self::Failed(m) => write!(f, "agent reported failure: {m}"),
            Self::DisplacedKept(m) => write!(f, "agent kept a displaced file: {m}"),
        }
    }
}

pub(crate) const SHORT: Duration = Duration::from_secs(30);
pub(crate) const PING: Duration = Duration::from_secs(60);
/// Longer than the agent's whole time budget for `service.control` (140 s)
/// plus the SSH connection, so a controller never gives up on an agent that is
/// still working and then races it with a rollback (audit EX-07).
pub(crate) const LONG: Duration = Duration::from_secs(180);

// The agent ends its own run before the controller stops waiting.
const _: () = {
    use super::proto::{AGENT_BUDGET_LONG, AGENT_BUDGET_PING, AGENT_BUDGET_SHORT};
    assert!(AGENT_BUDGET_SHORT.as_secs() + 5 <= SHORT.as_secs());
    assert!(AGENT_BUDGET_PING.as_secs() + 5 <= PING.as_secs());
    assert!(AGENT_BUDGET_LONG.as_secs() + 10 <= LONG.as_secs());
    assert!(LONG.as_secs() >= 150);
};

/// Call an operation and return its `data` or the mapped error.
pub(crate) fn invoke(
    remote: &dyn Remote,
    target: &Target,
    op: &str,
    args: Value,
    timeout: Duration,
) -> Result<Value, CallError> {
    match remote.call(target, op, args, timeout) {
        Err(e) => Err(CallError::Transport(e)),
        // The host that answered must be the host that was addressed: a
        // mistyped or re-used address would otherwise act on the wrong node.
        Ok(response) if response.node != target.label => {
            Err(CallError::Transport(TransportError::Protocol(format!(
                "{} answered as {:?}, not {:?}; refusing to act on the wrong host",
                target.host, response.node, target.label
            ))))
        }
        Ok(response) if response.ok => Ok(response.data),
        Ok(response) => {
            let (kind, message) = response
                .error
                .map(|e| (e.code, e.message))
                .unwrap_or_else(|| (code::FAILED.to_string(), "no error body".to_string()));
            // `bad_request` is the agent saying it did not understand the
            // request and therefore did nothing: like a refusal (R4).
            if kind == code::REFUSED || kind == code::BAD_REQUEST {
                Err(CallError::Refused(message))
            } else if kind == code::DISPLACED_KEPT {
                Err(CallError::DisplacedKept(message))
            } else {
                Err(CallError::Failed(message))
            }
        }
    }
}

pub(crate) struct SshRemote {
    ssh: String,
    key: String,
    user: String,
    sudo: String,
    binary: String,
    known_hosts: String,
    connect_timeout: u64,
}

impl SshRemote {
    pub(crate) fn new(cfg: &ControlConfig) -> Self {
        Self {
            ssh: cfg.ssh_tool.clone(),
            key: cfg.ssh_key.display().to_string(),
            user: cfg.ssh_user.clone(),
            sudo: cfg.sudo_tool.clone(),
            binary: cfg.agent_binary.clone(),
            known_hosts: cfg.known_hosts.display().to_string(),
            connect_timeout: cfg.ssh_timeout_s,
        }
    }

    /// The complete ssh argument vector (exposed for tests). The remote
    /// command is fixed text built from validated configuration only.
    pub(crate) fn argv(&self, target: &Target) -> Vec<String> {
        // `-F /dev/null`: no per-user ssh configuration (a ProxyCommand or a
        // `Match exec` line in `~/.ssh/config` would run with the operator's
        // rights); everything this plane needs is given below (audit E-08).
        let mut args = vec![
            "-F".to_string(),
            "/dev/null".to_string(),
            "-i".to_string(),
            self.key.clone(),
            "-T".to_string(),
        ];
        for option in [
            "ProxyCommand=none".to_string(),
            "PermitLocalCommand=no".to_string(),
            "RequestTTY=no".to_string(),
            "BatchMode=yes".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "PasswordAuthentication=no".to_string(),
            "KbdInteractiveAuthentication=no".to_string(),
            "StrictHostKeyChecking=accept-new".to_string(),
            format!("UserKnownHostsFile={}", ssh_value(&self.known_hosts)),
            format!("HostKeyAlias={}", target.host_key_alias),
            format!("ConnectTimeout={}", self.connect_timeout),
            "ServerAliveInterval=5".to_string(),
            "ServerAliveCountMax=3".to_string(),
            "ControlMaster=no".to_string(),
            "ControlPath=none".to_string(),
            "ForwardAgent=no".to_string(),
            "ClearAllForwardings=yes".to_string(),
            "LogLevel=ERROR".to_string(),
        ] {
            args.push("-o".to_string());
            args.push(option);
        }
        // `--` ends the options: the destination can never be read as one.
        args.push("--".to_string());
        args.push(format!("{}@{}", self.user, target.host));
        args.push(format!("{} -n {} agent", self.sudo, self.binary));
        args
    }
}

impl Remote for SshRemote {
    fn call(
        &self,
        target: &Target,
        op: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Response, TransportError> {
        let request = Request {
            v: PROTO_VERSION,
            id: proto::random_hex(8),
            op: op.to_string(),
            args,
        };
        let mut payload = serde_json::to_vec(&request)
            .map_err(|e| TransportError::Protocol(format!("cannot encode request: {e}")))?;
        if payload.len() > proto::MAX_MESSAGE {
            return Err(TransportError::Protocol("request too large".to_string()));
        }
        payload.push(b'\n');
        let command = ExecCommand::new(self.ssh.clone(), self.argv(target), timeout)
            .with_stdin(payload)
            .with_env("PATH", "/usr/bin:/bin")
            .with_env("LANG", "C");
        match exec::run(&command) {
            ExecOutcome::SpawnFailed(e) => Err(TransportError::Unreachable(format!("ssh: {e}"))),
            ExecOutcome::TimedOut { .. } => {
                Err(TransportError::Timeout(format!("{op} on {}", target.label)))
            }
            ExecOutcome::Exited {
                code,
                stdout,
                stderr,
            } => {
                if code == Some(255) {
                    return Err(TransportError::Unreachable(first_line(&stderr.text())));
                }
                if stdout.truncated {
                    return Err(TransportError::Protocol("response too large".to_string()));
                }
                let response: Response = serde_json::from_slice(&stdout.bytes).map_err(|_| {
                    TransportError::Protocol(format!(
                        "no valid agent response (exit {code:?}): {}",
                        first_line(&stderr.text())
                    ))
                })?;
                if response.v != PROTO_VERSION {
                    return Err(TransportError::Protocol("protocol version mismatch".into()));
                }
                if response.id != request.id {
                    return Err(TransportError::Protocol("response id mismatch".to_string()));
                }
                Ok(response)
            }
        }
    }
}

/// ssh parses `-o` values like configuration lines: whitespace separates
/// arguments unless the value is double-quoted.
fn ssh_value(value: &str) -> String {
    if value.chars().any(char::is_whitespace) {
        format!("\"{value}\"")
    } else {
        value.to_string()
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("(no output)")
        .chars()
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual::config::tests::sample;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn option_values_with_spaces_are_quoted_for_ssh() {
        assert_eq!(ssh_value("/a/b"), "/a/b");
        assert_eq!(ssh_value("/a b/c"), "\"/a b/c\"");
    }

    #[test]
    fn argv_pins_the_remote_command_and_host_key_policy() {
        let cfg = sample();
        let remote = SshRemote::new(&cfg);
        let target = Target {
            label: "node-a".into(),
            host: "10.0.0.10".into(),
            host_key_alias: "inst-a".into(),
        };
        let argv = remote.argv(&target);
        assert_eq!(
            argv.last().unwrap(),
            "/usr/bin/sudo -n /usr/local/bin/mikagami agent"
        );
        assert!(argv.contains(&"mkg@10.0.0.10".to_string()));
        assert!(argv.contains(&"HostKeyAlias=inst-a".to_string()));
        assert!(argv.contains(&"StrictHostKeyChecking=accept-new".to_string()));
        assert!(argv.contains(&"BatchMode=yes".to_string()));
        assert!(!argv.iter().any(|a| a.contains("StrictHostKeyChecking=no")));
        assert!(
            !argv
                .iter()
                .any(|a| a.contains("UserKnownHostsFile=/dev/null"))
        );
    }

    #[test]
    fn argv_ignores_the_users_ssh_config_and_ends_the_options_before_the_destination() {
        let remote = SshRemote::new(&sample());
        let argv = remote.argv(&target());
        // E-08: no user configuration, no proxy, no local command, no tty.
        assert_eq!(&argv[..2], ["-F", "/dev/null"]);
        for option in [
            "ProxyCommand=none",
            "PermitLocalCommand=no",
            "RequestTTY=no",
        ] {
            assert!(argv.contains(&option.to_string()), "{option}");
        }
        // The destination and the remote command follow `--` and nothing else.
        let n = argv.len();
        assert_eq!(argv[n - 3], "--");
        assert_eq!(argv[n - 2], "mkg@10.0.0.10");
        // Every -o value is an `Option=value` pair, none starts with a dash.
        for (i, a) in argv.iter().enumerate() {
            if a == "-o" {
                assert!(!argv[i + 1].starts_with('-'));
            }
        }
        // A hostile user or host (they cannot come from a validated
        // configuration, but the argv must not depend on that) stays behind `--`.
        let mut hostile = remote;
        hostile.user = "-oProxyCommand=evil".to_string();
        let argv = hostile.argv(&target());
        let dashes = argv.iter().position(|a| a == "--").unwrap();
        assert!(argv[..dashes].iter().all(|a| !a.contains("evil")));
    }

    /// Run a real subprocess "ssh" stand-in: a script that echoes a canned
    /// response, to exercise the framing and error mapping end to end.
    fn fake_ssh(dir: &std::path::Path, body: &str) -> String {
        let path = dir.join("fake-ssh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    /// Run `attempt` again while its result says that the script it executes
    /// was still open for writing (`ETXTBSY`, "Text file busy"): the test wrote
    /// the script a moment ago and another test thread forked a child at that
    /// instant, which holds a copy of the descriptor until its own `exec`. It
    /// is a property of running these scripts in a parallel test run, not of
    /// the code under test; it made the two tests below fail now and then
    /// under load (audit round 2, note under RA-B). Any other result, in
    /// particular every real failure, is returned at once.
    fn retry_while_text_file_busy<T>(
        mut attempt: impl FnMut() -> T,
        is_busy: impl Fn(&T) -> bool,
    ) -> T {
        let mut result = attempt();
        for _ in 0..200 {
            if !is_busy(&result) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
            result = attempt();
        }
        result
    }

    fn busy_transport(error: &TransportError) -> bool {
        matches!(error, TransportError::Unreachable(m) if m.contains("Text file busy"))
    }

    #[test]
    fn the_retry_helper_retries_only_a_busy_script() {
        let mut calls = 0;
        let done = retry_while_text_file_busy(
            || {
                calls += 1;
                if calls < 3 {
                    Err::<(), _>(TransportError::Unreachable(
                        "ssh: Text file busy (os error 26)".into(),
                    ))
                } else {
                    Ok(())
                }
            },
            |r| matches!(r, Err(e) if busy_transport(e)),
        );
        assert!(done.is_ok());
        assert_eq!(calls, 3);
        // A real failure is returned at once, not retried.
        let mut calls = 0;
        let failed = retry_while_text_file_busy(
            || {
                calls += 1;
                Err::<(), _>(TransportError::Unreachable(
                    "ssh: Connection refused".into(),
                ))
            },
            |r| matches!(r, Err(e) if busy_transport(e)),
        );
        assert!(failed.is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn the_retry_helper_is_bounded_and_never_turns_a_failure_into_a_success() {
        // A script that stays busy: the helper gives up after its bound
        // (the first attempt plus 200 retries) and hands back the busy error
        // itself, so a test that depends on it still fails.
        let mut calls = 0;
        let result = retry_while_text_file_busy(
            || {
                calls += 1;
                Err::<(), _>(TransportError::Unreachable(
                    "ssh: Text file busy (os error 26)".into(),
                ))
            },
            |r| matches!(r, Err(e) if busy_transport(e)),
        );
        assert_eq!(calls, 201);
        assert!(matches!(&result, Err(e) if busy_transport(e)), "{result:?}");
    }

    fn remote_with(script_path: String) -> SshRemote {
        let mut remote = SshRemote::new(&sample());
        remote.ssh = script_path;
        remote
    }

    fn target() -> Target {
        Target {
            label: "node-a".into(),
            host: "10.0.0.10".into(),
            host_key_alias: "inst-a".into(),
        }
    }

    #[test]
    fn ssh_failures_and_garbage_are_transport_errors_never_success() {
        let dir = crate::manual::fsutil::tests::temp_dir("remote-ssh");
        let t = target();
        let call = |script: &str| {
            retry_while_text_file_busy(
                || {
                    remote_with(fake_ssh(&dir, script)).call(
                        &t,
                        "ping",
                        serde_json::json!({}),
                        Duration::from_secs(5),
                    )
                },
                |r| matches!(r, Err(e) if busy_transport(e)),
            )
        };
        assert!(matches!(
            call("echo 'Connection refused' >&2; exit 255"),
            Err(TransportError::Unreachable(m)) if m.contains("refused")
        ));
        assert!(matches!(
            call("echo not-json"),
            Err(TransportError::Protocol(_))
        ));
        assert!(matches!(
            call("echo 'sudo: a password is required' >&2; exit 1"),
            Err(TransportError::Protocol(m)) if m.contains("password")
        ));
        // A well-formed response with the wrong id is rejected.
        assert!(matches!(
            call(r#"cat >/dev/null; echo '{"v":1,"id":"deadbeefdeadbeef","ok":true,"data":{}}'"#),
            Err(TransportError::Protocol(m)) if m.contains("id mismatch")
        ));
        assert!(matches!(
            call("sleep 30"),
            Err(TransportError::Unreachable(_) | TransportError::Timeout(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_matching_response_is_returned_and_mapped() {
        let dir = crate::manual::fsutil::tests::temp_dir("remote-echo");
        // Echo the request id back inside a refusal.
        let script = r#"read line; id=$(printf '%s' "$line" | sed 's/.*"id":"\([^"]*\)".*/\1/'); printf '{"v":1,"id":"%s","node":"node-a","ok":false,"error":{"code":"refused","message":"nope"}}\n' "$id""#;
        let remote = remote_with(fake_ssh(&dir, script));
        let result = retry_while_text_file_busy(
            || {
                invoke(
                    &remote,
                    &target(),
                    "ping",
                    serde_json::json!({}),
                    Duration::from_secs(5),
                )
            },
            |r| matches!(r, Err(CallError::Transport(e)) if busy_transport(e)),
        );
        assert_eq!(result, Err(CallError::Refused("nope".to_string())));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
