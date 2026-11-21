//! Bounded external command execution for the manual control plane.
//!
//! Every external effect (`ssh`, `gcloud`, `systemctl`, `chronyd`, ...) goes
//! through [`run`]: an absolute program path, an argument vector that is never
//! interpreted by a shell, a hard deadline, bounded captured output and a
//! cleared environment apart from an explicit allowlist. A command that
//! outlives its deadline is killed as a whole process group and reported as
//! [`ExecOutcome::TimedOut`] — the caller must treat the effect as UNKNOWN.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Captured output cap per stream. Anything beyond is discarded and the
/// result is flagged as truncated (never silently treated as complete).
pub(crate) const MAX_CAPTURE: usize = 1 << 20;

const POLL_SLICE: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Captured {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

impl Captured {
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExecOutcome {
    /// The process ended by itself. `code` is `None` when a signal killed it.
    Exited {
        code: Option<i32>,
        stdout: Captured,
        stderr: Captured,
    },
    /// The deadline passed; the process group was killed.
    TimedOut { stdout: Captured, stderr: Captured },
    /// The process could not be started at all (no effect happened).
    SpawnFailed(String),
}

/// Description of one command.
#[derive(Debug, Clone)]
pub(crate) struct ExecCommand {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) stdin: Option<Vec<u8>>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) timeout: Duration,
}

impl ExecCommand {
    pub(crate) fn new(program: impl Into<String>, args: Vec<String>, timeout: Duration) -> Self {
        Self {
            program: program.into(),
            args,
            stdin: None,
            env: Vec::new(),
            timeout,
        }
    }

    pub(crate) fn with_stdin(mut self, stdin: Vec<u8>) -> Self {
        self.stdin = Some(stdin);
        self
    }

    pub(crate) fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }
}

fn spawn_reader<R: Read + Send + 'static>(mut source: R) -> mpsc::Receiver<Captured> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut truncated = false;
        let mut buffer = [0u8; 8192];
        loop {
            match source.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if bytes.len() < MAX_CAPTURE {
                        let room = MAX_CAPTURE - bytes.len();
                        bytes.extend_from_slice(&buffer[..n.min(room)]);
                        if n > room {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    truncated = true;
                    break;
                }
            }
        }
        let _ = tx.send(Captured { bytes, truncated });
    });
    rx
}

fn collect(rx: mpsc::Receiver<Captured>, wait: Duration) -> Captured {
    rx.recv_timeout(wait).unwrap_or(Captured {
        bytes: Vec::new(),
        truncated: true,
    })
}

/// Run one command to completion or deadline.
pub(crate) fn run(command: &ExecCommand) -> ExecOutcome {
    if !Path::new(&command.program).is_absolute() {
        return ExecOutcome::SpawnFailed(format!(
            "program path must be absolute: {}",
            command.program
        ));
    }
    let mut process = Command::new(&command.program);
    process
        .args(&command.args)
        .env_clear()
        .stdin(if command.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    for (key, value) in &command.env {
        process.env(key, value);
    }
    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) => return ExecOutcome::SpawnFailed(error.to_string()),
    };
    let pid = child.id();
    let stdout_rx = child.stdout.take().map(spawn_reader);
    let stderr_rx = child.stderr.take().map(spawn_reader);
    let stdin_thread = match (child.stdin.take(), command.stdin.clone()) {
        (Some(mut pipe), Some(data)) => Some(thread::spawn(move || {
            // A broken pipe is reported through the exit status of the child.
            let _ = pipe.write_all(&data);
            let _ = pipe.flush();
        })),
        _ => None,
    };

    let deadline = Instant::now() + command.timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => break None,
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break None;
        }
        thread::sleep(POLL_SLICE);
    };
    if timed_out || status.is_none() {
        kill_group(pid);
        let _ = child.kill();
        let _ = child.wait();
    }
    // The readers end when every writer of the pipe is gone; after the group
    // kill that is immediate. A grandchild that escaped the group could keep
    // the pipe open, so the wait is bounded.
    let grace = Duration::from_secs(2);
    let stdout = stdout_rx.map_or(
        Captured {
            bytes: Vec::new(),
            truncated: false,
        },
        |rx| collect(rx, grace),
    );
    let stderr = stderr_rx.map_or(
        Captured {
            bytes: Vec::new(),
            truncated: false,
        },
        |rx| collect(rx, grace),
    );
    if let Some(handle) = stdin_thread {
        let _ = handle.join();
    }
    if timed_out {
        return ExecOutcome::TimedOut { stdout, stderr };
    }
    match status {
        Some(status) => ExecOutcome::Exited {
            code: status.code(),
            stdout,
            stderr,
        },
        None => ExecOutcome::Exited {
            code: None,
            stdout,
            stderr,
        },
    }
}

fn kill_group(pid: u32) {
    let Ok(pgid) = i32::try_from(pid) else {
        return;
    };
    if pgid > 1 {
        // The child leads its own process group (`process_group(0)`), so a
        // negative pid addresses exactly that group and nothing else.
        // SAFETY: plain syscall with integer arguments.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str, timeout: Duration) -> ExecOutcome {
        run(&ExecCommand::new(
            "/bin/sh",
            vec!["-c".into(), script.into()],
            timeout,
        ))
    }

    #[test]
    fn captures_stdout_stderr_and_exit_code() {
        let outcome = sh("echo out; echo err >&2; exit 7", Duration::from_secs(5));
        let ExecOutcome::Exited {
            code,
            stdout,
            stderr,
        } = outcome
        else {
            panic!("expected exit");
        };
        assert_eq!(code, Some(7));
        assert_eq!(stdout.text(), "out\n");
        assert_eq!(stderr.text(), "err\n");
        assert!(!stdout.truncated && !stderr.truncated);
    }

    #[test]
    fn deadline_kills_the_whole_process_group_and_reports_timeout() {
        let started = Instant::now();
        let outcome = sh("sleep 30 & sleep 30; echo late", Duration::from_millis(300));
        assert!(
            matches!(outcome, ExecOutcome::TimedOut { .. }),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn output_is_bounded_and_flagged_truncated() {
        let outcome = sh(
            "head -c 3000000 /dev/zero | tr '\\0' 'a'",
            Duration::from_secs(20),
        );
        let ExecOutcome::Exited { stdout, .. } = outcome else {
            panic!("expected exit");
        };
        assert_eq!(stdout.bytes.len(), MAX_CAPTURE);
        assert!(stdout.truncated);
    }

    #[test]
    fn relative_program_is_refused_without_spawning() {
        let outcome = run(&ExecCommand::new("sh", vec![], Duration::from_secs(1)));
        assert!(matches!(outcome, ExecOutcome::SpawnFailed(_)));
    }

    #[test]
    fn missing_program_is_spawn_failure_not_exit() {
        let outcome = run(&ExecCommand::new(
            "/nonexistent/mkg-test-program",
            vec![],
            Duration::from_secs(1),
        ));
        assert!(matches!(outcome, ExecOutcome::SpawnFailed(_)));
    }

    #[test]
    fn environment_is_cleared_except_the_allowlist() {
        let command = ExecCommand::new("/usr/bin/env", vec![], Duration::from_secs(5))
            .with_env("MKG_ALLOWED", "1");
        let ExecOutcome::Exited { stdout, .. } = run(&command) else {
            panic!("expected exit");
        };
        assert_eq!(stdout.text().trim(), "MKG_ALLOWED=1");
    }

    #[test]
    fn stdin_payload_is_delivered_without_a_shell() {
        let command = ExecCommand::new("/bin/cat", vec![], Duration::from_secs(5))
            .with_stdin(b"$(touch /nonexistent/x); `id`\n".to_vec());
        let ExecOutcome::Exited { stdout, code, .. } = run(&command) else {
            panic!("expected exit");
        };
        assert_eq!(code, Some(0));
        assert_eq!(stdout.text(), "$(touch /nonexistent/x); `id`\n");
    }
}
