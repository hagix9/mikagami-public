//! Command-line contract of the manual control plane, checked on the built
//! binary (audit E-01, E-05, E-13).
//!
//! * `mkg` and `mikagami` are the same program: same exit codes, same output
//!   up to the program name (E-13).
//! * A closed standard output / error never turns a result into a panic (101)
//!   (E-01).
//! * `MKG_CONFIG` does not change what `status` does (E-05).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mikagami"))
}

fn scratch(label: &str) -> PathBuf {
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("mkg-cli-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(program: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(program);
    command.args(args).env_clear().stdin(Stdio::null());
    for (k, v) in envs {
        command.env(k, v);
    }
    command.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn mkg_and_mikagami_are_the_same_program() {
    let dir = scratch("names");
    let mkg = dir.join("mkg");
    let _ = std::fs::remove_file(&mkg);
    std::os::unix::fs::symlink(binary(), &mkg).unwrap();
    let missing = dir.join("no-such-config.toml");
    let missing = missing.to_str().unwrap();
    let cases: Vec<Vec<&str>> = vec![
        vec!["resource", "list", "--config", missing],
        vec!["resource", "status", "vip", "--json", "--config", missing],
        vec![
            "resource", "move", "vip", "--to", "node-b", "--config", missing,
        ],
        vec!["chronyd", "show", "--config", missing],
        vec!["resource", "move"],
        vec!["resource", "nonsense"],
        vec!["--version"],
        vec!["status", "--config", missing],
    ];
    for args in cases {
        let a = run(&binary(), &args, &[]);
        let b = run(&mkg, &args, &[]);
        assert_eq!(
            a.status.code(),
            b.status.code(),
            "exit code differs for {args:?}"
        );
        let here = dir.to_str().unwrap();
        let normalise = |o: &Output, name: &str| {
            let clean = |bytes: &[u8]| text(bytes).replace(here, "<DIR>").replace(name, "PROG");
            (clean(&o.stdout), clean(&o.stderr))
        };
        assert_eq!(
            normalise(&a, "mikagami"),
            normalise(&b, "mkg"),
            "output differs beyond the program name for {args:?}"
        );
        assert_ne!(a.status.code(), Some(101), "{args:?}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_closed_standard_output_or_error_is_never_a_panic() {
    let dir = scratch("closed");
    let missing = dir.join("no-such-config.toml");
    let missing = missing.to_str().unwrap();
    // Failing commands write their message to stderr and, with --json, to
    // stdout. With the descriptors closed the write fails; that must not
    // change the exit code (3 = refused: a configuration that cannot be read
    // is a refusal to start, R4) into 101.
    for redirect in ["1>&-", "2>&-", "1>&- 2>&-"] {
        let script = format!("exec \"$0\" \"$@\" {redirect}");
        let out = Command::new("/bin/sh")
            .args(["-c", &script])
            .arg(binary())
            .args(["resource", "list", "--json", "--config", missing])
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(3),
            "{redirect}: {}",
            text(&out.stderr)
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// A pipe whose read end is already closed: every write to the other end
/// fails with `EPIPE` (the Rust runtime ignores `SIGPIPE`, so the process sees
/// the error, not a signal). Closing a descriptor, as the test above does,
/// gives `EBADF`, which Rust's standard streams swallow: that test could not
/// tell a program that checks write errors from one that does not (audit
/// RA-E-08).
fn broken_pipe() -> Stdio {
    Stdio::from(broken_pipe_fd())
}

fn broken_pipe_fd() -> std::os::fd::OwnedFd {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` has room for the two descriptors `pipe` writes.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: both descriptors were just created and are owned here.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    drop(read);
    write
}

#[test]
fn a_broken_pipe_on_standard_output_or_error_is_never_a_panic() {
    let dir = scratch("epipe");
    let missing = dir.join("no-such-config.toml");
    let missing = missing.to_str().unwrap();
    // `resource list --json` of a missing configuration writes the failure to
    // stderr and the JSON document to stdout; both writes now fail with EPIPE.
    // v0.3: every command of the manual plane, not only `resource list`
    // (the HA `status` command is not part of this check: its EPIPE panic is
    // the open item B-L8, `prototype/v0.3/HA_STATUS_EPIPE.md`).
    let command_lines: [&[&str]; 5] = [
        &["resource", "list", "--json"],
        &["resource", "status", "vip", "--json"],
        &["resource", "move", "vip", "--to", "node-b", "--json"],
        &["chronyd", "show", "--json"],
        &[
            "chronyd",
            "apply",
            "--node",
            "node-a",
            "/nonexistent-candidate",
            "--json",
        ],
    ];
    for (line, (label, out_pipe, err_pipe)) in command_lines.iter().flat_map(|line| {
        [
            ("stdout", true, false),
            ("stderr", false, true),
            ("both", true, true),
        ]
        .map(move |case| (*line, case))
    }) {
        let mut command = Command::new(binary());
        command
            .args(line)
            .args(["--config", missing])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(if out_pipe {
                broken_pipe()
            } else {
                Stdio::null()
            })
            .stderr(if err_pipe {
                broken_pipe()
            } else {
                Stdio::piped()
            });
        let out = command.spawn().unwrap().wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(3),
            "{label} {line:?}: a write error changed the exit code (101 is a panic): {}",
            text(&out.stderr)
        );
    }
    // The check has teeth: a write to such a pipe really fails with EPIPE
    // (it is not swallowed like the EBADF of a closed descriptor).
    use std::io::Write as _;
    let mut file = std::fs::File::from(broken_pipe_fd());
    let error = file.write_all(b"x").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_control_config_environment_variable_does_not_change_status() {
    let dir = scratch("status");
    let missing_ha = dir.join("no-ha.toml");
    let missing_ha = missing_ha.to_str().unwrap();
    let plain = run(&binary(), &["status", "--config", missing_ha], &[]);
    let with_env = run(
        &binary(),
        &["status", "--config", missing_ha],
        &[("MKG_CONFIG", "/nonexistent/control.toml")],
    );
    assert_eq!(plain.status.code(), Some(0), "{}", text(&plain.stderr));
    assert_eq!(with_env.status.code(), plain.status.code());
    assert_eq!(text(&with_env.stdout), text(&plain.stdout));
    assert_eq!(text(&with_env.stderr), text(&plain.stderr));
    // The explicit flag still asks for the overview (and fails here, because
    // the file is missing: the exit code says so).
    let asked = run(
        &binary(),
        &[
            "status",
            "--config",
            missing_ha,
            "--control-config",
            "/nonexistent/control.toml",
        ],
        &[],
    );
    assert_ne!(asked.status.code(), Some(0));
    assert_ne!(asked.status.code(), Some(101));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_usage_error_is_exit_2_and_prints_no_json() {
    let out = run(&binary(), &["resource", "move", "vip", "--json"], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        out.stdout.is_empty(),
        "usage errors produce no JSON on stdout"
    );
}

#[test]
fn status_json_has_a_top_level_ok_that_agrees_with_the_exit_code() {
    let dir = scratch("status-json");
    let missing_ha = dir.join("no-ha.toml");
    let missing_ha = missing_ha.to_str().unwrap();
    let plain = run(
        &binary(),
        &["status", "--json", "--config", missing_ha],
        &[],
    );
    assert_eq!(plain.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&plain.stdout).unwrap();
    assert_eq!(doc["ok"], true);
    let asked = run(
        &binary(),
        &[
            "status",
            "--json",
            "--config",
            missing_ha,
            "--control-config",
            "/nonexistent/control.toml",
        ],
        &[],
    );
    assert_ne!(asked.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&asked.stdout).unwrap();
    assert_eq!(doc["ok"], false);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_refusal_to_start_has_exit_3_and_a_json_that_says_so() {
    // R4: a configuration that cannot be read is REFUSED (nothing was sent
    // anywhere). The process exit code, `exit` and `result` agree, for the
    // resource and chronyd commands and for `status --control-config`.
    let dir = scratch("refusal-json");
    let missing = dir.join("no-such-config.toml");
    let missing = missing.to_str().unwrap();
    let missing_ha = dir.join("no-ha.toml");
    let missing_ha = missing_ha.to_str().unwrap();
    let cases: Vec<(Vec<&str>, bool)> = vec![
        (
            vec!["resource", "list", "--json", "--config", missing],
            false,
        ),
        (
            vec![
                "resource", "move", "vip", "--to", "node-b", "--json", "--config", missing,
            ],
            false,
        ),
        (
            vec!["chronyd", "show", "--json", "--config", missing],
            false,
        ),
        (
            vec![
                "status",
                "--json",
                "--config",
                missing_ha,
                "--control-config",
                missing,
            ],
            true,
        ),
    ];
    for (args, nested) in cases {
        let out = run(&binary(), &args, &[]);
        assert_eq!(
            out.status.code(),
            Some(3),
            "{args:?}: {}",
            text(&out.stderr)
        );
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(doc["ok"], false, "{args:?}");
        let failure = if nested { &doc["control"] } else { &doc };
        assert_eq!(failure["result"], "refused", "{args:?}");
        assert_eq!(failure["exit"], 3, "{args:?}");
        if nested {
            assert_eq!(doc["exit"], 3);
            assert_eq!(doc["result"], "refused");
        }
        assert!(
            text(&out.stderr).starts_with("REFUSED: "),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_broken_pipe_never_changes_the_exit_code_of_the_ha_status_command() {
    // The HA `status` report is read-only. With its standard output closed it must end
    // with the code it has when the output is read (here: whatever `status` returns for a
    // missing configuration), never with 101 (a panic of `println!` on EPIPE).
    let dir = scratch("ha-status-epipe");
    let missing = dir.join("no-such-config.toml");
    let missing = missing.to_str().unwrap();
    for json in [false, true] {
        let mut args = vec!["status", "--config", missing];
        if json {
            args.push("--json");
        }
        let normal = run(&binary(), &args, &[]);
        let mut command = Command::new(binary());
        command
            .args(&args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(broken_pipe())
            .stderr(Stdio::piped());
        let out = command.spawn().unwrap().wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            normal.status.code(),
            "json={json}: a closed pipe changed the exit code (101 is a panic): {}",
            text(&out.stderr)
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_broken_pipe_does_not_turn_a_successful_ha_status_report_into_a_failure() {
    // The same property as above for the success path: with a valid configuration the report
    // ends with 0 when its output is read, so it must also end with 0 when the output pipe is
    // closed (not 101).
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("contrib/examples/node-a.toml");
    let example = example.to_str().unwrap();
    for json in [false, true] {
        let mut args = vec!["status", "--config", example];
        if json {
            args.push("--json");
        }
        let normal = run(&binary(), &args, &[]);
        assert_eq!(
            normal.status.code(),
            Some(0),
            "json={json}: {}",
            text(&normal.stderr)
        );
        let mut command = Command::new(binary());
        command
            .args(&args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(broken_pipe())
            .stderr(Stdio::piped());
        let out = command.spawn().unwrap().wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "json={json}: a closed pipe changed the exit code of a successful report: {}",
            text(&out.stderr)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_full_disk_is_not_reported_as_a_successful_ha_status_report() {
    // EPIPE means "the reader is gone"; ENOSPC means "the report was not
    // delivered". `status` is read-only, but a silently lost report is not a
    // success. The test uses the kernel's /dev/full, which fails every write
    // with ENOSPC, so it is a real write failure rather than a closed fd.
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("contrib/examples/node-a.toml");
    let example = example.to_str().unwrap();
    for json in [false, true] {
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("/dev/full");
        let mut args = vec!["status", "--config", example];
        if json {
            args.push("--json");
        }
        let out = Command::new(binary())
            .args(&args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::from(full))
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(1),
            "json={json}: an ENOSPC write must fail the command: {}",
            text(&out.stderr)
        );
        assert!(
            text(&out.stderr).contains("cannot write the status report"),
            "json={json}: the failure must name the write problem: {}",
            text(&out.stderr)
        );
        assert_ne!(out.status.code(), Some(101), "json={json}: panic");
    }
}

#[test]
fn ha_status_with_a_missing_control_config_is_a_consistent_failure_not_a_panic() {
    // `--control-config` is the only way the manual overview is enabled
    // (audit E-05). A missing file must be a refusal of its own kind, and the
    // HA report plus the JSON envelope must still be produced. This is the
    // local half of the v0.4 NOT VERIFIED item; the cloud-contacting half is
    // run only on Linux with the prototype configuration.
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("contrib/examples/node-a.toml");
    let example = example.to_str().unwrap();
    let dir = scratch("control-missing");
    let missing = dir.join("no-such-control.toml");
    let missing = missing.to_str().unwrap();
    for json in [false, true] {
        let mut args = vec!["status", "--config", example, "--control-config", missing];
        if json {
            args.push("--json");
        }
        let out = run(&binary(), &args, &[]);
        assert_eq!(
            out.status.code(),
            Some(3),
            "json={json}: {}",
            text(&out.stderr)
        );
        assert!(
            !text(&out.stderr).contains("panicked"),
            "json={json}: {}",
            text(&out.stderr)
        );
        if json {
            let document: serde_json::Value =
                serde_json::from_slice(&out.stdout).expect("JSON envelope");
            assert_eq!(document["exit"], 3);
            assert_eq!(document["ok"], false);
            assert_eq!(document["result"], "refused");
            assert!(document["ha_local"]["report"].is_string());
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
