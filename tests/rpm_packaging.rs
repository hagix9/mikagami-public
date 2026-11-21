//! The RPM package of v0.7 (`packaging/rpm/`): what can be checked without rpm
//! and without a Linux host.
//!
//! * the spec: name, version, the packaged files, `%config(noreplace)`, no HA
//!   state in `%files`, no systemd macro or call that starts, restarts or
//!   presets a unit;
//! * the packaged systemd units: derived from `contrib/systemd/` by replacing
//!   only the binary path;
//! * the placeholder configuration files are refused by every entry point that
//!   reads them, so an unedited install can never start an HA daemon;
//! * `mkg` installed as a relative link to `mikagami` (the layout of
//!   `/usr/bin`) is the same program: same exit codes, same output up to the
//!   program name;
//! * the scriptlets, run from the spec text with a fake systemctl
//!   (`packaging/rpm/tests/test_rpm_scriptlets.sh`); the number of checks is
//!   pinned so that a harness that silently runs fewer cases cannot pass.
//!
//! The real install / upgrade / erase on Rocky Linux is
//! `packaging/rpm/tests/rpm-lifecycle-test.sh` (a disposable host, as root);
//! here it is only parsed (`sh -n`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The number of checks of the scriptlet harness when this guard was written.
const MIN_SCRIPTLET_CHECKS: usize = 279;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo().join(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

fn spec() -> String {
    read("packaging/rpm/mikagami.spec")
}

fn scratch(label: &str) -> PathBuf {
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("mkg-rpm-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The lines of one spec section (from its header to the next section header).
fn section(spec: &str, name: &str) -> Vec<String> {
    const HEADERS: [&str; 12] = [
        "%description",
        "%prep",
        "%build",
        "%install",
        "%check",
        "%pre",
        "%post",
        "%preun",
        "%postun",
        "%files",
        "%changelog",
        "%posttrans",
    ];
    let mut out = Vec::new();
    let mut on = false;
    for line in spec.lines() {
        let head = line.split_whitespace().next().unwrap_or("");
        if HEADERS.contains(&head) {
            on = head == name;
            continue;
        }
        if on {
            out.push(line.to_string());
        }
    }
    out
}

fn tag(spec: &str, name: &str) -> String {
    spec.lines()
        .find_map(|l| l.strip_prefix(&format!("{name}:")))
        .unwrap_or_else(|| panic!("no {name}: tag"))
        .trim()
        .to_string()
}

#[test]
fn spec_names_the_package_and_version() {
    let spec = spec();
    assert_eq!(tag(&spec, "Name"), "mikagami");
    assert_eq!(tag(&spec, "Version"), "0.8.0");
    // One version everywhere: the package, the crate (`--version`), build.sh, the lifecycle
    // test and the newest changelog entry.
    assert_eq!(tag(&spec, "Version"), env!("CARGO_PKG_VERSION"));
    let version = env!("CARGO_PKG_VERSION");
    assert!(read("packaging/rpm/build.sh").contains(&format!("VERSION={version}\n")));
    assert!(
        read("packaging/rpm/tests/rpm-lifecycle-test.sh")
            .contains(&format!("grep -qx 'mikagami {version}'"))
    );
    let newest = section(&spec, "%changelog")
        .into_iter()
        .find(|l| l.starts_with('*'))
        .unwrap();
    assert!(newest.ends_with(&format!(" - {version}-1")), "{newest}");
    assert!(tag(&spec, "Release").contains("%{?dist}"));
    assert!(spec.contains("%bcond_with system_rust"));
    // The pinned toolchain of the spec is the one of rust-toolchain.toml.
    let pinned = read("rust-toolchain.toml");
    let channel = pinned
        .lines()
        .find_map(|l| l.strip_prefix("channel = "))
        .unwrap()
        .trim_matches('"')
        .to_string();
    assert!(
        spec.contains(&format!("%global mkg_pinned_rust {channel}")),
        "the spec pins another toolchain than rust-toolchain.toml ({channel})"
    );
    assert!(spec.contains("cargo build --release --locked --offline --bin mikagami"));
    // The build directory (build host user and home names) is remapped out of the
    // binary, and %check proves it is absent.
    assert!(spec.contains(
        "export CARGO_ENCODED_RUSTFLAGS=\"--remap-path-prefix=$PWD=/usr/src/mikagami-%{version}\""
    ));
    assert!(spec.contains("grep -a -q -F \"$PWD\" target/release/mikagami"));
    for dependency in [
        "Requires:       /usr/sbin/arping",
        "Requires:       /usr/bin/curl",
        "Requires(pre):    systemd",
        "Requires(preun):  systemd",
        "Requires(post):   systemd",
        "Requires(postun): systemd",
        "Requires(pre):    coreutils",
        "Requires(preun):  coreutils",
        "BuildRequires:  systemd-rpm-macros",
    ] {
        assert!(spec.contains(dependency), "missing: {dependency}");
    }
}

#[test]
fn spec_packages_the_binary_the_link_the_units_and_the_config() {
    let spec = spec();
    let files: Vec<String> = section(&spec, "%files")
        .into_iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let expected = [
        "%license %{_licensedir}/%{name}",
        "%{_bindir}/mikagami",
        "%{_bindir}/mkg",
        "%dir %{_libexecdir}/mikagami",
        "%{_libexecdir}/mikagami/check-http",
        "%{_unitdir}/mikagami.service",
        "%{_unitdir}/mikagami-witness.service",
        "%dir %attr(0755,root,root) %{_sysconfdir}/mikagami",
        "%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/mikagami/mikagami.toml",
        "%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/mikagami/witness.toml",
        "%doc %{_docdir}/%{name}",
    ];
    assert_eq!(files, expected, "%files changed");
    // Every file under /etc is %config(noreplace).
    for line in &files {
        if line.contains("%{_sysconfdir}/mikagami/") {
            assert!(line.starts_with("%config(noreplace) "), "{line}");
        }
    }
    let install = section(&spec, "%install").join("\n");
    assert!(install.contains("ln -s mikagami %{buildroot}%{_bindir}/mkg"));
    assert!(
        install
            .contains("install -D -m 0755 target/release/mikagami %{buildroot}%{_bindir}/mikagami")
    );
}

#[test]
fn spec_never_packages_or_touches_the_ha_state() {
    let spec = spec();
    for name in ["%files", "%pre", "%post", "%preun", "%postun", "%install"] {
        let body = section(&spec, name).join("\n");
        for path in [
            "/var/lib",
            "%{_sharedstatedir}",
            "%{_localstatedir}",
            "/run/mikagami",
            "%{_rundir}",
            "mikagami-witness/",
            "state.toml",
            "two-node-state",
            "%ghost",
            "tmpfiles",
        ] {
            assert!(!body.contains(path), "{name} mentions {path}");
        }
    }
}

#[test]
fn spec_never_starts_restarts_or_presets_a_unit() {
    let spec = spec();
    for forbidden in [
        "%systemd_post",
        "%systemd_preun",
        "%systemd_postun",
        "%systemd_user",
        "%service_add",
        "%tmpfiles_create",
        "%posttrans",
        "%triggerin",
        "%filetriggerin",
    ] {
        // rpm expands macros inside comments too, so not even a comment may
        // name them (rpmbuild on el10 failed on a commented
        // systemd_postun_with_restart).
        assert!(!spec.contains(forbidden), "the spec names {forbidden}");
    }
    for line in spec.lines() {
        if !line.trim_start().starts_with('#') {
            assert!(!line.contains("try-restart"), "{line}");
        } else {
            assert!(
                !line.contains('%'),
                "a % in a spec comment is expanded by rpm: {line}"
            );
        }
    }
    for name in ["%pre", "%post", "%preun", "%postun"] {
        for line in section(&spec, name) {
            if line.trim_start().starts_with('#') || !line.contains("systemctl") {
                continue;
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            for verb in [
                "start", "restart", "stop", "enable", "reenable", "preset", "reload", "kill",
                "isolate", "mask", "unmask", "--now",
            ] {
                assert!(!words.contains(&verb), "{name}: {line}");
            }
        }
    }
}

#[test]
fn packaged_units_are_the_contrib_units_with_the_packaged_binary_path() {
    for (unit, exec) in [
        (
            "mikagami.service",
            "ExecStart=/usr/local/bin/mikagami daemon run --config /etc/mikagami/mikagami.toml --arping /usr/sbin/arping",
        ),
        (
            "mikagami-witness.service",
            "ExecStart=/usr/local/bin/mikagami witness run --config /etc/mikagami/witness.toml",
        ),
    ] {
        let text = read(&format!("contrib/systemd/{unit}"));
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("ExecStart"))
            .collect();
        assert_eq!(lines, [exec], "{unit}");
        // The %prep sed: the only /usr/local reference is the binary.
        let packaged = text.replace("/usr/local/bin/mikagami", "/usr/bin/mikagami");
        assert!(!packaged.contains("/usr/local/"), "{unit}");
        assert!(packaged.contains("ExecStart=/usr/bin/mikagami "), "{unit}");
        // The packaged unit is not enabled by anything but the operator: no
        // Install alias that would pull it in elsewhere.
        assert!(!text.contains("Alias="), "{unit}");
        assert!(
            text.contains("[Install]\nWantedBy=multi-user.target"),
            "{unit}"
        );
    }
    let prep = section(&spec(), "%prep").join("\n");
    assert!(prep.contains("sed 's#/usr/local/bin/mikagami#%{_bindir}/mikagami#g'"));
    assert!(spec().contains("%global mkg_units mikagami.service mikagami-witness.service"));
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mikagami"))
}

fn run(program: &Path, args: &[&str], cwd: &Path) -> Output {
    Command::new(program)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn placeholder_configs_are_refused_by_every_reader() {
    let node = repo().join("packaging/rpm/mikagami.toml");
    let witness = repo().join("packaging/rpm/witness.toml");
    for file in [&node, &witness] {
        let content = std::fs::read_to_string(file).unwrap();
        assert!(
            content
                .lines()
                .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#')),
            "{file:?} must hold comments only"
        );
    }
    let dir = scratch("placeholder");
    let node = node.to_str().unwrap();
    let witness = witness.to_str().unwrap();

    let status = run(&binary(), &["status", "--config", node], &dir);
    assert!(
        text(&status).contains("config.loaded: no ("),
        "{}",
        text(&status)
    );

    for args in [
        vec!["two-node", "status", "--config", node],
        vec!["two-node", "init", "--config", node],
        vec!["witness", "run", "--config", witness],
        vec!["witness", "init", "--config", witness],
        vec!["witness", "rearm", "--config", witness],
        vec!["witness", "run", "--config", node],
    ] {
        let out = run(&binary(), &args, &dir);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", text(&out));
        assert!(
            text(&out).contains("missing field `cluster`"),
            "{args:?}: {}",
            text(&out)
        );
    }
    // Nothing was created next to the scratch directory by the refused runs.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mkg_link_in_the_packaged_layout_is_the_same_program() {
    // /usr/bin/mikagami (a file) and /usr/bin/mkg -> mikagami (relative link).
    let dir = scratch("layout");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let mikagami = bin.join("mikagami");
    std::fs::copy(binary(), &mikagami).unwrap();
    let mkg = bin.join("mkg");
    std::os::unix::fs::symlink("mikagami", &mkg).unwrap();
    assert_eq!(std::fs::read_link(&mkg).unwrap(), Path::new("mikagami"));
    let cwd = scratch("layout-cwd");
    let missing = cwd.join("no-such.toml");
    let missing = missing.to_str().unwrap();
    let cases: Vec<Vec<&str>> = vec![
        vec!["--help"],
        vec!["--version"],
        vec!["status", "--help"],
        vec!["daemon", "--help"],
        vec!["daemon", "run", "--help"],
        vec!["witness", "--help"],
        vec!["witness", "run", "--help"],
        vec!["two-node", "--help"],
        vec!["two-node", "status", "--help"],
        vec!["two-node", "takeover", "--help"],
        vec!["resource", "--help"],
        vec!["chronyd", "--help"],
        vec!["recover", "--help"],
        vec!["nonsense"],
        vec!["status", "--config", missing],
        vec!["two-node", "status", "--config", missing],
        vec!["witness", "run", "--config", missing],
        vec!["daemon", "run"],
        vec!["recover", "svc"],
    ];
    for args in cases {
        let a = run(&mikagami, &args, &cwd);
        let b = run(&mkg, &args, &cwd);
        assert_eq!(
            a.status.code(),
            b.status.code(),
            "exit code differs for {args:?}"
        );
        assert_ne!(a.status.code(), Some(101), "{args:?}");
        // Only the program name differs: `mkg` output with the name spelled
        // `mikagami` is byte-identical (paths such as /etc/mikagami stay as
        // they are on both sides).
        // The scratch path (it may contain "mkg", e.g. a TMPDIR of ~/.mkg-tmp)
        // is masked first on both sides.
        let here = cwd.to_str().unwrap();
        let a_text = text(&a).replace(here, "<DIR>");
        let b_text = text(&b).replace(here, "<DIR>");
        assert!(
            !a_text.contains("mkg"),
            "{args:?}: literal mkg in the output"
        );
        assert_eq!(
            a_text,
            b_text.replace("mkg", "mikagami"),
            "output differs beyond the program name for {args:?}"
        );
    }
    let version = text(&run(&mkg, &["--version"], &cwd));
    assert!(version.starts_with("mkg "), "{version}");
    std::fs::remove_dir_all(dir).unwrap();
    std::fs::remove_dir_all(cwd).unwrap();
}

#[test]
fn scriptlets_refuse_while_ha_runs_and_never_start_anything() {
    let script = repo().join("packaging/rpm/tests/test_rpm_scriptlets.sh");
    let dir = scratch("scriptlets");
    let output = Command::new("sh")
        .arg(&script)
        .arg(dir.join("work"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "scriptlet tests failed:\n{out}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.contains(" 0 failures"), "{out}");
    let checks: usize = out
        .lines()
        .find_map(|l| {
            l.strip_prefix("rpm scriptlet tests: ")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or(0);
    assert!(
        checks >= MIN_SCRIPTLET_CHECKS,
        "only {checks} checks ran:\n{out}"
    );
}

#[test]
fn packaging_scripts_parse() {
    for script in [
        "packaging/rpm/build.sh",
        "packaging/rpm/tests/test_rpm_scriptlets.sh",
        "packaging/rpm/tests/rpm-lifecycle-test.sh",
    ] {
        let out = Command::new("sh")
            .arg("-n")
            .arg(repo().join(script))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // The lifecycle test refuses to run without the explicit disposable-host flag.
    let out = Command::new("sh")
        .arg(repo().join("packaging/rpm/tests/rpm-lifecycle-test.sh"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--i-am-a-disposable-host"));
}

#[test]
fn build_sources_list_covers_what_the_spec_reads() {
    let build = read("packaging/rpm/build.sh");
    let archived = "Cargo.toml Cargo.lock rust-toolchain.toml README.md LICENSE THIRD_PARTY_LICENSES.md \\\n      TWO_NODE_ARCHITECTURE.md \\\n      TWO_NODE_SAFETY_MODEL.md TWO_NODE_FAILURE_MATRIX.md src contrib docs packaging";
    assert!(build.contains(archived), "build.sh archive list changed");
    let spec = spec();
    for used in [
        "contrib/systemd/",
        "contrib/examples/",
        "packaging/rpm/mikagami.toml",
        "packaging/rpm/witness.toml",
        "packaging/rpm/README.md",
        "docs/*.md",
        "README.md",
    ] {
        assert!(spec.contains(used), "{used}");
        let top = used.split('/').next().unwrap();
        assert!(
            archived.split(' ').any(|a| a == top),
            "{used} is not in the source tarball"
        );
    }
}

/// The SHA-256 of the official text of https://www.apache.org/licenses/LICENSE-2.0.txt.
const APACHE_2_0_SHA256: &str = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";

#[test]
fn the_license_is_the_unmodified_apache_2_0_text_everywhere() {
    use sha2::{Digest, Sha256};
    let text = std::fs::read(repo().join("LICENSE")).unwrap();
    let digest: String = Sha256::digest(&text)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest, APACHE_2_0_SHA256,
        "LICENSE is not the official text"
    );
    assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
    let spec = spec();
    assert_eq!(tag(&spec, "License"), env!("CARGO_PKG_LICENSE"));
    assert!(spec.contains("BuildRequires:  python3"));
    let install = section(&spec, "%install").join("\n");
    assert!(
        install.contains("install -D -m 0644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE")
    );
    assert!(install.contains(
        "python3 packaging/rpm/third-party-licenses.py %{buildroot}%{_licensedir}/%{name}/third-party"
    ));
    assert!(read("README.md").contains("Apache License"));
}

#[test]
fn third_party_licenses_are_complete_and_listed() {
    // Every third-party crate of the Linux binary has a license file (the script fails
    // otherwise), and THIRD_PARTY_LICENSES.md lists exactly those crates.
    let dir = scratch("third-party");
    let script = repo().join("packaging/rpm/third-party-licenses.py");
    let out = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(dir.join("out"))
        .args(["--target", "x86_64-unknown-linux-gnu"])
        .current_dir(repo())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listing = std::fs::read_to_string(dir.join("out/README.txt")).unwrap();
    let crates: Vec<&str> = listing.lines().skip(3).collect();
    assert!(crates.len() > 40, "{listing}");
    for line in &crates {
        let (crate_version, _) = line.split_once(": ").unwrap();
        let folder = dir.join("out").join(crate_version.replace(' ', "-"));
        assert!(
            std::fs::read_dir(&folder).unwrap().count() > 0,
            "{crate_version}: no license text"
        );
    }
    let table = read("THIRD_PARTY_LICENSES.md");
    let rows: Vec<String> = table
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("| crate"))
        .map(|l| {
            let cells: Vec<&str> = l.trim_matches('|').split(" | ").map(str::trim).collect();
            format!("{} {}: {}", cells[0], cells[1], cells[2])
        })
        .collect();
    assert_eq!(rows, crates, "THIRD_PARTY_LICENSES.md is stale");
    // No crate of the binary ships a NOTICE file (so none has to be reproduced); the table
    // says so, and the collected texts confirm it.
    assert!(table.contains("No third-party crate ships a `NOTICE` file."));
    for line in &crates {
        let (crate_version, _) = line.split_once(": ").unwrap();
        let folder = dir.join("out").join(crate_version.replace(' ', "-"));
        for entry in std::fs::read_dir(folder).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().to_uppercase();
            assert!(!name.starts_with("NOTICE"), "{crate_version} ships {name}");
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
