# RPM package of Mikagami for Rocky Linux 9 / 10 (el9 / el10).
#
# Package-management safety rules (packaging/rpm/README.md, docs/rpm.md):
#   * install, upgrade and erase never start, stop, restart, enable or reload
#     an HA unit: no systemd_post macro (no preset), no systemd_postun_with_restart macro
#     (no try-restart), no `systemctl start`. The only systemctl calls are
#     `daemon-reload` (the unit files changed) and, on a full erase, `disable`
#     of the package's own unit file (no `--now`; the unit is already stopped).
#   * install, upgrade and erase are REFUSED (the scriptlet exits non-zero, so
#     rpm leaves the installed package as it was) while mikagami.service or
#     mikagami-witness.service is running, starting, stopping or queued, or
#     while any `mikagami|mkg daemon run` / `witness run` process exists. The
#     binary of a running HA daemon is never replaced or removed under it
#     (the rule of the v0.2 / v0.3 installers, audit EX-09). When systemd
#     cannot be asked, the scriptlet refuses (fail closed).
#   * the HA state is never packaged, created, modified or deleted: the node
#     state (/var/lib/mikagami/state.toml), the two-node record
#     (/var/lib/mikagami/two-node-state.json, two-node-operator/), the route
#     intents, the Witness state and journal (/var/lib/mikagami-witness), the
#     fencing marks and /run/mikagami are not in the files list and no scriptlet
#     touches them. Paths set in the configuration are equally untouched.
#   * the configuration files are config(noreplace): an edited file is kept
#     on upgrade (the new one is written as .rpmnew); a file that already
#     existed before the first install is kept (the packaged one is written
#     as .rpmnew).
#
# Release: `--define 'mkg_release N'` (default 1); the lifecycle test builds
# two releases for the upgrade.
#
# Toolchain: by default the build uses the `cargo` in PATH and requires the
# toolchain pinned by rust-toolchain.toml (the reproducible build); `--with
# system_rust` builds with the distribution's cargo/rust
# instead (BuildRequires added, the pin is not enforced).

%bcond_with system_rust

%global mkg_pinned_rust 1.98.0
# The release profile has no debug info, so a debuginfo subpackage would be
# empty (rpmbuild fails on an empty debugsourcefiles.list).
%global debug_package %{nil}
%global mkg_units mikagami.service mikagami-witness.service

Name:           mikagami
Version:        0.8.0
Release:        %{?mkg_release}%{!?mkg_release:1}%{?dist}
Summary:        Lightweight Linux HA service manager (Witness and witness-less two-node)
# Mikagami itself (LICENSE). The binary also contains third-party crates under
# permissive licenses (MIT, BSD-3-Clause, Unicode-3.0, ... ); their license texts and a
# list are shipped in the licenses directory (third-party/), see THIRD_PARTY_LICENSES.md.
License:        Apache-2.0
URL:            https://mikagami.fulltrust.co.jp
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.gz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  systemd-rpm-macros
BuildRequires:  gcc
# packaging/rpm/third-party-licenses.py
BuildRequires:  python3
%if %{with system_rust}
BuildRequires:  cargo >= 1.85
BuildRequires:  rust >= 1.85
%endif

# The daemon units pass --arping /usr/sbin/arping (iputils on el9 / el10).
Requires:       /usr/sbin/arping
# contrib/health/check-http (the HTTP health check) runs curl.
Requires:       /usr/bin/curl
# systemctl for the scriptlets (daemon-reload, the running-unit guard).
Requires(pre):    systemd
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd
# tr for the process check of the running-HA guard.
Requires(pre):    coreutils
Requires(preun):  coreutils

%description
Mikagami is a lightweight Linux HA service manager for one service and one
VIP on two nodes. It supports the Witness topology (two nodes and a third
Witness host) and the witness-less two-node topology
(cluster.topology = "two-node"). /usr/bin/mkg is the same program as
/usr/bin/mikagami.

Installing, upgrading or removing this package never starts, stops or
restarts the HA daemon, never moves the VIP and never deletes the HA state.
It refuses to run while the HA daemon or the Witness is running.

%prep
%setup -q
%setup -q -T -D -a 1
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"

[net]
offline = true
EOF
%if %{with system_rust}
rm -f rust-toolchain.toml
%endif
# The packaged units are the contrib units with the packaged binary path.
for unit in %{mkg_units}; do
  sed 's#/usr/local/bin/mikagami#%{_bindir}/mikagami#g' "contrib/systemd/$unit" > "packaging/rpm/$unit"
  if grep -q '/usr/local/' "packaging/rpm/$unit"; then
    echo "packaging/rpm/$unit still refers to /usr/local" >&2
    exit 1
  fi
done

%build
%if %{without system_rust}
if ! cargo --version | grep -q " %{mkg_pinned_rust} "; then
  echo "cargo is not the pinned toolchain %{mkg_pinned_rust} (rust-toolchain.toml): $(cargo --version)" >&2
  echo "build with the pinned toolchain in PATH, or pass --with system_rust" >&2
  exit 1
fi
%endif
export CARGO_HOME="$PWD/.cargo-home"
# The build directory (it holds the build host's user and home names) must not
# enter the binary: remap it to a fixed path (public hygiene; the binary then
# does not depend on where the build ran).
# One argument, not split on spaces (the build path may contain spaces).
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$PWD=/usr/src/mikagami-%{version}"
cargo build --release --locked --offline --bin mikagami

%install
install -D -m 0755 target/release/mikagami %{buildroot}%{_bindir}/mikagami
ln -s mikagami %{buildroot}%{_bindir}/mkg
install -D -m 0755 contrib/health/check-http %{buildroot}%{_libexecdir}/mikagami/check-http
for unit in %{mkg_units}; do
  install -D -m 0644 "packaging/rpm/$unit" "%{buildroot}%{_unitdir}/$unit"
done
install -d -m 0755 %{buildroot}%{_sysconfdir}/mikagami
install -m 0600 packaging/rpm/mikagami.toml %{buildroot}%{_sysconfdir}/mikagami/mikagami.toml
install -m 0600 packaging/rpm/witness.toml %{buildroot}%{_sysconfdir}/mikagami/witness.toml
install -d -m 0755 %{buildroot}%{_docdir}/%{name}/examples
install -m 0644 contrib/examples/*.toml %{buildroot}%{_docdir}/%{name}/examples/
install -m 0644 README.md TWO_NODE_ARCHITECTURE.md TWO_NODE_SAFETY_MODEL.md TWO_NODE_FAILURE_MATRIX.md %{buildroot}%{_docdir}/%{name}/
# Mikagami's license and the license texts of the third-party crates in the binary (the
# script fails when a crate has no license file).
export CARGO_HOME="$PWD/.cargo-home"
install -D -m 0644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE
install -m 0644 THIRD_PARTY_LICENSES.md %{buildroot}%{_licensedir}/%{name}/THIRD_PARTY_LICENSES.md
python3 packaging/rpm/third-party-licenses.py %{buildroot}%{_licensedir}/%{name}/third-party
install -m 0644 packaging/rpm/README.md %{buildroot}%{_docdir}/%{name}/README.rpm.md
install -d -m 0755 %{buildroot}%{_docdir}/%{name}/docs
install -m 0644 docs/*.md %{buildroot}%{_docdir}/%{name}/docs/

%check
# Both names are the same program (docs/cli-command-names.md).
./target/release/mikagami --help > help-mikagami.txt
ln -sf mikagami target/release/mkg
./target/release/mkg --help > help-mkg.txt
! grep -q mkg help-mikagami.txt
sed 's/mkg/mikagami/g' help-mkg.txt > help-mkg.norm
cmp help-mkg.norm help-mikagami.txt
./target/release/mikagami --version
./target/release/mkg --version
rm -f target/release/mkg
# The placeholder configuration must not be a usable configuration.
./target/release/mikagami status --config packaging/rpm/mikagami.toml > status-placeholder.txt 2>&1 || :
grep -q '^config.loaded: no ' status-placeholder.txt
if ./target/release/mikagami two-node status --config packaging/rpm/mikagami.toml >/dev/null 2>&1; then
  echo "the placeholder mikagami.toml was accepted" >&2
  exit 1
fi
# No build-host path in the binary.
if grep -a -q -F "$PWD" target/release/mikagami; then
  echo "the binary contains the build directory $PWD" >&2
  exit 1
fi

%pre
# BEGIN mkg-ha-guard (the same text in the pre and preun scriptlets, checked by the tests)
mkg_ha_guard() {
  mkg_what=$1
  if [ -d /proc ]; then
    for mkg_cmdline in /proc/[0-9]*/cmdline; do
      [ -r "$mkg_cmdline" ] || continue
      mkg_args=$(tr '\000' ' ' < "$mkg_cmdline" 2>/dev/null) || continue
      case "$mkg_args" in
        *mikagami\ daemon\ run*|*mikagami\ witness\ run*|*mkg\ daemon\ run*|*mkg\ witness\ run*)
          echo "mikagami: an HA process is running ($mkg_cmdline: $mkg_args); refusing to $mkg_what. Stop it first (docs/rpm.md)." >&2
          return 1 ;;
      esac
    done
  fi
  # No running systemd (a chroot or an image build): no unit can be running.
  [ -d /run/systemd/system ] || return 0
  if [ ! -x /usr/bin/systemctl ]; then
    echo "mikagami: cannot check the HA units (/usr/bin/systemctl missing); refusing to $mkg_what" >&2
    return 1
  fi
  if ! mkg_jobs=$(/usr/bin/systemctl list-jobs --no-pager --no-legend --full 2>/dev/null); then
    echo "mikagami: cannot list systemd jobs; refusing to $mkg_what" >&2
    return 1
  fi
  for mkg_unit in mikagami.service mikagami-witness.service; do
    mkg_state=$(/usr/bin/systemctl show --no-pager --property=ActiveState --value "$mkg_unit" 2>/dev/null) || mkg_state=unknown
    case "$mkg_state" in
      inactive|failed) ;;
      *)
        echo "mikagami: $mkg_unit is ${mkg_state:-unknown}; refusing to $mkg_what while the HA daemon is not stopped. Stop it first (docs/rpm.md)." >&2
        return 1 ;;
    esac
    case " $mkg_jobs " in
      *" $mkg_unit "*)
        echo "mikagami: a systemd job is queued for $mkg_unit; refusing to $mkg_what" >&2
        return 1 ;;
    esac
  done
  return 0
}
# END mkg-ha-guard
if [ "$1" -ge 2 ]; then
  mkg_ha_guard "upgrade the package" || exit 1
else
  mkg_ha_guard "install the package" || exit 1
fi
exit 0

%post
# daemon-reload only: no preset, no enable, no start.
if [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
  /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi
exit 0

%preun
# BEGIN mkg-ha-guard (the same text in the pre and preun scriptlets, checked by the tests)
mkg_ha_guard() {
  mkg_what=$1
  if [ -d /proc ]; then
    for mkg_cmdline in /proc/[0-9]*/cmdline; do
      [ -r "$mkg_cmdline" ] || continue
      mkg_args=$(tr '\000' ' ' < "$mkg_cmdline" 2>/dev/null) || continue
      case "$mkg_args" in
        *mikagami\ daemon\ run*|*mikagami\ witness\ run*|*mkg\ daemon\ run*|*mkg\ witness\ run*)
          echo "mikagami: an HA process is running ($mkg_cmdline: $mkg_args); refusing to $mkg_what. Stop it first (docs/rpm.md)." >&2
          return 1 ;;
      esac
    done
  fi
  # No running systemd (a chroot or an image build): no unit can be running.
  [ -d /run/systemd/system ] || return 0
  if [ ! -x /usr/bin/systemctl ]; then
    echo "mikagami: cannot check the HA units (/usr/bin/systemctl missing); refusing to $mkg_what" >&2
    return 1
  fi
  if ! mkg_jobs=$(/usr/bin/systemctl list-jobs --no-pager --no-legend --full 2>/dev/null); then
    echo "mikagami: cannot list systemd jobs; refusing to $mkg_what" >&2
    return 1
  fi
  for mkg_unit in mikagami.service mikagami-witness.service; do
    mkg_state=$(/usr/bin/systemctl show --no-pager --property=ActiveState --value "$mkg_unit" 2>/dev/null) || mkg_state=unknown
    case "$mkg_state" in
      inactive|failed) ;;
      *)
        echo "mikagami: $mkg_unit is ${mkg_state:-unknown}; refusing to $mkg_what while the HA daemon is not stopped. Stop it first (docs/rpm.md)." >&2
        return 1 ;;
    esac
    case " $mkg_jobs " in
      *" $mkg_unit "*)
        echo "mikagami: a systemd job is queued for $mkg_unit; refusing to $mkg_what" >&2
        return 1 ;;
    esac
  done
  return 0
}
# END mkg-ha-guard
# On an upgrade ($1 >= 1) the pre scriptlet of the new package has already checked.
if [ "$1" -eq 0 ]; then
  mkg_ha_guard "remove the package" || exit 1
  # Drop the enablement of the package's own unit file only (no --now: the
  # unit is stopped, checked above). A unit file or a mask of the same name in
  # /etc/systemd/system is the administrator's and is left alone.
  if [ -x /usr/bin/systemctl ]; then
    for mkg_unit in mikagami.service mikagami-witness.service; do
      if [ ! -e "/etc/systemd/system/$mkg_unit" ] && [ ! -L "/etc/systemd/system/$mkg_unit" ]; then
        /usr/bin/systemctl --no-reload disable "$mkg_unit" >/dev/null 2>&1 || :
      fi
    done
  fi
fi
exit 0

%postun
# daemon-reload only, on upgrade and on erase: never try-restart.
if [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
  /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi
exit 0

%files
%license %{_licensedir}/%{name}
%{_bindir}/mikagami
%{_bindir}/mkg
%dir %{_libexecdir}/mikagami
%{_libexecdir}/mikagami/check-http
%{_unitdir}/mikagami.service
%{_unitdir}/mikagami-witness.service
%dir %attr(0755,root,root) %{_sysconfdir}/mikagami
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/mikagami/mikagami.toml
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/mikagami/witness.toml
%doc %{_docdir}/%{name}

%changelog
* Fri Nov 20 2026 Mikagami project <noreply@example.invalid> - 0.8.0-1
- Version 0.8.0 (binary and package): the two-node shared configuration
  ([nodes.<id>], mikagami node register), resource groups ([[group.resource]]),
  [health] on_failure = warn | restart | failover, /usr/libexec/mikagami/check-http.
- The build path is remapped out of the binary.
* Fri Nov 20 2026 Mikagami project <noreply@example.invalid> - 0.7.0-1
- First RPM package (Witness topology and the witness-less two-node
  topology).
