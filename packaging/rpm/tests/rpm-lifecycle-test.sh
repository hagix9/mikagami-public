#!/bin/sh
# Install / upgrade / remove test of the Mikagami RPM on a DISPOSABLE Rocky
# Linux 9 or 10 host (a throw-away VM; never a cluster node, never a host with
# a Mikagami installation or HA state).
#
# usage (as root):
#   rpm-lifecycle-test.sh --rpm1 mikagami-0.8.0-1.elN.ARCH.rpm \
#                         --rpm2 mikagami-0.8.0-2.elN.ARCH.rpm \
#                         --i-am-a-disposable-host [--evidence DIR]
#
# What it checks:
#   * the package contents, modes, the mkg link and the dependencies;
#   * `mkg` and `mikagami` give the same output (up to the program name) and
#     the same exit codes;
#   * install, upgrade and erase never start or enable a unit, never change
#     the addresses or routes of the host;
#   * fixture HA state (Witness state and journal, node state, two-node record
#     and operator requests, route intents, /run/mikagami) is byte-identical
#     after install, upgrade, erase and reinstall;
#   * an edited configuration survives the upgrade (.rpmnew) and the erase
#     (.rpmsave); a configuration that existed before the first install is
#     not replaced;
#   * upgrade, downgrade and erase are refused while mikagami.service or
#     mikagami-witness.service is active (a stand-in unit drop-in running
#     /usr/bin/sleep, created and removed by this test), and the package is
#     then left as it was.
#
# The fixture state is created by this test under the default paths and is
# removed at the end; the test refuses to start when any of them exists.
set -u

rpm1=""; rpm2=""; disposable=0; evidence=""
while [ $# -gt 0 ]; do
  case "$1" in
    --rpm1) rpm1=$2; shift 2 ;;
    --rpm2) rpm2=$2; shift 2 ;;
    --i-am-a-disposable-host) disposable=1; shift ;;
    --evidence) evidence=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

die() { echo "rpm-lifecycle-test: $*" >&2; exit 2; }
[ "$disposable" -eq 1 ] || die "pass --i-am-a-disposable-host (this test installs packages and writes /etc, /var/lib, /run)"
[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -f "$rpm1" ] && [ -f "$rpm2" ] || die "--rpm1 and --rpm2 must be RPM files"
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  rocky:9*|rocky:10*|rhel:9*|rhel:10*|almalinux:9*|almalinux:10*) ;;
  *) die "not an el9 / el10 host: ${PRETTY_NAME:-unknown}" ;;
esac
[ -d /run/systemd/system ] || die "systemd is not running (the guard tests need it)"
! rpm -q mikagami >/dev/null 2>&1 || die "a mikagami package is installed; this host is not disposable"
for p in /etc/mikagami /var/lib/mikagami /var/lib/mikagami-witness /run/mikagami \
         /etc/systemd/system/mikagami.service /etc/systemd/system/mikagami-witness.service \
         /etc/systemd/system/mikagami.service.d /usr/local/bin/mikagami; do
  [ ! -e "$p" ] && [ ! -L "$p" ] || die "$p exists; this host is not disposable"
done
for u in mikagami.service mikagami-witness.service; do
  [ "$(systemctl show --property=LoadState --value "$u")" = not-found ] || die "$u is known to systemd"
done

evidence=${evidence:-/var/tmp/mkg-rpm-lifecycle-$(date +%Y%m%d%H%M%S)}
mkdir -p "$evidence"
log="$evidence/lifecycle.log"
: > "$log"
failures=0; cases=0
fail() { echo "FAIL: $*" | tee -a "$log"; failures=$((failures + 1)); cases=$((cases + 1)); }
pass() { echo "ok: $*" >> "$log"; cases=$((cases + 1)); }
check() { d=$1; shift; if "$@" >> "$log" 2>&1; then pass "$d"; else fail "$d"; fi; }

net_snapshot() { { ip -o addr show; ip -o route show table all; } | sed 's/ valid_lft.*//' | sort; }
units_snapshot() {
  for u in mikagami.service mikagami-witness.service; do
    echo "$u active=$(systemctl is-active "$u" 2>/dev/null) enabled=$(systemctl is-enabled "$u" 2>/dev/null)"
  done
}

# --- fixture HA state ----------------------------------------------------------
seed_state() {
  install -d -m 0700 /var/lib/mikagami /var/lib/mikagami/two-node-operator /var/lib/mikagami/route \
    /var/lib/mikagami-witness /run/mikagami
  printf 'fixture node state (term 7, generation 42)\n' > /var/lib/mikagami/state.toml
  printf '{"fixture":"two-node record","epoch":9}\n' > /var/lib/mikagami/two-node-state.json
  printf '{"fixture":"operator request"}\n' > /var/lib/mikagami/two-node-operator/00000000-0000-4000-8000-000000000001.json
  printf 'fixture route intent\n' > /var/lib/mikagami/route/intent
  printf 'fixture fencing mark\n' > /var/lib/mikagami/recovery-marker
  printf 'fixture witness state (current_term 7)\n' > /var/lib/mikagami-witness/state
  printf 'fixture witness journal\n' > /var/lib/mikagami-witness/journal
  printf '{"fixture":"status"}\n' > /run/mikagami/two-node-status.json
  touch /var/lib/mikagami/.mkg-rpm-lifecycle-fixture
}
state_manifest() {
  find /var/lib/mikagami /var/lib/mikagami-witness /run/mikagami -print0 2>/dev/null | LC_ALL=C sort -z \
    | xargs -0 stat -c '%n %a %U:%G %s' 2>/dev/null
  find /var/lib/mikagami /var/lib/mikagami-witness /run/mikagami -type f -print0 2>/dev/null | LC_ALL=C sort -z \
    | xargs -0 sha256sum 2>/dev/null
}

seed_state
state_manifest > "$evidence/state.before"
net_snapshot > "$evidence/net.before"
check "fixture state recorded" test -s "$evidence/state.before"
state_same() { state_manifest > "$evidence/state.now"; cmp "$evidence/state.before" "$evidence/state.now"; }
net_same() { net_snapshot > "$evidence/net.now"; cmp "$evidence/net.before" "$evidence/net.now"; }
units_quiet() { # no unit active, none enabled
  units_snapshot > "$evidence/units.now"; cat "$evidence/units.now"
  ! grep -q -e 'active=active' -e 'active=activating' -e 'enabled=enabled' "$evidence/units.now"
}

# --- package metadata (before installing) ----------------------------------------
rpm -qpi "$rpm1" > "$evidence/rpm1.info" 2>&1
rpm -qplv "$rpm1" > "$evidence/rpm1.files" 2>&1
rpm -qpR "$rpm1" > "$evidence/rpm1.requires" 2>&1
rpm -qp --scripts "$rpm1" > "$evidence/rpm1.scripts" 2>&1
rpm -qpc "$rpm1" > "$evidence/rpm1.config" 2>&1
rpm -qp --qf '[%{FILEFLAGS:fflags} %{FILENAMES}\n]' "$rpm1" > "$evidence/rpm1.fflags" 2>&1
check "name/version" sh -c "rpm -qp --qf '%{NAME} %{VERSION}\n' '$rpm1' | grep -qx 'mikagami 0.8.0'"
check "rpm2 is a newer release" sh -c "[ \"\$(rpm -qp --qf '%{RELEASE}' '$rpm2')\" != \"\$(rpm -qp --qf '%{RELEASE}' '$rpm1')\" ]"
for f in /usr/bin/mikagami /usr/bin/mkg /usr/lib/systemd/system/mikagami.service \
         /usr/lib/systemd/system/mikagami-witness.service /etc/mikagami/mikagami.toml /etc/mikagami/witness.toml; do
  check "package contains $f" grep -q " $f\$\| $f -> " "$evidence/rpm1.files"
done
check "mkg is a link to mikagami" grep -q ' /usr/bin/mkg -> mikagami$' "$evidence/rpm1.files"
check "mikagami.toml is %config(noreplace)" grep -qx 'cn /etc/mikagami/mikagami.toml' "$evidence/rpm1.fflags"
check "witness.toml is %config(noreplace)" grep -qx 'cn /etc/mikagami/witness.toml' "$evidence/rpm1.fflags"
check "license tag Apache-2.0" sh -c "rpm -qp --qf '%{LICENSE}' '$rpm1' | grep -qx 'Apache-2.0'"
for f in /usr/share/licenses/mikagami/LICENSE /usr/share/licenses/mikagami/THIRD_PARTY_LICENSES.md \
         /usr/share/licenses/mikagami/third-party/README.txt /usr/libexec/mikagami/check-http \
         /usr/share/doc/mikagami/TWO_NODE_ARCHITECTURE.md /usr/share/doc/mikagami/TWO_NODE_SAFETY_MODEL.md \
         /usr/share/doc/mikagami/examples/two-node-shared.toml /usr/share/doc/mikagami/examples/two-node-group.toml; do
  check "package contains $f" grep -q " $f\$" "$evidence/rpm1.files"
done
check "LICENSE is a license file" sh -c "rpm -qpL '$rpm1' | grep -qx /usr/share/licenses/mikagami/LICENSE"
check "no HA state path is packaged" sh -c "! grep -q -e /var/lib -e /run/mikagami '$evidence/rpm1.files'"
check "requires arping" grep -q '^/usr/sbin/arping' "$evidence/rpm1.requires"
check "requires glibc" grep -q '^libc.so.6' "$evidence/rpm1.requires"
check "no try-restart / preset / start in scripts" \
  sh -c "! grep -v '^[[:space:]]*#' '$evidence/rpm1.scripts' | grep -E -q 'try-restart|preset|systemctl (start|restart|enable)'"

# --- install rpm1 -----------------------------------------------------------------
rpm -ivh "$rpm1" >> "$log" 2>&1
check "install rpm1" rpm -q mikagami
check "install did not start or enable a unit" units_quiet
check "install kept the HA state" state_same
check "install did not change addresses / routes" net_same
check "mikagami.service resolves to the packaged unit" \
  sh -c "systemctl show --property=FragmentPath --value mikagami.service | grep -qx /usr/lib/systemd/system/mikagami.service"
check "ExecStart uses /usr/bin/mikagami" sh -c "systemctl cat mikagami.service | grep -q '^ExecStart=/usr/bin/mikagami daemon run'"
check "witness ExecStart uses /usr/bin/mikagami" sh -c "systemctl cat mikagami-witness.service | grep -q '^ExecStart=/usr/bin/mikagami witness run'"
check "config mode 0600 root" sh -c "[ \"\$(stat -c '%a %U:%G' /etc/mikagami/mikagami.toml)\" = '600 root:root' ]"
check "rpm -V is clean" rpm -V mikagami
check "mikagami --version is the package version" sh -c "[ \"\$(/usr/bin/mikagami --version)\" = \"mikagami \$(rpm -q --qf '%{VERSION}' mikagami)\" ]"
check "mkg --version is the package version" sh -c "[ \"\$(/usr/bin/mkg --version)\" = \"mkg \$(rpm -q --qf '%{VERSION}' mikagami)\" ]"
check "installed LICENSE is the official Apache-2.0 text" sh -c "sha256sum /usr/share/licenses/mikagami/LICENSE | grep -q '^cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 '"

# mkg == mikagami
for args in "--help" "--version" "status --help" "daemon --help" "daemon run --help" "witness --help" \
            "two-node --help" "two-node status --help" "resource --help" "recover --help" \
            "nonsense" "two-node status --config /nonexistent.toml" "status --config /nonexistent.toml" \
            "status --config /etc/mikagami/mikagami.toml"; do
  # shellcheck disable=SC2086
  a=$(cd / && /usr/bin/mikagami $args 2>&1); ra=$?
  # shellcheck disable=SC2086
  b=$(cd / && /usr/bin/mkg $args 2>&1); rb=$?
  check "mkg/mikagami exit code for '$args'" test "$ra" -eq "$rb"
  check "mkg/mikagami output for '$args'" \
    test "$a" = "$(printf '%s' "$b" | sed 's/mkg/mikagami/g')"
done
check "the placeholder configuration is refused" sh -c "! /usr/bin/mikagami two-node status --config /etc/mikagami/mikagami.toml"
check "the placeholder witness configuration is refused" \
  sh -c "/usr/bin/mikagami witness run --config /etc/mikagami/witness.toml 2>&1 | grep -q 'missing field'"
check "placeholder use kept the HA state" state_same

# --- edit the configuration, upgrade to rpm2 ------------------------------------------
printf '\n# edited by the operator (lifecycle test)\n' >> /etc/mikagami/mikagami.toml
cp -p /etc/mikagami/mikagami.toml "$evidence/mikagami.toml.edited"
systemctl enable mikagami.service >> "$log" 2>&1   # the operator's choice; the package must keep it as is
rpm -Uvh "$rpm2" >> "$log" 2>&1
check "upgrade to rpm2" sh -c "rpm -q mikagami | grep -q -- \"\$(rpm -qp --qf '%{RELEASE}' '$rpm2')\""
check "upgrade kept the edited configuration" cmp /etc/mikagami/mikagami.toml "$evidence/mikagami.toml.edited"
check "upgrade did not start a unit" sh -c "[ \"\$(systemctl is-active mikagami.service)\" != active ]"
check "upgrade kept the operator's enablement" sh -c "[ \"\$(systemctl is-enabled mikagami.service)\" = enabled ]"
check "upgrade kept the HA state" state_same
check "upgrade did not change addresses / routes" net_same
systemctl disable mikagami.service >> "$log" 2>&1

# --- refusal while a unit is active ------------------------------------------------
for unit in mikagami.service mikagami-witness.service; do
  mkdir -p "/etc/systemd/system/$unit.d"
  printf '[Service]\nExecStart=\nExecStart=/usr/bin/sleep infinity\nRestart=no\n' > "/etc/systemd/system/$unit.d/lifecycle-test.conf"
  systemctl daemon-reload
  systemctl start "$unit"
  check "$unit stand-in is active" sh -c "[ \"\$(systemctl is-active $unit)\" = active ]"
  before=$(rpm -q mikagami)
  rpm -Uvh --oldpackage "$rpm1" >> "$log" 2>&1
  check "downgrade refused while $unit is active" test "$(rpm -q mikagami)" = "$before"
  rpm -e mikagami >> "$log" 2>&1
  check "erase refused while $unit is active" rpm -q mikagami
  check "binary still present after the refused erase" test -x /usr/bin/mikagami
  check "$unit still active after the refusals (not stopped by rpm)" sh -c "[ \"\$(systemctl is-active $unit)\" = active ]"
  systemctl stop "$unit"
  rm -rf "/etc/systemd/system/$unit.d"
  systemctl daemon-reload
done
check "refusals kept the HA state" state_same
check "rpm -V reports only the edited config" sh -c "rpm -V mikagami | grep -v ' c /etc/mikagami/mikagami.toml\$' | grep -q . && exit 1 || exit 0"

# --- erase ----------------------------------------------------------------------
systemctl enable mikagami.service >> "$log" 2>&1
rpm -e mikagami >> "$log" 2>&1
check "erase" sh -c "! rpm -q mikagami"
check "binary removed" test ! -e /usr/bin/mikagami
check "mkg removed" sh -c "[ ! -e /usr/bin/mkg ] && [ ! -L /usr/bin/mkg ]"
check "units removed" test ! -e /usr/lib/systemd/system/mikagami.service
check "enablement of the packaged unit dropped" test ! -L /etc/systemd/system/multi-user.target.wants/mikagami.service
check "edited configuration kept as .rpmsave" cmp /etc/mikagami/mikagami.toml.rpmsave "$evidence/mikagami.toml.edited"
check "erase kept the HA state" state_same
check "erase did not change addresses / routes" net_same

# --- a configuration that existed before the first install ---------------------------
mv /etc/mikagami/mikagami.toml.rpmsave /etc/mikagami/mikagami.toml
rpm -ivh "$rpm1" >> "$log" 2>&1
check "reinstall" rpm -q mikagami
check "reinstall kept the existing configuration" cmp /etc/mikagami/mikagami.toml "$evidence/mikagami.toml.edited"
check "reinstall wrote the placeholder as .rpmnew" test -f /etc/mikagami/mikagami.toml.rpmnew
check "reinstall did not start or enable a unit" units_quiet
check "reinstall kept the HA state" state_same
rpm -e mikagami >> "$log" 2>&1
check "final erase" sh -c "! rpm -q mikagami"
check "final erase kept the HA state" state_same
check "final erase did not change addresses / routes" net_same

# --- cleanup of this test's own fixtures --------------------------------------------
cp "$evidence/state.now" "$evidence/state.final" 2>/dev/null || :
if [ -f /var/lib/mikagami/.mkg-rpm-lifecycle-fixture ]; then
  rm -rf /var/lib/mikagami /var/lib/mikagami-witness /run/mikagami
fi
rm -f /etc/mikagami/mikagami.toml /etc/mikagami/mikagami.toml.rpmnew /etc/mikagami/mikagami.toml.rpmsave \
  /etc/mikagami/witness.toml.rpmsave
rmdir /etc/mikagami 2>/dev/null || :
systemctl daemon-reload

echo "rpm lifecycle tests: $cases checks, $failures failures" | tee -a "$log"
echo "evidence: $evidence"
[ "$failures" -eq 0 ]
