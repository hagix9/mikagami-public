#!/bin/sh
# Tests of the RPM scriptlets of packaging/rpm/mikagami.spec, run on any host
# (macOS included) without rpm and without root.
#
# Each scriptlet (%pre, %post, %preun, %postun) is extracted from the spec
# verbatim; only its fixed system paths are rewritten to a scratch tree
# (/usr/bin/systemctl -> a fake that logs every call, /run/systemd/system,
# /etc/systemd/system, /proc). It is then run with the argument rpm passes ($1)
# and its exit status and systemctl calls are checked. The fake never fails a
# mutating call, so a forbidden call (start, restart, try-restart, enable,
# stop, preset, ...) is caught in the log, not hidden by an error.
#
# usage: test_rpm_scriptlets.sh [SCRATCH_DIR]
set -u

here=$(cd "$(dirname "$0")" && pwd)
spec="$here/../mikagami.spec"
scratch=${1:-$(mktemp -d "${TMPDIR:-/tmp}/mkg-rpm-scriptlets.XXXXXX")}
mkdir -p "$scratch"
failures=0
cases=0

fail() { echo "FAIL: $*"; failures=$((failures + 1)); cases=$((cases + 1)); }
pass() { cases=$((cases + 1)); }
check() { # check DESCRIPTION CONDITION...
  d=$1; shift
  if "$@"; then pass; else fail "$d"; fi
}

[ -f "$spec" ] || { echo "FAIL: no spec at $spec"; exit 1; }

# --- extract the scriptlets -----------------------------------------------
# A section runs from its header line to the next line that starts a section.
extract() { # extract SECTION
  awk -v want="$1" '
    /^%(pre|post|preun|postun|files|changelog|prep|build|install|check|description)([ \t]|$)/ {
      on = ($1 == want); next
    }
    on { print }
  ' "$spec"
}
for s in pre post preun postun; do
  extract "%$s" > "$scratch/$s.orig"
  [ -s "$scratch/$s.orig" ] || { echo "FAIL: %$s not found in the spec"; exit 1; }
done

# --- the fake system -------------------------------------------------------
fake_root="$scratch/sys"
reset_sys() {
  rm -rf "$fake_root"
  mkdir -p "$fake_root/bin" "$fake_root/run-systemd-system" "$fake_root/etc-systemd-system" \
    "$fake_root/proc" "$fake_root/sc"
  : > "$fake_root/sc/log"
  cat > "$fake_root/bin/systemctl" <<'FAKE'
#!/bin/sh
sc="${0%/bin/systemctl}/sc"
echo "$*" >> "$sc/log"
cmd=""
for a in "$@"; do
  case "$a" in --*) ;; *) cmd=$a; break ;; esac
done
case "$cmd" in
  show)
    [ ! -f "$sc/fail-show" ] || exit 1
    unit=""
    for a in "$@"; do case "$a" in --*|show) ;; *) unit=$a ;; esac; done
    st=inactive
    [ ! -f "$sc/$unit.state" ] || st=$(cat "$sc/$unit.state")
    echo "$st" ;;
  list-jobs)
    [ ! -f "$sc/fail-jobs" ] || exit 1
    cat "$sc/jobs" 2>/dev/null || true ;;
  daemon-reload|disable) ;;
  *) echo "UNEXPECTED $*" >> "$sc/log" ;;
esac
exit 0
FAKE
  chmod +x "$fake_root/bin/systemctl"
}
no_systemd() { rmdir "$fake_root/run-systemd-system"; }
unit_state() { printf '%s' "$2" > "$fake_root/sc/$1.state"; }
add_proc() { # add_proc PID ARG... (a NUL-separated cmdline)
  pid=$1; shift
  mkdir -p "$fake_root/proc/$pid"
  : > "$fake_root/proc/$pid/cmdline"
  for a in "$@"; do printf '%s\000' "$a" >> "$fake_root/proc/$pid/cmdline"; done
}

rewrite() { # rewrite SECTION -> path of the runnable copy
  # Relative paths (the scriptlet runs with the fake tree as its working
  # directory), so a scratch path with spaces cannot split a word.
  sed -e "s#/usr/bin/systemctl#./bin/systemctl#g" \
      -e "s#/run/systemd/system#./run-systemd-system#g" \
      -e "s#/etc/systemd/system#./etc-systemd-system#g" \
      -e "s#/proc#./proc#g" \
      "$scratch/$1.orig" > "$scratch/$1.run"
  echo "$scratch/$1.run"
}

rc=0
run() { # run SECTION ARG
  script=$(rewrite "$1")
  (cd "$fake_root" && sh "$script" "$2") > "$scratch/out" 2> "$scratch/err"
  rc=$?
}
log_has() { grep -q -- "$1" "$fake_root/sc/log"; }
log_lacks() { ! grep -q -- "$1" "$fake_root/sc/log"; }
no_unexpected() { log_lacks UNEXPECTED; }
err_has() { grep -q -- "$1" "$scratch/err"; }
only_reads() { # only show / list-jobs calls
  ! grep -v -e '^show ' -e '^list-jobs ' "$fake_root/sc/log" | grep -q .
}
log_empty() { [ ! -s "$fake_root/sc/log" ]; }
refused() { [ "$rc" -ne 0 ]; }
allowed() { [ "$rc" -eq 0 ]; }

# --- static properties of the extracted scriptlets ---------------------------
for s in pre post preun postun; do
  check "%$s contains a % (rpm macro expansion inside a scriptlet)" sh -c "! grep -q '%' '$scratch/$s.orig'"
  for word in 'rm ' 'mv ' '/var/lib' '/run/mikagami' 'ip addr' 'ip link' 'arping'; do
    check "%$s contains '$word'" sh -c "! grep -q -- '$word' '$scratch/$s.orig'"
  done
  check "%$s has a forbidden systemctl verb" sh -c "! grep systemctl '$scratch/$s.orig' | grep -E -q ' (start|restart|try-restart|condrestart|enable|reenable|stop|preset|preset-all|reload|reload-or-restart|try-reload-or-restart|kill|isolate|mask|unmask|link|set-default)( |\$)'"
done
sed -n '/^# BEGIN mkg-ha-guard/,/^# END mkg-ha-guard/p' "$scratch/pre.orig" > "$scratch/guard.pre"
sed -n '/^# BEGIN mkg-ha-guard/,/^# END mkg-ha-guard/p' "$scratch/preun.orig" > "$scratch/guard.preun"
check "the guard is present in %pre" test -s "$scratch/guard.pre"
check "the guard copies of %pre and %preun differ" cmp -s "$scratch/guard.pre" "$scratch/guard.preun"

# --- %pre: install ($1 = 1) and upgrade ($1 = 2) ------------------------------
for arg in 1 2; do
  reset_sys; no_systemd; run pre "$arg"
  check "%pre $arg without systemd is refused" allowed
  check "%pre $arg without systemd called systemctl" log_empty

  reset_sys; run pre "$arg"
  check "%pre $arg with stopped units is refused: $(cat "$scratch/err")" allowed
  check "%pre $arg asked the state of mikagami.service" log_has 'show .*mikagami.service'
  check "%pre $arg asked the state of mikagami-witness.service" log_has 'show .*mikagami-witness.service'
  check "%pre $arg did more than read" only_reads

  for unit in mikagami.service mikagami-witness.service; do
    reset_sys; unit_state "$unit" failed; run pre "$arg"
    check "%pre $arg with $unit failed (stopped) is refused" allowed
    for state in active activating deactivating reloading refreshing maintenance unknown ''; do
      reset_sys; unit_state "$unit" "$state"; run pre "$arg"
      check "%pre $arg with $unit '$state' is allowed" refused
      check "%pre $arg with $unit '$state': no reason" err_has "$unit"
      check "%pre $arg with $unit '$state' did more than read" only_reads
    done
    reset_sys; printf '42 %s start waiting\n' "$unit" > "$fake_root/sc/jobs"; run pre "$arg"
    check "%pre $arg with a job queued for $unit is allowed" refused
    check "%pre $arg job for $unit: no reason" err_has "job is queued for $unit"
  done
  reset_sys; printf '42 xmikagami.service start waiting\n43 mikagami-witness.service.d stop waiting\n' > "$fake_root/sc/jobs"
  run pre "$arg"
  check "%pre $arg refused on a job of another unit (substring match)" allowed

  reset_sys; touch "$fake_root/sc/fail-show"; run pre "$arg"
  check "%pre $arg allowed when systemctl show fails (fail closed)" refused
  reset_sys; touch "$fake_root/sc/fail-jobs"; run pre "$arg"
  check "%pre $arg allowed when systemctl list-jobs fails (fail closed)" refused
  check "%pre $arg list-jobs failure: no reason" err_has "cannot list systemd jobs"
  reset_sys; rm "$fake_root/bin/systemctl"; run pre "$arg"
  check "%pre $arg allowed without systemctl under a running systemd" refused

  for argv in "/usr/bin/mikagami daemon run --config /etc/mikagami/mikagami.toml" \
              "/usr/local/bin/mikagami daemon run --config /x" \
              "/usr/bin/mikagami witness run --config /etc/mikagami/witness.toml" \
              "/usr/local/bin/mkg daemon run --config /x" \
              "mkg witness run --config /x"; do
    reset_sys; no_systemd
    # shellcheck disable=SC2086
    add_proc 4242 $argv
    run pre "$arg"
    check "%pre $arg allowed with a running '$argv' (no systemd)" refused
    check "%pre $arg '$argv': no reason" err_has "an HA process is running"
    reset_sys
    # shellcheck disable=SC2086
    add_proc 4242 $argv
    run pre "$arg"
    check "%pre $arg allowed with a running '$argv' (systemd, units stopped)" refused
  done
  for argv in "/usr/bin/mikagami status --config /etc/mikagami/mikagami.toml" \
              "/usr/bin/mikagami two-node status --config /x" \
              "/usr/bin/mikagami agent" "vim /etc/mikagami/mikagami.toml" "dnf install mikagami"; do
    reset_sys
    # shellcheck disable=SC2086
    add_proc 4243 $argv
    run pre "$arg"
    check "%pre $arg refused by a non-HA process '$argv'" allowed
  done
  check "%pre $arg: forbidden systemctl call" no_unexpected
done

# --- %post: daemon-reload only --------------------------------------------------
for arg in 1 2; do
  reset_sys; run post "$arg"
  check "%post $arg failed" allowed
  check "%post $arg did not daemon-reload" log_has '^daemon-reload'
  check "%post $arg did more than daemon-reload" sh -c "! grep -v '^daemon-reload\$' '$fake_root/sc/log' | grep -q ."
  reset_sys; no_systemd; run post "$arg"
  check "%post $arg without systemd failed" allowed
  check "%post $arg without systemd called systemctl" log_empty
  reset_sys; unit_state mikagami.service active; run post "$arg"
  check "%post $arg with an active unit did more than daemon-reload" sh -c "! grep -v '^daemon-reload\$' '$fake_root/sc/log' | grep -q ."
done

# --- %preun: upgrade ($1 = 1) and erase ($1 = 0) ----------------------------------
reset_sys; unit_state mikagami.service active; run preun 1
check "%preun 1 (upgrade, the new %pre checked) failed" allowed
check "%preun 1 called systemctl" log_empty

reset_sys; run preun 0
check "%preun 0 with stopped units failed: $(cat "$scratch/err")" allowed
check "%preun 0 did not disable mikagami.service" log_has '^--no-reload disable mikagami.service$'
check "%preun 0 did not disable mikagami-witness.service" log_has '^--no-reload disable mikagami-witness.service$'
check "%preun 0 disabled with --now" log_lacks '--now'
check "%preun 0 called systemctl beyond show/list-jobs/disable" \
  sh -c "! grep -v -e '^show ' -e '^list-jobs ' -e '^--no-reload disable mikagami' '$fake_root/sc/log' | grep -q ."

for unit in mikagami.service mikagami-witness.service; do
  for state in active activating deactivating reloading unknown; do
    reset_sys; unit_state "$unit" "$state"; run preun 0
    check "%preun 0 with $unit '$state' is allowed" refused
    check "%preun 0 with $unit '$state' disabled a unit" log_lacks disable
  done
  reset_sys; printf '7 %s stop running\n' "$unit" > "$fake_root/sc/jobs"; run preun 0
  check "%preun 0 with a job for $unit is allowed" refused
  check "%preun 0 with a job for $unit disabled a unit" log_lacks disable
done
reset_sys; add_proc 99 /usr/bin/mikagami daemon run --config /x; run preun 0
check "%preun 0 with a running daemon process is allowed" refused
check "%preun 0 with a running daemon process disabled a unit" log_lacks disable
reset_sys; touch "$fake_root/sc/fail-show"; run preun 0
check "%preun 0 allowed when systemctl show fails" refused

# An administrator's unit file or mask in /etc/systemd/system is left alone.
reset_sys; printf '[Service]\n' > "$fake_root/etc-systemd-system/mikagami.service"; run preun 0
check "%preun 0 with an /etc unit failed" allowed
check "%preun 0 disabled the administrator's /etc mikagami.service" log_lacks 'disable mikagami.service'
check "%preun 0 did not disable the packaged witness unit" log_has 'disable mikagami-witness.service'
reset_sys; ln -s /dev/null "$fake_root/etc-systemd-system/mikagami-witness.service"; run preun 0
check "%preun 0 with a mask failed" allowed
check "%preun 0 touched a masked unit" log_lacks 'disable mikagami-witness.service'
check "%preun 0 with a mask: the other unit not disabled" log_has 'disable mikagami.service'
reset_sys; ln -s /nonexistent "$fake_root/etc-systemd-system/mikagami.service"; run preun 0
check "%preun 0 disabled through a dangling /etc link" log_lacks 'disable mikagami.service'

# Erase without a running systemd (chroot): offline disable, no state query.
reset_sys; no_systemd; run preun 0
check "%preun 0 without systemd failed" allowed
check "%preun 0 without systemd queried the unit state" log_lacks '^show '
check "%preun 0 without systemd: no offline disable" log_has 'disable mikagami.service'
check "%preun: forbidden systemctl call" no_unexpected

# --- %postun: daemon-reload only, never try-restart --------------------------------
for arg in 0 1; do
  reset_sys; unit_state mikagami.service active; run postun "$arg"
  check "%postun $arg failed" allowed
  check "%postun $arg did not daemon-reload" log_has '^daemon-reload'
  check "%postun $arg did more than daemon-reload" sh -c "! grep -v '^daemon-reload\$' '$fake_root/sc/log' | grep -q ."
  reset_sys; no_systemd; run postun "$arg"
  check "%postun $arg without systemd called systemctl" log_empty
done

# --- the scriptlets touch nothing outside the fake tree ------------------------------
# Every path a scriptlet names is one of the four rewritten ones.
for s in pre post preun postun; do
  others=$(grep -o '/[A-Za-z][A-Za-z0-9_./-]*' "$scratch/$s.orig" \
    | grep -v -e '^/usr/bin/systemctl$' -e '^/run/systemd/system$' -e '^/etc/systemd/system' \
              -e '^/proc' -e '^/cmdline$' -e '^/dev/null$' -e '^/usr/local/' -e '^/rpm.md$' -e '^/null$' \
    | sort -u | tr '\n' ' ')
  check "%$s names other paths: $others" test -z "$others"
done

echo "rpm scriptlet tests: $cases checks, $failures failures"
rm -rf "$scratch"
[ "$failures" -eq 0 ]
