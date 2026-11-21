#!/bin/sh
# Phase 14.12 MC-1 driver integration: self-test of the management-network
# check as the lab driver (closeout-lab.sh) actually runs it.
#
# It drives the REAL closeout-lab.sh — the same mgmt_before_capture /
# mgmt_after_check functions `up` and `down` call — over STORED fixtures. A
# stub `ip` (MKM_MGMT_TEST_MODE=1) serves the fixtures and records every
# invocation, so the test also proves the driver only runs read-only `ip`
# forms. It never runs the real `ip`, never changes or inspects the live
# network, and is safe on any host.
#
# Part 3 runs the driver's `down` branch itself on a path-substituted copy of
# closeout-lab.sh (every system path / privileged command replaced by a
# scratch one; the check is asserted below) to prove that a failed
# management-network check makes `down` exit non-zero AFTER the teardown ran.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$HERE/closeout-lab.sh"
FX="$HERE/fixtures/mgmt-net"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/closeout-mgmt-selftest.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
fail=0
total=0
ok() { total=$((total + 1)); echo "PASS $1"; }
bad() { total=$((total + 1)); fail=$((fail + 1)); echo "FAIL $1"; }
check() { # check <label> <command...>: the command must succeed
    label="$1"; shift
    if "$@"; then ok "$label"; else bad "$label"; fi
}

# ---- stub ip: serves $STUB_DIR/<part>.txt, logs every call ---------------
cat > "$TMP/ip-stub.sh" <<'STUB'
#!/bin/sh
echo "$*" >> "${STUB_LOG:?}"
case "$*" in
    "-o addr show") f=addr ;;
    "-4 route show") f=route4 ;;
    "-6 route show") f=route6 ;;
    "rule show") f=rule ;;
    "-o link show") f=link ;;
    *) echo "ip-stub: not a read-only form: $*" >&2; exit 99 ;;
esac
if [ "${STUB_FAIL:-}" = "$f" ]; then echo "ip-stub: forced failure of $f" >&2; exit 1; fi
cat "${STUB_DIR:?}/$f.txt"
STUB
chmod +x "$TMP/ip-stub.sh"
: > "$TMP/stub.log"

# A snapshot set: mkset <name> <addr-fixture> <route4-fixture>; the other
# parts come from the stored driver-* fixtures and can be overridden by the
# caller afterwards.
mkset() {
    d="$TMP/set-$1"; mkdir -p "$d"
    cp "$FX/$2" "$d/addr.txt"
    cp "$FX/$3" "$d/route4.txt"
    cp "$FX/driver-route6.txt" "$d/route6.txt"
    cp "$FX/driver-rule.txt" "$d/rule.txt"
    cp "$FX/driver-link.txt" "$d/link.txt"
}
mkset before real-addr-before.txt real-route-before.txt

n=0
# run_case <label> <want-rc> <before-set> <after-set> [env assignments...]
# Captures the "before" set through the driver, then runs the driver's
# after-check with the "after" set (the extra env assignments apply to the
# after-check only); the driver's exit status is judged.
run_case() {
    label="$1"; want="$2"; bset="$3"; aset="$4"; shift 4
    n=$((n + 1)); rt="$TMP/rt-$n"; ev="$TMP/ev-$n"; mkdir -p "$rt"
    env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" \
        STUB_DIR="$TMP/set-$bset" bash "$LAB" mgmt-before-capture "$rt" >/dev/null 2>&1
    brc=$?
    if [ "$brc" -ne 0 ]; then
        bad "$label (before-capture failed unexpectedly, rc=$brc)"; return
    fi
    LAST_RT="$rt"; LAST_EV="$ev"
    out="$(env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" \
        STUB_DIR="$TMP/set-$aset" "$@" bash "$LAB" mgmt-after-check "$rt" "$ev" 2>&1)"
    got=$?
    LAST_OUT="$out"
    if [ "$got" -eq "$want" ]; then
        ok "$label (driver exit $got)"
    else
        bad "$label: expected driver exit $want, got $got"
        echo "$out" | sed 's/^/    /'
    fi
}

echo "== 1. normal: lease seconds only must PASS =="
mkset after-lease real-addr-after.txt real-route-after.txt
run_case "lease seconds only (addr + route, real audit pair)" 0 before after-lease
check "evidence: before and after snapshots kept" \
    test -f "$LAST_EV/mgmt-before/addr.txt" -a -f "$LAST_EV/mgmt-after/addr.txt"
check "every part was judged" test "$(printf '%s\n' "$LAST_OUT" | grep -c ': PASS$')" -eq 5
run_case "identical snapshots" 0 before before

echo "== 2. abnormal: a real change must FAIL =="
mkset after-ip addr-ip-changed-after.txt real-route-after.txt
run_case "IP address changed" 1 before after-ip
mkset after-prefix addr-prefix-changed-after.txt real-route-after.txt
run_case "prefix changed" 1 before after-prefix
mkset after-gw real-addr-after.txt route-gateway-changed-after.txt
run_case "default route (gateway) changed" 1 before after-gw
mkset after-metric real-addr-after.txt route-metric-changed-after.txt
run_case "route metric changed" 1 before after-metric
mkset after-nodef real-addr-after.txt route-default-removed-after.txt
run_case "default route removed" 1 before after-nodef
mkset after-dev real-addr-after.txt route-device-changed-after.txt
run_case "route device changed" 1 before after-dev
mkset after-if addr-interface-renamed-after.txt real-route-after.txt
run_case "interface renamed" 1 before after-if
mkset after-metric-a addr-metric-changed-after.txt real-route-after.txt
run_case "address metric changed" 1 before after-metric-a
mkset after-rule real-addr-after.txt real-route-after.txt
echo '100:	from 10.0.0.0/8 lookup 100' >> "$TMP/set-after-rule/rule.txt"
run_case "policy rule added" 1 before after-rule
mkset after-link real-addr-after.txt real-route-after.txt
sed 's/state UP/state DOWN/' "$FX/driver-link.txt" > "$TMP/set-after-link/link.txt"
run_case "link state changed" 1 before after-link
mkset after-r6 real-addr-after.txt real-route-after.txt
echo 'default via fe80::1 dev ens4 proto ra metric 1024' >> "$TMP/set-after-r6/route6.txt"
run_case "IPv6 route added" 1 before after-r6
mkset after-lease-and-ip addr-lease-and-ip-changed-after.txt real-route-after.txt
run_case "lease seconds AND IP changed (change not masked)" 1 before after-lease-and-ip

echo "== 3. abnormal: missing / failing snapshots and a failing comparison =="
run_case "after-capture fails (ip route show -4 fails)" 1 before after-lease STUB_FAIL=route4
# before part missing after a good capture
n=$((n + 1)); rt="$TMP/rt-$n"; mkdir -p "$rt"
env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" STUB_DIR="$TMP/set-before" \
    bash "$LAB" mgmt-before-capture "$rt" >/dev/null 2>&1
rm -f "$rt/mgmt-before/route4.txt"
env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" STUB_DIR="$TMP/set-before" \
    bash "$LAB" mgmt-after-check "$rt" "$TMP/ev-$n" > "$TMP/out-$n" 2>&1
rc=$?
check "before snapshot part missing => driver FAILS (exit $rc)" test "$rc" -eq 1
check "the missing part is named" grep -q 'route4: FAIL snapshot missing' "$TMP/out-$n"
# whole before directory missing (the up step never ran)
n=$((n + 1)); rt="$TMP/rt-$n"; mkdir -p "$rt"
env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" STUB_DIR="$TMP/set-before" \
    bash "$LAB" mgmt-after-check "$rt" "$TMP/ev-$n" > "$TMP/out-$n" 2>&1
rc=$?
check "no before snapshot at all => driver FAILS (exit $rc)" test "$rc" -eq 1
# before-capture itself failing is reported to the caller (`up` then aborts)
n=$((n + 1)); rt="$TMP/rt-$n"; mkdir -p "$rt"
env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" STUB_DIR="$TMP/set-before" \
    STUB_FAIL=addr bash "$LAB" mgmt-before-capture "$rt" >/dev/null 2>&1
rc=$?
check "before-capture failure is a non-zero exit (exit $rc)" test "$rc" -ne 0
# an empty addr capture is a broken capture, not "no addresses"
mkset empty real-addr-before.txt real-route-before.txt
: > "$TMP/set-empty/addr.txt"
n=$((n + 1)); rt="$TMP/rt-$n"; mkdir -p "$rt"
env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" STUB_DIR="$TMP/set-empty" \
    bash "$LAB" mgmt-before-capture "$rt" >/dev/null 2>&1
rc=$?
check "empty addr capture is refused (exit $rc)" test "$rc" -ne 0

# The comparison script itself failing must never read as success.
printf '#!/bin/sh\nexit 2\n' > "$TMP/cmp-exit2.sh"
printf '#!/bin/sh\nexit 126\n' > "$TMP/cmp-exit126.sh"
printf '#!/bin/sh\nkill -9 $$\n' > "$TMP/cmp-killed.sh"
printf '#!/bin/sh\necho "$@" >> "%s/cmp-calls.log"\necho "mgmt-net-compare: IDENTICAL"\nexit 0\n' "$TMP" > "$TMP/cmp-ok.sh"
run_case "comparison script exits 2 (input error)" 1 before before "MKM_MGMT_COMPARE=$TMP/cmp-exit2.sh"
run_case "comparison script exits 126" 1 before before "MKM_MGMT_COMPARE=$TMP/cmp-exit126.sh"
run_case "comparison script is killed" 1 before before "MKM_MGMT_COMPARE=$TMP/cmp-killed.sh"
run_case "comparison script does not exist" 1 before before "MKM_MGMT_COMPARE=$TMP/no-such-compare.sh"
# Sanity: the override really is what the driver runs (5 parts, 2 files each).
run_case "substituted comparison that passes is accepted" 0 before before "MKM_MGMT_COMPARE=$TMP/cmp-ok.sh"
check "the driver invoked the comparison once per part" \
    test "$(wc -l < "$TMP/cmp-calls.log" | tr -d ' ')" -eq 5

# F-MC-S1: exit 0 alone is not a PASS. The comparison must have printed
# EXACTLY one of its two verdict lines (and nothing on stderr).
mkcmp() { # mkcmp <name> <shell body>: a comparison stub that ends with exit 0
    printf '#!/bin/sh\n%s\nexit 0\n' "$2" > "$TMP/cmp-$1.sh"
}
V_ID='mgmt-net-compare: IDENTICAL'
V_ST='mgmt-net-compare: STABLE-IDENTICAL (only finite lease seconds differ)'
mkcmp unknown 'echo "all good"'
mkcmp empty 'true'
mkcmp padded "echo '$V_ID'; echo extra"
mkcmp blankline "echo '$V_ID'; echo"
mkcmp twice "echo '$V_ID'; echo '$V_ID'"
mkcmp failtext 'echo "mgmt-net-compare: CHANGED"'
mkcmp noeol "printf '%s' '$V_ID'"
mkcmp trailing "echo '$V_ID '"
mkcmp prefixed "echo ' $V_ID'"
mkcmp stable-short 'echo "mgmt-net-compare: STABLE-IDENTICAL"'
mkcmp stable-extra "echo '$V_ST and more'"
mkcmp lower 'echo "mgmt-net-compare: identical"'
mkcmp stderr-noise "echo '$V_ID'; echo warning >&2"
mkcmp stable-exact "echo '$V_ST'"
for c in unknown empty padded blankline twice failtext noeol trailing prefixed stable-short stable-extra lower stderr-noise; do
    run_case "comparison exit 0 + $c output is refused" 1 before before "MKM_MGMT_COMPARE=$TMP/cmp-$c.sh"
done
run_case "comparison exit 0 + the exact STABLE-IDENTICAL line is accepted" 0 before before "MKM_MGMT_COMPARE=$TMP/cmp-stable-exact.sh"
printf '#!/bin/sh\nexit 1\n' > "$TMP/cmp-exit1.sh"
printf '#!/bin/sh\nexit 127\n' > "$TMP/cmp-exit127.sh"
printf '#!/bin/sh\necho "mgmt-net-compare: IDENTICAL"\nexit 1\n' > "$TMP/cmp-exit1-ok-text.sh"
printf '#!/bin/sh\necho "mgmt-net-compare: IDENTICAL"\nkill -9 $$\n' > "$TMP/cmp-killed-ok-text.sh"
run_case "comparison exits 1 with no output" 1 before before "MKM_MGMT_COMPARE=$TMP/cmp-exit1.sh"
run_case "comparison exits 127" 1 before before "MKM_MGMT_COMPARE=$TMP/cmp-exit127.sh"
run_case "comparison exit 1 + a success line is still a FAIL" 1 before before "MKM_MGMT_COMPARE=$TMP/cmp-exit1-ok-text.sh"
run_case "comparison killed after a success line is a FAIL" 1 before before "MKM_MGMT_COMPARE=$TMP/cmp-killed-ok-text.sh"
# One unknown part out of five fails the whole check (and the others still run).
cat > "$TMP/cmp-one-unknown.sh" <<'ONE'
#!/bin/sh
case "$1" in
    */rule.txt) echo "something else" ;;
    *) echo "mgmt-net-compare: IDENTICAL" ;;
esac
exit 0
ONE
run_case "one unknown part of five fails the whole check" 1 before before "MKM_MGMT_COMPARE=$TMP/cmp-one-unknown.sh"
check "the other four parts were still judged and passed" test "$(printf '%s\n' "$LAST_OUT" | grep -c ': PASS$')" -eq 4
check "the unknown part is named" sh -c "printf '%s\n' \"\$1\" | grep -q 'rule: FAIL comparison exited 0 without exactly one known verdict line'" _ "$LAST_OUT"

# F-MC-C0 through the REAL comparison script and the REAL driver: a tool the
# comparison depends on failing must never read as an unchanged network.
for tool in sort sed grep diff cmp; do
    mkdir -p "$TMP/bin-$tool"
    printf '#!/bin/sh\nexit 2\n' > "$TMP/bin-$tool/$tool"; chmod +x "$TMP/bin-$tool/$tool"
done
run_case "driver: sort fails, IP really changed => FAIL" 1 before after-ip "PATH=$TMP/bin-sort:$PATH"
run_case "driver: sort fails, nothing changed => FAIL" 1 before before "PATH=$TMP/bin-sort:$PATH"
check "driver: no part passed while sort was failing" test "$(printf '%s\n' "$LAST_OUT" | grep -c ': PASS$')" -eq 0
run_case "driver: sed fails, IP really changed => FAIL" 1 before after-ip "PATH=$TMP/bin-sed:$PATH"
run_case "driver: diff fails, nothing changed => FAIL" 1 before before "PATH=$TMP/bin-diff:$PATH"
run_case "driver: cmp fails on a lease-only change => FAIL" 1 before after-lease "PATH=$TMP/bin-cmp:$PATH"

echo "== 4. the driver only runs read-only ip forms; overrides need test mode =="
check "stub saw only the five read-only forms" sh -c "
    ! grep -v -x -e '-o addr show' -e '-4 route show' -e '-6 route show' \
        -e 'rule show' -e '-o link show' '$TMP/stub.log' | grep -q ."
check "stub log is non-empty (the driver did call ip)" test -s "$TMP/stub.log"
: > "$TMP/stub.log"
n=$((n + 1)); rt="$TMP/rt-$n"; mkdir -p "$rt"
env MKM_IP="$TMP/ip-stub.sh" MKM_MGMT_COMPARE="$TMP/cmp-ok.sh" STUB_LOG="$TMP/stub.log" \
    STUB_DIR="$TMP/set-before" bash "$LAB" mgmt-before-capture "$rt" >/dev/null 2>&1
check "without MKM_MGMT_TEST_MODE the ip override is ignored (stub never called)" \
    test ! -s "$TMP/stub.log"

echo "== 5. static integration of the driver =="
sed -n '/^up)/,/^    ;;/p' "$LAB" > "$TMP/up-branch.txt"
sed -n '/^down)/,/^    ;;/p' "$LAB" > "$TMP/down-branch.txt"
check "up calls mgmt_before_capture" grep -q -F 'mgmt_before_capture "$RUNTIME"' "$TMP/up-branch.txt"
check "up aborts when the snapshot fails" grep -q -F 'management-network snapshot failed' "$TMP/up-branch.txt"
check "down calls mgmt_after_check" grep -q -F 'mgmt_after_check "$RUNTIME" "$EVID"' "$TMP/down-branch.txt"
check "down exits non-zero on a failed check" grep -q -F 'MANAGEMENT-NETWORK CHECK FAILED' "$TMP/down-branch.txt"
check "the driver compares with mgmt-net-compare.sh" grep -q 'mgmt-net-compare.sh' "$LAB"
check "the driver has no raw cmp on snapshots" sh -c "! grep -n -w cmp '$LAB' | grep -v '^[0-9]*:#'"

echo "== 6. the driver's own down branch (path-substituted copy) =="
W="$TMP/down"; mkdir -p "$W/bin" "$W/lab"
cp "$HERE/mgmt-net-compare.sh" "$W/lab/"
printf '#!/bin/sh\nexit 0\n' > "$W/lab/vf-topology.sh"
printf '#!/bin/sh\nexit 0\n' > "$W/bin/systemctl"
chmod +x "$W/bin/systemctl"
sed -e "s|^LIBEXEC=.*|LIBEXEC=\"$W/libexec\"|" \
    -e "s|^RUNTIME=.*|RUNTIME=\"$W/run\"|" \
    -e "s|^UNIT=.*|UNIT=\"$W/mikagami-closeout.service\"|" \
    -e "s|/usr/bin/systemctl|\"$W/bin/systemctl\"|g" \
    -e "s|/usr/bin/bash|bash|g" "$LAB" > "$W/lab/closeout-lab.sh"
want_changed="$(grep -c -E '^(LIBEXEC|RUNTIME|UNIT)=|/usr/bin/systemctl|/usr/bin/bash' "$LAB")"
got_changed="$(diff "$LAB" "$W/lab/closeout-lab.sh" | grep -c '^>')"
check "substituted copy differs from the driver only on path/command lines ($got_changed of $want_changed)" \
    test "$got_changed" -eq "$want_changed"
down_case() { # down_case <label> <want-rc> <after-set> [env...]
    label="$1"; want="$2"; aset="$3"; shift 3
    rm -rf "$W/run" "$W/libexec" "$W/ev"
    mkdir -p "$W/run" "$W/libexec"
    : > "$W/mikagami-closeout.service"
    # the link ownership record `up` leaves (OBS-CLOSEOUT-DOWN-MIN): without it
    # `down` deletes nothing at all (see min-ownership-selftest.sh)
    echo "mikagami-min-owned v1" > "$W/run/min-owned"
    env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" \
        STUB_DIR="$TMP/set-before" bash "$W/lab/closeout-lab.sh" mgmt-before-capture "$W/run" >/dev/null 2>&1
    env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" \
        STUB_DIR="$TMP/set-$aset" "$@" bash "$W/lab/closeout-lab.sh" down "$W/ev" > "$W/down.out" 2>&1
    got=$?
    if [ "$got" -eq "$want" ] && [ ! -e "$W/run" ] && [ ! -e "$W/libexec" ] && [ ! -e "$W/mikagami-closeout.service" ]; then
        ok "$label (down exit $got, teardown completed)"
    else
        bad "$label: want exit $want got $got; teardown leftovers: $(ls "$W" | tr '\n' ' ')"
        sed 's/^/    /' "$W/down.out"
    fi
}
down_case "down: stable management network => exit 0" 0 after-lease
down_case "down: IP changed => exit non-zero, teardown still completed" 1 after-ip
down_case "down: after-snapshot fails => exit non-zero, teardown still completed" 1 after-lease STUB_FAIL=link
check "down evidence holds the check output" test -s "$W/ev/mgmt-net-check.txt"
check "down evidence keeps the ownership record" test -s "$W/ev/min-owned.txt"

# OBS-CLOSEOUT-DOWN-MIN: a failed link cleanup keeps the record and the lab dirs
# (retry), and a missing record refuses everything.
printf '#!/bin/sh\nexit 1\n' > "$W/lab/vf-topology.sh"
rm -rf "$W/run" "$W/libexec" "$W/ev"; mkdir -p "$W/run" "$W/libexec"
echo "mikagami-min-owned v1" > "$W/run/min-owned"; : > "$W/mikagami-closeout.service"
env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" STUB_DIR="$TMP/set-before" \
    bash "$W/lab/closeout-lab.sh" mgmt-before-capture "$W/run" >/dev/null 2>&1
env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" STUB_DIR="$TMP/set-after-lease" \
    bash "$W/lab/closeout-lab.sh" down "$W/ev" > "$W/down.out" 2>&1
got=$?
check "down: link cleanup fails => exit 1 (exit $got)" test "$got" -eq 1
check "down: link cleanup fails => record, run dir and libexec are kept" test -f "$W/run/min-owned" -a -d "$W/libexec"
check "down: link cleanup fails => it says so" grep -q 'LINK CLEANUP INCOMPLETE' "$W/down.out"
rm -rf "$W/run" "$W/ev"; mkdir -p "$W/run"; : > "$W/mikagami-closeout.service"
env MKM_MGMT_TEST_MODE=1 MKM_IP="$TMP/ip-stub.sh" STUB_LOG="$TMP/stub.log" STUB_DIR="$TMP/set-before" \
    bash "$W/lab/closeout-lab.sh" down "$W/ev" > "$W/down.out" 2>&1
got=$?
check "down: no ownership record => exit 1 (exit $got)" test "$got" -eq 1
check "down: no ownership record => nothing removed" test -d "$W/run" -a -d "$W/libexec" -a -f "$W/mikagami-closeout.service"

echo "closeout-lab-mgmt-selftest: $total checks, $fail failed"
[ "$fail" -eq 0 ]
