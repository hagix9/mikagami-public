#!/bin/sh
# Phase 14.12 MC-1: self-test of mgmt-net-compare.sh over STORED before/after
# data (fixtures/mgmt-net). It reads files only: it never runs `ip` and never
# changes or inspects the live network, so it is safe on any host. The
# fault-injection checks replace sed / sort / grep / diff / cmp / mktemp with
# stubs on a private PATH (the comparison script is the only thing run with it).
#
# real-*      : the management NIC of the lab VM captured by the Phase 14.12
#               independent audit (the false positive that raised MC-1: only
#               the DHCP lease seconds differ).
# *-after     : the real "after" with exactly one real change applied.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CMP="$HERE/mgmt-net-compare.sh"
FX="$HERE/fixtures/mgmt-net"
fail=0
total=0
expect() {
    want="$1"; label="$2"; before="$3"; after="$4"
    total=$((total + 1))
    out="$(sh "$CMP" "$FX/$before" "$FX/$after" 2>&1)"; got=$?
    if [ "$got" -eq "$want" ]; then
        echo "PASS $label (exit $got)"
    else
        echo "FAIL $label: expected exit $want, got $got"
        echo "$out" | sed 's/^/    /'
        fail=$((fail + 1))
    fi
}
# The raw comparison the audit driver used: it DOES see the lease renewal.
total=$((total + 1))
if cmp -s "$FX/real-addr-before.txt" "$FX/real-addr-after.txt"; then
    echo "FAIL premise: raw cmp should differ on the real pair"; fail=$((fail + 1))
else
    echo "PASS premise: raw cmp differs on the real pair (the MC-1 false positive)"
fi
# Must NOT be reported (time-dependent only).
expect 0 "lease seconds only: addr (real audit pair)" real-addr-before.txt real-addr-after.txt
expect 0 "identical route (real audit pair)" real-route-before.txt real-route-after.txt
expect 0 "identical against itself" real-addr-before.txt real-addr-before.txt
# Must be reported (a real management-network change).
expect 1 "IP address changed" real-addr-before.txt addr-ip-changed-after.txt
expect 1 "prefix changed" real-addr-before.txt addr-prefix-changed-after.txt
expect 1 "interface renamed" real-addr-before.txt addr-interface-renamed-after.txt
expect 1 "address metric changed" real-addr-before.txt addr-metric-changed-after.txt
expect 1 "lease became forever (static)" real-addr-before.txt addr-lease-became-forever-after.txt
expect 1 "dynamic flag lost" real-addr-before.txt addr-dynamic-flag-lost-after.txt
expect 1 "link-local address changed" real-addr-before.txt addr-linklocal-changed-after.txt
expect 1 "lease expired (0sec)" real-addr-before.txt addr-lease-expired-after.txt
expect 1 "lease seconds AND IP changed (change not masked)" real-addr-before.txt addr-lease-and-ip-changed-after.txt
expect 1 "extra address added" real-addr-before.txt addr-extra-address-after.txt
expect 1 "default gateway changed" real-route-before.txt route-gateway-changed-after.txt
expect 1 "route metric changed" real-route-before.txt route-metric-changed-after.txt
expect 1 "default route removed" real-route-before.txt route-default-removed-after.txt
expect 1 "route device changed" real-route-before.txt route-device-changed-after.txt
expect 1 "address removed (before has more than after)" addr-extra-address-after.txt real-addr-after.txt
# Input errors.
expect 2 "missing input file" real-addr-before.txt does-not-exist.txt
total=$((total + 1))
if sh "$CMP" >/dev/null 2>&1; then
    echo "FAIL usage: no arguments must not succeed"; fail=$((fail + 1))
else
    echo "PASS usage: no arguments is refused"
fi

# ---- F-MC-C0: a failing normalisation must never read as "unchanged" -----
# Each tool the comparison uses is replaced, one at a time, through PATH. The
# inputs are a real IP change (and, separately, identical files): every
# sabotage must end in a non-zero exit and never in a PASS verdict.
TMP="$(mktemp -d "${TMPDIR:-/tmp}/mgmt-net-compare-selftest.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
stubdir() { mkdir -p "$TMP/bin-$1"; printf '%s\n' "#!/bin/sh" "$2" > "$TMP/bin-$1/$3"; chmod +x "$TMP/bin-$1/$3"; }
sabotage() { # sabotage <label> <tool> <stub body> <want exit> <before> <after>
    label="$1"; tool="$2"; body="$3"; want="$4"; before="$5"; after="$6"
    total=$((total + 1))
    stubdir "$label" "$body" "$tool"
    out="$(PATH="$TMP/bin-$label:$PATH" sh "$CMP" "$FX/$before" "$FX/$after" 2>"$TMP/err-$label")"; got=$?
    if [ "$got" -eq "$want" ] && ! printf '%s\n' "$out" | grep -q -e 'IDENTICAL'; then
        echo "PASS sabotage $label (exit $got, no PASS verdict)"
    else
        echo "FAIL sabotage $label: expected exit $want without an IDENTICAL verdict, got $got"
        printf '%s\n' "$out" | sed 's/^/    out: /'; sed 's/^/    err: /' "$TMP/err-$label"
        fail=$((fail + 1))
    fi
}
sabotage sort-exit2-ipchange sort 'exit 2' 2 real-addr-before.txt addr-ip-changed-after.txt
sabotage sort-exit2-identical sort 'exit 2' 2 real-addr-before.txt real-addr-before.txt
sabotage sort-exit1 sort 'exit 1' 2 real-addr-before.txt addr-ip-changed-after.txt
sabotage sed-exit2-ipchange sed 'exit 2' 2 real-addr-before.txt addr-ip-changed-after.txt
sabotage sed-exit2-identical sed 'exit 2' 2 real-addr-before.txt real-addr-before.txt
sabotage sort-silently-empty sort 'exit 0' 2 real-addr-before.txt addr-ip-changed-after.txt
sabotage sed-silently-empty sed 'exit 0' 2 real-addr-before.txt addr-ip-changed-after.txt
sabotage grep-exit2 grep 'exit 2' 2 real-addr-before.txt addr-ip-changed-after.txt
sabotage diff-exit2 diff 'exit 2' 2 real-addr-before.txt addr-ip-changed-after.txt
sabotage diff-exit2-identical diff 'exit 2' 2 real-addr-before.txt real-addr-before.txt
sabotage cmp-exit2 cmp 'exit 2' 2 real-addr-before.txt real-addr-after.txt
sabotage mktemp-fails mktemp 'exit 1' 2 real-addr-before.txt real-addr-before.txt
# F-AUD-C0-DIAG: a scratch directory that cannot be made is exit 2, nothing on
# stdout, and the comparison's OWN reason on stderr (the stub mktemp prints
# nothing at all, so a non-empty stderr can only be the comparison's).
diag() { # diag <label> <stub body>
    total=$((total + 1))
    stubdir "diag-$1" "$2" mktemp
    PATH="$TMP/bin-diag-$1:$PATH" sh "$CMP" "$FX/real-addr-before.txt" "$FX/real-addr-before.txt" \
        > "$TMP/diag-$1.out" 2> "$TMP/diag-$1.err"; got=$?
    if [ "$got" -eq 2 ] && [ ! -s "$TMP/diag-$1.out" ] \
        && grep -q '^mgmt-net-compare: cannot create a private scratch directory' "$TMP/diag-$1.err"; then
        echo "PASS mktemp $1: exit 2, stdout empty, own diagnostic on stderr"
    else
        echo "FAIL mktemp $1: exit $got, stdout $(wc -c < "$TMP/diag-$1.out") bytes, stderr:"
        sed 's/^/    err: /' "$TMP/diag-$1.err"
        fail=$((fail + 1))
    fi
}
diag silent-exit1 'exit 1'
diag exit0-prints-nothing 'exit 0'
diag exit0-prints-no-directory 'echo /nonexistent/mgmt-net-compare.none; exit 0'
# The tool does its work correctly and only its EXIT STATUS reports a failure:
# the status itself must be honoured (not only the shape of the output).
for tool in sort sed grep diff cmp; do
    sabotage "$tool-output-ok-exit2" "$tool" "/usr/bin/$tool \"\$@\"; exit 2" 2 real-addr-before.txt real-addr-after.txt
done
# sed runs twice (volatile seconds, then blank lines): each stage on its own.
sabotage sed-first-stage-output-ok-exit2 sed "case \"\$1\" in -E) /usr/bin/sed \"\$@\"; exit 2 ;; esac; exec /usr/bin/sed \"\$@\"" 2 real-addr-before.txt real-addr-after.txt
sabotage sed-blank-stage-output-ok-exit2 sed "case \"\$*\" in *'/^\$/d'*) /usr/bin/sed \"\$@\"; exit 2 ;; esac; exec /usr/bin/sed \"\$@\"" 2 real-addr-before.txt real-addr-after.txt
# The sabotage harness itself is sound: an unsabotaged IP change is exit 1.
expect 1 "control: unsabotaged IP change is still exit 1" real-addr-before.txt addr-ip-changed-after.txt
# An input that is readable per `-r` but cannot be read as a file (a directory).
total=$((total + 1))
mkdir -p "$TMP/adir"
sh "$CMP" "$TMP/adir" "$FX/real-addr-before.txt" >/dev/null 2>&1; got=$?
if [ "$got" -eq 2 ]; then echo "PASS unreadable input (directory) is exit 2"; else echo "FAIL unreadable input (directory): exit $got"; fail=$((fail + 1)); fi
# Write failure of the normalised output: the file-size limit makes the first
# stage's output file fail to be written; both sides would otherwise be empty.
total=$((total + 1))
i=0; : > "$TMP/big-before"
while [ "$i" -lt 200 ]; do
    printf '2: ens4    inet 10.146.0.%d/32 metric 100 scope global dynamic ens4\\       valid_lft %dsec preferred_lft %dsec\n' "$i" "$((i + 100))" "$((i + 100))" >> "$TMP/big-before"
    i=$((i + 1))
done
sed 's/10\.146\.0\./10.146.9./' "$TMP/big-before" > "$TMP/big-after"
out="$( (ulimit -f 4 2>/dev/null; sh "$CMP" "$TMP/big-before" "$TMP/big-after") 2>/dev/null)"; got=$?
if [ "$got" -ne 0 ] && ! printf '%s\n' "$out" | grep -q 'IDENTICAL'; then
    echo "PASS output write failure (file size limit) is non-zero (exit $got)"
else
    echo "FAIL output write failure: exit $got out=$out"; fail=$((fail + 1))
fi

# ---- the stdout / stderr / exit contract on success and on a change ------
contract() { # contract <label> <before> <after> <want exit> <want stdout> (stdout compared exactly)
    label="$1"; before="$2"; after="$3"; want="$4"; wout="$5"
    total=$((total + 1))
    sh "$CMP" "$FX/$before" "$FX/$after" > "$TMP/c.out" 2> "$TMP/c.err"; got=$?
    printf '%s\n' "$wout" > "$TMP/c.want"
    if [ "$got" -eq "$want" ] && diff -q "$TMP/c.want" "$TMP/c.out" >/dev/null && [ ! -s "$TMP/c.err" ]; then
        echo "PASS contract $label (exit $got, stdout exact, stderr empty)"
    else
        echo "FAIL contract $label: exit $got"; sed 's/^/    out: /' "$TMP/c.out"; sed 's/^/    err: /' "$TMP/c.err"
        fail=$((fail + 1))
    fi
}
contract identical real-addr-before.txt real-addr-before.txt 0 'mgmt-net-compare: IDENTICAL'
contract stable-identical real-addr-before.txt real-addr-after.txt 0 'mgmt-net-compare: STABLE-IDENTICAL (only finite lease seconds differ)'
total=$((total + 1))
sh "$CMP" "$FX/real-addr-before.txt" "$FX/addr-ip-changed-after.txt" > "$TMP/c.out" 2> "$TMP/c.err"; got=$?
if [ "$got" -eq 1 ] && [ "$(sed -n 1p "$TMP/c.out")" = "mgmt-net-compare: CHANGED" ] && [ ! -s "$TMP/c.err" ]; then
    echo "PASS contract changed (exit 1, CHANGED first line, stderr empty)"
else
    echo "FAIL contract changed: exit $got"; fail=$((fail + 1))
fi

# ---- stable fields: route expiry seconds, link state / MTU ----------------
pair() { # pair <name> <want exit> <before text> <after text>
    total=$((total + 1))
    printf '%s\n' "$3" > "$TMP/p-before"; printf '%s\n' "$4" > "$TMP/p-after"
    sh "$CMP" "$TMP/p-before" "$TMP/p-after" >/dev/null 2>&1; got=$?
    if [ "$got" -eq "$2" ]; then echo "PASS $1 (exit $got)"; else echo "FAIL $1: expected $2, got $got"; fail=$((fail + 1)); fi
}
R6='default via fe80::1 dev ens4 proto ra metric 1024 expires 1790sec pref medium'
pair "route expires seconds only (finite)" 0 "$R6" "$(printf '%s' "$R6" | sed 's/1790/1700/')"
pair "route expires 0sec" 1 "$R6" "$(printf '%s' "$R6" | sed 's/expires 1790sec/expires 0sec/')"
pair "route expiry removed (static)" 1 "$R6" "$(printf '%s' "$R6" | sed 's/ expires 1790sec//')"
L1='2: ens4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1460 qdisc mq state UP mode DEFAULT group default qlen 1000\    link/ether 42:01:0a:92:00:15 brd ff:ff:ff:ff:ff:ff'
pair "link state UP -> DOWN" 1 "$L1" "$(printf '%s' "$L1" | sed 's/state UP/state DOWN/')"
pair "link MTU changed" 1 "$L1" "$(printf '%s' "$L1" | sed 's/mtu 1460/mtu 1500/')"
pair "whitespace-only lines are not content" 0 "$L1" "$(printf '%s\n   \n' "$L1")"
# A part can legitimately be empty (no policy rule / no IPv6 route): empty
# against empty is stable, empty against a route is a change, and neither is a
# failed normalisation.
pair "empty part against empty part" 0 "" ""
pair "empty part against a route" 1 "" "$R6"
pair "a route against an empty part" 1 "$R6" ""

echo "mgmt-net-compare-selftest: $total checks, $fail failed"
[ "$fail" -eq 0 ]
