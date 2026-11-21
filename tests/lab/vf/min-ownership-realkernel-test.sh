#!/bin/bash
# OBS-CLOSEOUT-DOWN-MIN: the closeout lab's link ownership against a REAL
# kernel (real iproute2, real veth/dummy devices). Run as root, ONLY inside a
# fresh private network + mount namespace, e.g.
#
#   sudo unshare --mount --net --propagation private -- \
#        /bin/bash tests/lab/vf/min-ownership-realkernel-test.sh
#
# The script refuses to start unless the network namespace holds nothing but
# `lo` (so it can never run in the host namespace, where ens4 or any other
# link exists), and it creates and deletes only links inside that namespace;
# they vanish with it. It does not touch the management network, /run/netns,
# systemd or any service: closeout-lab.sh runs from a path-substituted copy
# with a no-op `systemctl` and scratch directories.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
IP=/usr/sbin/ip
[ "$(id -u)" = 0 ] || { echo "refusing: run as root inside unshare --mount --net" >&2; exit 2; }
others="$($IP -o link show | awk '{ n = $2; sub(/:$/, "", n); if (n != "lo") print n }')"
[ -z "$others" ] || { echo "refusing: this network namespace holds links other than lo ($others): run inside 'unshare --net'" >&2; exit 2; }
$IP link set lo up
TMP="$(mktemp -d /tmp/min-ownership-real.XXXXXX)" || exit 2
trap 'rm -rf "$TMP"' EXIT
fail=0; total=0
ok() { total=$((total + 1)); echo "PASS $1"; }
bad() { total=$((total + 1)); fail=$((fail + 1)); echo "FAIL $1"; }
check() { label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
idx() { $IP -o link show "$1" 2> /dev/null | cut -d: -f1; }
has() { $IP -o link show "$1" > /dev/null 2>&1; }
mac() { $IP -o link show "$1" 2> /dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "link/ether") print $(i + 1) }'; }
nonlo() { $IP -o link show | awk '$2 !~ /^lo:/' | wc -l | tr -d ' '; }
none_of_ours() { ! has vh-node-b && ! has vp-node-b && ! has mkm0 && ! has mkm0p; }
reset_net() { for l in vh-node-b vp-node-b mkm0 mkm0p other0 if99; do $IP link del "$l" 2> /dev/null || true; done; }
REC="$TMP/rec"
topo() { bash "$HERE/vf-topology.sh" "$@" > "$TMP/out" 2> "$TMP/err"; }

echo "== R1. real kernel: up-min, identity, down-min =="
reset_net; rm -f "$REC"
topo up-min "$REC"; rc=$?
check "up-min succeeds on a real kernel (rc $rc)" test "$rc" -eq 0
up_all=yes; for l in vh-node-b vp-node-b mkm0 mkm0p; do $IP -o link show "$l" | grep -q ',UP' || up_all=no; done
check "all four links exist and are UP" test "$up_all" = yes
read -r _ a ia ma b ib mb < <(sed -n 2p "$REC")
check "the record matches the kernel: ifindex and MAC of both ends" test "$(idx vh-node-b)" = "$ia" -a "$(mac vh-node-b)" = "$ma" -a "$(idx vp-node-b)" = "$ib" -a "$(mac vp-node-b)" = "$mb"
check "the pair is a real veth" test "$($IP -d link show vh-node-b | grep -c veth)" -ge 1
check "the MACs are run-unique and locally administered (02:)" test "${ma#02:}" != "$ma" -a "${mb#02:}" != "$mb" -a "$ma" != "$mb"
topo up-min "$TMP/rec2"; rc=$?
check "a second up-min over the existing links refuses (rc $rc)" test "$rc" -eq 1
check "...and left everything as it was" test "$(idx vh-node-b)" = "$ia"
topo down-min "$REC"; rc=$?
check "down-min removes our links (rc $rc)" test "$rc" -eq 0
check "none of our links is left" none_of_ours
topo down-min "$REC"; rc=$?
check "a second down-min is a no-op success (rc $rc)" test "$rc" -eq 0

echo "== R2. a link of one of our names exists first (real dummy device) =="
for n in vh-node-b vp-node-b mkm0 mkm0p; do
    reset_net; rm -f "$REC"; $IP link add "$n" type dummy; i0="$(idx "$n")"; m0="$(mac "$n")"
    topo up-min "$REC"; rc=$?
    check "$n exists: up-min refuses (rc $rc)" test "$rc" -eq 1
    check "$n exists: no other link was created" test "$(nonlo)" -eq 1
    check "$n exists: no record was made" test ! -e "$REC"
    topo down-min "$REC"; rc=$?
    check "$n exists: down-min without a record refuses (rc $rc)" test "$rc" -eq 1
    check "$n exists: the foreign link is intact (same ifindex and MAC)" test "$(idx "$n")" = "$i0" -a "$(mac "$n")" = "$m0"
done

echo "== R3. one pair is replaced by a foreign pair after up =="
reset_net; rm -f "$REC"; topo up-min "$REC"
$IP link add other0 type dummy
$IP link del vh-node-b
$IP link add vh-node-b type veth peer name vp-node-b
fi_a="$(idx vh-node-b)"; fm_a="$(mac vh-node-b)"
topo down-min "$REC"; rc=$?
check "down-min fails closed (rc $rc)" test "$rc" -eq 1
check "the foreign pair is intact (same ifindex and MAC)" test "$(idx vh-node-b)" = "$fi_a" -a "$(mac vh-node-b)" = "$fm_a" -a "$(idx vp-node-b)" != ""
check "our other pair was still removed" bash -c "! $IP link show mkm0 > /dev/null 2>&1 && ! $IP link show mkm0p > /dev/null 2>&1"
check "an unrelated link survives" has other0
topo down-min "$REC"; rc=$?
check "rerunning the cleanup still leaves the foreign pair (rc $rc)" test "$rc" -eq 1 -a "$(idx vh-node-b)" = "$fi_a"

echo "== R4. foreign links appear under our names after a clean down =="
reset_net; rm -f "$REC"; topo up-min "$REC"; topo down-min "$REC"
$IP link add mkm0 type dummy; fi_m="$(idx mkm0)"
topo down-min "$REC"; rc=$?
check "rerun refuses (rc $rc) and deletes nothing" test "$rc" -eq 1 -a "$(idx mkm0)" = "$fi_m"

echo "== R5. a link named like an ifindex (if99) is never confused with one =="
reset_net; rm -f "$REC"; topo up-min "$REC"; $IP link add if99 type dummy
topo down-min "$REC"; rc=$?
check "down-min refuses while an if<N> link exists (rc $rc)" test "$rc" -eq 1
check "...and deletes nothing" bash -c "$IP link show vh-node-b > /dev/null 2>&1 && $IP link show if99 > /dev/null 2>&1"
$IP link del if99
topo down-min "$REC"; rc=$?
check "after the lookalike is gone the cleanup completes (rc $rc)" test "$rc" -eq 0
check "...and removes our links" none_of_ours

echo "== R6. the kernel refuses the second pair (real kernel, injected add failure) =="
reset_net; rm -f "$REC"; $IP link add other0 type dummy
cat > "$TMP/ip-failing2.sh" <<EOF
#!/bin/bash
if [ "\$1 \$2" = "link add" ]; then
    n=\$(cat "$TMP/addcount" 2>/dev/null || echo 0); n=\$((n + 1)); echo \$n > "$TMP/addcount"
    if [ \$n -eq 2 ]; then echo "injected: second pair refused" >&2; exit 2; fi
fi
exec $IP "\$@"
EOF
chmod +x "$TMP/ip-failing2.sh"; rm -f "$TMP/addcount"
MKM_MIN_TEST_MODE=1 MKM_IP="$TMP/ip-failing2.sh" bash "$HERE/vf-topology.sh" up-min "$REC" > "$TMP/out" 2> "$TMP/err"; rc=$?
check "up-min fails with a clean rollback (rc $rc)" test "$rc" -eq 1
check "the first pair (real veth) was removed through the record" none_of_ours
check "the unrelated link survives" has other0
check "the record is gone" test ! -e "$REC"

echo "== R7. closeout-lab.sh up / down over the real kernel (path-substituted copy) =="
W="$TMP/cl"; mkdir -p "$W/bin" "$W/lab" "$W/pl"
cp "$HERE"/*.sh "$W/lab/"
printf '#!/bin/sh\nexit 0\n' > "$W/bin/systemctl"; chmod +x "$W/bin/systemctl"
sed -e "s|^LIBEXEC=.*|LIBEXEC=\"$W/pl/mikagami-vf\"|" -e "s|^RUNTIME=.*|RUNTIME=\"$W/run\"|" \
    -e "s|^UNIT=.*|UNIT=\"$W/mikagami-closeout.service\"|" -e "s|/usr/bin/systemctl|\"$W/bin/systemctl\"|g" \
    -e "s|/usr/local/libexec|$W/pl|g" -e "s|/usr/bin/bash|bash|g" "$HERE/closeout-lab.sh" > "$W/lab/closeout-lab.sh"
cl() { bash "$W/lab/closeout-lab.sh" "$@" > "$W/out" 2> "$W/err"; }
no_leftovers() { [ ! -e "$W/run" ] && [ ! -e "$W/pl/mikagami-vf" ] && [ ! -e "$W/mikagami-closeout.service" ]; }
reset_net; rm -rf "$W/run" "$W/pl/mikagami-vf" "$W/ev"; $IP link add other0 type dummy
cl up; rc=$?
check "closeout up succeeds (rc $rc)" test "$rc" -eq 0
check "...the record and the scripts exist" test -f "$W/run/min-owned" -a -x "$W/pl/mikagami-vf/fence.sh"
check "...the four real links exist" test "$(nonlo)" -eq 5
i_vh="$(idx vh-node-b)"
cl down "$W/ev"; rc=$?
check "closeout down succeeds (rc $rc)" test "$rc" -eq 0
check "...our links are gone" none_of_ours
check "...the lab files are gone" no_leftovers
check "...the bystander is kept" has other0
check "...the record is kept as evidence" test -s "$W/ev/min-owned.txt"
check "...and the management check passed (sandbox lo only)" grep -q 'mgmt-net: link: PASS' "$W/ev/mgmt-net-check.txt"
rm -rf "$W/run" "$W/pl/mikagami-vf" "$W/ev"; $IP link add vp-node-b type dummy; fm="$(mac vp-node-b)"
cl up; rc=$?
check "closeout up with a foreign vp-node-b (only the peer name!) refuses (rc $rc)" test "$rc" -eq 1
check "...creating nothing" no_leftovers
check "...no other link exists besides the bystander and the foreign vp-node-b" test "$(nonlo)" -eq 2
check "...the foreign vp-node-b is intact" test "$(mac vp-node-b)" = "$fm"
$IP link del vp-node-b
rm -rf "$W/run" "$W/pl/mikagami-vf" "$W/ev"
cl up
$IP link del vh-node-b; $IP link add vh-node-b type veth peer name vp-node-b; fi_b="$(idx vh-node-b)"
cl down "$W/ev"; rc=$?
check "closeout down over a replaced pair: rc 1 (rc $rc)" test "$rc" -eq 1
check "...the foreign pair is intact" test "$(idx vh-node-b)" = "$fi_b"
check "...the run dir with the record is kept for the operator" test -f "$W/run/min-owned"

echo "min-ownership-realkernel-test: $total checks, $fail failed"
[ "$fail" -eq 0 ]
