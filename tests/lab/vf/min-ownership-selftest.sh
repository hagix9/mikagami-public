#!/bin/bash
# OBS-CLOSEOUT-DOWN-MIN: self-test of the closeout lab's link ownership
# (vf-topology.sh check-min / up-min / down-min and closeout-lab.sh up / down).
#
# It drives the REAL scripts over a STATEFUL stub `ip` (MKM_MIN_TEST_MODE=1)
# that keeps a small fake host network in a scratch directory, enforces
# create-only `link add`, resolves `dev if<N>` like iproute2 (a link NAMED
# if<N> wins), logs every call and every deletion, and can inject failures
# and race-style replacements. It never runs the real `ip` and never touches
# the host network, so it is safe on any host. The stub's `ip -o -d link show`
# format is the one captured from a real kernel (fixtures/min-ownership/).
#
# Every case that must NOT delete something asserts the deletion log AND that
# the foreign link is still in the fake network.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TOPO="$HERE/vf-topology.sh"
LAB="$HERE/closeout-lab.sh"
FX="$HERE/fixtures"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/min-ownership-selftest.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
fail=0
total=0
ok() { total=$((total + 1)); echo "PASS $1"; }
bad() { total=$((total + 1)); fail=$((fail + 1)); echo "FAIL $1"; }
check() { # check <label> <command...>
    label="$1"; shift
    if "$@"; then ok "$label"; else bad "$label"; fi
}

# ---- the stateful stub ----------------------------------------------------
cat > "$TMP/ip-state-stub.sh" <<'STUB'
#!/bin/bash
S="${STUB_STATE:?}"
echo "$*" >> "$S/calls.log"
bump() { n=$(cat "$S/count.$1" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$S/count.$1"; echo "$n"; }
fail_on() { # STUB_FAIL_<KIND>=N fails the Nth call of that kind; "all" fails every one
    var="STUB_FAIL_$1"; want="${!var:-}"; n=$(bump "$1")
    [ -n "$want" ] && { [ "$want" = all ] || [ "$want" = "$n" ]; }
}
resolve() { # a name wins over if<N>, like iproute2
    if [ -e "$S/links/$1" ]; then echo "$1"; return 0; fi
    case "$1" in
        if[0-9]*)
            for f in "$S"/links/*; do
                [ -e "$f" ] || continue
                read -r i _ < "$f"
                [ "$i" = "${1#if}" ] && { basename "$f"; return 0; }
            done ;;
    esac
    return 1
}
newidx() { n=$(cat "$S/next"); echo $((n + 1)) > "$S/next"; echo "$n"; }
mgmt() { # the five read-only forms of the management-network capture
    f="$1"
    [ -n "${STUB_MGMT_DIR:-}" ] || { echo "stub: no management fixtures" >&2; exit 99; }
    if [ "${STUB_FAIL_MGMT:-}" = "$f" ]; then echo "stub: forced failure of $f" >&2; exit 1; fi
    cat "$STUB_MGMT_DIR/$f.txt"
}
case "$*" in
    "-o addr show") mgmt addr; exit ;;
    "-4 route show") mgmt route4; exit ;;
    "-6 route show") mgmt route6; exit ;;
    "rule show") mgmt rule; exit ;;
    "-o link show") mgmt link; exit ;;
    "-o -d link show")
        if fail_on LIST; then echo "stub: forced list failure" >&2; exit 1; fi
        [ "${STUB_LIST_EMPTY:-}" != 1 ] || exit 0
        echo '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0  allmulti 0 minmtu 0 maxmtu 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1'
        echo '2: ens4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1460 qdisc mq state UP mode DEFAULT group default qlen 1000\    link/ether 42:01:0a:92:00:15 brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 addrgenmode eui64 numtxqueues 2 numrxqueues 2'
        for f in "$S"/links/*; do
            [ -e "$f" ] || continue
            read -r i _ < "$f"; echo "$i $(basename "$f")"
        done | sort -n | while read -r _ name; do
            read -r idx mac kind peer < "$S/links/$name"
            shown="$name"; [ "$peer" = "-" ] || shown="$name@$peer"
            echo "$idx: $shown: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether $mac brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 \\    $kind addrgenmode eui64 numtxqueues 2 numrxqueues 2"
        done
        exit 0 ;;
esac
case "${1:-} ${2:-}" in
    "link add")
        if fail_on ADD; then echo "stub: forced add failure" >&2; exit 2; fi
        shift 2; name="$1"; shift; mac=""; peer=-; pmac=""; kind=""
        while [ $# -gt 0 ]; do
            case "$1" in
                address) if [ "$peer" = - ]; then mac="$2"; else pmac="$2"; fi; shift 2 ;;
                type) kind="$2"; shift 2 ;;
                peer) shift; [ "$1" = name ] && { peer="$2"; shift 2; } ;;
                *) shift ;;
            esac
        done
        [ ! -e "$S/links/$name" ] || { echo "RTNETLINK answers: File exists" >&2; exit 2; }
        if [ "$peer" != - ] && [ -e "$S/links/$peer" ]; then echo "RTNETLINK answers: File exists" >&2; exit 2; fi
        [ -n "$mac" ] || mac="$(printf '5e:00:00:%02x:%02x:%02x' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))"
        [ -n "$pmac" ] || pmac="$(printf '5e:01:00:%02x:%02x:%02x' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))"
        if [ "$peer" != - ]; then
            pidx=$(newidx); idx=$(newidx)
            echo "$pidx $pmac $kind $name" > "$S/links/$peer"
        else
            idx=$(newidx)
        fi
        echo "$idx $mac $kind $peer" > "$S/links/$name"
        echo "ADDED $name${peer:+ $peer}" >> "$S/events.log"
        n=$(cat "$S/count.ADD")
        if [ -n "${STUB_ADD_HOOK:-}" ]; then "$STUB_ADD_HOOK" "$S" "$n" "$name"; fi
        exit 0 ;;
    "link set")
        if fail_on SET; then echo "stub: forced set failure" >&2; exit 2; fi
        [ "$3" = dev ] && resolve "$4" > /dev/null || { echo "Cannot find device \"$4\"" >&2; exit 1; }
        exit 0 ;;
    "link del")
        if fail_on DEL; then echo "stub: forced delete failure" >&2; exit 2; fi
        [ "$3" = dev ] || { echo "stub: del needs dev" >&2; exit 99; }
        name=$(resolve "$4") || { echo "RTNETLINK answers: No such device" >&2; exit 2; }
        echo "DELETED $name" >> "$S/del.log"
        if [ "${STUB_DEL_LEAVES:-}" != 1 ]; then
            read -r _ _ _ peer < "$S/links/$name"
            rm -f "$S/links/$name"
            [ "$peer" = - ] || rm -f "$S/links/$peer"
        fi
        exit 0 ;;
esac
echo "ip-state-stub: unsupported: $*" >&2
exit 99
STUB
chmod +x "$TMP/ip-state-stub.sh"

# ---- helpers on the fake network ------------------------------------------
new_net() { # a fresh fake network in $S (lo + ens4 only)
    S="$TMP/net-$1"; export S; rm -rf "$S"; mkdir -p "$S/links"
    echo 10 > "$S/next"; : > "$S/calls.log"; : > "$S/del.log"; : > "$S/events.log"
    export STUB_STATE="$S" MKM_MIN_TEST_MODE=1 MKM_IP="$TMP/ip-state-stub.sh"
    unset STUB_FAIL_ADD STUB_FAIL_DEL STUB_FAIL_LIST STUB_FAIL_SET STUB_DEL_LEAVES STUB_ADD_HOOK STUB_LIST_EMPTY
}
ipx() { "$TMP/ip-state-stub.sh" "$@"; }
arm() { rm -f "$S/count.$1"; export "STUB_FAIL_$1=$2"; }   # arm <ADD|DEL|LIST|SET> <n|all>: fail the nth call FROM NOW
foreign() { # foreign <name> [peer]: a link nobody asked for, identifiable by its MAC
    if [ -n "${2:-}" ]; then ipx link add "$1" address 02:ff:ff:00:00:01 type veth peer name "$2" address 02:ff:ff:00:00:02
    else ipx link add "$1" address 02:ff:ff:00:00:03 type dummy; fi
}
has() { [ -e "$S/links/$1" ]; }
mac_of() { read -r _ m _ < "$S/links/$1"; echo "$m"; }
deleted() { grep -c '^DELETED' "$S/del.log" | tr -d ' '; }
adds() { grep -c '^link add' "$S/calls.log" | tr -d ' '; }
none_of_ours() { ! has vh-node-b && ! has vp-node-b && ! has mkm0 && ! has mkm0p; }
export -f has mac_of deleted adds none_of_ours
topo() { bash "$TOPO" "$@" > "$TMP/topo.out" 2> "$TMP/topo.err"; }
REC="$TMP/rec"
fresh_rec() { rm -f "$REC"; }

echo "== 0. the parser reads a REAL ip -o -d link show =="
# shellcheck disable=SC1090
( sed -n '/^link_table() {/,/^}/p' "$TOPO" > "$TMP/lt.sh"
  sed -n '/^row_of() {/,/^}/p;/^row_is() {/,/^}/p' "$TOPO" >> "$TMP/lt.sh" )
cat > "$TMP/real-ip.sh" <<EOF
#!/bin/sh
cat "$FX/min-ownership/real-ip-o-d-link-show.txt"
EOF
chmod +x "$TMP/real-ip.sh"
tbl="$(IP="$TMP/real-ip.sh"; . "$TMP/lt.sh"; link_table)"
check "real output: lo is no veth (no mac, no kind)" bash -c "printf '%s\n' \"\$1\" | grep -q '^lo 1 - - -\$'" _ "$tbl"
check "real output: veth peer, mac, kind, ifindex parsed" bash -c "printf '%s\n' \"\$1\" | grep -q '^vh-node-b 3 02:aa:bb:cc:dd:01 veth vp-node-b\$'" _ "$tbl"
check "real output: the peer end parsed too" bash -c "printf '%s\n' \"\$1\" | grep -q '^vp-node-b 2 02:aa:bb:cc:dd:02 veth vh-node-b\$'" _ "$tbl"

echo "== 1. normal: up-min then down-min =="
new_net 1; fresh_rec
topo up-min "$REC"; rc=$?
check "up-min succeeds (rc $rc)" test "$rc" -eq 0
check "four links exist" bash -c "[ -e '$S/links/vh-node-b' ] && [ -e '$S/links/vp-node-b' ] && [ -e '$S/links/mkm0' ] && [ -e '$S/links/mkm0p' ]"
check "record: header + one line per pair" test "$(wc -l < "$REC" | tr -d ' ')" -eq 3
check "record header" test "$(sed -n 1p "$REC")" = "mikagami-min-owned v1"
check "the pairs are created by exactly two create-only adds" test "$(adds)" -eq 2
check "run-unique MACs are locally administered" bash -c "grep -q ' 02:' '$REC'"
check "no deletion during up" test "$(deleted)" -eq 0
foreign other0
topo down-min "$REC"; rc=$?
check "down-min succeeds (rc $rc)" test "$rc" -eq 0
check "exactly our two pairs were deleted (2 deletions)" test "$(deleted)" -eq 2
check "none of our links is left" none_of_ours
check "an unrelated link survives" has other0
topo down-min "$REC"; rc=$?
check "a second down-min is a no-op success (rc $rc)" test "$rc" -eq 0
check "...and deletes nothing more" test "$(deleted)" -eq 2

echo "== 2. a name that exists before up is refused; nothing is created or deleted =="
for n in vh-node-b vp-node-b mkm0 mkm0p; do
    new_net "pre-$n"; fresh_rec; foreign "$n"; before_mac="$(mac_of "$n")"; : > "$S/calls.log"
    topo check-min; rc=$?
    check "$n pre-exists: check-min refuses (rc $rc)" test "$rc" -eq 1
    topo up-min "$REC"; rc=$?
    check "$n pre-exists: up-min refuses (rc $rc)" test "$rc" -eq 1
    check "$n pre-exists: nothing was created" test "$(adds)" -eq 0
    check "$n pre-exists: no record was made" test ! -e "$REC"
    check "$n pre-exists: the foreign link is intact (same MAC)" test "$(mac_of "$n")" = "$before_mac"
    check "$n pre-exists: nothing deleted" test "$(deleted)" -eq 0
    topo down-min "$REC"; rc=$?
    check "$n pre-exists: down-min without a record refuses (rc $rc), foreign intact" bash -c "[ $rc -eq 1 ] && [ -e '$S/links/$n' ] && [ '$(deleted)' = 0 ]"
done
new_net listfail; fresh_rec; arm LIST 1
topo check-min; rc=$?
check "links cannot be listed: check-min exits 2 (rc $rc)" test "$rc" -eq 2
arm LIST 1
topo up-min "$REC"; rc=$?
check "links cannot be listed: up-min refuses, creates nothing (rc $rc)" bash -c "[ $rc -ne 0 ] && [ '$(adds)' = 0 ] && [ ! -e '$REC' ]"
new_net listempty; fresh_rec; export STUB_LIST_EMPTY=1
topo up-min "$REC"; rc=$?
check "an empty link list (a broken ip) is refused, nothing created (rc $rc)" bash -c "[ $rc -ne 0 ] && [ '$(adds)' = 0 ]"

echo "== 3. the second pair fails after the first was made: roll back only the first =="
new_net 3; fresh_rec; foreign other0; arm ADD 2
topo up-min "$REC"; rc=$?
check "up-min fails with a clean rollback (rc $rc)" test "$rc" -eq 1
check "the first pair was rolled back (one delete, of that pair)" bash -c "[ '$(deleted)' = 1 ] && grep -Eq '^DELETED (vh-node-b|vp-node-b)\$' '$S/del.log'"
check "nothing of ours is left" none_of_ours
check "the unrelated link survives" has other0
check "the record is removed after a clean rollback" test ! -e "$REC"
cat > "$TMP/hook-appear.sh" <<'H'
#!/bin/bash
# after the first successful add, a third party creates mkm0p (the second pair then fails: File exists)
S="$1"; n="$2"
[ "$n" = 1 ] || exit 0
i=$(cat "$S/next"); echo $((i + 1)) > "$S/next"
echo "$i 02:ee:ee:00:00:09 dummy -" > "$S/links/mkm0p"
H
chmod +x "$TMP/hook-appear.sh"
new_net 3c; fresh_rec; rm -f "$S/count.ADD"; export STUB_ADD_HOOK="$TMP/hook-appear.sh"
topo up-min "$REC"; rc=$?
check "a third party takes mkm0p between the pairs: up-min fails, links left (rc $rc)" test "$rc" -eq 2
check "our first pair was rolled back" bash -c "! [ -e '$S/links/vh-node-b' ] && ! [ -e '$S/links/vp-node-b' ]"
check "the third party's mkm0p was NOT deleted" bash -c "[ -e '$S/links/mkm0p' ] && [ \"\$(cut -d' ' -f2 '$S/links/mkm0p')\" = 02:ee:ee:00:00:09 ] && ! grep -q mkm0p '$S/del.log'"

echo "== 4. replaced by a different link right after creation =="
cat > "$TMP/hook-replace-after-add.sh" <<'H'
#!/bin/bash
# after the first add the pair is swapped for a foreign link of the same name
S="$1"; n="$2"; name="$3"
[ "$n" = 1 ] || exit 0
read -r _ _ _ peer < "$S/links/$name"
rm -f "$S/links/$name" "$S/links/$peer"
i=$(cat "$S/next"); echo $((i + 1)) > "$S/next"
echo "$i 02:ff:ff:00:00:77 dummy -" > "$S/links/$name"
H
chmod +x "$TMP/hook-replace-after-add.sh"
new_net 4; fresh_rec; rm -f "$S/count.ADD"; export STUB_ADD_HOOK="$TMP/hook-replace-after-add.sh"
topo up-min "$REC"; rc=$?
check "up-min notices the swap and fails with links left in place (rc $rc)" test "$rc" -eq 2
check "the impostor was NOT deleted" bash -c "[ -e '$S/links/vh-node-b' ] && [ '$(deleted)' = 0 ]"
check "the record is kept" test -f "$REC"
check "the impostor pair is not in the record" bash -c "! grep -q vh-node-b '$REC'"
check "no second pair was attempted after the failure" test "$(adds)" -eq 1

cat > "$TMP/hook-replace-pair.sh" <<'H'
#!/bin/bash
# after the first add the WHOLE pair is swapped for a foreign veth pair of the same names
S="$1"; n="$2"; name="$3"
[ "$n" = 1 ] || exit 0
read -r _ _ _ peer < "$S/links/$name"
rm -f "$S/links/$name" "$S/links/$peer"
i=$(cat "$S/next"); echo $((i + 2)) > "$S/next"
echo "$i 02:ff:ff:00:00:71 veth $name" > "$S/links/$peer"
echo "$((i + 1)) 02:ff:ff:00:00:72 veth $peer" > "$S/links/$name"
H
chmod +x "$TMP/hook-replace-pair.sh"
new_net 4b; fresh_rec; rm -f "$S/count.ADD"; export STUB_ADD_HOOK="$TMP/hook-replace-pair.sh"
topo up-min "$REC"; rc=$?
check "a whole foreign veth pair takes the names right after creation: up-min fails, links left (rc $rc)" test "$rc" -eq 2
check "the foreign pair was NOT adopted (not in the record) and NOT deleted" bash -c "! grep -q vh-node-b '$REC' && [ -e '$S/links/vh-node-b' ] && [ '$(deleted)' = 0 ]"

echo "== 5. replaced / changed between up and down =="
for what in swap-pair ifindex mac-a mac-b peer-moved kind half; do
    new_net "5-$what"; fresh_rec; topo up-min "$REC"; foreign bystander
    case "$what" in
        swap-pair) ipx link del dev vh-node-b; : > "$S/del.log"; foreign vh-node-b vp-node-b ;;
        ifindex) read -r i m k p < "$S/links/vp-node-b"; echo "$((i + 500)) $m $k $p" > "$S/links/vp-node-b" ;;
        mac-a) read -r i m k p < "$S/links/vh-node-b"; echo "$i 02:12:34:56:78:9a $k $p" > "$S/links/vh-node-b" ;;
        mac-b) read -r i m k p < "$S/links/vp-node-b"; echo "$i 02:12:34:56:78:9b $k $p" > "$S/links/vp-node-b" ;;
        peer-moved) read -r i m k p < "$S/links/vh-node-b"; echo "$i $m $k elsewhere" > "$S/links/vh-node-b" ;;
        kind) read -r i m k p < "$S/links/vh-node-b"; echo "$i $m macvlan $p" > "$S/links/vh-node-b" ;;
        half) rm -f "$S/links/vp-node-b" ;;
    esac
    mkm_before="$(deleted)"
    topo down-min "$REC"; rc=$?
    check "$what: down-min fails closed (rc $rc)" test "$rc" -eq 1
    check "$what: vh-node-b is not deleted" has vh-node-b
    check "$what: no deletion names vh-node-b or vp-node-b" bash -c "! grep -Eq 'vh-node-b|vp-node-b' '$S/del.log'"
    check "$what: the other pair (still ours) was cleaned" bash -c "! [ -e '$S/links/mkm0' ] && ! [ -e '$S/links/mkm0p' ]"
    check "$what: the bystander survives" has bystander
    topo down-min "$REC"; rc=$?
    check "$what: rerunning the cleanup still deletes nothing foreign (rc $rc)" bash -c "[ $rc -eq 1 ] && ! grep -Eq 'vh-node-b|vp-node-b' '$S/del.log'"
done
new_net 5-both; fresh_rec; topo up-min "$REC"
ipx link del dev vh-node-b; ipx link del dev mkm0; : > "$S/del.log"; foreign vh-node-b; foreign mkm0
topo down-min "$REC"; rc=$?
check "both pairs replaced by foreign links: nothing deleted, fail closed (rc $rc)" bash -c "[ $rc -eq 1 ] && [ '$(deleted)' = 0 ] && [ -e '$S/links/vh-node-b' ] && [ -e '$S/links/mkm0' ]"

echo "== 6. the ownership record is missing or unusable =="
mkrec() { # mkrec <name> <content>: a fresh pair set with a replaced record
    new_net "6-$1"; fresh_rec; topo up-min "$REC"; foreign bystander; : > "$S/del.log"
}
mkrec missing; rm -f "$REC"
topo down-min "$REC"; rc=$?
check "record missing: refuses (rc $rc)" test "$rc" -eq 1
check "record missing: nothing deleted, all links still there" bash -c "[ '$(deleted)' = 0 ] && [ -e '$S/links/vh-node-b' ] && [ -e '$S/links/mkm0p' ]"
topo down-min ""; rc=$?
check "no record path at all: refuses (rc $rc)" test "$rc" -eq 1
for bad_rec in header line short unknown dup nomac noidx extra blank; do
    mkrec "$bad_rec"
    good1="$(sed -n 2p "$REC")"; good2="$(sed -n 3p "$REC")"
    case "$bad_rec" in
        header) { echo "other v1"; echo "$good1"; echo "$good2"; } > "$REC" ;;
        line) { sed -n 1p "$REC"; echo "garbage"; echo "$good2"; } > "$TMP/r"; cp "$TMP/r" "$REC" ;;
        short) { echo "mikagami-min-owned v1"; echo "$good1"; echo "pair mkm0 12 02:00:00:00:00:01"; } > "$REC" ;;
        unknown) { echo "mikagami-min-owned v1"; echo "$good1"; echo "pair eth0 3 02:00:00:00:00:01 eth9 4 02:00:00:00:00:02"; } > "$REC" ;;
        dup) { echo "mikagami-min-owned v1"; echo "$good1"; echo "$good1"; } > "$REC" ;;
        nomac) { echo "mikagami-min-owned v1"; echo "$good1"; echo "$good2" | sed 's/02:[0-9a-f:]* /nomac /'; } > "$REC" ;;
        noidx) { echo "mikagami-min-owned v1"; echo "$good1"; echo "$good2" | sed 's/^pair mkm0 [0-9]*/pair mkm0 x/'; } > "$REC" ;;
        extra) { echo "mikagami-min-owned v1"; echo "$good1"; echo "$good2 extra"; } > "$REC" ;;
        blank) { echo "mikagami-min-owned v1"; echo "$good1"; echo; echo "$good2"; } > "$REC" ;;
    esac
    topo down-min "$REC"; rc=$?
    check "record $bad_rec: refuses and deletes NOTHING, not even the valid line (rc $rc)" bash -c "[ $rc -eq 1 ] && [ '$(deleted)' = 0 ] && [ -e '$S/links/vh-node-b' ] && [ -e '$S/links/mkm0' ]"
done
mkrec symlink; mv "$REC" "$TMP/real-rec"; ln -s "$TMP/real-rec" "$REC"
topo down-min "$REC"; rc=$?
check "record is a symlink: refuses (rc $rc)" bash -c "[ $rc -eq 1 ] && [ '$(deleted)' = 0 ]"
new_net 6-up-existing-rec; fresh_rec; echo "mikagami-min-owned v1" > "$REC"
topo up-min "$REC"; rc=$?
check "up-min refuses to reuse an existing record (rc $rc), creates nothing" bash -c "[ $rc -eq 1 ] && [ '$(adds)' = 0 ]"

echo "== 7. the cleanup itself fails =="
new_net 7a; fresh_rec; topo up-min "$REC"; foreign bystander; : > "$S/del.log"
arm DEL 1
topo down-min "$REC"; rc=$?
check "the first delete fails: rc 1 (rc $rc)" test "$rc" -eq 1
check "the failed pair is reported as left in place" bash -c "grep -q 'removing vh-node-b/vp-node-b failed' '$TMP/topo.err' && grep -q 'still present' '$TMP/topo.err'"
check "the other pair was still cleaned" bash -c "! [ -e '$S/links/mkm0' ] && [ -e '$S/links/vh-node-b' ]"
unset STUB_FAIL_DEL
topo down-min "$REC"; rc=$?
check "retry succeeds once the failure is gone (rc $rc)" test "$rc" -eq 0
check "retry: everything of ours is gone, the bystander is not" bash -c "[ -e '$S/links/bystander' ] && ! [ -e '$S/links/vh-node-b' ]"
new_net 7b; fresh_rec; topo up-min "$REC"; : > "$S/del.log"; export STUB_DEL_LEAVES=1
topo down-min "$REC"; rc=$?
check "delete reports success but the link is still there: fail closed (rc $rc)" test "$rc" -eq 1
check "residue is named" grep -q "'vh-node-b' is still present" "$TMP/topo.err"
new_net 7c; fresh_rec; topo up-min "$REC"; : > "$S/del.log"; arm LIST 1
topo down-min "$REC"; rc=$?
check "the identity cannot be read (list fails first): nothing deleted (rc $rc)" bash -c "[ $rc -eq 1 ] && [ '$(deleted)' = 0 ]"
new_net 7d; fresh_rec; topo up-min "$REC"; : > "$S/del.log"; arm LIST 2
topo down-min "$REC"; rc=$?
check "the list fails after the first delete: fail closed (rc $rc)" test "$rc" -eq 1
check "...and it does not claim the unread second pair is 'already gone'" bash -c "! grep -q 'already gone' '$TMP/topo.out'"
check "...and nothing foreign was touched (only our recorded vh pair deleted)" bash -c "[ '$(deleted)' = 1 ] && grep -Eq '^DELETED (vh-node-b|vp-node-b)\$' '$S/del.log'"
new_net 7e; fresh_rec; topo up-min "$REC"; : > "$S/del.log"; export STUB_LIST_EMPTY=1
topo down-min "$REC"; rc=$?
check "an empty link list is an unreadable identity: nothing deleted (rc $rc)" bash -c "[ $rc -eq 1 ] && [ '$(deleted)' = 0 ]"
new_net 7f; fresh_rec; topo up-min "$REC"; foreign if3; : > "$S/del.log"
topo down-min "$REC"; rc=$?
check "a link named like an ifindex (if3) exists: nothing is addressed by ifindex (rc $rc)" bash -c "[ $rc -eq 1 ] && [ '$(deleted)' = 0 ] && [ -e '$S/links/if3' ]"
new_net 7g; fresh_rec; arm SET all
topo up-min "$REC"; rc=$?
check "bringing a pair up fails: rolled back through the record (rc $rc)" bash -c "[ $rc -eq 1 ] && [ '$(deleted)' = 1 ]"
check "...and no link of ours remains" none_of_ours

echo "== 8. cleanup twice never deletes someone else's link =="
new_net 8; fresh_rec; topo up-min "$REC"; topo down-min "$REC"
foreign vh-node-b vp-node-b; foreign mkm0; : > "$S/del.log"
topo down-min "$REC"; rc=$?
check "foreign links with our names appear after a clean down: a rerun refuses (rc $rc)" test "$rc" -eq 1
check "...and deletes nothing" test "$(deleted)" -eq 0
check "...all three foreign links are intact" bash -c "[ -e '$S/links/vh-node-b' ] && [ -e '$S/links/vp-node-b' ] && [ -e '$S/links/mkm0' ]"

echo "== 9. the stub override is test-mode only =="
new_net 9; : > "$S/calls.log"
env -u MKM_MIN_TEST_MODE bash "$TOPO" check-min > /dev/null 2>&1
check "without MKM_MIN_TEST_MODE the ip override is ignored (stub never called)" test ! -s "$S/calls.log"

echo "== 10. static: where the delete code lives =="
check "link deletion appears only inside down_min" bash -c "
    [ \"\$(grep -c 'link del' '$TOPO')\" = 1 ] &&
    sed -n '/^down_min() {/,/^}/p' '$TOPO' | grep -q '\"\$IP\" link del dev \"if\$ia\"'"
check "no deletion by bare name" bash -c "! grep -E 'link del( dev)? \"?[a-z\$]' '$TOPO' | grep -v 'if\$ia' | grep -q ."
check "up_min and down_min are not the old unconditional name delete" bash -c "! grep -q '2>/dev/null || true' '$TOPO'"
check "vf-topology.sh parses" bash -n "$TOPO"
check "closeout-lab.sh parses" bash -n "$LAB"

# ---- closeout-lab.sh up / down on a path-substituted copy -------------------
echo "== 11. closeout-lab.sh up / down (path-substituted copy, stateful stub) =="
mkset() { # a management fixture set the stub serves
    d="$TMP/mset"; mkdir -p "$d"
    cp "$FX/mgmt-net/real-addr-before.txt" "$d/addr.txt"; cp "$FX/mgmt-net/real-route-before.txt" "$d/route4.txt"
    cp "$FX/mgmt-net/driver-route6.txt" "$d/route6.txt"; cp "$FX/mgmt-net/driver-rule.txt" "$d/rule.txt"
    cp "$FX/mgmt-net/driver-link.txt" "$d/link.txt"
}
mkset
W="$TMP/cl"; export W; mkdir -p "$W/bin" "$W/lab"
cp "$HERE"/*.sh "$W/lab/"
printf '#!/bin/sh\nif [ "${STUB_FAIL_SYSTEMCTL:-}" = 1 ]; then exit 1; fi\nexit 0\n' > "$W/bin/systemctl"; chmod +x "$W/bin/systemctl"
sed -e "s|^LIBEXEC=.*|LIBEXEC=\"$W/pl/mikagami-vf\"|" \
    -e "s|^RUNTIME=.*|RUNTIME=\"$W/run\"|" \
    -e "s|^UNIT=.*|UNIT=\"$W/mikagami-closeout.service\"|" \
    -e "s|/usr/bin/systemctl|\"$W/bin/systemctl\"|g" \
    -e "s|-o root -g root||" \
    -e "s|/usr/local/libexec|$W/pl|g" \
    -e "s|/usr/bin/bash|bash|g" "$LAB" > "$W/lab/closeout-lab.sh"
want_changed="$(grep -c -E '^(LIBEXEC|RUNTIME|UNIT)=|/usr/bin/systemctl|-o root -g root|/usr/local/libexec|/usr/bin/bash' "$LAB")"
got_changed="$(diff "$LAB" "$W/lab/closeout-lab.sh" | grep -c '^>')"
check "substituted copy differs from the driver only on path/command lines ($got_changed of $want_changed)" test "$got_changed" -eq "$want_changed"
cl_reset() { rm -rf "$W/run" "$W/pl" "$W/ev" "$W/mikagami-closeout.service"; mkdir -p "$W/pl"; unset STUB_FAIL_SYSTEMCTL; }
cl() { # cl <up|down> [args]: run the driver; MKM_IP serves both the links and the management capture
    env MKM_MGMT_TEST_MODE=1 STUB_MGMT_DIR="$TMP/mset" bash "$W/lab/closeout-lab.sh" "$@" > "$W/out" 2> "$W/err"
}
no_leftovers() { [ ! -e "$W/run" ] && [ ! -e "$W/pl/mikagami-vf" ] && [ ! -e "$W/mikagami-closeout.service" ]; }
export -f no_leftovers

new_net c1; cl_reset
cl up; rc=$?
check "closeout up succeeds (rc $rc)" test "$rc" -eq 0
check "closeout up: record, scripts and unit exist; four links exist" bash -c "[ -f '$W/run/min-owned' ] && [ -x '$W/pl/mikagami-vf/fence.sh' ] && [ -f '$W/mikagami-closeout.service' ] && [ -e '$S/links/mkm0p' ] && [ -e '$S/links/vp-node-b' ]"
foreign bystander
cl down "$W/ev"; rc=$?
check "closeout down succeeds (rc $rc)" test "$rc" -eq 0
check "closeout down: lab files gone, our links gone, bystander kept" bash -c "no_leftovers && none_of_ours && has bystander"
check "closeout down: the record is kept as evidence" test -s "$W/ev/min-owned.txt"
check "closeout down: management check ran and passed" grep -q 'mgmt-net: link: PASS' "$W/ev/mgmt-net-check.txt"
cl down "$W/ev2"; rc=$?
check "closeout down a second time refuses (no record), rc $rc" test "$rc" -eq 1
check "...and deleted nothing (the bystander is intact)" bash -c "[ '$(deleted)' = 2 ] && [ -e '$S/links/bystander' ]"

for n in vh-node-b vp-node-b mkm0 mkm0p; do
    new_net "c2-$n"; cl_reset; foreign "$n"; : > "$S/calls.log"
    cl up; rc=$?
    check "closeout up with a pre-existing $n refuses (rc $rc)" test "$rc" -eq 1
    check "...creates nothing: no runtime dir, scripts, unit, no link add" bash -c "no_leftovers && [ \"\$(adds)\" = 0 ]"
    check "...and the pre-existing $n is intact and undeleted" bash -c "[ -e '$S/links/$n' ] && [ '$(deleted)' = 0 ]"
    cl down "$W/ev"; rc=$?
    check "...a following closeout down refuses and deletes nothing (rc $rc)" bash -c "[ $rc -eq 1 ] && [ -e '$S/links/$n' ] && [ '$(deleted)' = 0 ]"
done

new_net c3; cl_reset; foreign bystander; arm ADD 2
cl up; rc=$?
check "closeout up: the second pair fails -> undone, rc 1 (rc $rc)" test "$rc" -eq 1
check "...no lab files, no links of ours, the bystander intact" bash -c "no_leftovers && none_of_ours && has bystander"

new_net c4; cl_reset; export STUB_FAIL_SYSTEMCTL=1
cl up; rc=$?
check "closeout up: a late step fails -> everything created is undone, rc 1 (rc $rc)" test "$rc" -eq 1
check "...including the links, through the record" bash -c "no_leftovers && none_of_ours"
check "...deleting only our two pairs" test "$(deleted)" -eq 2

new_net c5; cl_reset; rm -f "$S/count.ADD"; export STUB_ADD_HOOK="$TMP/hook-replace-after-add.sh"
cl up; rc=$?
check "closeout up: pair swapped after creation -> fails, rc 1 (rc $rc)" test "$rc" -eq 1
check "...the impostor is intact, the runtime dir (record) is KEPT" bash -c "[ -e '$S/links/vh-node-b' ] && [ -f '$W/run/min-owned' ] && [ '$(deleted)' = 0 ]"
unset STUB_ADD_HOOK
cl down "$W/ev"; rc=$?
check "closeout down after that: fail closed, rc 1 (rc $rc)" test "$rc" -eq 1
check "...the impostor is still intact and the runtime dir (record) is kept for the operator" bash -c "[ -e '$S/links/vh-node-b' ] && [ '$(deleted)' = 0 ] && [ -f '$W/run/min-owned' ]"
check "...it says so" grep -q 'LINK CLEANUP INCOMPLETE' "$W/err"

new_net c6; cl_reset; cl up; rm -f "$W/run/min-owned"; foreign bystander
cl down "$W/ev"; rc=$?
check "closeout down with no record: refuses (rc $rc)" test "$rc" -eq 1
check "...nothing deleted: links, runtime dir, scripts, unit all still there" bash -c "[ '$(deleted)' = 0 ] && [ -e '$S/links/vh-node-b' ] && [ -d '$W/run' ] && [ -d '$W/pl/mikagami-vf' ] && [ -f '$W/mikagami-closeout.service' ]"

new_net c7; cl_reset; cl up; foreign bystander; arm DEL 1
cl down "$W/ev"; rc=$?
check "closeout down: a delete fails -> rc 1 (rc $rc)" test "$rc" -eq 1
check "...runtime dir and scripts are kept for a retry; the unit is gone" bash -c "[ -d '$W/run' ] && [ -f '$W/run/min-owned' ] && [ -d '$W/pl/mikagami-vf' ] && [ ! -e '$W/mikagami-closeout.service' ]"
unset STUB_FAIL_DEL
cl down "$W/ev3"; rc=$?
check "the retry completes (rc $rc)" test "$rc" -eq 0
check "...everything is cleaned, the bystander intact" bash -c "no_leftovers && none_of_ours && has bystander"

new_net c8; cl_reset; cl up; ipx link del dev mkm0; foreign mkm0; : > "$S/del.log"
cl down "$W/ev"; rc=$?
check "closeout down: mkm0 replaced by a foreign link -> rc 1 (rc $rc)" test "$rc" -eq 1
check "...the foreign mkm0 was not deleted; our vh pair was" bash -c "[ -e '$S/links/mkm0' ] && ! grep -q mkm0 '$S/del.log' && ! [ -e '$S/links/vh-node-b' ]"

new_net c9; cl_reset; cl up; export STUB_FAIL_MGMT=link
cl down "$W/ev"; rc=$?
unset STUB_FAIL_MGMT
check "closeout down: management snapshot fails -> rc 1 (rc $rc)" test "$rc" -eq 1
check "...but our links were still cleaned and lab files removed" bash -c "no_leftovers && none_of_ours"

echo "min-ownership-selftest: $total checks, $fail failed"
[ "$fail" -eq 0 ]
