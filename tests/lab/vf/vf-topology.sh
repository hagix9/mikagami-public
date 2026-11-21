#!/usr/bin/bash
# Phase 14.12 VF lab: topology steps (test-only; environment construction only).
#
# Creates ONLY: netns node-a node-b witness client, bridge br-mkm, and the
# veth pairs vh-<ns> (host side, enslaved to br-mkm) <-> eth0 (inside <ns>).
# The bridge and the host-side veths carry NO address and NO route; nothing
# here touches ens4, the default route, ip_forward, a firewall or sshd.
#
# MC-1 (remaining findings): the Rust VF lab runs these steps ONE AT A TIME
# and, after each one, reads back and records the identity of what it made
# (ifindex, MAC and kind of a device; the veth's peer inside the lab's own
# netns; the netns through a handle the lab holds). Only what is recorded is
# ever deleted, and only by the lab, after checking that identity again. So:
#   - every step here is create-only (the kernel refuses an existing name);
#   - a netns is created by the lab itself (a holder process in a new
#     namespace, held by the lab from then on); `netns` only attaches the
#     name to it, create-only;
#   - the bridge gets a run-unique MAC from the lab (a bridge with a MAC set
#     at creation keeps it: the kernel no longer re-derives it from ports);
#   - the veth's peer is placed into the lab's netns through the HANDLE the
#     lab holds (`/proc/<pid>/fd/<n>`), never by name, and the inside of the
#     netns is configured through that handle too;
#   - there is NO `down`: nothing here deletes the topology by name.
# "min" mode (Stage 13.6 closeout, closeout-lab.sh): only the veth pair
# vh-node-b <-> vp-node-b (both ends in the host netns, no address, no bridge)
# used as the virtual fencing target, plus the veth pair mkm0 <-> mkm0p used as
# the VIP interface. OBS-CLOSEOUT-DOWN-MIN: the same ownership rule as above.
#   - check-min refuses (exit 1) if ANY of the four names exists, and exits 2
#     if the links cannot be listed; up-min repeats the check before creating;
#   - each pair is created with ONE create-only `ip link add` and run-unique
#     locally administered MACs on both ends, then READ BACK (ifindex, MAC,
#     kind veth, the peer's name); only a pair whose read-back matches is
#     written to the ownership record <record> (appended, one line per pair);
#   - down-min deletes a pair only if the record names it AND both ends still
#     show the recorded ifindex, MAC, kind and peer, checked immediately before
#     the delete, which addresses the device by its ifindex. A missing or invalid
#     record, a mismatch, a half-present pair, an unlistable network or a name
#     still present afterwards leaves everything in place / fails (exit 1);
#   - up-min that fails after creating something rolls back through the same
#     record: exit 1 = nothing of ours is left, exit 2 = something is left in
#     place (the record is kept so down-min can finish or the operator can look).
# A name alone is never proof of ownership. The delete code lives ONLY in
# `down_min`, which up-min's rollback reuses.
# Only the self-test (min-ownership-selftest.sh) sets MKM_MIN_TEST_MODE=1 to
# substitute `ip`; without it the override is not read.
set -eu
IP=/usr/sbin/ip
if [ "${MKM_MIN_TEST_MODE:-}" = 1 ]; then
    IP="${MKM_IP:-$IP}"
fi
NSENTER=/usr/bin/nsenter
BR=br-mkm
NS_LIST="node-a node-b witness client"
addr_of() {
    case "$1" in
        node-a) echo 192.168.77.11 ;;
        node-b) echo 192.168.77.12 ;;
        witness) echo 192.168.77.13 ;;
        client) echo 192.168.77.14 ;;
    esac
}
lab_ns() {
    case " $NS_LIST " in
        *" ${1:-} "*) ;;
        *) echo "vf-topology: not a lab netns: '${1:-}'" >&2; exit 64 ;;
    esac
}
MIN_PAIRS="vh-node-b:vp-node-b mkm0:mkm0p"
MIN_NAMES="vh-node-b vp-node-b mkm0 mkm0p"
MIN_RECORD_HEADER="mikagami-min-owned v1"
MAC_RE='^([0-9a-f]{2}:){5}[0-9a-f]{2}$'

# One line per link of the host netns: name ifindex mac kind peer ("-" when
# none). `ip -o -d link show` joins the three lines of a link with a backslash:
# header \ link/ether <mac> ... \ <kind> ...
link_table() {
    raw="$("$IP" -o -d link show)" || return 1
    [ -n "$raw" ] || return 1
    printf '%s\n' "$raw" | awk '
        {
            ns = split($0, seg, "\\")
            split(seg[1], h, " ")
            idx = h[1]; sub(/:$/, "", idx)
            nm = h[2]; sub(/:$/, "", nm)
            peer = "-"
            at = index(nm, "@")
            if (at > 0) { peer = substr(nm, at + 1); nm = substr(nm, 1, at - 1) }
            mac = "-"; kind = "-"
            m = split(seg[2], d, " ")
            for (i = 1; i < m; i++) if (d[i] == "link/ether") { mac = d[i + 1]; break }
            if (ns >= 3) { split(seg[3], k, " "); if (k[1] != "") kind = k[1] }
            print nm, idx, mac, kind, peer
        }'
}
# The row of exactly one link of that name in $TABLE (fails if none or several).
row_of() {
    printf '%s\n' "$TABLE" | awk -v n="$1" '$1 == n { print; c++ } END { exit !(c == 1) }'
}
# row_is <name> <ifindex> <mac> <peer>: that one link is a veth with exactly this identity.
row_is() {
    printf '%s\n' "$TABLE" | awk -v n="$1" -v i="$2" -v m="$3" -v p="$4" \
        '$1 == n { c++; if ($2 == i && $3 == m && $4 == "veth" && $5 == p) ok = 1 } END { exit !(c == 1 && ok) }'
}
# has_link <name>: a link of that name is in $TABLE.
has_link() {
    printf '%s\n' "$TABLE" | awk -v n="$1" '$1 == n { f = 1 } END { exit !f }'
}
# A link literally named if<digits> would be taken for an ifindex by `ip`:
# refuse to address anything by ifindex while one exists.
no_ifindex_lookalike() {
    ! printf '%s\n' "$TABLE" | awk '$1 ~ /^if[0-9]+$/ { f = 1 } END { exit !f }'
}
new_mac() {
    h="$(od -An -N5 -tx1 /dev/urandom | tr -d ' \n')" || return 1
    [ "${#h}" -eq 10 ] || return 1
    printf '02:%s:%s:%s:%s:%s\n' "$(printf '%s' "$h" | cut -c1-2)" "$(printf '%s' "$h" | cut -c3-4)" \
        "$(printf '%s' "$h" | cut -c5-6)" "$(printf '%s' "$h" | cut -c7-8)" "$(printf '%s' "$h" | cut -c9-10)"
}
# Reads and validates the whole record into $RECORDS (lines "pair a ia ma b ib mb").
load_records() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    [ "$(sed -n 1p "$1")" = "$MIN_RECORD_HEADER" ] || return 1
    RECORDS="$(sed 1d "$1")"
    [ -z "$RECORDS" ] && return 0
    printf '%s\n' "$RECORDS" | awk -v pairs="$MIN_PAIRS" -v mre="$MAC_RE" '
        BEGIN { np = split(pairs, P, " "); for (i = 1; i <= np; i++) known[P[i]] = 1 }
        NF != 7 || $1 != "pair" || !(($2 ":" $5) in known) || seen[$2] ||
        $3 !~ /^[0-9]+$/ || $6 !~ /^[0-9]+$/ || $4 !~ mre || $7 !~ mre { bad = 1 }
        { seen[$2] = 1 }
        END { exit bad }'
}
# 0 = none of the four names exists; 1 = one does; 2 = cannot list the links.
check_min() {
    TABLE="$(link_table)" || { echo "check-min: cannot list the links" >&2; return 2; }
    for n in $MIN_NAMES; do
        if has_link "$n"; then
            echo "check-min: refusing: link '$n' already exists (not ours)" >&2
            return 1
        fi
    done
}
down_min() {
    rec="${1:-}"
    if [ -z "$rec" ] || ! load_records "$rec"; then
        echo "down-min: ownership record '$rec' missing or invalid: nothing deleted" >&2
        return 1
    fi
    if ! TABLE="$(link_table)" || ! no_ifindex_lookalike; then
        echo "down-min: cannot list the links unambiguously: nothing deleted" >&2
        return 1
    fi
    status=0
    while read -r kw a ia ma b ib mb; do
        [ -n "$kw" ] || continue
        in_a=0
        in_b=0
        if has_link "$a"; then in_a=1; fi
        if has_link "$b"; then in_b=1; fi
        if [ "$in_a$in_b" = 00 ]; then
            echo "down-min: $a/$b already gone"
        elif row_is "$a" "$ia" "$ma" "$b" && row_is "$b" "$ib" "$mb" "$a"; then
            if "$IP" link del dev "if$ia"; then
                echo "down-min: removed $a/$b (ifindex $ia/$ib)"
            else
                echo "down-min: removing $a/$b failed" >&2
                status=1
            fi
        else
            echo "down-min: $a/$b does not match its ownership record (a present=$in_a, b present=$in_b): left in place" >&2
            status=1
        fi
        TABLE="$(link_table)" || { echo "down-min: cannot list the links again" >&2; return 1; }
    done <<EOF
$RECORDS
EOF
    for n in $MIN_NAMES; do
        if has_link "$n"; then
            echo "down-min: link '$n' is still present: left in place" >&2
            status=1
        fi
    done
    return "$status"
}
up_min() {
    rec="${1:-}"
    [ -n "$rec" ] || { echo "up-min: ownership record path required" >&2; exit 64; }
    check_min || exit 1
    [ ! -e "$rec" ] && [ ! -L "$rec" ] || { echo "up-min: refusing: ownership record '$rec' exists" >&2; exit 1; }
    ( set -C; printf '%s\n' "$MIN_RECORD_HEADER" > "$rec" ) || { echo "up-min: cannot create the ownership record" >&2; exit 1; }
    for pair in $MIN_PAIRS; do
        a="${pair%%:*}"
        b="${pair##*:}"
        up_fail=
        ma="$(new_mac)" && mb="$(new_mac)" && [ "$ma" != "$mb" ] || up_fail="cannot make MAC addresses"
        if [ -z "$up_fail" ] && ! "$IP" link add "$a" address "$ma" type veth peer name "$b" address "$mb"; then
            up_fail="creating $a/$b failed"
        fi
        if [ -z "$up_fail" ]; then
            TABLE="$(link_table)" || up_fail="cannot list the links after creating $a/$b"
        fi
        if [ -z "$up_fail" ]; then
            ia="$(row_of "$a" | cut -d' ' -f2)"
            ib="$(row_of "$b" | cut -d' ' -f2)"
            if [ -n "$ia" ] && [ -n "$ib" ] && no_ifindex_lookalike && row_is "$a" "$ia" "$ma" "$b" && row_is "$b" "$ib" "$mb" "$a"; then
                printf 'pair %s %s %s %s %s %s\n' "$a" "$ia" "$ma" "$b" "$ib" "$mb" >> "$rec" ||
                    up_fail="cannot record $a/$b: left in place, not recorded"
            else
                up_fail="$a/$b read back with an unexpected identity: left in place, not owned"
            fi
        fi
        if [ -z "$up_fail" ]; then
            "$IP" link set dev "if$ia" up && "$IP" link set dev "if$ib" up || up_fail="cannot bring $a/$b up"
        fi
        if [ -n "$up_fail" ]; then
            echo "up-min: $up_fail; rolling back what this run owns" >&2
            if down_min "$rec"; then
                rm -f "$rec"
                exit 1
            fi
            echo "up-min: rollback left links in place (record kept: $rec)" >&2
            exit 2
        fi
    done
}

case "${1:-}" in
    # bridge <mac>: the bridge, with the lab's run-unique MAC.
    bridge) $IP link add "$BR" address "${2:?bridge MAC}" type bridge ;;
    bridge-up) $IP link set "$BR" up ;;
    # netns <ns> <pid>: name the lab's own new namespace (that of its holder
    # process <pid>) <ns>; refused if the name exists.
    netns) lab_ns "${2:-}"; $IP netns attach "$2" "${3:?pid of the namespace holder}" ;;
    # veth <ns> <handle>: vh-<ns> in the host netns, its peer eth0 inside the
    # netns the HANDLE names (the lab's own, held since its creation).
    veth) lab_ns "${2:-}"; $IP link add "vh-$2" type veth peer name eth0 netns "${3:?netns handle}" ;;
    # port <ns>: vh-<ns> into the bridge, up.
    port)
        lab_ns "${2:-}"
        $IP link set "vh-$2" master "$BR"
        $IP link set "vh-$2" up
        ;;
    # inside <ns> <handle>: address, lo and eth0 up — through the handle.
    inside)
        lab_ns "${2:-}"
        $NSENTER --net="${3:?netns handle}" -- $IP addr add "$(addr_of "$2")/24" dev eth0
        $NSENTER --net="$3" -- $IP link set lo up
        $NSENTER --net="$3" -- $IP link set eth0 up
        ;;
    check-min) check_min ;;
    up-min) up_min "${2:-}" ;;
    down-min) down_min "${2:-}" ;;
    *)
        echo "usage: $0 bridge <mac> | bridge-up | netns <ns> <pid> | veth <ns> <handle> | port <ns> | inside <ns> <handle> | check-min | up-min <record> | down-min <record>" >&2
        exit 64
        ;;
esac
