#!/usr/bin/bash
# Phase 14.12 Stage 13.6 closeout lab (test-only; run as root on the lab VM).
#   closeout-lab.sh up   <evidence-dir-unused>
#   closeout-lab.sh down <evidence-dir>
#
# Creates ONLY what the Stage 13.5/13.6 closeouts need, plus the virtual
# fencing target:
#   * veth pair mkm0 <-> mkm0p       (the closeout's VIP interface)
#   * veth pair vh-node-b <-> vp-node-b (the virtual fencing target; no
#     address, no bridge, no route)
#   * /run/systemd/system/mikagami-closeout.service (Type=simple, sleep
#     infinity; loaded + inactive until the daemon starts it)
#   * /usr/local/libexec/mikagami-vf/{fence,verify,...}.sh (root:root 0755)
#   * /run/mikagami-vf (script-event log directory)
# It never touches the management interface, routes, firewall or sshd. It
# refuses to run over existing objects of the same names.
#
# OBS-CLOSEOUT-DOWN-MIN (link ownership): `up` refuses if ANY of vh-node-b,
# vp-node-b, mkm0, mkm0p exists, creates each veth pair create-only with
# run-unique MACs, reads the identity back and records it in
# $RUNTIME/min-owned (see vf-topology.sh). `down` deletes a pair only through
# that record after re-checking its identity, and refuses everything (no link,
# file or directory is removed) when the record is missing. A `down` whose link
# cleanup fails keeps $RUNTIME and $LIBEXEC (the record) so it can be retried,
# and exits non-zero. A failing `up` undoes only what it created itself.
#
# Phase 14.12 MC-1: `up` records a read-only management-network snapshot
# before anything is created and `down` records another after teardown and
# compares the two with mgmt-net-compare.sh (only the remaining seconds of a
# finite DHCP lease are volatile). The check is fail-closed: a snapshot that
# cannot be taken, a missing snapshot file, a changed management network or a
# comparison that itself fails makes `down` exit non-zero (the teardown still
# runs to completion first). Exit 0 of the comparison is not enough: a part
# passes only if the comparison printed exactly one of its two verdict lines
# on stdout and nothing on stderr (an unknown, empty, padded or failing text is
# a FAIL; one unknown part of five fails the whole check). The two steps are also available on their own:
#   closeout-lab.sh mgmt-before-capture <runtime-dir>
#   closeout-lab.sh mgmt-after-check    <runtime-dir> <evidence-dir>
# Only the self-test (closeout-lab-mgmt-selftest.sh) sets MKM_MGMT_TEST_MODE=1
# to substitute `ip` and the comparison script; without it neither override
# is read.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
LIBEXEC=/usr/local/libexec/mikagami-vf
RUNTIME=/run/mikagami-vf
UNIT=/run/systemd/system/mikagami-closeout.service
MARK=$RUNTIME/created-libexec-parent
REC=$RUNTIME/min-owned
MGMT_IP=/usr/sbin/ip
MGMT_COMPARE="$HERE/mgmt-net-compare.sh"
if [ "${MKM_MGMT_TEST_MODE:-}" = 1 ]; then
    MGMT_IP="${MKM_IP:-$MGMT_IP}"
    MGMT_COMPARE="${MKM_MGMT_COMPARE:-$MGMT_COMPARE}"
fi
MGMT_PARTS="addr route4 route6 rule link"

# Read-only capture of the management network into <dir>/<part>.txt. Every
# `ip` invocation must succeed; `addr` and `link` can never legitimately be
# empty (a host always has `lo`), so an empty one means a broken capture.
mgmt_capture() {
    dir="$1"
    mkdir -p "$dir" || return 1
    "$MGMT_IP" -o addr show > "$dir/addr.txt" || return 1
    "$MGMT_IP" -4 route show > "$dir/route4.txt" || return 1
    "$MGMT_IP" -6 route show > "$dir/route6.txt" || return 1
    "$MGMT_IP" rule show > "$dir/rule.txt" || return 1
    "$MGMT_IP" -o link show > "$dir/link.txt" || return 1
    [ -s "$dir/addr.txt" ] && [ -s "$dir/link.txt" ] || {
        echo "mgmt-net: empty addr/link capture in $dir" >&2
        return 1
    }
}

# The two stdout lines mgmt-net-compare.sh prints on exit 0 (its output
# contract; the Rust lab, daemon_run.rs mgmt_net, accepts exactly the same two).
MGMT_VERDICT_IDENTICAL="mgmt-net-compare: IDENTICAL"
MGMT_VERDICT_STABLE="mgmt-net-compare: STABLE-IDENTICAL (only finite lease seconds differ)"

# Compare every part of two captures with mgmt-net-compare.sh. Every part is
# judged (no early exit hides a later change). Returns 0 only if every part
# is stable. A part passes only if the comparison exited 0, printed EXACTLY
# one of the two verdict lines above on stdout and nothing on stderr: a
# missing file, an unrunnable or failing comparison (any exit status other
# than 0 or 1), a reported change and an exit 0 with an unknown, empty,
# padded or failing text are all failures.
mgmt_compare() {
    before="$1"
    after="$2"
    status=0
    jdir="$(mktemp -d "${TMPDIR:-/tmp}/mgmt-net-judge.XXXXXX")" || {
        echo "mgmt-net: FAIL cannot create a scratch directory for the comparison"
        return 1
    }
    printf '%s\n' "$MGMT_VERDICT_IDENTICAL" > "$jdir/want-identical" &&
        printf '%s\n' "$MGMT_VERDICT_STABLE" > "$jdir/want-stable" || {
        echo "mgmt-net: FAIL cannot write the expected verdicts"
        rm -rf "$jdir"
        return 1
    }
    for part in $MGMT_PARTS; do
        if [ ! -f "$before/$part.txt" ] || [ ! -f "$after/$part.txt" ]; then
            echo "mgmt-net: $part: FAIL snapshot missing (before=$before after=$after)"
            status=1
            continue
        fi
        rc=0
        sh "$MGMT_COMPARE" "$before/$part.txt" "$after/$part.txt" > "$jdir/out" 2> "$jdir/err" || rc=$?
        cat "$jdir/out" "$jdir/err" 2>/dev/null
        case "$rc" in
            0)
                if [ ! -s "$jdir/err" ] && {
                    diff -q "$jdir/out" "$jdir/want-identical" >/dev/null 2>&1 ||
                        diff -q "$jdir/out" "$jdir/want-stable" >/dev/null 2>&1
                }; then
                    echo "mgmt-net: $part: PASS"
                else
                    echo "mgmt-net: $part: FAIL comparison exited 0 without exactly one known verdict line"
                    status=1
                fi
                ;;
            1) echo "mgmt-net: $part: FAIL management network changed"; status=1 ;;
            *) echo "mgmt-net: $part: FAIL comparison error (exit $rc)"; status=1 ;;
        esac
    done
    rm -rf "$jdir"
    return "$status"
}

# `up` side: snapshot taken before the lab creates anything.
mgmt_before_capture() {
    mgmt_capture "$1/mgmt-before"
}

# `down` side: snapshot after teardown, compare with the `up` snapshot, keep
# both as evidence. Returns non-zero on any failure.
mgmt_after_check() {
    runtime="$1"
    evid="$2"
    status=0
    mkdir -p "$evid" || return 1
    mgmt_capture "$runtime/mgmt-after" || { echo "mgmt-net: after-snapshot FAILED"; status=1; }
    if [ "$status" -eq 0 ]; then
        mgmt_compare "$runtime/mgmt-before" "$runtime/mgmt-after" || status=1
    fi
    for d in mgmt-before mgmt-after; do
        [ ! -d "$runtime/$d" ] || cp -R "$runtime/$d" "$evid/$d" || status=1
    done
    return "$status"
}

case "${1:-}" in
up)
    for p in "$RUNTIME" "$LIBEXEC" "$UNIT"; do
        [ ! -e "$p" ] || { echo "refusing: $p exists" >&2; exit 1; }
    done
    # Every link name the lab will create, checked before anything is created.
    /usr/bin/bash "$HERE/vf-topology.sh" check-min || {
        echo "refusing: a link the closeout lab would create exists or the links cannot be listed" >&2
        exit 1
    }
    umask 022
    mkdir -m 0755 "$RUNTIME"
    UP_OK=no
    UP_KEEP=no
    MADE_LIBEXEC=no
    MADE_UNIT=no
    LINKS_MADE=no
    # A failing `up` undoes only what this run created (the links through the
    # record, which up-min's own rollback already used); anything left in place
    # keeps $RUNTIME so that `down` and the operator can see it.
    up_cleanup() {
        [ "$UP_OK" = no ] || return 0
        trap - EXIT
        if [ "$MADE_UNIT" = yes ]; then rm -f "$UNIT"; fi
        if [ "$LINKS_MADE" = yes ]; then
            /usr/bin/bash "$HERE/vf-topology.sh" down-min "$REC" || UP_KEEP=yes
        fi
        if [ "$MADE_LIBEXEC" = yes ]; then rm -rf "$LIBEXEC"; fi
        if [ "$UP_KEEP" = yes ]; then
            echo "closeout lab up FAILED: links left in place, $RUNTIME kept (run down)" >&2
        else
            CREATED_PARENT=no
            [ ! -f "$MARK" ] || CREATED_PARENT=yes
            rm -rf "$RUNTIME"
            if [ "$CREATED_PARENT" = yes ]; then rmdir /usr/local/libexec 2>/dev/null || true; fi
            echo "closeout lab up FAILED: undone" >&2
        fi
        exit 1
    }
    trap up_cleanup EXIT
    # Nothing else exists yet: if the snapshot cannot be taken, undo and stop.
    mgmt_before_capture "$RUNTIME" || {
        echo "refusing: management-network snapshot failed" >&2
        exit 1
    }
    if [ ! -d /usr/local/libexec ]; then
        mkdir -m 0755 /usr/local/libexec
        : > "$MARK"
    fi
    mkdir -m 0755 "$LIBEXEC"
    MADE_LIBEXEC=yes
    for f in vf-common.sh fence.sh verify.sh verify-forced-not-isolated.sh fence-hang.sh arping-stub.sh; do
        install -m 0755 -o root -g root "$HERE/$f" "$LIBEXEC/$f"
    done
    UP_RC=0
    /usr/bin/bash "$HERE/vf-topology.sh" up-min "$REC" || UP_RC=$?
    if [ "$UP_RC" -ne 0 ]; then
        # 2 = the rollback left something in place; anything else = nothing of ours is left
        if [ "$UP_RC" -eq 2 ]; then UP_KEEP=yes; fi
        exit 1
    fi
    LINKS_MADE=yes
    MADE_UNIT=yes
    printf '[Unit]\nDescription=Mikagami closeout placeholder service\n\n[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\n' > "$UNIT"
    /usr/bin/systemctl daemon-reload
    UP_OK=yes
    trap - EXIT
    echo "closeout lab up"
    ;;
down)
    EVID="${2:?evidence dir}"
    # No ownership record: nothing proves that anything here is ours.
    if [ ! -f "$REC" ]; then
        echo "refusing: no ownership record $REC; nothing was deleted" >&2
        exit 1
    fi
    mkdir -p "$EVID"
    [ ! -f "$RUNTIME/script-events.log" ] || cp "$RUNTIME/script-events.log" "$EVID/closeout-script-events.log"
    /usr/bin/systemctl stop mikagami-closeout.service 2>/dev/null || true
    LINK_STATUS=0
    /usr/bin/bash "$HERE/vf-topology.sh" down-min "$REC" || LINK_STATUS=1
    rm -f "$UNIT"
    /usr/bin/systemctl daemon-reload
    MGMT_STATUS=0
    mgmt_after_check "$RUNTIME" "$EVID" > "$EVID/mgmt-net-check.txt" 2>&1 || MGMT_STATUS=1
    cat "$EVID/mgmt-net-check.txt"
    cp "$REC" "$EVID/min-owned.txt" || LINK_STATUS=1
    if [ "$LINK_STATUS" -eq 0 ]; then
        CREATED_PARENT=no
        [ ! -f "$MARK" ] || CREATED_PARENT=yes
        rm -rf "$LIBEXEC" "$RUNTIME"
        if [ "$CREATED_PARENT" = yes ]; then rmdir /usr/local/libexec 2>/dev/null || true; fi
    fi
    if [ "$LINK_STATUS" -ne 0 ]; then
        echo "closeout lab down: LINK CLEANUP INCOMPLETE; nothing foreign was deleted, $RUNTIME and $LIBEXEC kept (record $EVID/min-owned.txt)" >&2
    fi
    if [ "$MGMT_STATUS" -ne 0 ]; then
        echo "closeout lab down: MANAGEMENT-NETWORK CHECK FAILED (see $EVID/mgmt-net-check.txt)" >&2
    fi
    if [ "$LINK_STATUS" -ne 0 ] || [ "$MGMT_STATUS" -ne 0 ]; then
        exit 1
    fi
    echo "closeout lab down"
    ;;
mgmt-before-capture)
    mgmt_before_capture "${2:?runtime dir}"
    ;;
mgmt-after-check)
    mgmt_after_check "${2:?runtime dir}" "${3:?evidence dir}"
    ;;
*)
    echo "usage: $0 up|down [evidence-dir]" >&2
    exit 64
    ;;
esac
