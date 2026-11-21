#!/bin/sh
# Phase 14.12 MC-1: management-network before/after comparison (test-only).
#
#   mgmt-net-compare.sh <before-file> <after-file>
#
# Each file is the text of `ip -o addr show <if>` and/or `ip route show ...`
# captured before / after a lab run. The comparison replaces the raw `cmp`
# that reported a DHCP lease renewal as a management-network change.
#
# Compared exactly (any difference is a change): interface name, address
# family, address and prefix, scope and flags (e.g. `dynamic`), metric,
# routes (destination, gateway, device, proto, src, metric), and every
# address / route line that appears or disappears.
#
# Excluded as time-dependent, and ONLY these: the remaining seconds of a
# finite DHCP lease — `valid_lft <N>sec`, `preferred_lft <N>sec` and a route's
# `expires <N>sec` with N >= 1. `forever` and `0sec` are NOT normalised: a
# lease that became static, or one that expired, is a real difference.
#
# Order of lines is not significant (`ip` ordering is not a contract);
# duplicates are.
#
# Fail-closed: the comparison never reads a normalisation that failed as an
# empty-but-equal result. Every stage (sed, sed, sort) writes its own file and
# its exit status is checked (POSIX sh: no `pipefail`, no pipeline whose
# earlier stages would go unnoticed); the sorted result must hold exactly the
# number of non-blank lines of the input; diff and cmp are judged on their own
# exit status (0 / 1 are answers, anything else is an error). Any stage that
# cannot be completed is exit 2 with the reason on stderr.
#
# Output contract (the shell driver and the Rust lab both enforce it):
#   exit 0  stdout is EXACTLY one line, one of
#             mgmt-net-compare: IDENTICAL
#             mgmt-net-compare: STABLE-IDENTICAL (only finite lease seconds differ)
#           and stderr is empty
#   exit 1  stdout starts with `mgmt-net-compare: CHANGED` and the diff
#   exit 2  usage, unreadable input, or a normalisation / comparison failure
#           (reason on stderr)
set -u
if [ "$#" -ne 2 ]; then
    echo "usage: $0 <before-file> <after-file>" >&2
    exit 2
fi
BEFORE="$1"
AFTER="$2"
for f in "$BEFORE" "$AFTER"; do
    if [ ! -r "$f" ]; then
        echo "mgmt-net-compare: cannot read $f" >&2
        exit 2
    fi
done
# normalise <input> <output>: sed, sed, sort as separate checked steps.
normalise() {
    in="$1"
    out="$2"
    sed -E \
        -e 's/(valid_lft|preferred_lft|expires) [1-9][0-9]*sec/\1 <volatile>sec/g' \
        -e 's/[[:space:]]+$//' "$in" > "$out.1" || {
        echo "mgmt-net-compare: normalisation failed (sed, volatile seconds / trailing blanks) on $in" >&2
        return 1
    }
    LC_ALL=C sed -e '/^$/d' "$out.1" > "$out.2" || {
        echo "mgmt-net-compare: normalisation failed (sed, blank lines) on $in" >&2
        return 1
    }
    LC_ALL=C sort "$out.2" > "$out" || {
        echo "mgmt-net-compare: normalisation failed (sort) on $in" >&2
        return 1
    }
    # grep exits 1 for "no non-blank line" (a legitimate count of 0); 2+ is an error.
    want="$(grep -c '[^[:space:]]' "$in")"
    case $? in 0 | 1) ;; *)
        echo "mgmt-net-compare: normalisation check failed (grep) on $in" >&2
        return 1
        ;;
    esac
    got="$(LC_ALL=C sed -n '$=' "$out")" || {
        echo "mgmt-net-compare: normalisation check failed (sed count) on $in" >&2
        return 1
    }
    got="${got:-0}"
    if [ "$want" != "$got" ]; then
        echo "mgmt-net-compare: normalisation lost lines on $in (input has $want non-blank lines, result has $got)" >&2
        return 1
    fi
    return 0
}
# The scratch directory is checked like every other stage: a mktemp that fails
# (even silently) or prints no usable directory is exit 2 with our own reason.
if ! TMP="$(mktemp -d "${TMPDIR:-/tmp}/mgmt-net-compare.XXXXXX")"; then
    echo "mgmt-net-compare: cannot create a private scratch directory (mktemp failed under ${TMPDIR:-/tmp})" >&2
    exit 2
fi
if [ -z "$TMP" ] || [ ! -d "$TMP" ]; then
    echo "mgmt-net-compare: cannot create a private scratch directory (mktemp printed no usable directory: '$TMP')" >&2
    exit 2
fi
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
normalise "$BEFORE" "$TMP/before" || exit 2
normalise "$AFTER" "$TMP/after" || exit 2
diff -u "$TMP/before" "$TMP/after" > "$TMP/diff"
case $? in
    0)
        cmp -s "$BEFORE" "$AFTER"
        case $? in
            0) echo "mgmt-net-compare: IDENTICAL" || exit 2 ;;
            1) echo "mgmt-net-compare: STABLE-IDENTICAL (only finite lease seconds differ)" || exit 2 ;;
            *)
                echo "mgmt-net-compare: cannot compare the raw inputs (cmp failed)" >&2
                exit 2
                ;;
        esac
        exit 0
        ;;
    1)
        echo "mgmt-net-compare: CHANGED" || exit 2
        cat "$TMP/diff" || exit 2
        exit 1
        ;;
    *)
        echo "mgmt-net-compare: cannot compare the normalised inputs (diff failed)" >&2
        exit 2
        ;;
esac
