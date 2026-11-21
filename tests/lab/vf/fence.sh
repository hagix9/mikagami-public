#!/usr/bin/bash
# Virtual fence action: set the target's HOST-SIDE veth DOWN (Rev5 §34.9).
# argv[1] = host-side interface (vh-node-a | vh-node-b). Environment is the
# production allowlist (MIKAGAMI_CLUSTER, MIKAGAMI_FENCE_TARGET, ..._INCIDENT,
# ..._ATTEMPT); it is only logged here.
. /usr/local/libexec/mikagami-vf/vf-common.sh
IF="${1:-}"
require_target_interface "$IF"
log "fence interface=$IF target=${MIKAGAMI_FENCE_TARGET:-} incident=${MIKAGAMI_FENCE_INCIDENT:-} attempt=${MIKAGAMI_FENCE_ATTEMPT:-} cluster=${MIKAGAMI_CLUSTER:-} pgid=$(/usr/bin/ps -o pgid= -p $$ | /usr/bin/tr -d ' ')"
$NSENTER -t 1 -n -- $IP link set dev "$IF" down
rc=$?
log "fence-done interface=$IF rc=$rc"
exit $rc
