#!/usr/bin/bash
# VF-8: a fence action that never finishes and ignores SIGTERM, with a
# TERM-ignoring child that holds the captured pipes. Only SIGKILL of the
# whole process group ends it. It never touches any device.
. /usr/local/libexec/mikagami-vf/vf-common.sh
trap '' TERM
log "fence-hang start leader=$$ pgid=$(/usr/bin/ps -o pgid= -p $$ | /usr/bin/tr -d ' ') target=${MIKAGAMI_FENCE_TARGET:-} attempt=${MIKAGAMI_FENCE_ATTEMPT:-}"
echo $$ > /run/mikagami-vf/hang-leader.pid
( trap '' TERM; exec /usr/bin/sleep 600 ) &
echo $! > /run/mikagami-vf/hang-child.pid
while :; do
    /usr/bin/sleep 600 &
    wait $!
done
