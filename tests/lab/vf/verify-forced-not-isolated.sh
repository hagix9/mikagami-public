#!/usr/bin/bash
# VF-3: a verify command that reports `not-isolated` regardless of the device.
. /usr/local/libexec/mikagami-vf/vf-common.sh
log "verify-forced interface=${1:-} result=not-isolated"
echo not-isolated
