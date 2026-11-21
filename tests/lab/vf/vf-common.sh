# Sourced by the fence / verify scripts. Test-only environment glue.
LOG=/run/mikagami-vf/script-events.log
IP=/usr/sbin/ip
NSENTER=/usr/bin/nsenter
log() {
    printf '%s %s\n' "$(/usr/bin/date +%s%3N)" "$*" >> "$LOG" 2>/dev/null || true
}
# Only the two virtual fencing targets may ever be touched.
require_target_interface() {
    case "${1:-}" in
        vh-node-a | vh-node-b) ;;
        *) log "refused interface=${1:-} (not an allowed virtual target)"; exit 64 ;;
    esac
    # It must be a veth in the host network namespace and must not carry the
    # default route (never the management interface).
    if ! $NSENTER -t 1 -n -- $IP -d link show dev "$1" 2>/dev/null | /usr/bin/grep -q 'veth'; then
        log "refused interface=$1 (not a veth in the host netns)"
        exit 65
    fi
    if $NSENTER -t 1 -n -- $IP route show default 2>/dev/null | /usr/bin/grep -q " dev $1 "; then
        log "refused interface=$1 (carries the default route)"
        exit 66
    fi
}
