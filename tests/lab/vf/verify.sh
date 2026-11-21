#!/usr/bin/bash
# Virtual verify: read the HOST-SIDE veth administrative state
# (Rev5 §34.9): `isolated` iff DOWN, `not-isolated` iff UP, otherwise no output.
. /usr/local/libexec/mikagami-vf/vf-common.sh
IF="${1:-}"
require_target_interface "$IF"
line="$($NSENTER -t 1 -n -- $IP -o link show dev "$IF" 2>/dev/null)" || { log "verify interface=$IF unreadable"; exit 3; }
flags="$(printf '%s\n' "$line" | /usr/bin/sed -n 's/^[0-9]*: [^<]*<\([^>]*\)>.*/\1/p')"
if [ -z "$flags" ]; then
    log "verify interface=$IF no-flags"
    exit 3
fi
case ",$flags," in
    *,UP,*) log "verify interface=$IF result=not-isolated flags=$flags"; echo not-isolated ;;
    *) log "verify interface=$IF result=isolated flags=$flags"; echo isolated ;;
esac
