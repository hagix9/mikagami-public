#!/usr/bin/bash
# The VM has no arping binary. The production VIP backend executes the path
# given with --arping; this stub records its arguments and exits 0.
printf '%s %s\n' "$(/usr/bin/date +%s%3N)" "$*" >> /run/mikagami-vf/arping.log
exit 0
