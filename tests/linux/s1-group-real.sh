#!/bin/sh
# S1: one real node (the peer is absent; manual takeover on the operator's attestation).
# A group of a real systemd unit, a command resource and the VIP on a veth; the health check
# and on_failure = "restart"; the release order at stop. Disposable host only, as root.
# usage: s1-group-real.sh BINARY EVIDENCE_DIR
set -u
BIN=$1; EV=$2
mkdir -p "$EV"; LOG="$EV/s1.log"; : > "$LOG"
fails=0; checks=0
ok() { checks=$((checks+1)); echo "ok: $*" >> "$LOG"; }
bad() { checks=$((checks+1)); fails=$((fails+1)); echo "FAIL: $*" | tee -a "$LOG"; }
check() { d=$1; shift; if "$@" >> "$LOG" 2>&1; then ok "$d"; else bad "$d"; fi; }
wait_for() { n=$1; shift; i=0; while [ $i -lt $((n*5)) ]; do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; i=$((i+1)); done; return 1; }

for p in /etc/mkgtest /run/mkgtest /usr/local/libexec/mkgtest /etc/systemd/system/mkgtest-db.service; do
  [ ! -e "$p" ] || { echo "S1: $p exists; not a clean host" >&2; exit 2; }
done
ip link show mkgt0 >/dev/null 2>&1 && { echo "S1: mkgt0 exists" >&2; exit 2; }

# --- fixtures -------------------------------------------------------------------------
ip link add mkgt0 type veth peer name mkgt1
ip addr add 198.51.100.1/24 dev mkgt0
ip link set mkgt0 up; ip link set mkgt1 up
install -d -m 0755 /usr/local/libexec/mkgtest
install -d -m 0700 /run/mkgtest /run/mkgtest/control /etc/mkgtest
cat > /usr/local/libexec/mkgtest/app-start <<'EOF'
#!/bin/sh
echo app+ >> /run/mkgtest/order.log
rm -f /run/mkgtest/health-fail
touch /run/mkgtest/app.running
EOF
cat > /usr/local/libexec/mkgtest/app-stop <<'EOF'
#!/bin/sh
echo app- >> /run/mkgtest/order.log
rm -f /run/mkgtest/app.running
EOF
cat > /usr/local/libexec/mkgtest/app-status <<'EOF'
#!/bin/sh
if [ -e /run/mkgtest/app.running ]; then echo running; else echo stopped; fi
EOF
cat > /usr/local/libexec/mkgtest/health <<'EOF'
#!/bin/sh
[ -e /run/mkgtest/app.running ] && [ ! -e /run/mkgtest/health-fail ] && systemctl is-active --quiet mkgtest-db.service
EOF
chmod 0755 /usr/local/libexec/mkgtest/*
cat > /etc/systemd/system/mkgtest-db.service <<'EOF'
[Unit]
Description=Mikagami S1 test database stand-in
[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
ExecStartPost=/bin/sh -c 'echo db+ >> /run/mkgtest/order.log'
ExecStopPost=/bin/sh -c 'echo db- >> /run/mkgtest/order.log'
EOF
systemctl daemon-reload
umask 077
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/mkgtest/cluster.psk
cat > /etc/mkgtest/mikagami.toml <<'EOF'
[cluster]
id = "s1-test"
topology = "two-node"

[nodes.node-a]
preferred = true
[nodes.node-b]

[two_node]
fencing_device = "none"
state_path = "/run/mkgtest/state.json"
status_path = "/run/mkgtest/status.json"
operator_dir = "/run/mkgtest/operator"

[[two_node.link]]
segment = "ha"
role = "ha"
port = 17946
address = { node-a = "127.0.0.1", node-b = "127.0.0.2" }
interface = { node-a = "lo", node-b = "lo" }

[vip]
address = "198.51.100.50/24"
interface = "mkgt0"

[[group.resource]]
name = "db"
type = "systemd"
unit = "mkgtest-db.service"

[[group.resource]]
name = "app"
type = "command"
start = ["/usr/local/libexec/mkgtest/app-start"]
stop = ["/usr/local/libexec/mkgtest/app-stop"]
status = ["/usr/local/libexec/mkgtest/app-status"]

[[group.resource]]
name = "vip"
type = "vip"

[health]
command = ["/usr/local/libexec/mkgtest/health"]
failure_threshold = 2
success_threshold = 1
on_failure = "restart"

[security]
psk_file = "/etc/mkgtest/cluster.psk"

[failover]
auto = false

[control]
lock_path = "/run/mkgtest/control/control.lock"
manual_barrier_path = "/run/mkgtest/control/manual-barrier.json"
EOF
chmod 0600 /etc/mkgtest/mikagami.toml
CFG=/etc/mkgtest/mikagami.toml
role() { "$BIN" two-node status --config "$CFG" --json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin)["daemon"]; print(d["role"] if d else "none")'; }
is_role() { [ "$(role)" = "$1" ]; }
vip_present() { ip -o addr show dev mkgt0 | grep -q ' 198.51.100.50/24'; }

check "unregistered refused" sh -c "! '$BIN' two-node status --config $CFG"
check "register node-a" "$BIN" node register --config $CFG --node-id node-a
check "init" "$BIN" two-node init --config $CFG
systemd-run --unit=mkgtest-daemon --collect "$BIN" daemon run --config $CFG --arping /usr/sbin/arping >> "$LOG" 2>&1
check "daemon starts Standby" wait_for 20 is_role standby
check "nothing started before a takeover" sh -c "[ ! -e /run/mkgtest/order.log ] || ! grep -q '+' /run/mkgtest/order.log"
check "VIP absent on Standby" sh -c "! ip -o addr show dev mkgt0 | grep -q 198.51.100.50"
check "takeover request" "$BIN" two-node takeover --config $CFG --attest-peer-stopped node-b
systemctl kill --kill-whom=main -s USR1 mkgtest-daemon
check "Active after the attested takeover" wait_for 30 is_role active
check "VIP present on Active" vip_present
check "start order db, app" sh -c "[ \"\$(grep '+' /run/mkgtest/order.log | tr '\n' ' ')\" = 'db+ app+ ' ]"
check "db unit active" systemctl is-active --quiet mkgtest-db.service
"$BIN" two-node status --config $CFG >> "$LOG" 2>&1
check "status shows the resources" sh -c "'$BIN' two-node status --config $CFG | grep -q 'resources (as last observed, start order): db=running app=running vip=present'"
check "status shows health healthy" wait_for 10 sh -c "'$BIN' two-node status --config $CFG | grep -q 'health (Active only): healthy'"

# --- health restart ------------------------------------------------------------------
: > /run/mkgtest/order.log
touch /run/mkgtest/health-fail
check "restart happened" wait_for 30 sh -c "grep -q 'app+' /run/mkgtest/order.log"
sleep 3
check "restart order app-, db-, db+, app+" sh -c "[ \"\$(tr '\n' ' ' < /run/mkgtest/order.log)\" = 'app- db- db+ app+ ' ]"
check "still Active after the restart" is_role active
check "VIP kept during the restart" vip_present
check "status: last action restarted" sh -c "'$BIN' two-node status --config $CFG | grep -q 'last action restarted'"

# --- stop: reverse release -----------------------------------------------------------------
: > /run/mkgtest/order.log
systemctl stop mkgtest-daemon
check "stop order app-, db-" sh -c "[ \"\$(tr '\n' ' ' < /run/mkgtest/order.log)\" = 'app- db- ' ]"
check "VIP removed at stop" sh -c "! ip -o addr show dev mkgt0 | grep -q 198.51.100.50"
check "db unit stopped" sh -c "! systemctl is-active --quiet mkgtest-db.service"
check "app stopped" test ! -e /run/mkgtest/app.running
journalctl -u mkgtest-daemon -o cat --no-pager > "$EV/s1-daemon.journal" 2>&1 || :
cp /run/mkgtest/state.json "$EV/s1-state.json" 2>/dev/null || :

# --- cleanup of the fixtures -----------------------------------------------------------------
systemctl reset-failed mkgtest-daemon 2>/dev/null || :
rm -f /etc/systemd/system/mkgtest-db.service; systemctl daemon-reload
ip link del mkgt0
rm -rf /run/mkgtest /etc/mkgtest /usr/local/libexec/mkgtest
echo "S1: $checks checks, $fails failures" | tee -a "$LOG"
[ "$fails" -eq 0 ]
