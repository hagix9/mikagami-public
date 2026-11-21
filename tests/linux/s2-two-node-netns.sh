#!/bin/sh
# S2: two real daemons in two network namespaces on one disposable host (as root), one shared
# configuration (only the node-local paths differ: state, status, operator, control lock).
# A group of a command resource and the VIP. Checks: cold start elects one Active and starts
# the group there only; health failover hands the group over through a release (no fence
# device is declared, so no fence is possible); a configuration mismatch is refused and is
# not a peer loss. A sampler checks that the app never runs on both nodes at once.
# usage: s2-two-node-netns.sh BINARY EVIDENCE_DIR
set -u
BIN=$1; EV=$2
mkdir -p "$EV"; LOG="$EV/s2.log"; : > "$LOG"
fails=0; checks=0
ok() { checks=$((checks+1)); echo "ok: $*" >> "$LOG"; }
bad() { checks=$((checks+1)); fails=$((fails+1)); echo "FAIL: $*" | tee -a "$LOG"; }
check() { d=$1; shift; if "$@" >> "$LOG" 2>&1; then ok "$d"; else bad "$d"; fi; }
wait_for() { n=$1; shift; i=0; while [ $i -lt $((n*5)) ]; do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; i=$((i+1)); done; return 1; }

for p in /etc/mkgtest2 /run/mkgtest2 /usr/local/libexec/mkgtest2 /run/netns/mkgA /run/netns/mkgB; do
  [ ! -e "$p" ] || { echo "S2: $p exists; not a clean host" >&2; exit 2; }
done

ip netns add mkgA; ip netns add mkgB
ip link add mkgva type veth peer name mkgvb
ip link set mkgva netns mkgA; ip link set mkgvb netns mkgB
ip -n mkgA addr add 10.88.0.1/24 dev mkgva; ip -n mkgB addr add 10.88.0.2/24 dev mkgvb
for n in mkgA mkgB; do ip -n $n link set lo up; done
ip -n mkgA link set mkgva up; ip -n mkgB link set mkgvb up

install -d -m 0755 /usr/local/libexec/mkgtest2
for n in mkgA mkgB; do install -d -m 0700 /run/mkgtest2/$n /run/mkgtest2/$n/control; done
install -d -m 0700 /etc/mkgtest2/a /etc/mkgtest2/b
# The scripts are the same files on both nodes; the node is the network namespace.
cat > /usr/local/libexec/mkgtest2/app-start <<'EOF'
#!/bin/sh
n=$(ip netns identify $$); touch /run/mkgtest2/$n/app.running; echo "$(date +%s.%N) $n app+" >> /run/mkgtest2/events.log
EOF
cat > /usr/local/libexec/mkgtest2/app-stop <<'EOF'
#!/bin/sh
n=$(ip netns identify $$); rm -f /run/mkgtest2/$n/app.running; echo "$(date +%s.%N) $n app-" >> /run/mkgtest2/events.log
EOF
cat > /usr/local/libexec/mkgtest2/app-status <<'EOF'
#!/bin/sh
n=$(ip netns identify $$); if [ -e /run/mkgtest2/$n/app.running ]; then echo running; else echo stopped; fi
EOF
cat > /usr/local/libexec/mkgtest2/health <<'EOF'
#!/bin/sh
n=$(ip netns identify $$); [ -e /run/mkgtest2/$n/app.running ] && [ ! -e /run/mkgtest2/$n/health-fail ]
EOF
chmod 0755 /usr/local/libexec/mkgtest2/*
umask 077
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/mkgtest2/cluster.psk

# vip_interface differs per node: written in the shared file as a per-node override.
write_config() { # write_config DIR NODE-LOCAL EXTRA_HEALTH
  cat > "$1/mikagami.toml" <<EOF
[cluster]
id = "s2-test"
topology = "two-node"

[nodes.node-a]
preferred = true
[nodes.node-b]
vip_interface = "mkgvb"

[two_node]
fencing_device = "none"
state_path = "$2/state.json"
status_path = "$2/status.json"
operator_dir = "$2/operator"

[[two_node.link]]
segment = "ha"
role = "combined"
port = 17947
address = { node-a = "10.88.0.1", node-b = "10.88.0.2" }
interface = { node-a = "mkgva", node-b = "mkgvb" }

[vip]
address = "10.88.0.50/24"
interface = "mkgva"

[[group.resource]]
name = "app"
type = "command"
start = ["/usr/local/libexec/mkgtest2/app-start"]
stop = ["/usr/local/libexec/mkgtest2/app-stop"]
status = ["/usr/local/libexec/mkgtest2/app-status"]

[[group.resource]]
name = "vip"
type = "vip"

[health]
command = ["/usr/local/libexec/mkgtest2/health"]
failure_threshold = 2
success_threshold = 1
on_failure = "failover"$3

[security]
psk_file = "/etc/mkgtest2/cluster.psk"

[failover]
bootstrap_dwell_sec = 3
bootstrap_defer_sec = 3

[control]
lock_path = "$2/control/control.lock"
manual_barrier_path = "$2/control/manual-barrier.json"
EOF
  chmod 0600 "$1/mikagami.toml"
}
write_config /etc/mkgtest2/a /run/mkgtest2/mkgA ""
write_config /etc/mkgtest2/b /run/mkgtest2/mkgB ""
# The two files differ only in node-local paths (excluded from the summary).
check "configs differ only in node-local paths" sh -c "diff /etc/mkgtest2/a/mikagami.toml /etc/mkgtest2/b/mikagami.toml | grep '^[<>]' | grep -v -e state_path -e status_path -e operator_dir -e lock_path -e manual_barrier_path | grep -q . && exit 1 || exit 0"
check "register a" "$BIN" node register --config /etc/mkgtest2/a/mikagami.toml --node-id node-a
check "register b" "$BIN" node register --config /etc/mkgtest2/b/mikagami.toml --node-id node-b
check "summaries equal" sh -c "[ \"\$('$BIN' node show --config /etc/mkgtest2/a/mikagami.toml | grep summary)\" = \"\$('$BIN' node show --config /etc/mkgtest2/b/mikagami.toml | grep summary)\" ]"
check "init a" "$BIN" two-node init --config /etc/mkgtest2/a/mikagami.toml
check "init b" "$BIN" two-node init --config /etc/mkgtest2/b/mikagami.toml

start_node() { # start_node UNIT NS CONFIG
  systemd-run --unit="$1" --collect -p NetworkNamespacePath=/run/netns/$2 \
    "$BIN" daemon run --config "$3" --arping /usr/sbin/arping >> "$LOG" 2>&1
}
role_of() { "$BIN" two-node status --config "$1" --json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin)["daemon"]; print(d["role"] if d else "none")'; }
is() { [ "$(role_of "$1")" = "$2" ]; }
A=/etc/mkgtest2/a/mikagami.toml; B=/etc/mkgtest2/b/mikagami.toml

# Sampler: the app must never run on both nodes.
( while [ ! -e /run/mkgtest2/stop-sampler ]; do
    if [ -e /run/mkgtest2/mkgA/app.running ] && [ -e /run/mkgtest2/mkgB/app.running ]; then echo "$(date +%s.%N) BOTH" >> /run/mkgtest2/violations; fi
    if ip -n mkgA -o addr show | grep -q 10.88.0.50 && ip -n mkgB -o addr show | grep -q 10.88.0.50; then echo "$(date +%s.%N) VIP-BOTH" >> /run/mkgtest2/violations; fi
    sleep 0.1
  done ) &

start_node mkgtest2-a mkgA $A
start_node mkgtest2-b mkgB $B
check "cold start: node-a Active" wait_for 60 is $A active
check "cold start: node-b Standby" wait_for 10 is $B standby
check "app runs on node-a only" sh -c "[ -e /run/mkgtest2/mkgA/app.running ] && [ ! -e /run/mkgtest2/mkgB/app.running ]"
check "VIP on node-a" sh -c "ip -n mkgA -o addr show | grep -q 10.88.0.50"
sleep 4

# Health failover: node-a's health fails.
touch /run/mkgtest2/mkgA/health-fail
check "health failover: node-b Active" wait_for 60 is $B active
check "health failover: node-a Standby" wait_for 10 is $A standby
check "app moved to node-b" sh -c "[ ! -e /run/mkgtest2/mkgA/app.running ] && [ -e /run/mkgtest2/mkgB/app.running ]"
check "VIP moved to node-b" sh -c "ip -n mkgB -o addr show | grep -q 10.88.0.50 && ! ip -n mkgA -o addr show | grep -q 10.88.0.50"
check "node-a log: health failover releasing" sh -c "journalctl -u mkgtest2-a -o cat --no-pager | grep -q 'health failover: releasing'"
check "no fence anywhere" sh -c "! journalctl -u mkgtest2-a -u mkgtest2-b -o cat --no-pager | grep -q 'fencing the peer'"
check "node-b promoted on node-a's grant" sh -c "journalctl -u mkgtest2-b -o cat --no-pager | grep -q 'promoting at epoch [0-9]* (granted by node-a)'"
sleep 5

# Configuration mismatch: node-a restarts with another file (a different health threshold).
systemctl stop mkgtest2-a
write_config /etc/mkgtest2/a /run/mkgtest2/mkgA "
timeout_sec = 3"
start_node mkgtest2-a2 mkgA $A
check "mismatch seen on node-b" wait_for 30 sh -c "'$BIN' two-node status --config $B | grep -q 'config mismatch'"
check "mismatch seen on node-a" wait_for 30 sh -c "'$BIN' two-node status --config $A | grep -q 'config mismatch'"
sleep 15
check "node-b stays Active during the mismatch" is $B active
check "node-a stays Standby during the mismatch" is $A standby
check "node-b log names the differing section" sh -c "journalctl -u mkgtest2-b -o cat --no-pager | grep -q 'config mismatch.*(health)'"

touch /run/mkgtest2/stop-sampler; sleep 0.3
check "never both running, never VIP on both" test ! -s /run/mkgtest2/violations
journalctl -u mkgtest2-a -o cat --no-pager > "$EV/s2-a.journal" 2>&1 || :
journalctl -u mkgtest2-a2 -o cat --no-pager > "$EV/s2-a2.journal" 2>&1 || :
journalctl -u mkgtest2-b -o cat --no-pager > "$EV/s2-b.journal" 2>&1 || :
cp /run/mkgtest2/events.log "$EV/s2-events.log" 2>/dev/null || :

systemctl stop mkgtest2-a2 mkgtest2-b 2>/dev/null
systemctl reset-failed mkgtest2-a mkgtest2-a2 mkgtest2-b 2>/dev/null || :
ip netns del mkgA; ip netns del mkgB
rm -rf /run/mkgtest2 /etc/mkgtest2 /usr/local/libexec/mkgtest2
echo "S2: $checks checks, $fails failures" | tee -a "$LOG"
[ "$fails" -eq 0 ]
