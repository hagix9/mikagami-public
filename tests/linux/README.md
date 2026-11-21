# Linux acceptance scripts (disposable host, as root)

Not run by `cargo test`. Each script refuses to start on a host that has its fixtures, creates
them, checks, and removes them. Run them only on a throw-away VM, never on a cluster node.

| script | what it checks |
|---|---|
| `s1-group-real.sh BINARY EVIDENCE_DIR` | One node (peer absent, operator-attested takeover): a group of a real systemd unit, a command resource and the VIP on a veth; start order, `[health] on_failure = "restart"` (stop in reverse, VIP kept, start in order), release in reverse at `systemctl stop` |
| `s2-two-node-netns.sh BINARY EVIDENCE_DIR` | Two daemons in two network namespaces with one shared configuration: cold start elects one Active, `on_failure = "failover"` hands the group over through a confirmed release and the peer's grant (no fence), a configuration mismatch is refused without a takeover; a sampler checks the app and the VIP are never on both nodes |
