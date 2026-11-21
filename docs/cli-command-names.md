# CLI command names

- The executable is `mikagami`; `mkg` is the same program (the RPM installs `/usr/bin/mkg` as a
  relative link to `mikagami`). It is an installed link, not a shell alias.
- `mkg` and `mikagami` accept identical arguments, return the same exit codes and apply the same
  authorization and safety checks; only the program name in the usage text differs. This is
  tested on the built binary (`tests/cli_contract.rs`, `tests/rpm_packaging.rs`).
- Commands: `status`, `daemon run`, `witness init|run|rearm`, `recover`, `two-node
  init|status|takeover`, `node register|show`, and the manual control plane (`resource list`,
  `resource status <vip|chronyd|demo>`, `resource move vip --to NODE [--confirm-fenced NODE]`,
  `resource init|reconcile vip`, `resource start|stop|restart chronyd --node NODE`,
  `chronyd show|validate|diff|apply`).
- There is no `promote` or `failover` command: promotion always goes through the daemon's gates.
  The manual control plane refuses to act on a host while the HA daemon is active.
- Exit codes of the manual control plane: 0 success, 1 failed, 2 usage, 3 safety refusal,
  4 UNKNOWN.
