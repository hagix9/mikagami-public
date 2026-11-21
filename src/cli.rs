use crate::manual::cli_def::{ChronydCommands, ResourceCommands};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::path::PathBuf;

/// Parse the command line. `mkg` and `mikagami` are the same program: the
/// invoked name only changes how usage text spells the program.
pub fn parse_invoked() -> Cli {
    let invoked = std::env::args_os()
        .next()
        .and_then(|arg| {
            std::path::Path::new(&arg)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let name: &'static str = if invoked == "mkg" { "mkg" } else { "mikagami" };
    let matches = Cli::command().name(name).bin_name(name).get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

#[derive(Debug, Parser)]
#[command(
    name = "mikagami",
    version,
    about = "A lightweight Linux HA service manager"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Commands {
    /// Print a one-shot read-only status report and exit.
    ///
    /// The report is built from the configuration file and persisted node
    /// state only. It never contacts the peer or the Witness, never inspects
    /// a running daemon's memory, and never mutates state.
    ///
    /// Only with `--control-config` is the report followed by a read-only
    /// manual control-plane overview (neither `MKG_CONFIG` nor a file at the
    /// default location enables it). That part contacts the cloud API and the
    /// node agents; the HA part does not.
    Status {
        /// Configuration file path (defaults to /etc/mikagami/mikagami.toml).
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Manual control-plane configuration (adds the cluster overview).
        #[arg(long = "control-config", value_name = "PATH")]
        control_config: Option<PathBuf>,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Daemon lifecycle commands.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommands,
    },
    /// Witness server commands (run on the Witness host only).
    Witness {
        #[command(subcommand)]
        command: WitnessCommands,
    },
    /// Manual control plane: list, inspect and hand over the managed resources.
    Resource {
        #[command(subcommand)]
        command: ResourceCommands,
    },
    /// chronyd configuration and service management on one node.
    Chronyd {
        #[command(subcommand)]
        command: ChronydCommands,
    },
    /// Node agent of the manual control plane (started over SSH; reads one
    /// JSON request from standard input).
    #[command(hide = true)]
    Agent {
        /// Agent configuration file (defaults to /etc/mikagami/agent.toml).
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Node identity of a shared two-node configuration (`[nodes.<id>]`).
    Node {
        #[command(subcommand)]
        command: NodeCommands,
    },
    /// Two-node (witness-less) topology commands (`cluster.topology = "two-node"`).
    #[command(name = "two-node")]
    TwoNode {
        #[command(subcommand)]
        command: TwoNodeCommands,
    },
    /// Attest that the peer is isolated for one fencing incident. Records
    /// one intent file for the daemon to ingest; request activation with
    /// SIGUSR1 afterwards.
    Recover {
        #[arg(value_name = "SERVICE")]
        service: String,
        #[arg(long = "confirm-fenced", value_name = "NODE")]
        confirm_fenced: String,
        #[arg(long, value_name = "SEQ")]
        incident: u64,
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum NodeCommands {
    /// Record once which node of the shared configuration this host is. Written next to
    /// the configuration file as `node-id` (mode 0600). Never guessed from the host name.
    Register {
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        #[arg(long = "node-id", value_name = "ID")]
        node_id: String,
        /// Change an existing registration (refused while a two-node record exists).
        #[arg(long)]
        replace: bool,
    },
    /// Print the registered node id, the peer and the configuration summary (read-only).
    Show {
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum TwoNodeCommands {
    /// Create the durable ownership record once. Refuses when a valid record exists, so
    /// its knowledge is never silently reset.
    Init {
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        /// Move a corrupt record aside (never deleted) and create a fresh one.
        #[arg(long)]
        replace_corrupt: bool,
    },
    /// Print the durable record and the daemon's last status file (read-only).
    Status {
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Record an operator takeover request for the running daemon; send SIGUSR1 to it
    /// afterwards. Refused by the daemon while the peer is connected.
    Takeover {
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        /// Attest that the peer node's OS is stopped (manual failover on the operator's
        /// responsibility; confirm it at the power, hypervisor or cloud control plane).
        #[arg(
            long = "attest-peer-stopped",
            value_name = "NODE",
            conflicts_with = "fence"
        )]
        attest_peer_stopped: Option<String>,
        /// Ask the daemon to fence the peer and promote only after verify confirms the stop
        /// (needs an independent fence device).
        #[arg(long, value_name = "NODE")]
        fence: Option<String>,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum WitnessCommands {
    /// Create the Witness state once. Refuses to run if a state already
    /// exists, so the term can never be silently reset to 0.
    Init {
        /// Witness configuration file path.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
    /// Serve the Witness in the foreground until SIGTERM or SIGINT.
    ///
    /// Starts only on an existing, consistent state. After a host reboot an
    /// active lease is re-armed automatically unless `on_reboot = "refuse"`
    /// or the state is older than `rearm_max_downtime_sec`.
    Run {
        /// Witness configuration file path.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
    /// Re-arm the state after a host reboot when `witness run` refused to.
    ///
    /// Only run this after confirming the state was NOT restored from a
    /// backup: a restored state cannot be detected.
    Rearm {
        /// Witness configuration file path.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum DaemonCommands {
    /// Run the Mikagami daemon in the foreground.
    ///
    /// The process loads its configuration, constructs the production Linux
    /// runtime, attaches the production Witness session, passes the recovery
    /// gate, then drives non-overlapping observation ticks until shutdown.
    /// Promotion happens only on an operator's SIGUSR1 or through the
    /// automatic trigger (`[failover] auto`); both enter the same single
    /// attempt path, which re-evaluates every safety gate each time.
    Run {
        /// Configuration file path.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        /// Absolute path to the arping binary used by the VIP backend.
        #[arg(long, value_name = "PATH")]
        arping: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::path::Path;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// The shipped unit files start the real subcommands with real flags.
    #[test]
    fn shipped_systemd_units_use_valid_commands() {
        for (text, expected) in [
            (
                include_str!("../contrib/systemd/mikagami.service"),
                "daemon",
            ),
            (
                include_str!("../contrib/systemd/mikagami-witness.service"),
                "witness",
            ),
        ] {
            let exec = text
                .lines()
                .find_map(|line| line.strip_prefix("ExecStart="))
                .expect("ExecStart");
            let mut args = exec.split_whitespace();
            let binary = args.next().unwrap();
            assert!(binary.ends_with("/mikagami"), "{binary}");
            let cli = Cli::try_parse_from(std::iter::once("mikagami").chain(args))
                .expect("ExecStart arguments parse");
            match (expected, cli.command) {
                (
                    "daemon",
                    Some(Commands::Daemon {
                        command: DaemonCommands::Run { config, arping },
                    }),
                ) => {
                    assert_eq!(config, PathBuf::from("/etc/mikagami/mikagami.toml"));
                    assert!(arping.is_absolute());
                }
                (
                    "witness",
                    Some(Commands::Witness {
                        command: WitnessCommands::Run { config },
                    }),
                ) => {
                    assert_eq!(config, PathBuf::from("/etc/mikagami/witness.toml"));
                }
                (_, other) => panic!("{expected}: {other:?}"),
            }
            assert!(text.contains("Restart=always"));
        }
    }

    /// Stage 14 §18.1: `recover <service> --confirm-fenced <node> --incident
    /// <seq> [--config <path>]`.
    #[test]
    fn stage14_8_parses_recover() {
        let cli = Cli::try_parse_from([
            "mikagami",
            "recover",
            "nginx.service",
            "--confirm-fenced",
            "node-b",
            "--incident",
            "7",
            "--config",
            "/etc/mikagami/mikagami.toml",
        ])
        .expect("recover should parse");
        assert_eq!(
            cli.command,
            Some(Commands::Recover {
                service: "nginx.service".into(),
                confirm_fenced: "node-b".into(),
                incident: 7,
                config: Some(PathBuf::from("/etc/mikagami/mikagami.toml")),
            })
        );
    }

    /// §18.1: `--confirm-fenced` and `--incident` are mandatory; the
    /// sequence is a non-negative integer.
    #[test]
    fn stage14_8_recover_requires_node_and_incident() {
        for args in [
            vec!["mikagami", "recover", "nginx.service", "--incident", "7"],
            vec![
                "mikagami",
                "recover",
                "nginx.service",
                "--confirm-fenced",
                "node-b",
            ],
            vec![
                "mikagami",
                "recover",
                "--confirm-fenced",
                "node-b",
                "--incident",
                "7",
            ],
            vec![
                "mikagami",
                "recover",
                "nginx.service",
                "--confirm-fenced",
                "node-b",
                "--incident",
                "seven",
            ],
            vec![
                "mikagami",
                "recover",
                "nginx.service",
                "--confirm-fenced",
                "node-b",
                "--incident",
                "-1",
            ],
        ] {
            assert!(Cli::try_parse_from(args.clone()).is_err(), "{args:?}");
        }
    }

    #[test]
    fn parses_status() {
        let cli = Cli::try_parse_from(["mikagami", "status"]).expect("status should parse");

        assert_eq!(
            cli.command,
            Some(Commands::Status {
                config: None,
                control_config: None,
                json: false,
            })
        );
    }

    #[test]
    fn parses_status_with_config() {
        let cli = Cli::try_parse_from(["mikagami", "status", "--config", "/tmp/mikagami.toml"])
            .expect("status --config should parse");

        assert_eq!(
            cli.command,
            Some(Commands::Status {
                config: Some(PathBuf::from("/tmp/mikagami.toml")),
                control_config: None,
                json: false,
            })
        );
    }

    #[test]
    fn parses_daemon_run() {
        let cli = Cli::try_parse_from([
            "mikagami",
            "daemon",
            "run",
            "--config",
            "/etc/mikagami/mikagami.toml",
            "--arping",
            "/usr/sbin/arping",
        ])
        .expect("daemon run should parse");

        assert_eq!(
            cli.command,
            Some(Commands::Daemon {
                command: DaemonCommands::Run {
                    config: PathBuf::from("/etc/mikagami/mikagami.toml"),
                    arping: PathBuf::from("/usr/sbin/arping"),
                }
            })
        );
    }

    #[test]
    fn daemon_run_requires_config_and_arping() {
        assert!(
            Cli::try_parse_from(["mikagami", "daemon", "run"]).is_err(),
            "daemon run without required flags must not parse"
        );
        assert!(
            Cli::try_parse_from(["mikagami", "daemon", "run", "--config", "/tmp/c.toml"]).is_err(),
            "daemon run without --arping must not parse"
        );
    }

    /// MKM-13.4-11: a raw PSK value is never accepted as a CLI argument.
    /// There is no flag that could carry it.
    #[test]
    fn no_cli_argument_accepts_a_raw_psk() {
        for args in [
            vec![
                "mikagami",
                "daemon",
                "run",
                "--config",
                "/tmp/c.toml",
                "--arping",
                "/usr/sbin/arping",
                "--psk",
                "abc123",
            ],
            vec![
                "mikagami",
                "daemon",
                "run",
                "--config",
                "/tmp/c.toml",
                "--arping",
                "/usr/sbin/arping",
                "--psk-file",
                "abc123",
            ],
            vec!["mikagami", "status", "--psk", "abc123"],
            vec!["mikagami", "daemon", "psk", "abc123"],
        ] {
            assert!(
                Cli::try_parse_from(args.clone()).is_err(),
                "command line must not accept secret-bearing arguments: {args:?}"
            );
        }
    }

    #[test]
    fn no_promote_or_failover_subcommand_exists() {
        for args in [
            vec!["mikagami", "promote"],
            vec!["mikagami", "daemon", "promote"],
            vec!["mikagami", "daemon", "failover"],
        ] {
            assert!(
                Cli::try_parse_from(args.clone()).is_err(),
                "Stage 13.4 must not expose: {args:?}"
            );
        }
    }

    #[test]
    fn parses_without_subcommand() {
        let cli = Cli::try_parse_from(["mikagami"]).expect("empty command should parse");

        assert_eq!(cli.command, None);
    }

    #[test]
    fn exposes_version() {
        let command = Cli::command();
        let version = command.get_version().expect("version should be configured");

        assert_eq!(version, env!("CARGO_PKG_VERSION"));
        assert_eq!(version, "0.8.0");
    }

    #[test]
    fn config_flag_takes_a_path_not_a_secret() {
        // --config accepts a filesystem path; it cannot smuggle secret bytes.
        let cli = Cli::try_parse_from(["mikagami", "status", "--config", "/x"])
            .expect("status --config should parse");
        let Some(Commands::Status {
            config: Some(path), ..
        }) = cli.command
        else {
            panic!("expected Status with config");
        };
        assert_eq!(path, Path::new("/x"));
    }
}
