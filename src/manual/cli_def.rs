//! Command-line definitions of the manual control plane.

use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Flags shared by every control-plane command.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct Common {
    /// Control configuration file (default: $MKG_CONFIG, then
    /// /etc/mikagami/prototype.toml).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Machine-readable JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ResourceName {
    Vip,
    Chronyd,
    Demo,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum MovableResource {
    Vip,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ServiceResource {
    Chronyd,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum ResourceCommands {
    /// List the managed resources: configuration facts and live observation.
    List {
        #[command(flatten)]
        common: Common,
    },
    /// Show one resource. Exit 0 only when the observed state is consistent.
    Status {
        #[arg(value_enum)]
        resource: ResourceName,
        /// Limit a per-node resource (chronyd) to one node.
        #[arg(long, value_name = "NODE")]
        node: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Hand the VIP (and its service) over to the other node, by hand.
    ///
    /// The source is quiesced and the alias released and verified before the
    /// target receives it. An unreachable source is accepted only when the
    /// cloud itself reports it TERMINATED; `--confirm-fenced NODE` names the
    /// node the operator attests to, it does not replace that proof.
    Move {
        #[arg(value_enum)]
        resource: MovableResource,
        #[arg(long, value_name = "NODE")]
        to: String,
        #[arg(long = "confirm-fenced", value_name = "NODE")]
        confirm_fenced: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Record the current, observed VIP owner once (creates the ownership record).
    ///
    /// The observed owner must run the service, answer on the VIP and the
    /// other node must be quiet. `--reinit` re-creates a record whose file is
    /// gone although the store was initialised before.
    Init {
        #[arg(value_enum)]
        resource: MovableResource,
        #[arg(long, value_name = "NODE")]
        owner: String,
        /// Re-create a lost ownership record (sequence and epoch start above
        /// what the nodes have already seen).
        #[arg(long)]
        reinit: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Adopt the verified observed state after an interrupted operation.
    ///
    /// An operation that already changed something is cut only when you name
    /// it with `--abandon-op` (the id is shown by `status`) after its
    /// controller has been silent for 15 minutes. Open cloud operations
    /// block the reconcile.
    Reconcile {
        #[arg(value_enum)]
        resource: MovableResource,
        /// The id of the interrupted operation you declare dead.
        #[arg(long = "abandon-op", value_name = "OP_ID")]
        abandon_op: Option<String>,
        /// Go on although a cloud change recorded by the interrupted
        /// operation is not confirmed by any finished cloud operation (it may
        /// still land). Say this only after you have looked at both
        /// instances and the cloud's operation list yourself.
        #[arg(long = "accept-unconfirmed-cloud-change")]
        accept_unconfirmed_cloud_change: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Start a service resource on one node.
    Start {
        #[arg(value_enum)]
        resource: ServiceResource,
        #[arg(long, value_name = "NODE")]
        node: String,
        #[command(flatten)]
        common: Common,
    },
    /// Stop a service resource on one node.
    Stop {
        #[arg(value_enum)]
        resource: ServiceResource,
        #[arg(long, value_name = "NODE")]
        node: String,
        #[command(flatten)]
        common: Common,
    },
    /// Restart a service resource on one node.
    Restart {
        #[arg(value_enum)]
        resource: ServiceResource,
        #[arg(long, value_name = "NODE")]
        node: String,
        #[command(flatten)]
        common: Common,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum ChronydCommands {
    /// Show the live chrony state of a node (read-only).
    Show {
        #[arg(long, value_name = "NODE")]
        node: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Check a candidate configuration with the node's own chronyd (read-only).
    Validate {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, value_name = "NODE")]
        node: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Show the difference between the live configuration and a candidate.
    Diff {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, value_name = "NODE")]
        node: String,
        #[command(flatten)]
        common: Common,
    },
    /// Validate, back up, publish atomically, restart and verify; roll back on failure.
    Apply {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, value_name = "NODE")]
        node: String,
        /// Validate and show the difference only.
        #[arg(long)]
        dry_run: bool,
        #[command(flatten)]
        common: Common,
    },
}
