pub mod attestation;
pub(crate) mod auto_failover;
pub(crate) mod bootstrap_admission;
mod cli;
pub mod config;
pub mod connection_manager;
pub(crate) mod control_lock;
pub(crate) mod daemon;
pub(crate) mod daemon_peer_runtime;
pub(crate) mod daemon_run;
pub mod demotion_runtime;
pub mod evidence_fusion;
pub mod failover_policy;
pub mod failure_assessment;
pub mod fencing;
pub mod fencing_backend;
pub mod framing;
pub(crate) mod gce_fencing;
pub mod handshake;
pub(crate) mod health_hysteresis;
pub mod heartbeat;
pub mod heartbeat_runtime;
#[cfg(target_os = "linux")]
pub(crate) mod linux_node_runtime;
pub mod listener;
pub mod liveness;
// Phase 1-J24 TEST-ONLY fault injection; compiled only with the `j24-fault-injection` feature.
#[cfg(feature = "j24-fault-injection")]
pub(crate) mod j24_fault_injection;
// Phase 1-J25 TEST-ONLY crash points; compiled only with the `j25-fault-injection` feature.
#[cfg(feature = "j25-fault-injection")]
pub(crate) mod j25_fault_injection;
// Phase 1-J24 (N-6): the Witness side of the C-F generation fence, tested against the unchanged Witness.
#[cfg(all(test, target_os = "linux"))]
mod j24_witness_fence_contract_tests;
// Phase 1-J24 (J24-E): the fencing failure matrix against the existing Stage 14 incident model.
#[cfg(test)]
mod j24_fencing_matrix_tests;
// Phase 1-J25 candidate: the GCE fencing backend decision core. The daemon never calls it; the
// helper binary `mikagami-gce-fence` (feature `j25-gce-fence`) includes it, and here it is compiled
// for the J25 tests only.
#[cfg(test)]
pub(crate) mod gce_fence_backend;
// Phase 1-J25 (J25-B/C/D): GCE fencing backend and gate hand-off tests (test-only).
#[cfg(test)]
mod j25_gce_fence_tests;
// v0.7 G-2: the helper's route decisions (route-check / route-observe / route-assign).
#[cfg(test)]
mod g2_route_helper_tests;
// Phase 1-J27 (OD-J26-6): the fencing gate with refreshed local-loss evidence (test-only).
#[cfg(test)]
mod j27_freshness_gate_tests;
// Phase 1-J28 (H-1): the automatic trigger's facts of real durable incidents (test-only, Linux).
#[cfg(all(test, target_os = "linux"))]
mod j28_incident_facts_tests;
pub(crate) mod manual;
pub(crate) mod manual_barrier;
pub(crate) mod node_lease_authority;
pub mod node_mutation;
pub(crate) mod obligation_reconciliation;
pub(crate) mod operator_log;
pub mod peer_dispatch;
pub(crate) mod peer_observer;
pub mod peer_runtime;
pub(crate) mod promotion_attempt;
pub mod promotion_authorization;
pub mod promotion_runtime;
pub mod protocol;
pub mod receive;
pub(crate) mod recover;
pub mod recovery;
pub(crate) mod resource_executor;
pub(crate) mod resource_workflow;
// v0.7 G-2 route handoff (G2_SAFETY_CONTRACT.md R4.1).
pub(crate) mod route_handoff;
pub mod security;
pub mod session;
pub(crate) mod session_runtime;
pub mod state_machine;
pub mod state_runtime;
pub(crate) mod status;
pub mod tcp;
pub(crate) mod tcp_runtime;
pub mod transport;
pub mod two_node;
pub mod witness_authority;
pub mod witness_journal;
pub mod witness_runtime;
pub mod witness_scheduler;
pub(crate) mod witness_server;
pub mod witness_state;

use cli::{Commands, DaemonCommands, WitnessCommands};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = cli::parse_invoked();

    match cli.command {
        Some(Commands::Status {
            config,
            control_config,
            json,
        }) => status::run_with(config, control_config, json),
        Some(Commands::Resource { command }) => manual::run::resource(command),
        Some(Commands::Chronyd { command }) => manual::run::chronyd(command),
        Some(Commands::Agent { config }) => manual::run::agent(config),
        Some(Commands::Daemon {
            command: DaemonCommands::Run { config, arping },
        }) => two_node::cli::run_daemon(&config, &arping),
        Some(Commands::TwoNode { command }) => two_node::cli::run(command),
        Some(Commands::Node { command }) => two_node::cli::run_node(command),
        Some(Commands::Witness { command }) => match command {
            WitnessCommands::Init { config } => witness_server::run_init(&config),
            WitnessCommands::Run { config } => witness_server::run_witness(&config),
            WitnessCommands::Rearm { config } => witness_server::run_rearm(&config),
        },
        Some(Commands::Recover {
            service,
            confirm_fenced,
            incident,
            config,
        }) => recover::run(recover::RecoverRequest {
            service,
            node: confirm_fenced,
            incident,
            config,
        }),
        None => ExitCode::SUCCESS,
    }
}
