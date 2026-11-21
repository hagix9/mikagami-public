//! Two-node (witness-less) HA topology. See `TWO_NODE_ARCHITECTURE.md` and
//! `TWO_NODE_SAFETY_MODEL.md`.
//!
//! Layering:
//! * `config` — the `[two_node]` section, validation and the static policy.
//! * `store` — the durable ownership record (epoch, owner, grant, fence history).
//! * `controller` — the pure decision core (no clock, no I/O): every promotion gate.
//! * `wire` — the authenticated two-node peer messages (separate from the frozen
//!   Protocol v1, which this topology does not use or change).
//! * `runtime` — the I/O driver (links, fence commands, resources, operator requests).
//! * `shared` — the shared configuration file (`[nodes.<id>]`) and the node identity file.
//!
//! The Witness topology does not use any of this module.

pub(crate) mod cli;
pub mod config;
pub mod controller;
pub(crate) mod runtime;
pub mod shared;
pub mod store;
pub mod wire;

#[cfg(test)]
mod sim;
