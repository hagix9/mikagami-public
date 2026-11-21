//! Phase 1-J25 TEST-ONLY crash points of the daemon (cargo feature `j25-fault-injection`, which
//! implies `j24-fault-injection`; never a default feature, so the production build does not compile
//! this module).
//!
//! A point fires through the J24 fault file (`MIKAGAMI_J24_FAULT_FILE`, a single `<point> <count>`
//! line, consumed and logged as `J24_FAULT_FIRED` by `j24_fault_injection::fire`) and then aborts the
//! process: a crash of the promoting node at exactly that point, which systemd restarts. It forges
//! no answer, skips no check and writes nothing; with no armed fault the code runs unchanged.

/// Aborts the process if the armed fault names `point`.
pub(crate) fn crash_if(point: &str) {
    if crate::j24_fault_injection::fire(point) {
        std::process::abort();
    }
}
