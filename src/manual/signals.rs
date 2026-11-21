//! Signals during a command that changes something (audit E-01).
//!
//! A controller killed half-way through a move leaves the lease in a
//! mutating phase (fail-closed, but the operator learns nothing and a
//! verified rollback never runs). So, while a changing command runs,
//! SIGINT / SIGTERM / SIGHUP are **held**: the handler only records them and
//! the command runs to its end (every call it makes has a deadline). A second
//! signal means the operator insists: the process says so and ends at once
//! with the UNKNOWN exit code; the record stays as it is and `status` /
//! `reconcile` take over.
//!
//! Read-only commands keep the default behaviour.

use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

static FIRST: AtomicI32 = AtomicI32::new(0);
static COUNT: AtomicU32 = AtomicU32::new(0);

const HELD: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

extern "C" fn on_signal(signal: libc::c_int) {
    let _ = FIRST.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
    if COUNT.fetch_add(1, Ordering::SeqCst) >= 1 {
        const MESSAGE: &[u8] = b"mkg: second signal - abandoning the command now. The result is UNKNOWN: run `resource status vip` (and `resource reconcile vip` if a move was in progress).\n";
        // SAFETY: write(2) and _exit(2) are async-signal-safe; the buffer is
        // a static byte string.
        unsafe {
            libc::write(2, MESSAGE.as_ptr().cast(), MESSAGE.len());
            libc::_exit(i32::from(super::EXIT_UNKNOWN));
        }
    }
}

/// Start holding the signals for the rest of the command.
pub(crate) fn hold() {
    FIRST.store(0, Ordering::SeqCst);
    COUNT.store(0, Ordering::SeqCst);
    for signal in HELD {
        // SAFETY: installing a handler that only touches atomics and the
        // async-signal-safe calls above.
        unsafe {
            libc::signal(signal, on_signal as *const () as libc::sighandler_t);
        }
    }
}

/// Restore the default behaviour (tests; a command never needs to).
#[cfg(test)]
pub(crate) fn release() {
    for signal in HELD {
        // SAFETY: restoring the default disposition.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
        }
    }
}

/// The first signal that arrived while held, if any.
pub(crate) fn received() -> Option<i32> {
    match FIRST.load(Ordering::SeqCst) {
        0 => None,
        signal => Some(signal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_signal_is_recorded_and_does_not_end_the_process() {
        hold();
        assert_eq!(received(), None);
        // SAFETY: raising a signal that is handled above.
        unsafe {
            libc::raise(libc::SIGHUP);
        }
        assert_eq!(received(), Some(libc::SIGHUP));
        release();
        FIRST.store(0, Ordering::SeqCst);
        COUNT.store(0, Ordering::SeqCst);
    }

    /// Runs only as the child of the next test (the environment variable is
    /// set there): two signals in a row must end the process with 4.
    #[test]
    fn child_receives_two_signals() {
        if std::env::var_os("MKG_SIGNAL_TEST_CHILD").is_none() {
            return;
        }
        hold();
        // SAFETY: raising signals that are handled above.
        unsafe {
            libc::raise(libc::SIGINT);
        }
        eprintln!("first signal survived");
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        eprintln!("NOT REACHED");
    }

    #[test]
    fn a_second_signal_abandons_the_command_with_the_unknown_exit_code() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "manual::signals::tests::child_receives_two_signals",
                "--nocapture",
            ])
            .env("MKG_SIGNAL_TEST_CHILD", "1")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(i32::from(crate::manual::EXIT_UNKNOWN)),
            "{stderr}"
        );
        assert!(stderr.contains("first signal survived"), "{stderr}");
        assert!(stderr.contains("second signal"), "{stderr}");
        assert!(!stderr.contains("NOT REACHED"), "{stderr}");
    }
}
