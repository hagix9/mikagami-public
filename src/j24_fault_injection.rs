//! Phase 1-J24 TEST-ONLY fault injection (cargo feature `j24-fault-injection`).
//!
//! The feature is never a default feature: the production build
//! (`cargo build --release --locked --bin mikagami`) does not compile this module, and no command,
//! configuration key or protocol message reaches it. A feature build arms a fault only through the
//! environment variable `MIKAGAMI_J24_FAULT_FILE`, which names a file whose single line is
//! `<point> <count>`. Each firing at `<point>` decrements the count, rewrites the file and prints
//! `J24_FAULT_FIRED point=<point> remaining=<count>` on stderr, so the position and the number of
//! firings are part of the daemon's journal. A missing variable, a missing or unreadable file, a
//! malformed line, another point or a count of zero fire nothing: the code then runs unchanged.
//! The fault only makes an existing durable write report an I/O failure before it touches the
//! store; it never forges a Witness answer and does not bypass any protocol check.

use std::fs;

const ENV: &str = "MIKAGAMI_J24_FAULT_FILE";

/// Whether the armed fault fires at `point` now (and consumes one firing).
pub(crate) fn fire(point: &str) -> bool {
    let Some(path) = std::env::var_os(ENV) else {
        return false;
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return false;
    };
    let mut words = text.split_whitespace();
    let (Some(armed), Some(count), None) = (words.next(), words.next(), words.next()) else {
        return false;
    };
    let Ok(count) = count.parse::<u64>() else {
        return false;
    };
    if armed != point || count == 0 {
        return false;
    }
    let remaining = count - 1;
    if fs::write(&path, format!("{point} {remaining}\n")).is_err() {
        // A fault whose consumption cannot be recorded does not fire.
        return false;
    }
    eprintln!("J24_FAULT_FIRED point={point} remaining={remaining}");
    true
}

#[cfg(test)]
mod tests {
    use super::fire;
    use std::fs;

    #[test]
    fn j24_fault_fires_only_for_its_point_and_count() {
        let file = std::env::temp_dir().join(format!(
            "mikagami-j24-fault-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // SAFETY: this is the only test that sets the variable. It arms only its own point, which no
        // production code names, so a concurrent test reaching `arm-release-obligation` in a
        // feature build is never affected.
        unsafe { std::env::set_var(super::ENV, &file) };
        assert!(!fire("j24-unit-test-point"), "a missing file fires nothing");
        fs::write(&file, "j24-unit-test-point 2\n").unwrap();
        assert!(!fire("another-point"));
        assert!(fire("j24-unit-test-point"));
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "j24-unit-test-point 1\n"
        );
        assert!(fire("j24-unit-test-point"));
        assert!(
            !fire("j24-unit-test-point"),
            "a count of zero fires nothing"
        );
        fs::write(&file, "j24-unit-test-point x\n").unwrap();
        assert!(
            !fire("j24-unit-test-point"),
            "a malformed count fires nothing"
        );
        unsafe { std::env::remove_var(super::ENV) };
        let _ = fs::remove_file(file);
    }
}
