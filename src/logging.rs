//! Structured logging setup.
//!
//! Initialises `tracing_subscriber` reading `RUST_LOG` for the env filter
//! (default `info`) and `LOG_FORMAT` for the output format (`json` for
//! line-delimited JSON; anything else → human-readable text).
//!
//! Call once from `main()` before any spawn/log call. Calling it twice in the
//! same process is a no-op past the first invocation (the subscriber is
//! installed as the global default).

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

/// Install the global tracing subscriber. See module docs for env vars.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let format = std::env::var("LOG_FORMAT").unwrap_or_default();
    if format.eq_ignore_ascii_case("json") {
        // Setting the global default fails if one is already installed (e.g.
        // by a previous call within the same process). That's a no-op we
        // intentionally swallow rather than panic — keeps tests that may
        // spawn library code re-entrant.
        let _ = fmt()
            .with_env_filter(filter)
            .with_target(false)
            .json()
            .try_init();
    } else {
        let _ = fmt().with_env_filter(filter).with_target(false).try_init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // Both branches of init() run their full body — `try_init` returns Err
    // silently when a global subscriber is already installed, which is the
    // expected steady state after the first test in this module runs.
    //
    // Tests are serialized because they mutate the LOG_FORMAT env var, which
    // is process-global and would race with parallel test execution.

    #[test]
    #[serial]
    fn init_text_branch_does_not_panic() {
        // SAFETY: `#[serial]` ensures no other test is reading/writing env
        // vars concurrently; remove_var has no other ordering hazard in tests.
        unsafe {
            std::env::remove_var("LOG_FORMAT");
        }
        init();
    }

    #[test]
    #[serial]
    fn init_json_branch_does_not_panic() {
        // SAFETY: same as above — serialized, single-writer.
        unsafe {
            std::env::set_var("LOG_FORMAT", "json");
        }
        init();
        unsafe {
            std::env::remove_var("LOG_FORMAT");
        }
    }

    #[test]
    #[serial]
    fn init_envfilter_default_when_rust_log_unset() {
        // Exercises the `unwrap_or_else(|_| EnvFilter::new("info"))` path.
        // SAFETY: serialized; tests aren't reading RUST_LOG concurrently.
        unsafe {
            std::env::remove_var("RUST_LOG");
            std::env::remove_var("LOG_FORMAT");
        }
        init();
    }
}
