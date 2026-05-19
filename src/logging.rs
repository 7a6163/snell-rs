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
