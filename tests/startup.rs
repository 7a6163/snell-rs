//! Configuration the binaries must refuse at startup.
//!
//! `cipher::validate_psk` is unit-tested; these pin the *wiring* -- that both
//! binaries actually call it before doing anything else. The client is why this
//! file exists: it had no length check at all until 6.3.0, so an out-of-range
//! key surfaced as an authentication failure on the first connection rather
//! than as a startup error.

mod common;

use common::*;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Run a binary to completion and return its stderr, asserting it refused to
/// start. A binary that accepts the PSK runs forever, so the timeout failing is
/// itself the diagnosis.
async fn refusal_reason(bin: &str, psk: String, args: &[&str], env: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env("PSK", psk)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("an out-of-range PSK must be fatal, not start a listener")
        .expect("spawn");
    assert!(!out.status.success(), "expected a non-zero exit");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[tokio::test]
#[serial_test::serial]
async fn server_refuses_a_psk_outside_the_documented_range() {
    let addr = format!("127.0.0.1:{}", random_tcp_port());
    let bin = env!("CARGO_BIN_EXE_snell-server");

    let e = refusal_reason(bin, "x".repeat(15), &[&addr], &[]).await;
    assert!(e.contains("at least 16"), "unhelpful refusal: {e}");
    // The floor is stricter than official, so the message has to say so.
    assert!(
        e.contains("Official"),
        "refusal must name official's 12: {e}"
    );

    let e = refusal_reason(bin, "x".repeat(256), &[&addr], &[]).await;
    assert!(e.contains("at most 255"), "unhelpful refusal: {e}");
}

#[tokio::test]
#[serial_test::serial]
async fn client_refuses_a_psk_outside_the_documented_range() {
    let listen = format!("127.0.0.1:{}", random_tcp_port());
    let bin = env!("CARGO_BIN_EXE_snell-client");
    let env = [("LISTEN", listen.as_str())];

    let e = refusal_reason(bin, "x".repeat(15), &[], &env).await;
    assert!(e.contains("at least 16"), "unhelpful refusal: {e}");

    let e = refusal_reason(bin, "x".repeat(256), &[], &env).await;
    assert!(e.contains("at most 255"), "unhelpful refusal: {e}");
}
