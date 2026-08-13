//! End-to-end tests for the v6 `MODE` env: SOCKS5 client → snell-rs server →
//! echo target, with matching `MODE` set on both binaries. Covers all three
//! modes (default / unshaped / unsafe-raw) plus a client/server mode mismatch.

mod common;

use common::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let mut out = Vec::with_capacity(5 + n);
                    out.extend_from_slice(b"ECHO:");
                    out.extend_from_slice(&buf[..n]);
                    if s.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn socks5_connect(socks_port: u16, host: &str, target_port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet_resp = [0u8; 2];
    s.read_exact(&mut greet_resp).await.unwrap();
    assert_eq!(greet_resp, [0x05, 0x00], "SOCKS5 greeting failed");

    let host_bytes = host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut req_resp = [0u8; 10];
    s.read_exact(&mut req_resp).await.unwrap();
    assert_eq!(req_resp[0], 0x05);
    assert_eq!(req_resp[1], 0x00, "SOCKS5 connect rejected");
    s
}

/// The echo target prepends `ECHO:` to each read it services.
fn recv_contains(recv: &[u8], needle: &[u8]) -> bool {
    recv.starts_with(b"ECHO:") && recv.windows(needle.len()).any(|w| w == needle)
}

/// Round-trip a payload through a proxy pair running the given `MODE`.
async fn roundtrip_in_mode(mode: &str) {
    let echo_port = spawn_echo().await;
    let server_port = random_tcp_port();
    let socks_port = random_tcp_port();

    let _server = spawn_server_with_envs(server_port, false, &[("MODE", mode)]);
    wait_tcp(server_port).await;
    let _client = spawn_client_with_envs(server_port, socks_port, &[("MODE", mode)]);
    wait_tcp(socks_port).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = format!("hello-{mode}-roundtrip");
    stream.write_all(payload.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 128];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read failed");
    let recv = &buf[..n];
    assert!(
        recv.starts_with(b"ECHO:"),
        "[{mode}] no ECHO: prefix: {recv:?}"
    );
    assert!(
        recv.windows(payload.len()).any(|w| w == payload.as_bytes()),
        "[{mode}] payload not echoed back"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mode_default_shaped_roundtrip() {
    roundtrip_in_mode("default").await;
}

#[tokio::test]
#[serial_test::serial]
async fn mode_unshaped_roundtrip() {
    roundtrip_in_mode("unshaped").await;
}

#[tokio::test]
#[serial_test::serial]
async fn mode_unsafe_raw_roundtrip() {
    roundtrip_in_mode("unsafe-raw").await;
}

#[tokio::test]
#[serial_test::serial]
async fn mode_larger_payload_default_roundtrip() {
    // Exercise multi-record framing (payload > one write) under the shaped mode.
    let echo_port = spawn_echo().await;
    let server_port = random_tcp_port();
    let socks_port = random_tcp_port();

    let _server = spawn_server_with_envs(server_port, false, &[("MODE", "default")]);
    wait_tcp(server_port).await;
    let _client = spawn_client_with_envs(server_port, socks_port, &[("MODE", "default")]);
    wait_tcp(socks_port).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = vec![b'z'; 20_000];
    stream.write_all(&payload).await.unwrap();

    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut buf = vec![0u8; 8192];
    while got.len() < payload.len() {
        let n = timeout(
            deadline - tokio::time::Instant::now(),
            stream.read(&mut buf),
        )
        .await
        .expect("read timeout")
        .expect("read failed");
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    // The echo target prepends "ECHO:" per read, so the exact length varies with
    // how the payload was split; assert every payload byte made the round trip.
    assert!(got.starts_with(b"ECHO:"), "no ECHO: prefix");
    let z_count = got.iter().filter(|&&b| b == b'z').count();
    assert_eq!(z_count, payload.len(), "not all payload bytes echoed back");
}

/// A client that drops the TCP connection instead of sending the authenticated
/// zero record is routine (aborted requests, reachability probes, a killed app).
/// The shaped reader is mid-record-structure when that EOF lands, so this pins
/// that the listener keeps accepting afterwards.
#[tokio::test]
#[serial_test::serial]
async fn abrupt_disconnect_leaves_the_server_healthy() {
    let echo_port = spawn_echo().await;
    let server_port = random_tcp_port();
    let socks_port = random_tcp_port();

    let _server = spawn_server_with_envs(server_port, false, &[("MODE", "default")]);
    wait_tcp(server_port).await;
    let _client = spawn_client_with_envs(server_port, socks_port, &[("MODE", "default")]);
    wait_tcp(socks_port).await;

    // A bare connect-and-close, before any handshake byte is sent.
    drop(
        TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap(),
    );

    // A partial first frame, then gone.
    {
        let mut s = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        s.write_all(&[0x41; 40]).await.unwrap();
    }

    // A real session torn down mid-stream without a zero record.
    {
        let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
        stream.write_all(b"then-vanish").await.unwrap();
        let mut buf = vec![0u8; 128];
        let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read failed");
        assert!(recv_contains(&buf[..n], b"then-vanish"));
    }

    // The server must still serve a fresh connection normally.
    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    stream.write_all(b"still-alive").await.unwrap();
    let mut buf = vec![0u8; 128];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("server stopped responding after an abrupt disconnect")
        .expect("read failed");
    assert!(
        recv_contains(&buf[..n], b"still-alive"),
        "server did not recover from an abrupt disconnect"
    );
}

/// The classification itself, asserted against the server's own log output.
///
/// A silent probe must not be reported, but a `MODE` mismatch must be — and both
/// arrive as an EOF or reset from a `read_exact`, so anything that keys off the
/// io error kind alone silences the mismatch along with the probe. That is a real
/// regression this repo shipped once; only a test at this level catches it,
/// because the unit tests cannot see which phase the call site was in.
#[tokio::test]
#[serial_test::serial]
async fn a_mode_mismatch_is_reported_but_a_silent_probe_is_not() {
    let server_port = random_tcp_port();
    let socks_port = random_tcp_port();
    // `debug` so the benign classification is visible as a positive assertion
    // rather than only as the absence of an ERROR, which an empty capture would
    // satisfy for free.
    let (_server, mut logs) =
        spawn_server_capturing_logs(server_port, &[("MODE", "default"), ("RUST_LOG", "debug")]);
    wait_tcp(server_port).await;

    // Silent probes: connect, say nothing, close.
    for _ in 0..3 {
        drop(
            TcpStream::connect(("127.0.0.1", server_port))
                .await
                .unwrap(),
        );
    }
    let quiet = drain_logs(&mut logs, Duration::from_millis(600)).await;
    assert!(
        quiet.contains("connection closed early"),
        "a silent probe should be recorded as a benign close, got:\n{quiet}"
    );
    assert!(
        !quiet.contains("ERROR"),
        "a silent probe must not be reported as a failure, got:\n{quiet}"
    );

    // A peer that spoke and then stopped short is the sharp case: it fails with
    // the very same `UnexpectedEof` as the silent probe, so only a phase-aware
    // classification can keep it loud. Matching on the io error kind buried it.
    {
        let mut s = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        s.write_all(&[0x41; 40]).await.unwrap();
        s.flush().await.unwrap();
    }
    let truncated = drain_logs(&mut logs, Duration::from_millis(600)).await;
    assert!(
        truncated.contains("ERROR"),
        "a truncated handshake must be reported, got:\n{truncated}"
    );

    // Same PSK, wrong MODE: the operator must be told, and told to suspect MODE.
    let echo_port = spawn_echo().await;
    let _client = spawn_client_with_envs(server_port, socks_port, &[("MODE", "unshaped")]);
    wait_tcp(socks_port).await;
    let mut s = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    // The v5 client pipelines its salt and first sealed chunk. Send enough that
    // the shaped server's PSK-sized first-frame read is certainly satisfied, so
    // the mismatch fails the AEAD promptly instead of idling to the 10 s
    // handshake timeout. Both are reported; only this way is the test quick.
    let _ = s.write_all(&vec![b'x'; 8192]).await;
    let mut sink = [0u8; 64];
    let _ = timeout(Duration::from_secs(3), s.read(&mut sink)).await;

    let loud = drain_logs(&mut logs, Duration::from_millis(900)).await;
    assert!(
        loud.contains("ERROR"),
        "a MODE mismatch must be reported at ERROR, got:\n{loud}"
    );
    assert!(
        loud.contains("MODE"),
        "the report must name MODE as a suspect, got:\n{loud}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mode_mismatch_fails_to_tunnel() {
    // Server in `default` (shaped) can't parse a client speaking `unsafe-raw`,
    // so the SOCKS5 CONNECT must not yield a working echo tunnel.
    let echo_port = spawn_echo().await;
    let server_port = random_tcp_port();
    let socks_port = random_tcp_port();

    let _server = spawn_server_with_envs(server_port, false, &[("MODE", "default")]);
    wait_tcp(server_port).await;
    let _client = spawn_client_with_envs(server_port, socks_port, &[("MODE", "unsafe-raw")]);
    wait_tcp(socks_port).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    stream.write_all(b"mismatch").await.unwrap();

    let mut buf = vec![0u8; 64];
    let res = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    // Either the read times out or the peer closes with no echoed data.
    let echoed = matches!(res, Ok(Ok(n)) if n > 0 && buf[..n].windows(8).any(|w| w == b"mismatch"));
    assert!(
        !echoed,
        "mismatched modes must not produce a working tunnel"
    );
}
