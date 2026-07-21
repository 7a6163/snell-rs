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
