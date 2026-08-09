//! Address-family policy (`IPV6` / `DNS_IP_PREFERENCE`) and official error-code
//! alignment with snell-server v6.0.0rc2: IP-literal targets are gated before
//! DNS by the `*-only` policies, and every rejection carries the official code.

mod common;
use common::*;

use snell::snell::{
    CMD_CONNECT_V2, MSG_DNS_FAILED, MSG_IPV4_DISABLED, MSG_IPV6_DISABLED, RESP_ERROR, RESP_TUNNEL,
    errcode, read_chunk, write_chunk,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

/// Echo listener on an explicit bind address. `None` means the address family
/// isn't available on this host (e.g. no IPv6 loopback) — callers skip.
async fn spawn_echo_on(bind: &str) -> Option<u16> {
    let listener = TcpListener::bind(bind).await.ok()?;
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
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
    Some(port)
}

/// Send one `CONNECT` for `host:port` over a fresh v5 handshake and return the
/// server's first reply frame (either `[RESP_TUNNEL]` or a `RESP_ERROR` frame).
async fn connect_reply(server_port: u16, host: &str, target_port: u16) -> Vec<u8> {
    let (mut conn, mut c2s, mut s2c) = snell_handshake(server_port).await;
    let mut req = vec![0x01, CMD_CONNECT_V2, 0x00, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&target_port.to_be_bytes());
    write_chunk(&mut conn, &mut c2s, &req).await.unwrap();
    timeout(Duration::from_secs(5), read_chunk(&mut conn, &mut s2c))
        .await
        .expect("no reply within 5s")
        .expect("read failed")
        .expect("server closed without replying")
}

/// Assert an exact `[RESP_ERROR][code][msg_len][msg]` frame.
fn assert_error_frame(frame: &[u8], code: u8, msg: &str) {
    assert_eq!(frame[0], RESP_ERROR, "not an error frame: {frame:?}");
    assert_eq!(frame[1], code, "wrong error code");
    assert_eq!(frame[2] as usize, msg.len(), "wrong msg_len");
    assert_eq!(&frame[3..], msg.as_bytes(), "wrong msg");
    assert_eq!(frame.len(), 3 + msg.len(), "trailing bytes in frame");
}

/// Round-trip a payload through an established tunnel.
async fn assert_tunnel_echoes(server_port: u16, host: &str, target_port: u16) {
    let (mut conn, mut c2s, mut s2c) = snell_handshake(server_port).await;
    let mut req = vec![0x01, CMD_CONNECT_V2, 0x00, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&target_port.to_be_bytes());
    req.extend_from_slice(b"policy-ping");
    write_chunk(&mut conn, &mut c2s, &req).await.unwrap();

    let ack = timeout(Duration::from_secs(5), read_chunk(&mut conn, &mut s2c))
        .await
        .expect("no reply within 5s")
        .unwrap()
        .unwrap();
    assert_eq!(ack, vec![RESP_TUNNEL], "expected a tunnel for {host}");

    let echoed = timeout(Duration::from_secs(5), read_chunk(&mut conn, &mut s2c))
        .await
        .expect("no echo within 5s")
        .unwrap()
        .unwrap();
    assert_eq!(echoed, b"ECHO:policy-ping".to_vec());
}

// ── literal targets blocked by an *-only policy ───────────────────────────────

#[tokio::test]
async fn ipv4_only_rejects_ipv6_literal() {
    // Neither IPV6 nor DNS_IP_PREFERENCE set → ipv4-only, the default.
    let server_port = random_tcp_port();
    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    let frame = connect_reply(server_port, "2606:4700::1111", 80).await;
    assert_error_frame(&frame, errcode::AF_DISABLED, MSG_IPV6_DISABLED);
}

#[tokio::test]
async fn ipv6_only_rejects_ipv4_literal() {
    let server_port = random_tcp_port();
    let _server =
        spawn_server_with_envs(server_port, false, &[("DNS_IP_PREFERENCE", "ipv6-only")]);
    wait_tcp(server_port).await;

    let frame = connect_reply(server_port, "1.1.1.1", 80).await;
    assert_error_frame(&frame, errcode::AF_DISABLED, MSG_IPV4_DISABLED);
}

#[tokio::test]
async fn ipv4_only_rejects_bracketed_ipv6_literal() {
    // The bracketed spelling must take the same literal fast path.
    let server_port = random_tcp_port();
    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    let frame = connect_reply(server_port, "[2606:4700::1111]", 443).await;
    assert_error_frame(&frame, errcode::AF_DISABLED, MSG_IPV6_DISABLED);
}

// ── literal targets permitted by the policy ──────────────────────────────────

#[tokio::test]
async fn ipv4_only_allows_ipv4_literal() {
    let echo_port = spawn_echo_on("127.0.0.1:0").await.expect("bind v4 echo");
    let server_port = random_tcp_port();
    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    assert_tunnel_echoes(server_port, "127.0.0.1", echo_port).await;
}

#[tokio::test]
async fn ipv6_only_allows_ipv6_literal() {
    let Some(echo_port) = spawn_echo_on("[::1]:0").await else {
        eprintln!("skipping: no IPv6 loopback on this host");
        return;
    };
    let server_port = random_tcp_port();
    let _server =
        spawn_server_with_envs(server_port, false, &[("DNS_IP_PREFERENCE", "ipv6-only")]);
    wait_tcp(server_port).await;

    assert_tunnel_echoes(server_port, "::1", echo_port).await;
}

#[tokio::test]
async fn prefer_and_default_policies_allow_ipv6_literal() {
    // prefer-* must never gate a literal — only the *-only policies do.
    let Some(echo_port) = spawn_echo_on("[::1]:0").await else {
        eprintln!("skipping: no IPv6 loopback on this host");
        return;
    };
    for pref in ["default", "first-result", "prefer-ipv4", "prefer-ipv6"] {
        let server_port = random_tcp_port();
        let _server = spawn_server_with_envs(server_port, false, &[("DNS_IP_PREFERENCE", pref)]);
        wait_tcp(server_port).await;
        assert_tunnel_echoes(server_port, "::1", echo_port).await;
    }
}

// ── DNS_IP_PREFERENCE overrides IPV6 regardless of value ─────────────────────

#[tokio::test]
async fn preference_overrides_unset_ipv6_flag() {
    // IPV6 unset (would be ipv4-only) + ipv6-only → the IPv4 literal is blocked.
    let server_port = random_tcp_port();
    let _server =
        spawn_server_with_envs(server_port, false, &[("DNS_IP_PREFERENCE", "only-ipv6")]);
    wait_tcp(server_port).await;

    let frame = connect_reply(server_port, "1.1.1.1", 80).await;
    assert_error_frame(&frame, errcode::AF_DISABLED, MSG_IPV4_DISABLED);
}

#[tokio::test]
async fn preference_overrides_ipv6_zero() {
    // IPV6=0 alone means ipv4-only, but an explicit preference wins: the IPv6
    // literal must connect.
    let Some(echo_port) = spawn_echo_on("[::1]:0").await else {
        eprintln!("skipping: no IPv6 loopback on this host");
        return;
    };
    let server_port = random_tcp_port();
    let _server = spawn_server_with_envs(
        server_port,
        false,
        &[("IPV6", "0"), ("DNS_IP_PREFERENCE", "default")],
    );
    wait_tcp(server_port).await;

    assert_tunnel_echoes(server_port, "::1", echo_port).await;
}

#[tokio::test]
async fn preference_overrides_ipv6_true() {
    // The override works in the other direction too: IPV6=true would allow both
    // families, but ipv4-only still blocks the IPv6 literal.
    let server_port = random_tcp_port();
    let _server = spawn_server_with_envs(
        server_port,
        false,
        &[("IPV6", "true"), ("DNS_IP_PREFERENCE", "ipv4-only")],
    );
    wait_tcp(server_port).await;

    let frame = connect_reply(server_port, "2606:4700::1111", 80).await;
    assert_error_frame(&frame, errcode::AF_DISABLED, MSG_IPV6_DISABLED);
}

#[tokio::test]
async fn ipv6_flag_true_allows_ipv6_literal() {
    // IPV6 with a true-like value maps to the `default` policy.
    let Some(echo_port) = spawn_echo_on("[::1]:0").await else {
        eprintln!("skipping: no IPv6 loopback on this host");
        return;
    };
    let server_port = random_tcp_port();
    let _server = spawn_server_with_envs(server_port, false, &[("IPV6", "yes")]);
    wait_tcp(server_port).await;

    assert_tunnel_echoes(server_port, "::1", echo_port).await;
}

// ── error codes ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn unresolvable_domain_reports_dns_failed() {
    let server_port = random_tcp_port();
    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    // .invalid is guaranteed never to resolve (RFC 6761).
    let frame = connect_reply(server_port, "snell-rs-no-such-host.invalid", 80).await;
    assert_error_frame(&frame, errcode::DNS_FAILED, MSG_DNS_FAILED);
    assert_eq!(frame[1], 0x64);
}

#[tokio::test]
async fn refused_connect_reports_econnrefused() {
    let closed = random_tcp_port(); // bound then dropped → connect is refused
    let server_port = random_tcp_port();
    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    let frame = connect_reply(server_port, "127.0.0.1", closed).await;
    assert_eq!(frame[0], RESP_ERROR);
    assert_eq!(
        frame[1],
        errcode::CONN_REFUSED,
        "ECONNREFUSED must map to 0x06"
    );
}

#[tokio::test]
async fn invalid_preference_value_aborts_startup() {
    let server_port = random_tcp_port();
    let mut server = spawn_server_with_envs(server_port, false, &[("DNS_IP_PREFERENCE", "ipv7")]);
    let status = timeout(Duration::from_secs(5), server.0.wait())
        .await
        .expect("server should exit promptly")
        .unwrap();
    assert!(!status.success(), "unknown preference must be fatal");
}
