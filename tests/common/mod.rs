//! Shared test helpers for integration tests.
//!
//! Each integration test file (`tests/*.rs`) gets its own compilation, so
//! items used in only one file appear unused in others. Allow dead code.

#![allow(dead_code)]

use snell::cipher::{SALT_LEN, SnellCipher};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;

pub const PSK: &str = "integration-test-psk-32-bytes--";
// Length 31. Server enforces >= 16.

pub fn random_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

pub fn random_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    port
}

pub async fn wait_tcp(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("port {port} did not open within 5s");
}

/// Perform a plain Snell v5 handshake against the server and return the
/// connection plus the (client→server, server→client) ciphers.
pub async fn snell_handshake(server_port: u16) -> (TcpStream, SnellCipher, SnellCipher) {
    let psk = PSK.as_bytes();
    let mut conn = TcpStream::connect(("127.0.0.1", server_port))
        .await
        .unwrap();
    // First byte must avoid the obfs auto-detect (0x16 = TLS, 'G' = HTTP).
    let mut salt = [0u8; SALT_LEN];
    salt[0] = 0x01;
    for b in salt.iter_mut().skip(1) {
        *b = rand::random();
    }
    let c2s = SnellCipher::new(psk, &salt).unwrap();
    conn.write_all(&salt).await.unwrap();
    // The server sends its salt up front, before reading the request.
    let mut server_salt = [0u8; SALT_LEN];
    conn.read_exact(&mut server_salt).await.unwrap();
    let s2c = SnellCipher::new(psk, &server_salt).unwrap();
    (conn, c2s, s2c)
}

pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Send SIGTERM and wait briefly so the child's atexit handlers run
        // (notably LLVM coverage's profile-flush hook). SIGKILL via
        // start_kill() would drop the .profraw and zero out bin coverage.
        #[cfg(unix)]
        if let Some(pid) = self.0.id() {
            // SAFETY: pid comes from a live Child; SIGTERM is a defined signal.
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            for _ in 0..40 {
                if matches!(self.0.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let _ = self.0.start_kill();
    }
}

pub fn spawn_server(listen_port: u16, quic: bool) -> ChildGuard {
    spawn_server_with_envs(listen_port, quic, &[])
}

pub fn spawn_server_with_envs(
    listen_port: u16,
    quic: bool,
    extra_env: &[(&str, &str)],
) -> ChildGuard {
    let bin = env!("CARGO_BIN_EXE_snell-server");
    let mut cmd = Command::new(bin);
    cmd.arg(format!("0.0.0.0:{listen_port}"))
        .env("PSK", PSK)
        // H-7: Disable the TCP per-IP handshake cooldown for tests. wait_tcp
        // and the real test connection both originate from 127.0.0.1 within
        // milliseconds of each other and would otherwise trip the 100 ms
        // production default. Tests that want to verify the rate limiter pass
        // an override in `extra_env` — Command::env is last-write-wins.
        .env("TCP_HANDSHAKE_COOLDOWN_MS", "0")
        // Most suites exercise the v5 wire (obfs auto-detect, UoT, CONNECT
        // paths), which is `unshaped`. The production default is `default`
        // (shaped) to match official snell-server, so pin it here rather than
        // leaning on whatever the unset default happens to be. Tests covering
        // other modes pass MODE in `extra_env` — Command::env is last-write-wins.
        .env("MODE", "unshaped")
        .kill_on_drop(true);
    // Note: as of v5.2.0 the SSRF guard is off by default, so we no longer need
    // to set BLOCK_PRIVATE_TARGETS=0 — proxying to 127.0.0.1 just works.
    if quic {
        cmd.env("QUIC", "1");
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    ChildGuard(cmd.spawn().expect("spawn snell-server"))
}

pub fn spawn_client(server_port: u16, socks_port: u16) -> ChildGuard {
    spawn_client_with_envs(server_port, socks_port, &[])
}

pub fn spawn_client_with_envs(
    server_port: u16,
    socks_port: u16,
    extra_env: &[(&str, &str)],
) -> ChildGuard {
    let bin = env!("CARGO_BIN_EXE_snell-client");
    let mut cmd = Command::new(bin);
    cmd.env("PSK", PSK)
        .env("SNELL_SERVER", format!("127.0.0.1:{server_port}"))
        .env("LISTEN", format!("127.0.0.1:{socks_port}"))
        // Mirror spawn_server_with_envs: default to the v5 wire, let callers override.
        .env("MODE", "unshaped")
        .kill_on_drop(true);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    ChildGuard(cmd.spawn().expect("spawn snell-client"))
}
