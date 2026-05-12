//! Shared test helpers for integration tests.
//!
//! Each integration test file (`tests/*.rs`) gets its own compilation, so
//! items used in only one file appear unused in others. Allow dead code.

#![allow(dead_code)]

use std::time::Duration;
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
    let bin = env!("CARGO_BIN_EXE_snell-server");
    let mut cmd = Command::new(bin);
    cmd.arg(format!("0.0.0.0:{listen_port}"))
        .env("PSK", PSK)
        .kill_on_drop(true);
    // Note: as of v5.2.0 the SSRF guard is off by default, so we no longer need
    // to set BLOCK_PRIVATE_TARGETS=0 — proxying to 127.0.0.1 just works.
    if quic {
        cmd.env("QUIC", "1");
    }
    ChildGuard(cmd.spawn().expect("spawn snell-server"))
}

pub fn spawn_client(server_port: u16, socks_port: u16) -> ChildGuard {
    let bin = env!("CARGO_BIN_EXE_snell-client");
    let child = Command::new(bin)
        .env("PSK", PSK)
        .env("SNELL_SERVER", format!("127.0.0.1:{server_port}"))
        .env("LISTEN", format!("127.0.0.1:{socks_port}"))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn snell-client");
    ChildGuard(child)
}
