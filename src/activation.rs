//! systemd Socket Activation (sd_listen_fds).
//!
//! When launched by systemd with socket units, the daemon inherits pre-bound
//! file descriptors starting at fd 3. This module reads LISTEN_PID and
//! LISTEN_FDS, validates ownership, and converts the raw FDs to Tokio listeners.
//!
//! Reference: <https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html>

#[cfg(unix)]
use anyhow::Result;
#[cfg(unix)]
use std::os::unix::io::RawFd;

/// Return file descriptors passed by systemd, or an empty vec if not activated.
///
/// Clears `LISTEN_PID` and `LISTEN_FDS` after reading (per sd_listen_fds spec).
#[cfg(unix)]
pub fn take_listener_fds() -> Vec<RawFd> {
    let our_pid: u32 = std::process::id();
    let listen_pid: u32 = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let n: u32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // SAFETY: called at startup before any threads are spawned, so no
    // concurrent env reads can race with this write (sd_listen_fds convention).
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
    }

    if listen_pid != our_pid {
        return vec![];
    }

    (3..3 + n).map(|fd| fd as RawFd).collect()
}

/// Convert a raw fd (passed by systemd) into a Tokio `TcpListener`.
#[cfg(unix)]
pub fn into_tcp_listener(fd: RawFd) -> Result<tokio::net::TcpListener> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: fd was passed by systemd and is a valid, owned socket.
    let std_ln = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    std_ln.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(std_ln).map_err(Into::into)
}

/// Convert a raw fd (passed by systemd) into a Tokio `UdpSocket`.
#[cfg(unix)]
pub fn into_udp_socket(fd: RawFd) -> Result<tokio::net::UdpSocket> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: fd was passed by systemd and is a valid, owned socket.
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    std_sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(std_sock).map_err(Into::into)
}

/// Non-unix stub — always returns empty (no activation).
#[cfg(not(unix))]
pub fn take_listener_fds() -> Vec<i32> {
    vec![]
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::os::unix::io::IntoRawFd;

    #[test]
    #[serial]
    fn take_listener_fds_returns_numbered_fds_when_pid_matches() {
        // SAFETY: serialized test; no other threads read these env vars here.
        unsafe {
            std::env::set_var("LISTEN_PID", std::process::id().to_string());
            std::env::set_var("LISTEN_FDS", "2");
        }
        assert_eq!(take_listener_fds(), vec![3, 4]);
        // Vars are cleared after reading, per the sd_listen_fds spec.
        assert!(std::env::var("LISTEN_PID").is_err());
        assert!(std::env::var("LISTEN_FDS").is_err());
    }

    #[test]
    #[serial]
    fn take_listener_fds_empty_when_pid_mismatches() {
        // SAFETY: serialized test.
        unsafe {
            std::env::set_var("LISTEN_PID", "1");
            std::env::set_var("LISTEN_FDS", "3");
        }
        assert!(take_listener_fds().is_empty());
    }

    #[test]
    #[serial]
    fn take_listener_fds_empty_when_unset() {
        // SAFETY: serialized test.
        unsafe {
            std::env::remove_var("LISTEN_PID");
            std::env::remove_var("LISTEN_FDS");
        }
        assert!(take_listener_fds().is_empty());
    }

    #[tokio::test]
    async fn into_tcp_listener_adopts_a_bound_socket() {
        let std_ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ln = into_tcp_listener(std_ln.into_raw_fd()).unwrap();
        assert!(ln.local_addr().is_ok());
    }

    #[tokio::test]
    async fn into_udp_socket_adopts_a_bound_socket() {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock = into_udp_socket(std_sock.into_raw_fd()).unwrap();
        assert!(sock.local_addr().is_ok());
    }
}
