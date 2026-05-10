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
