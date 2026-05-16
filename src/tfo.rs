//! TCP Fast Open (RFC 7413) helpers.
//!
//! `enable_listen_tfo` sets the server-side `TCP_FASTOPEN` option on a bound
//! listener so the kernel will issue / accept SYN-data cookies. The effective
//! state still depends on the kernel: Linux honors it when
//! `net.ipv4.tcp_fastopen` includes the server bit (2 or 3); macOS honors it
//! when `net.inet.tcp.fastopen` includes the server bit (2 or 3).
//!
//! `enable_connect_tfo` opts the connecting socket into client-side TFO.
//! Only meaningful on Linux (`TCP_FASTOPEN_CONNECT`, kernel >= 4.11). On macOS
//! the client path requires `connectx()` with `CONNECT_DATA_IDEMPOTENT`, which
//! we deliberately do not wire up; this helper is a no-op there.

#![cfg_attr(not(unix), allow(dead_code))]

/// Default Linux TFO listen queue. Matches the official `snell-server` default.
#[cfg(target_os = "linux")]
const LINUX_TFO_QLEN: libc::c_int = 256;

#[cfg(unix)]
use std::os::unix::io::RawFd;

/// Enable server-side TCP Fast Open on a listening socket fd.
///
/// On Linux the option carries the SYN-queue length; on macOS it's a boolean.
/// On other unixes this is a no-op. Returns an `io::Error` only when the
/// `setsockopt` itself fails — callers typically log and continue.
#[cfg(target_os = "linux")]
pub fn enable_listen_tfo(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fd is a borrowed listening socket owned by the caller.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &LINUX_TFO_QLEN as *const _ as *const libc::c_void,
            std::mem::size_of_val(&LINUX_TFO_QLEN) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn enable_listen_tfo(fd: RawFd) -> std::io::Result<()> {
    // macOS does not expose libc::TCP_FASTOPEN in the libc crate; use the raw
    // value documented in /usr/include/netinet/tcp.h.
    const MACOS_TCP_FASTOPEN: libc::c_int = 261;
    let on: libc::c_int = 1;
    // SAFETY: fd is a borrowed listening socket owned by the caller.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            MACOS_TCP_FASTOPEN,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub fn enable_listen_tfo(_fd: RawFd) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
pub fn enable_listen_tfo(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

/// Enable client-side TCP Fast Open on an outbound socket fd.
///
/// Linux >= 4.11: sets `TCP_FASTOPEN_CONNECT` (opt 30) so a subsequent
/// `connect()` may carry SYN data from the first write. On macOS the kernel
/// requires `connectx()` instead of an opt, so this is a documented no-op.
#[cfg(target_os = "linux")]
pub fn enable_connect_tfo(fd: RawFd) -> std::io::Result<()> {
    // libc 0.2 may not export TCP_FASTOPEN_CONNECT for every target; pin to
    // the canonical Linux value (see include/uapi/linux/tcp.h).
    const TCP_FASTOPEN_CONNECT: libc::c_int = 30;
    let on: libc::c_int = 1;
    // SAFETY: fd is a borrowed unconnected TCP socket owned by the caller.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_FASTOPEN_CONNECT,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn enable_connect_tfo(_fd: RawFd) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
pub fn enable_connect_tfo(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Smoke test: setsockopt path must accept a freshly bound listener
    // regardless of the kernel's sysctl state. The call may succeed
    // unconditionally (sysctl bit set) or surface a specific errno; either way
    // it must not panic and must not corrupt the socket. We only assert it
    // doesn't crash — the kernel-state branch is exercised in integration.
    #[cfg(unix)]
    #[test]
    fn enable_listen_tfo_does_not_panic() {
        use std::os::unix::io::AsRawFd;
        let std_ln = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        // Result intentionally ignored: success and EOPNOTSUPP are both fine.
        let _ = enable_listen_tfo(std_ln.as_raw_fd());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enable_connect_tfo_does_not_panic() {
        use std::os::unix::io::AsRawFd;
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("socket");
        let _ = enable_connect_tfo(sock.as_raw_fd());
    }
}
