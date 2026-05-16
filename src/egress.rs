//! Egress interface binding for outgoing TCP and UDP connections.
//!
//! Set `EGRESS_INTERFACE=eth0` (or any interface name) to force all outgoing
//! connections through that interface. Requires CAP_NET_RAW on Linux or root
//! on macOS. On other platforms the option is accepted but ignored.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};

/// Connect to `addr`, optionally binding the socket to `iface` and/or opting
/// the socket into client-side TCP Fast Open before connecting.
pub async fn connect_tcp(addr: SocketAddr, iface: Option<&str>, tfo: bool) -> Result<TcpStream> {
    if iface.is_none() && !tfo {
        return TcpStream::connect(addr).await.context("connect");
    }

    let sock = if addr.is_ipv6() {
        tokio::net::TcpSocket::new_v6()
    } else {
        tokio::net::TcpSocket::new_v4()
    }
    .context("create TCP socket")?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if let Some(iface) = iface {
            bind_to_iface(sock.as_raw_fd(), iface, addr.is_ipv6())
                .with_context(|| format!("bind to interface {iface}"))?;
        }
        if tfo && let Err(e) = crate::tfo::enable_connect_tfo(sock.as_raw_fd()) {
            // Best-effort: log and continue without TFO if the kernel rejects it.
            eprintln!("TCP Fast Open connect setsockopt failed ({e}); continuing without TFO");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tfo;
    }

    sock.connect(addr).await.context("connect")
}

/// Bind a UDP socket to `local`, optionally locking it to `iface`.
pub fn bind_udp(local: SocketAddr, iface: Option<&str>) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if local.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create UDP socket")?;
    sock.set_reuse_address(true).context("SO_REUSEADDR")?;
    sock.bind(&local.into()).context("bind UDP")?;

    if let Some(iface) = iface {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            bind_to_iface(sock.as_raw_fd(), iface, local.is_ipv6())
                .with_context(|| format!("bind UDP to interface {iface}"))?;
        }
        #[cfg(not(unix))]
        {
            let _ = iface;
        }
    }

    sock.set_nonblocking(true).context("set nonblocking")?;
    UdpSocket::from_std(std::net::UdpSocket::from(sock)).context("tokio UdpSocket")
}

#[cfg(all(unix, target_os = "linux"))]
fn bind_to_iface(fd: std::os::unix::io::RawFd, iface: &str, _ipv6: bool) -> Result<()> {
    use std::ffi::CString;
    let name = CString::new(iface)?;
    // SAFETY: fd is valid, name is null-terminated and not outlived.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const _,
            iface.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("SO_BINDTODEVICE={iface} — needs CAP_NET_RAW or root"));
    }
    Ok(())
}

#[cfg(all(unix, target_os = "macos"))]
fn bind_to_iface(fd: std::os::unix::io::RawFd, iface: &str, ipv6: bool) -> Result<()> {
    use std::ffi::CString;
    let name = CString::new(iface)?;
    // SAFETY: name is null-terminated.
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if idx == 0 {
        anyhow::bail!("interface '{iface}' not found");
    }
    let idx = idx as libc::c_int;
    // IP_BOUND_IF = 25, IPV6_BOUND_IF = 125 on macOS.
    let (level, opt) = if ipv6 {
        (libc::IPPROTO_IPV6 as libc::c_int, 125_i32)
    } else {
        (libc::IPPROTO_IP as libc::c_int, 25_i32)
    };
    // SAFETY: fd and idx are valid.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &idx as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn bind_to_iface(_fd: std::os::unix::io::RawFd, iface: &str, _ipv6: bool) -> Result<()> {
    anyhow::bail!("EGRESS_INTERFACE not supported on this platform (iface={iface})");
}
