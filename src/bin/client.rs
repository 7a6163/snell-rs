//! snell-client — Snell v5 SOCKS5 proxy client.
//! Usage: PSK=yourpsk SNELL_SERVER=host:port [LISTEN=127.0.0.1:1080] snell-client
//!
//! Handles SOCKS5 CONNECT (TCP) and UDP ASSOCIATE (UDP-over-TCP): UDP datagrams
//! from a SOCKS5-UDP app are relayed through the Snell tunnel via CMD_CONNECT_UDP.
//!
//! Optional env vars:
//!   TCP_FASTOPEN=1  Opt the outbound socket to the snell server into
//!                   client-side TFO (Linux >= 4.11 only; no-op on macOS).

use anyhow::{Result, bail};
use parking_lot::Mutex;
use snell::cipher::{SALT_LEN, SnellCipher};
use snell::snell::{CMD_CONNECT_UDP, RESP_TUNNEL, read_chunk, write_chunk};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    snell::logging::init();

    // Graceful shutdown on SIGTERM/SIGINT so atexit handlers run
    // (systemd restart lifecycle + LLVM coverage profile flush during tests).
    #[cfg(unix)]
    tokio::spawn(async {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        std::process::exit(0);
    });

    let server: SocketAddr = std::env::var("SNELL_SERVER")
        .unwrap_or_else(|_| "127.0.0.1:6180".into())
        .parse()?;
    // T2-G: Wrap in Zeroizing so the PSK bytes are scrubbed when the Arc's
    // final clone is dropped (best-effort defense against core dumps / swap).
    let psk: Arc<Zeroizing<Vec<u8>>> = Arc::new(Zeroizing::new(
        std::env::var("PSK")
            .map_err(|_| anyhow::anyhow!("PSK environment variable is required"))?
            .into_bytes(),
    ));
    let listen: SocketAddr = std::env::var("LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:1080".into())
        .parse()?;
    let tfo_out = std::env::var("TCP_FASTOPEN")
        .map(|v| v == "1")
        .unwrap_or(false);

    let ln = TcpListener::bind(listen).await?;
    eprintln!("Snell v5 SOCKS5 proxy  {listen} → {server}");
    if tfo_out {
        eprintln!("<NOTIFY> TCP Fast Open enabled (outbound)");
    }
    loop {
        let (conn, _) = ln.accept().await?;
        let psk = psk.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(conn, server, &psk, tfo_out).await {
                tracing::error!(error = %e, "client connection failed");
            }
        });
    }
}

/// Generate a 16-byte handshake salt whose first byte cannot collide with the
/// server-side obfs auto-detect (`dispatch()` routes `0x16` → TLS, `'G'` →
/// HTTP, anything else → plain). With a uniform random salt the collision rate
/// is ~0.78% per connection; for connection-reuse-heavy clients the cumulative
/// failure rate is non-trivial and surfaces as `UnknownProtocolVersion` errors
/// on the server's TLS handler. Re-rolling the first byte is a no-op for the
/// Snell protocol (the salt is opaque KDF input — uniform distribution is not
/// required) and eliminates the flake without changing the wire format.
fn fresh_handshake_salt(psk: &[u8]) -> Result<([u8; SALT_LEN], SnellCipher)> {
    use rand::RngCore;
    let mut salt = [0u8; SALT_LEN];
    loop {
        rand::thread_rng().fill_bytes(&mut salt);
        if salt[0] != 0x16 && salt[0] != b'G' {
            break;
        }
    }
    let cipher = SnellCipher::new(psk, &salt)?;
    Ok((salt, cipher))
}

/// Connect to the snell server, optionally opting into client-side TFO.
async fn connect_server(server: SocketAddr, tfo_out: bool) -> anyhow::Result<TcpStream> {
    if !tfo_out {
        return Ok(TcpStream::connect(server).await?);
    }
    let sock = if server.is_ipv6() {
        tokio::net::TcpSocket::new_v6()
    } else {
        tokio::net::TcpSocket::new_v4()
    }?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if let Err(e) = snell::tfo::enable_connect_tfo(sock.as_raw_fd()) {
            tracing::warn!(error = %e, "TCP Fast Open connect setsockopt failed; continuing without TFO");
        }
    }
    Ok(sock.connect(server).await?)
}

async fn handle(mut local: TcpStream, server: SocketAddr, psk: &[u8], tfo_out: bool) -> Result<()> {
    // SOCKS5 greeting: VER(1) + NMETHODS(1) + METHODS(n)
    let mut greeting = [0u8; 2];
    local.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        bail!("not a SOCKS5 client (ver={:#04x})", greeting[0]);
    }
    let nmethods = greeting[1] as usize;
    let mut methods = vec![0u8; nmethods];
    local.read_exact(&mut methods).await?;
    local.write_all(&[0x05, 0x00]).await?; // select no-auth

    // SOCKS5 request: VER(1) + CMD(1) + RSV(1) + ATYP(1) + addr + port
    let mut req_hdr = [0u8; 4];
    local.read_exact(&mut req_hdr).await?;
    if req_hdr[0] != 0x05 {
        bail!("invalid SOCKS5 request version");
    }
    let socks_cmd = req_hdr[1];

    let (host, port) = match req_hdr[3] {
        0x01 => {
            // IPv4: 4 bytes + 2 bytes port
            let mut buf = [0u8; 6];
            local.read_exact(&mut buf).await?;
            let ip = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            (ip, port)
        }
        0x03 => {
            // Domain: 1-byte length + domain + 2-byte port
            let mut len_buf = [0u8; 1];
            local.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain_port = vec![0u8; len + 2];
            local.read_exact(&mut domain_port).await?;
            let host = std::str::from_utf8(&domain_port[..len])?.to_owned();
            let port = u16::from_be_bytes([domain_port[len], domain_port[len + 1]]);
            (host, port)
        }
        0x04 => {
            // IPv6: 16 bytes + 2 bytes port
            let mut buf = [0u8; 18];
            local.read_exact(&mut buf).await?;
            let arr: [u8; 16] = buf[..16].try_into()?;
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            (std::net::Ipv6Addr::from(arr).to_string(), port)
        }
        t => bail!("unsupported SOCKS5 ATYP {t:#04x}"),
    };

    // UDP ASSOCIATE → Snell UoT bridge. The DST addr/port parsed above are the
    // client's advertised source and are ignored (RFC 1928).
    if socks_cmd == 0x03 {
        return udp_associate(local, server, psk, tfo_out).await;
    }
    if socks_cmd != 0x01 {
        bail!("unsupported SOCKS5 command {socks_cmd:#04x}");
    }

    // Reply: success (bound addr 0.0.0.0:0)
    local
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Connect to Snell server and perform handshake
    let mut remote = connect_server(server, tfo_out).await?;
    let (salt, mut c2s) = fresh_handshake_salt(psk)?;
    remote.write_all(&salt).await?;

    // Snell v5 CONNECT_V2 request: [ver=1][cmd=5][client_id_len=0][host_len][host][port BE]
    let hb = host.as_bytes();
    let mut hs = vec![0x01u8, 0x05, 0x00, hb.len() as u8];
    hs.extend_from_slice(hb);
    hs.push((port >> 8) as u8);
    hs.push((port & 0xff) as u8);
    remote.write_all(&c2s.seal(&hs)?).await?;

    // Official snell-server v5 doesn't send the server salt upfront — it
    // waits for the target to produce data, then sends [server_salt][RESP_TUNNEL
    // + target_data] together. So salt-reading must happen in the down task,
    // concurrently with the up task that forwards local data to remote.
    let psk_arc = psk.to_vec();
    let (mut lr, mut lw) = local.split();
    let (mut rr, mut rw) = remote.split();

    let up = async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = lr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_chunk(&mut rw, &mut c2s, &buf[..n]).await?;
        }
        rw.write_all(&c2s.seal_zero()?).await?;
        Ok::<_, anyhow::Error>(())
    };
    let down = async move {
        let mut ss = [0u8; SALT_LEN];
        rr.read_exact(&mut ss).await?;
        let mut s2c = SnellCipher::new(&psk_arc, &ss)?;
        let mut first = true;
        loop {
            match read_chunk(&mut rr, &mut s2c).await? {
                None => break,
                Some(d) if first => {
                    first = false;
                    if d.first() != Some(&RESP_TUNNEL) {
                        anyhow::bail!("expected ResponseTunnel, got {:?}", d.first());
                    }
                    if d.len() > 1 {
                        lw.write_all(&d[1..]).await?;
                    }
                }
                Some(d) => lw.write_all(&d).await?,
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(up, down)?;
    Ok(())
}

/// SOCKS5 UDP ASSOCIATE → Snell UDP-over-TCP bridge.
///
/// Binds a local UDP relay socket, tells the SOCKS5 app where to send its
/// datagrams (BND.ADDR/PORT), opens a `CONNECT_UDP` session to the snell server,
/// and bridges local SOCKS5 UDP datagrams ↔ Snell UoT frames. The association
/// lives while the SOCKS5 TCP control connection is open (RFC 1928).
async fn udp_associate(
    mut local: TcpStream,
    server: SocketAddr,
    psk: &[u8],
    tfo_out: bool,
) -> Result<()> {
    // Relay socket on loopback — the SOCKS5 app is local.
    let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let bound = udp.local_addr()?;

    // SOCKS5 success reply with BND.ADDR/PORT = our relay socket.
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    match bound.ip() {
        IpAddr::V4(v4) => reply.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => bail!("UDP relay bound to unexpected IPv6 address"),
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    local.write_all(&reply).await?;

    // Open the Snell CONNECT_UDP session: empty placeholder target (real targets
    // travel per-datagram). Header: [ver=1][cmd=0x06][client_id_len=0][host_len=0][port=0].
    let mut remote = connect_server(server, tfo_out).await?;
    let (salt, mut c2s) = fresh_handshake_salt(psk)?;
    remote.write_all(&salt).await?;
    let open = [0x01u8, CMD_CONNECT_UDP, 0x00, 0x00, 0x00, 0x00];
    remote.write_all(&c2s.seal(&open)?).await?;

    let (mut rr, mut rw) = remote.into_split();
    let psk_vec = psk.to_vec();
    // The SOCKS5 app's source addr, learned on its first datagram.
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // local UDP → tunnel
    let up_udp = udp.clone();
    let up_addr = client_addr.clone();
    let up = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = up_udp.recv_from(&mut buf).await?;
            *up_addr.lock() = Some(src);
            // SOCKS5 UDP header: [RSV2][FRAG1][ATYP][addr][port][data].
            let Some((host, port, data)) = parse_socks5_udp(&buf[..n]) else {
                continue; // drop fragments / malformed
            };
            let frame = snell::snell::encode_udp_request(&host, port, data);
            write_chunk(&mut rw, &mut c2s, &frame).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    // tunnel → local UDP
    let down_udp = udp.clone();
    let down_addr = client_addr.clone();
    let down = async move {
        let mut ss = [0u8; SALT_LEN];
        rr.read_exact(&mut ss).await?;
        let mut s2c = SnellCipher::new(&psk_vec, &ss)?;
        let mut first = true;
        while let Some(d) = read_chunk(&mut rr, &mut s2c).await? {
            if first {
                first = false;
                if d.first() != Some(&RESP_TUNNEL) {
                    bail!("expected ResponseTunnel, got {:?}", d.first());
                }
                if d.len() > 1 {
                    forward_to_app(&d[1..], &down_udp, &down_addr).await;
                }
            } else {
                forward_to_app(&d, &down_udp, &down_addr).await;
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    // The association ends when the SOCKS5 control connection closes.
    let ctrl = async move {
        let mut b = [0u8; 1];
        loop {
            match local.read(&mut b).await {
                Ok(0) => break,
                Ok(_) => continue, // control conn carries no data
                Err(e) => return Err(anyhow::Error::from(e)),
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = up => r,
        r = down => r,
        r = ctrl => r,
    }
}

/// Parse a SOCKS5 UDP request datagram into `(host, port, payload)`. Returns
/// `None` for fragments (`FRAG != 0`) or malformed packets.
fn parse_socks5_udp(buf: &[u8]) -> Option<(String, u16, &[u8])> {
    // [RSV 2][FRAG 1][ATYP 1][addr][port 2][data]
    if buf.len() < 4 || buf[2] != 0x00 {
        return None;
    }
    let (host, mut pos) = match buf[3] {
        0x01 => {
            let b = buf.get(4..8)?;
            (format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), 8)
        }
        0x03 => {
            let len = *buf.get(4)? as usize;
            let d = buf.get(5..5 + len)?;
            (std::str::from_utf8(d).ok()?.to_owned(), 5 + len)
        }
        0x04 => {
            let b = buf.get(4..20)?;
            let arr: [u8; 16] = b.try_into().ok()?;
            (std::net::Ipv6Addr::from(arr).to_string(), 20)
        }
        _ => return None,
    };
    let pb = buf.get(pos..pos + 2)?;
    let port = u16::from_be_bytes([pb[0], pb[1]]);
    pos += 2;
    Some((host, port, &buf[pos..]))
}

/// Wrap a Snell UoT response frame into a SOCKS5 UDP datagram and send it to the
/// app's learned source address.
async fn forward_to_app(
    frame: &[u8],
    udp: &tokio::net::UdpSocket,
    client_addr: &Arc<Mutex<Option<SocketAddr>>>,
) {
    let Ok((src, payload)) = snell::snell::parse_udp_response(frame) else {
        return;
    };
    let Some(dst) = *client_addr.lock() else {
        return; // no app addr learned yet
    };
    // SOCKS5 UDP response: [RSV2=0][FRAG=0][ATYP][addr][port][data].
    let mut pkt = vec![0x00, 0x00, 0x00];
    match src.ip() {
        IpAddr::V4(v4) => {
            pkt.push(0x01);
            pkt.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            pkt.push(0x04);
            pkt.extend_from_slice(&v6.octets());
        }
    }
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(payload);
    let _ = udp.send_to(&pkt, dst).await;
}
