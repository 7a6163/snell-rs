//! snell-server — open-source Snell v5 server.
//! Usage: PSK=yourpsk snell-server [listen_addr]
//! Default listen: 0.0.0.0:6180
//!
//! Environment variables:
//!   PSK                   Pre-shared key (required, min 16 chars)
//!   EGRESS_INTERFACE      Bind outgoing connections to this network interface
//!   QUIC=1                Enable QUIC proxy mode (opens UDP on same port)
//!   ALLOW_PRIVATE_TARGETS=1  Allow connecting to loopback/private addresses
//!
//! Obfuscation auto-detected from first byte:
//!   plain    — random Snell salt
//!   obfs=http — 'G' (HTTP GET WebSocket upgrade)
//!   obfs=tls  — 0x16 (TLS ClientHello)

use anyhow::{Result, bail};
use snell::cipher::{SALT_LEN, SnellCipher};
use snell::quic::{SessionTable, UdpSession, gc_sessions, new_session_table};
use snell::relay::copy_t2c_adaptive;
use snell::snell::{
    CMD_CONNECT, CMD_CONNECT_V2, CMD_PING, RESP_ERROR, RESP_PONG, RESP_TUNNEL, parse_request,
    read_chunk,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::interval;
use tokio_rustls::{TlsAcceptor, rustls};

#[cfg(unix)]
use std::os::unix::io::RawFd;

const HANDSHAKE_TIMEOUT_SECS: u64 = 30;
const MAX_CONCURRENT_CONNS: usize = 4096;

// C-3: Cap on concurrent QUIC sessions to bound argon2id work.
const MAX_UDP_SESSIONS: usize = 8192;
// C-3: Minimum milliseconds between Init packets from the same source IP.
const INIT_COOLDOWN_MS: u128 = 1000;

fn main() -> Result<()> {
    // Read systemd FDs before any threads exist.
    #[cfg(unix)]
    let activation_fds = snell::activation::take_listener_fds();
    #[cfg(not(unix))]
    let activation_fds: Vec<i32> = vec![];

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main(activation_fds))
}

#[cfg(unix)]
async fn async_main(activation_fds: Vec<RawFd>) -> Result<()> {
    async_main_inner(activation_fds).await
}

#[cfg(not(unix))]
async fn async_main(activation_fds: Vec<i32>) -> Result<()> {
    async_main_inner(activation_fds).await
}

async fn async_main_inner(activation_fds: Vec<impl Into<i32> + Copy>) -> Result<()> {
    let listen: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:6180".into())
        .parse()?;

    let psk_str = std::env::var("PSK")
        .map_err(|_| anyhow::anyhow!("PSK environment variable is required"))?;
    if psk_str.len() < 16 {
        anyhow::bail!("PSK must be at least 16 characters (got {})", psk_str.len());
    }
    let psk = Arc::new(psk_str.into_bytes());

    let egress_iface: Option<Arc<String>> = std::env::var("EGRESS_INTERFACE").ok().map(Arc::new);
    let quic_enabled = std::env::var("QUIC").map(|v| v == "1").unwrap_or(false);
    // C-4: Read ALLOW_PRIVATE_TARGETS once at startup instead of on every call.
    let allow_private = std::env::var("ALLOW_PRIVATE_TARGETS")
        .map(|v| v == "1")
        .unwrap_or(false);

    let tls_acceptor = Arc::new(make_tls_acceptor()?);
    let session_table = new_session_table();
    let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS));

    // C-3: Per-source-IP rate limiter for Init packets (bounds argon2id work).
    let init_cooldown: Arc<tokio::sync::Mutex<HashMap<IpAddr, std::time::Instant>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let activation_fds_i32: Vec<i32> = activation_fds.iter().map(|&fd| fd.into()).collect();

    // systemd socket activation: adopt pre-bound FDs if present.
    let tcp_ln = if !activation_fds_i32.is_empty() {
        #[cfg(unix)]
        {
            eprintln!(
                "snell-server: using systemd socket activation (fd {})",
                activation_fds_i32[0]
            );
            let tcp_ln = snell::activation::into_tcp_listener(activation_fds_i32[0])?;
            if quic_enabled && let Some(&udp_fd) = activation_fds_i32.get(1) {
                let udp_sock = snell::activation::into_udp_socket(udp_fd)?;
                spawn_udp_listener(
                    udp_sock,
                    session_table.clone(),
                    psk.clone(),
                    egress_iface.clone(),
                    allow_private,
                    init_cooldown.clone(),
                );
            }
            tcp_ln
        }
        #[cfg(not(unix))]
        {
            TcpListener::bind(listen).await?
        }
    } else {
        let ln = TcpListener::bind(listen).await?;
        if quic_enabled {
            let udp_sock = snell::egress::bind_udp(listen, None)?;
            spawn_udp_listener(
                udp_sock,
                session_table.clone(),
                psk.clone(),
                egress_iface.clone(),
                allow_private,
                init_cooldown.clone(),
            );
        }
        ln
    };

    eprintln!(
        "snell-server v5 listening on {listen}  \
         (plain / obfs=http / obfs=tls{}{})",
        if quic_enabled { " / QUIC" } else { "" },
        egress_iface
            .as_deref()
            .map(|i| format!(" / egress={i}"))
            .unwrap_or_default(),
    );

    // GC idle QUIC sessions every 30 s.
    if quic_enabled {
        let table = session_table.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                gc_sessions(&table, 60).await;
            }
        });
    }

    loop {
        let (conn, peer) = tcp_ln.accept().await?;
        let permit = match conn_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("[{peer}] dropped: connection limit");
                continue;
            }
        };
        let psk = psk.clone();
        let tls_acceptor = tls_acceptor.clone();
        let iface = egress_iface.clone();
        tokio::spawn(async move {
            let _permit = permit; // released on drop
            if let Err(e) = dispatch(
                conn,
                &psk,
                &tls_acceptor,
                iface.as_deref().map(String::as_str),
                allow_private,
            )
            .await
            {
                eprintln!("[{peer}] {e}");
            }
        });
    }
}

fn make_tls_acceptor() -> Result<TlsAcceptor> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["snell".to_string()])?;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let certs = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn spawn_udp_listener(
    sock: tokio::net::UdpSocket,
    table: SessionTable,
    psk: Arc<Vec<u8>>,
    iface: Option<Arc<String>>,
    allow_private: bool,
    init_cooldown: Arc<tokio::sync::Mutex<HashMap<IpAddr, std::time::Instant>>>,
) {
    let sock = Arc::new(sock);
    tokio::spawn(async move {
        if let Err(e) = run_udp_relay(sock, table, psk, iface, allow_private, init_cooldown).await {
            eprintln!("[QUIC UDP] {e}");
        }
    });
}

/// Check whether an IPv4 address is safe to proxy to.
fn is_safe_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    // Block: loopback, private, link-local, broadcast, this-host (0.0.0.0/8),
    // CGNAT (100.64.0.0/10), unspecified.
    !v4.is_loopback()
        && !v4.is_private()
        && !v4.is_link_local()
        && !v4.is_broadcast()
        && !v4.is_unspecified()
        && (octets[0] != 0) // 0.0.0.0/8 this-host (RFC 1122)
        && !(octets[0] == 100 && (octets[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT (RFC 6598)
}

/// Returns false for addresses that should never be proxy targets (SSRF guard).
/// `allow_private` is read once at startup and passed in (C-4).
fn is_safe_target(addr: &SocketAddr, allow_private: bool) -> bool {
    if allow_private {
        return true;
    }
    let ip = addr.ip();
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => is_safe_v4(v4),
        IpAddr::V6(v6) => {
            // C-1: Unwrap IPv4-mapped addresses (::ffff:a.b.c.d) and apply IPv4 rules.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_safe_v4(v4);
            }
            !v6.is_loopback()
                && !v6.is_unspecified()
                && (v6.segments()[0] & 0xfe00) != 0xfc00 // unique local fc00::/7
                && (v6.segments()[0] & 0xffc0) != 0xfe80 // link-local fe80::/10
        }
    }
}

/// UDP relay loop: classify datagrams by byte[0] and route by source sockaddr.
async fn run_udp_relay(
    sock: Arc<tokio::net::UdpSocket>,
    table: SessionTable,
    psk: Arc<Vec<u8>>,
    iface: Option<Arc<String>>,
    allow_private: bool,
    init_cooldown: Arc<tokio::sync::Mutex<HashMap<IpAddr, std::time::Instant>>>,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        if n == 0 {
            continue;
        }

        let kind = match snell::quic::classify(&buf[..n]) {
            Some(k) => k,
            None => continue,
        };

        // H-6: Data path uses read lock for concurrency.
        let session = { table.read().await.get(&src).cloned() };

        match (kind, session) {
            (snell::quic::PacketKind::Data, None) => {
                eprintln!("[QUIC] data packet without session from {src}");
            }
            (snell::quic::PacketKind::Data, Some(session)) => {
                session.touch();
                let _ = session.target_sock.send(&buf[..n]).await;
            }
            (snell::quic::PacketKind::Init, _) => {
                if n < 16 + snell::cipher::HDR_CT_LEN + 16 {
                    eprintln!("[QUIC] init too short from {src}");
                    continue;
                }

                // C-3: Per-IP rate limit to throttle argon2id work.
                {
                    let now = std::time::Instant::now();
                    let mut cool = init_cooldown.lock().await;
                    if let Some(&last) = cool.get(&src.ip())
                        && now.duration_since(last).as_millis() < INIT_COOLDOWN_MS
                    {
                        eprintln!("[QUIC] init rate-limited from {src}");
                        continue;
                    }
                    cool.insert(src.ip(), now);
                    // GC stale entries to bound map growth.
                    if cool.len() > 10_000 {
                        let cutoff = now
                            .checked_sub(std::time::Duration::from_secs(60))
                            .unwrap_or(now);
                        cool.retain(|_, t| *t >= cutoff);
                    }
                }

                // C-3: Cap on total concurrent sessions.
                {
                    if table.read().await.len() >= MAX_UDP_SESSIONS {
                        eprintln!("[QUIC] session table full, dropping init from {src}");
                        continue;
                    }
                }

                // SAFETY: length guarded by the `< 16 + HDR_CT_LEN + 16` check above.
                let salt: [u8; 16] = buf[..16].try_into().expect("guarded above");
                let req = match snell::quic::decrypt_init(&psk, &salt, &buf[16..n]) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[QUIC] decrypt fail from {src}: {e}");
                        continue;
                    }
                };
                eprintln!("[QUIC] CONNECT_UDP from {src} -> {}:{}", req.host, req.port);

                // Resolve and SSRF-check
                let target_addr: SocketAddr =
                    match tokio::net::lookup_host(format!("{}:{}", req.host, req.port))
                        .await
                        .ok()
                        .and_then(|mut it| it.next())
                    {
                        Some(a) => a,
                        None => continue,
                    };
                if !is_safe_target(&target_addr, allow_private) {
                    eprintln!("[QUIC SSRF] blocked {target_addr}");
                    continue;
                }

                // Bind outbound UDP socket (with optional egress interface)
                let target_sock = match snell::egress::bind_udp(
                    "0.0.0.0:0".parse().expect("static"),
                    iface.as_deref().map(String::as_str),
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[QUIC] bind: {e}");
                        continue;
                    }
                };
                if let Err(e) = target_sock.connect(target_addr).await {
                    eprintln!("[QUIC] connect: {e}");
                    continue;
                }
                let target_sock = Arc::new(target_sock);

                // If trailing data exists in init payload, forward it to target now.
                if !req.trailing.is_empty() {
                    let _ = target_sock.send(&req.trailing).await;
                }

                let session = Arc::new(UdpSession {
                    client_addr: src,
                    target_sock: target_sock.clone(),
                    last_seen: AtomicU64::new(0),
                });
                session.touch();
                // H-6: Init path uses write lock.
                table.write().await.insert(src, session.clone());

                // Spawn target -> client forwarding task.
                // H-1: Remove the session from the table when the relay exits.
                let sock_back = sock.clone();
                let table_cleanup = table.clone();
                tokio::spawn(async move {
                    let mut rbuf = vec![0u8; 65535];
                    while let Ok(m) = target_sock.recv(&mut rbuf).await {
                        if m == 0 {
                            break;
                        }
                        if sock_back.send_to(&rbuf[..m], src).await.is_err() {
                            break;
                        }
                        session.touch();
                    }
                    table_cleanup.write().await.remove(&src);
                });
            }
        }
    }
}

async fn dispatch(
    mut conn: TcpStream,
    psk: &[u8],
    tls: &TlsAcceptor,
    iface: Option<&str>,
    allow_private: bool,
) -> Result<()> {
    // Bound only the obfs handshake (peek + optional HTTP/TLS upgrade).
    // The relay loop inside handle() must not be bounded.
    let handshake_deadline = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);

    let mut first = [0u8; 1];
    tokio::time::timeout(handshake_deadline, conn.peek(&mut first))
        .await
        .map_err(|_| anyhow::anyhow!("obfs peek timeout"))??;

    match first[0] {
        0x16 => {
            let stream = tokio::time::timeout(handshake_deadline, tls.accept(conn))
                .await
                .map_err(|_| anyhow::anyhow!("TLS accept timeout"))??;
            handle(stream, psk, iface, allow_private).await
        }
        b'G' => {
            tokio::time::timeout(handshake_deadline, absorb_http_request(&mut conn))
                .await
                .map_err(|_| anyhow::anyhow!("HTTP obfs timeout"))??;
            conn.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\r\n",
            )
            .await?;
            handle(conn, psk, iface, allow_private).await
        }
        _ => handle(conn, psk, iface, allow_private).await,
    }
}

/// H-5: Chunked read with sliding-window terminator search instead of byte-by-byte.
async fn absorb_http_request(conn: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8; 4096];
    // Carry the last 3 bytes across reads so the \r\n\r\n boundary is never split.
    let mut tail = [0u8; 3];
    let mut tail_len = 0usize;
    let mut total = 0usize;
    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            bail!("connection closed during HTTP obfs");
        }
        total += n;
        if total > 8192 {
            bail!("HTTP obfs request too large");
        }
        // Build search slice from carry-over + new bytes.
        let mut search = Vec::with_capacity(tail_len + n);
        search.extend_from_slice(&tail[..tail_len]);
        search.extend_from_slice(&buf[..n]);
        if search.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(());
        }
        // Carry the last 3 bytes into the next iteration.
        let keep = n.min(3);
        tail[..keep].copy_from_slice(&buf[n - keep..n]);
        tail_len = keep;
    }
}

async fn handle<S>(mut conn: S, psk: &[u8], iface: Option<&str>, allow_private: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Bound the initial salt-exchange read; the relay loop below must not be bounded.
    let mut client_salt = [0u8; SALT_LEN];
    tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        conn.read_exact(&mut client_salt),
    )
    .await
    .map_err(|_| anyhow::anyhow!("salt-exchange timeout"))??;
    let mut c2s = SnellCipher::new(psk, &client_salt)?;

    let (server_salt, mut s2c) = SnellCipher::with_random_salt(psk)?;
    conn.write_all(&server_salt).await?;

    loop {
        let Some(payload) = read_chunk(&mut conn, &mut c2s).await? else {
            break;
        };
        let req = parse_request(&payload)?;

        if req.command == CMD_PING {
            conn.write_all(&s2c.seal(&[RESP_PONG])?).await?;
            continue;
        }

        // ── Normal TCP CONNECT ────────────────────────────────────────────────
        if req.command != CMD_CONNECT && req.command != CMD_CONNECT_V2 {
            bail!("unknown command {:#04x}", req.command);
        }

        eprintln!("CONNECT → {}:{}", req.host, req.port);

        let target_addr: SocketAddr = tokio::net::lookup_host(format!("{}:{}", req.host, req.port))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS: no address for {}", req.host))?;

        if !is_safe_target(&target_addr, allow_private) {
            eprintln!(
                "[SSRF] blocked CONNECT → {}:{} (resolved to {})",
                req.host, req.port, target_addr
            );
            let mut r = vec![RESP_ERROR, 0u8, 9];
            r.extend_from_slice(b"forbidden");
            conn.write_all(&s2c.seal(&r)?).await?;
            continue;
        }

        let mut target = match snell::egress::connect_tcp(target_addr, iface).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[connect-fail] {}:{}: {e}", req.host, req.port); // server-side detail
                // Generic public error — don't leak internal details
                let msg = b"connection failed";
                let mut r = vec![RESP_ERROR, 0u8, msg.len() as u8];
                r.extend_from_slice(msg);
                conn.write_all(&s2c.seal(&r)?).await?;
                continue;
            }
        };

        conn.write_all(&s2c.seal(&[RESP_TUNNEL])?).await?;

        if !req.trailing.is_empty() {
            target.write_all(&req.trailing).await?;
        }

        let (cr, cw) = tokio::io::split(conn);
        let (tr, mut tw) = tokio::io::split(target);

        // c2t: client → target (decrypt Snell chunks, write raw to target)
        let c2t = async move {
            let mut cr = cr;
            let mut c2s = c2s;
            loop {
                match read_chunk(&mut cr, &mut c2s).await? {
                    None => break,
                    Some(d) => tw.write_all(&d).await?,
                }
            }
            tw.shutdown().await?;
            Ok::<_, anyhow::Error>((cr, c2s))
        };

        // t2c: target → client (adaptive chunk sizing, encrypt Snell chunks)
        let t2c = copy_t2c_adaptive(tr, cw, s2c);

        let ((cr, c2s_new), (cw, s2c_new)) = tokio::try_join!(c2t, t2c)?;

        c2s = c2s_new;
        s2c = s2c_new;
        conn = cr.unsplit(cw);
    }

    Ok(())
}
