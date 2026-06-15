//! snell-server — open-source Snell v5 server.
//! Usage: PSK=yourpsk snell-server [listen_addr]
//! Default listen: 0.0.0.0:6180
//!
//! Environment variables:
//!   PSK                   Pre-shared key (required, min 16 chars)
//!   EGRESS_INTERFACE      Bind outgoing connections to this network interface
//!   IPV6=1                Allow IPv6 outbound targets. Default off (IPv4-only
//!                         egress), matching official snell-server `ipv6=false`:
//!                         AAAA results are skipped unless this is set.
//!   DNS                   Comma-separated upstream DNS server IPs for resolving
//!                         target hostnames (e.g. DNS=1.1.1.1,8.8.8.8). Queried
//!                         over UDP+TCP port 53. Unset = system resolver.
//!   QUIC=1                Enable QUIC proxy mode (opens UDP on same port)
//!   BLOCK_PRIVATE_TARGETS=1  Refuse to proxy to loopback/private/reserved addresses
//!                            (default: allow — proxying to LAN is a legit use case)
//!   TCP_FASTOPEN=0        Disable server-side TCP Fast Open (default: on, matches
//!                         official snell-server). The effective state still needs
//!                         the kernel sysctl (Linux net.ipv4.tcp_fastopen bit 2;
//!                         macOS net.inet.tcp.fastopen bit 2).
//!   TCP_FASTOPEN_OUT=1    Opt outbound CONNECT sockets into TCP Fast Open.
//!                         Off by default — many targets don't speak TFO and the
//!                         kernel falls back to a normal handshake, but enabling
//!                         it requires Linux >= 4.11 and the sysctl client bit
//!                         (no-op on macOS).
//!   TCP_HANDSHAKE_COOLDOWN_MS  Minimum milliseconds between fresh TCP handshakes
//!                         from the same source IP. Default 100. Set to 0 to
//!                         disable. Bounds the argon2id work an attacker can
//!                         induce from a single IP.
//!
//! Obfuscation auto-detected from first byte:
//!   plain    — random Snell salt
//!   obfs=http — 'G' (HTTP GET WebSocket upgrade)
//!   obfs=tls  — 0x16 (TLS ClientHello)

use anyhow::{Result, bail};
use snell::cipher::{SALT_LEN, SnellCipher};
use snell::quic::{SessionTable, UdpSession, gc_sessions, new_session_table};
use snell::relay::copy_t2c_adaptive;
use snell::resolver::Resolver;
use snell::salt_cache::SaltCache;
use snell::snell::{
    CMD_CONNECT, CMD_CONNECT_UDP, CMD_CONNECT_V2, CMD_PING, RESP_ERROR, RESP_PONG, RESP_TUNNEL,
    parse_request, read_chunk, write_chunk,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::interval;
use tokio_rustls::{TlsAcceptor, rustls};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::io::RawFd;

/// PSK byte buffer that zeros itself on drop. Wrap in `Arc<...>` so workers
/// share the single allocation; when the last clone drops at process exit /
/// teardown, the bytes are scrubbed (best-effort: defends against core dumps
/// and swap, but not against transient compiler-spilled register copies).
type Psk = Arc<Zeroizing<Vec<u8>>>;

// T2-F: Per-phase handshake budgets. The single 30s blanket was too generous
// for slowloris-style attackers (one socket could squat for the full window
// even before any argon2id work). These splits keep ~10x headroom over real
// handshakes on high-latency mobile links (~300 ms RTT) while shrinking the
// per-connection occupancy ceiling from 30 s to ~25 s worst case.
const PEEK_TIMEOUT_SECS: u64 = 5; //   first-byte obfs detect peek
const OBFS_HANDSHAKE_TIMEOUT_SECS: u64 = 10; //   TLS accept / HTTP absorb
const SALT_HANDSHAKE_TIMEOUT_SECS: u64 = 10; //   16-byte salt read + argon2id

const MAX_CONCURRENT_CONNS: usize = 4096;

// C-3: Cap on concurrent QUIC sessions to bound argon2id work.
const MAX_UDP_SESSIONS: usize = 8192;
// C-3: Minimum milliseconds between Init packets from the same source IP.
const INIT_COOLDOWN_MS: u128 = 1000;
// H-7: Default TCP handshake cooldown per source IP — bounds argon2id work
// the way INIT_COOLDOWN_MS does for QUIC. Tunable via TCP_HANDSHAKE_COOLDOWN_MS,
// 0 to disable. Default favors connection-reuse-heavy clients (Surge) over
// rapid reconnects from a single IP.
const TCP_HANDSHAKE_COOLDOWN_MS_DEFAULT: u128 = 100;
// Cap on cooldown-map size before GC kicks in (mirrors QUIC init_cooldown).
const COOLDOWN_GC_THRESHOLD: usize = 10_000;
// Idle window after which a cooldown entry is eligible for GC eviction.
const COOLDOWN_GC_IDLE_SECS: u64 = 60;

type IpCooldownMap = Arc<parking_lot::Mutex<HashMap<IpAddr, std::time::Instant>>>;

fn main() -> Result<()> {
    snell::logging::init();

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

    let listen: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:6180".into())
        .parse()?;

    let psk_str = std::env::var("PSK")
        .map_err(|_| anyhow::anyhow!("PSK environment variable is required"))?;
    if psk_str.len() < 16 {
        anyhow::bail!("PSK must be at least 16 bytes (got {})", psk_str.len());
    }
    // T2-G: Wrap in Zeroizing so the PSK bytes are scrubbed when the Arc's
    // final clone is dropped (best-effort defense against core dumps / swap).
    let psk: Psk = Arc::new(Zeroizing::new(psk_str.into_bytes()));

    let egress_iface: Option<Arc<String>> = std::env::var("EGRESS_INTERFACE").ok().map(Arc::new);
    let quic_enabled = std::env::var("QUIC").map(|v| v == "1").unwrap_or(false);
    // C-4: Read BLOCK_PRIVATE_TARGETS once at startup instead of on every call.
    // Default is false (allow private targets) — this is a proxy tool and LAN
    // access is a legitimate use case. Set BLOCK_PRIVATE_TARGETS=1 for hardened
    // VPS deployments where the server is exposed to the internet.
    let block_private = std::env::var("BLOCK_PRIVATE_TARGETS")
        .map(|v| v == "1")
        .unwrap_or(false);
    // IPv6 egress toggle. Default false (IPv4-only outbound) to match official
    // snell-server's `ipv6=false`: AAAA results are skipped unless explicitly
    // enabled. Set IPV6=1 to allow IPv6 targets.
    let ipv6 = std::env::var("IPV6").map(|v| v == "1").unwrap_or(false);
    // Outbound DNS resolver. Defaults to the system resolver; when DNS lists
    // upstream IPs (e.g. DNS=1.1.1.1,8.8.8.8) a hickory resolver is built. The
    // IPv6 toggle is folded in so all resolution honors it uniformly.
    let resolver = Arc::new(Resolver::from_env(ipv6)?);
    // TCP_FASTOPEN defaults to on (matches official snell-server).
    // Explicitly set TCP_FASTOPEN=0 to disable. Anything else (including unset
    // or "1") leaves it enabled. The effective state still requires the kernel
    // sysctl to permit server-side TFO.
    let tfo_listen = std::env::var("TCP_FASTOPEN")
        .map(|v| v != "0")
        .unwrap_or(true);
    // Outbound TFO is opt-in: many targets don't speak it, and although the
    // kernel transparently falls back, the extra syscall costs nothing only
    // when it actually buys us a half-RTT win on persistent destinations.
    let tfo_out = std::env::var("TCP_FASTOPEN_OUT")
        .map(|v| v == "1")
        .unwrap_or(false);
    // H-7: Per-source-IP TCP handshake cooldown. Read once at startup; the
    // env var accepts a decimal millisecond count, 0 disables.
    let tcp_handshake_cooldown_ms: u128 = std::env::var("TCP_HANDSHAKE_COOLDOWN_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(TCP_HANDSHAKE_COOLDOWN_MS_DEFAULT);

    let tls_acceptor = Arc::new(make_tls_acceptor()?);
    let session_table = new_session_table();
    let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS));

    // C-3: Per-source-IP rate limiter for QUIC Init packets (bounds argon2id work).
    // parking_lot::Mutex chosen over tokio::sync::Mutex — the critical section is
    // microseconds (peek + maybe insert), so the synchronous lock is correct here.
    let init_cooldown: IpCooldownMap = Arc::new(parking_lot::Mutex::new(HashMap::new()));
    // H-7: Per-source-IP TCP handshake cooldown (parallel to QUIC INIT_COOLDOWN).
    // Lazily constructed only when the env-configured cooldown is non-zero, since
    // the accept loop fast-paths around it when disabled.
    let tcp_cooldown: IpCooldownMap = Arc::new(parking_lot::Mutex::new(HashMap::new()));

    // CVE-3: Salt replay protection — shared across TCP and QUIC paths.
    let salt_cache = SaltCache::new();

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
                    block_private,
                    resolver.clone(),
                    init_cooldown.clone(),
                    salt_cache.clone(),
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
                block_private,
                resolver.clone(),
                init_cooldown.clone(),
                salt_cache.clone(),
            );
        }
        ln
    };

    let tfo_active = if tfo_listen {
        apply_listen_tfo(&tcp_ln)
    } else {
        false
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
    if tfo_active {
        eprintln!("<NOTIFY> TCP Fast Open enabled");
    }

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

        // H-7: Per-source-IP TCP handshake cooldown — checked before the
        // semaphore acquire so a rate-limited IP doesn't briefly consume a slot.
        if tcp_handshake_cooldown_ms > 0
            && !cooldown_check_and_insert(&tcp_cooldown, peer.ip(), tcp_handshake_cooldown_ms)
        {
            tracing::warn!(%peer, "dropped: handshake rate-limited");
            drop(conn);
            continue;
        }

        let permit = match conn_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(%peer, "dropped: connection limit");
                continue;
            }
        };
        let psk = psk.clone();
        let tls_acceptor = tls_acceptor.clone();
        let iface = egress_iface.clone();
        let resolver = resolver.clone();
        let salt_cache_per_conn = salt_cache.clone();
        tokio::spawn(async move {
            let _permit = permit; // released on drop
            if let Err(e) = dispatch(
                conn,
                &psk,
                &tls_acceptor,
                iface.as_deref().map(String::as_str),
                block_private,
                &resolver,
                tfo_out,
                &salt_cache_per_conn,
            )
            .await
            {
                tracing::error!(%peer, error = %e, "connection failed");
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

/// Atomic per-source-IP cooldown check. Returns `true` if the IP is allowed
/// through (and records the current timestamp); `false` if the previous entry
/// is younger than `cooldown_ms`. Used by both the TCP accept loop and the
/// QUIC Init handler with their own cooldown maps and intervals.
fn cooldown_check_and_insert(
    map: &Arc<parking_lot::Mutex<HashMap<IpAddr, std::time::Instant>>>,
    ip: IpAddr,
    cooldown_ms: u128,
) -> bool {
    let now = std::time::Instant::now();
    let mut cool = map.lock();
    if let Some(&last) = cool.get(&ip)
        && now.duration_since(last).as_millis() < cooldown_ms
    {
        return false;
    }
    cool.insert(ip, now);
    if cool.len() > COOLDOWN_GC_THRESHOLD {
        let cutoff = now
            .checked_sub(Duration::from_secs(COOLDOWN_GC_IDLE_SECS))
            .unwrap_or(now);
        cool.retain(|_, t| *t >= cutoff);
    }
    true
}

/// Best-effort `TCP_FASTOPEN` setsockopt on the listening socket.
/// Returns true when the option was successfully applied. Failures are logged
/// and swallowed — the listener still works without TFO when the kernel sysctl
/// doesn't permit server-side cookies.
fn apply_listen_tfo(_ln: &TcpListener) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        match snell::tfo::enable_listen_tfo(_ln.as_raw_fd()) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "TCP Fast Open setsockopt failed; continuing without TFO"
                );
                false
            }
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_udp_listener(
    sock: tokio::net::UdpSocket,
    table: SessionTable,
    psk: Psk,
    iface: Option<Arc<String>>,
    block_private: bool,
    resolver: Arc<Resolver>,
    init_cooldown: IpCooldownMap,
    salt_cache: SaltCache,
) {
    let sock = Arc::new(sock);
    tokio::spawn(async move {
        if let Err(e) = run_udp_relay(
            sock,
            table,
            psk,
            iface,
            block_private,
            resolver,
            init_cooldown,
            salt_cache,
        )
        .await
        {
            tracing::error!(error = %e, "QUIC UDP relay loop fatal");
        }
    });
}

/// Check whether an IPv4 address is safe to proxy to.
fn is_safe_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    // Block: loopback, private, link-local, broadcast, this-host (0.0.0.0/8),
    // CGNAT (100.64.0.0/10), IETF Protocol Assignments (192.0.0.0/24), unspecified.
    !v4.is_loopback()
        && !v4.is_private()
        && !v4.is_link_local()
        && !v4.is_broadcast()
        && !v4.is_unspecified()
        && (octets[0] != 0) // 0.0.0.0/8 this-host (RFC 1122)
        && !(octets[0] == 100 && (octets[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT (RFC 6598)
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // 192.0.0.0/24 IETF Protocol Assignments (RFC 6890)
}

/// Returns false for addresses that should never be proxy targets (SSRF guard).
/// `block_private` is read once at startup and passed in (C-4).
/// When false (the default), all targets are allowed — snell is a proxy tool
/// and LAN forwarding is a legitimate use case.
fn is_safe_target(addr: &SocketAddr, block_private: bool) -> bool {
    if !block_private {
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
#[allow(clippy::too_many_arguments)]
async fn run_udp_relay(
    sock: Arc<tokio::net::UdpSocket>,
    table: SessionTable,
    psk: Psk,
    iface: Option<Arc<String>>,
    block_private: bool,
    resolver: Arc<Resolver>,
    init_cooldown: IpCooldownMap,
    salt_cache: SaltCache,
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
                tracing::warn!(%src, "QUIC data packet without session");
            }
            (snell::quic::PacketKind::Data, Some(session)) => {
                session.touch();
                let _ = session.target_sock.send(&buf[..n]).await;
            }
            (snell::quic::PacketKind::Init, _) => {
                handle_quic_init(
                    &buf[..n],
                    src,
                    &sock,
                    &table,
                    &psk,
                    iface.as_deref().map(String::as_str),
                    block_private,
                    &resolver,
                    &init_cooldown,
                    &salt_cache,
                )
                .await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_quic_init(
    packet: &[u8],
    src: SocketAddr,
    sock: &Arc<tokio::net::UdpSocket>,
    table: &SessionTable,
    psk: &[u8],
    iface: Option<&str>,
    block_private: bool,
    resolver: &Resolver,
    init_cooldown: &IpCooldownMap,
    salt_cache: &SaltCache,
) {
    let n = packet.len();

    if n < 16 + snell::cipher::HDR_CT_LEN + 16 {
        tracing::warn!(%src, "QUIC init too short");
        return;
    }

    // C-3: Per-IP rate limit to throttle argon2id work.
    if !cooldown_check_and_insert(init_cooldown, src.ip(), INIT_COOLDOWN_MS) {
        tracing::warn!(%src, "QUIC init rate-limited");
        return;
    }

    // C-3: Cap on total concurrent sessions.
    if table.read().await.len() >= MAX_UDP_SESSIONS {
        tracing::warn!(%src, "QUIC session table full, dropping init");
        return;
    }

    // SAFETY: length guarded by the `< 16 + HDR_CT_LEN + 16` check above.
    let salt: [u8; 16] = packet[..16].try_into().expect("guarded above");

    // CVE-3: Reject replayed salts before the costly argon2id KDF runs.
    if !salt_cache.check_and_insert(&salt) {
        tracing::warn!(%src, "QUIC salt replay detected, dropping");
        return;
    }

    let req = match snell::quic::decrypt_init(psk, &salt, &packet[16..]) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%src, error = %e, "QUIC decrypt failed");
            return;
        }
    };
    tracing::debug!(%src, host = %req.host, port = req.port, "QUIC CONNECT_UDP");

    // Resolve and SSRF-check
    let target_addr: SocketAddr = match resolver.resolve(&req.host, req.port).await {
        Ok(Some(a)) => a,
        Ok(None) | Err(_) => return,
    };
    if !is_safe_target(&target_addr, block_private) {
        tracing::warn!(%target_addr, "QUIC SSRF blocked");
        return;
    }

    // Bind outbound UDP socket (with optional egress interface)
    let target_sock = match snell::egress::bind_udp("0.0.0.0:0".parse().expect("static"), iface) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "QUIC outbound bind failed");
            return;
        }
    };
    if let Err(e) = target_sock.connect(target_addr).await {
        tracing::warn!(error = %e, "QUIC outbound connect failed");
        return;
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

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    mut conn: TcpStream,
    psk: &[u8],
    tls: &TlsAcceptor,
    iface: Option<&str>,
    block_private: bool,
    resolver: &Resolver,
    tfo_out: bool,
    salt_cache: &SaltCache,
) -> Result<()> {
    // T2-F: each handshake phase has its own budget so a slow attacker can't
    // squat the full 30 s on a single phase. The relay loop inside handle()
    // is intentionally unbounded — only the handshake stages are timed.
    let peek_budget = Duration::from_secs(PEEK_TIMEOUT_SECS);
    let obfs_budget = Duration::from_secs(OBFS_HANDSHAKE_TIMEOUT_SECS);

    let mut first = [0u8; 1];
    tokio::time::timeout(peek_budget, conn.peek(&mut first))
        .await
        .map_err(|_| anyhow::anyhow!("obfs peek timeout"))??;

    match first[0] {
        0x16 => {
            let stream = tokio::time::timeout(obfs_budget, tls.accept(conn))
                .await
                .map_err(|_| anyhow::anyhow!("TLS accept timeout"))??;
            handle(
                stream,
                psk,
                iface,
                block_private,
                resolver,
                tfo_out,
                salt_cache,
            )
            .await
        }
        b'G' => {
            tokio::time::timeout(obfs_budget, absorb_http_request(&mut conn))
                .await
                .map_err(|_| anyhow::anyhow!("HTTP obfs timeout"))??;
            conn.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\r\n",
            )
            .await?;
            handle(
                conn,
                psk,
                iface,
                block_private,
                resolver,
                tfo_out,
                salt_cache,
            )
            .await
        }
        _ => {
            handle(
                conn,
                psk,
                iface,
                block_private,
                resolver,
                tfo_out,
                salt_cache,
            )
            .await
        }
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

#[allow(clippy::too_many_arguments)]
async fn handle<S>(
    mut conn: S,
    psk: &[u8],
    iface: Option<&str>,
    block_private: bool,
    resolver: &Resolver,
    tfo_out: bool,
    salt_cache: &SaltCache,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Bound the salt-exchange + KDF phase; the relay loop below must not be bounded.
    let mut client_salt = [0u8; SALT_LEN];
    tokio::time::timeout(
        Duration::from_secs(SALT_HANDSHAKE_TIMEOUT_SECS),
        conn.read_exact(&mut client_salt),
    )
    .await
    .map_err(|_| anyhow::anyhow!("salt-exchange timeout"))??;

    // CVE-3: Reject replayed salts before the costly argon2id KDF runs.
    if !salt_cache.check_and_insert(&client_salt) {
        bail!("salt replay detected");
    }

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

        // ── UDP-over-TCP ──────────────────────────────────────────────────────
        // Consumes the connection (no v5 reuse for UDP sessions).
        if req.command == CMD_CONNECT_UDP {
            tracing::debug!("CONNECT_UDP");
            return relay_udp(conn, c2s, s2c, req.trailing, iface, block_private, resolver).await;
        }

        // ── Normal TCP CONNECT ────────────────────────────────────────────────
        if req.command != CMD_CONNECT && req.command != CMD_CONNECT_V2 {
            bail!("unknown command {:#04x}", req.command);
        }

        tracing::debug!(host = %req.host, port = req.port, "CONNECT");

        let target_addr: SocketAddr = resolver
            .resolve(&req.host, req.port)
            .await?
            .ok_or_else(|| anyhow::anyhow!("DNS: no address for {}", req.host))?;

        if !is_safe_target(&target_addr, block_private) {
            tracing::warn!(
                host = %req.host,
                port = req.port,
                resolved = %target_addr,
                "SSRF blocked CONNECT"
            );
            let mut r = vec![RESP_ERROR, 0u8, 9];
            r.extend_from_slice(b"forbidden");
            conn.write_all(&s2c.seal(&r)?).await?;
            continue;
        }

        let mut target = match snell::egress::connect_tcp(target_addr, iface, tfo_out).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(host = %req.host, port = req.port, error = %e, "outbound connect failed");
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

/// Relay a Snell UDP-over-TCP session. Consumes the connection (no v5 reuse for
/// UDP). The handshake is done; `c2s`/`s2c` are the live ciphers and `trailing`
/// is any datagram bundled with the request chunk. One datagram = one chunk.
async fn relay_udp<S>(
    mut conn: S,
    mut c2s: SnellCipher,
    mut s2c: SnellCipher,
    trailing: Vec<u8>,
    iface: Option<&str>,
    block_private: bool,
    resolver: &Resolver,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    conn.write_all(&s2c.seal(&[RESP_TUNNEL])?).await?;

    let sock = Arc::new(snell::egress::bind_udp(
        "0.0.0.0:0".parse().expect("static"),
        iface,
    )?);

    // The first datagram may be bundled with the handshake chunk.
    if !trailing.is_empty() {
        forward_udp_frame(&trailing, &sock, block_private, resolver).await;
    }

    let (mut cr, mut cw) = tokio::io::split(conn);
    let up_sock = sock.clone();

    // tunnel → target: each inbound chunk is one datagram frame.
    let up = async move {
        while let Some(frame) = read_chunk(&mut cr, &mut c2s).await? {
            forward_udp_frame(&frame, &up_sock, block_private, resolver).await;
        }
        Ok::<_, anyhow::Error>(())
    };

    // target → tunnel: one datagram → one chunk, source address prepended.
    let down = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = sock.recv_from(&mut buf).await?;
            let frame = snell::snell::encode_udp_response(src, &buf[..n]);
            write_chunk(&mut cw, &mut s2c, &frame).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    // The session ends when the tunnel closes (up returns) or either errors.
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

/// Decode one UoT datagram frame, resolve + SSRF-check the target, and forward
/// the payload out the egress socket. A single malformed/blocked datagram is
/// logged and dropped — it must not tear down the session.
async fn forward_udp_frame(
    frame: &[u8],
    sock: &tokio::net::UdpSocket,
    block_private: bool,
    resolver: &Resolver,
) {
    let req = match snell::snell::parse_udp_request(frame) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "dropping malformed UDP frame");
            return;
        }
    };
    let target = match resolver.resolve(&req.host, req.port).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            tracing::warn!(host = %req.host, "UDP target unresolved");
            return;
        }
        Err(e) => {
            tracing::warn!(host = %req.host, error = %e, "UDP resolve failed");
            return;
        }
    };
    if !is_safe_target(&target, block_private) {
        tracing::warn!(%target, "UDP SSRF blocked");
        return;
    }
    if let Err(e) = sock.send_to(req.payload, target).await {
        tracing::warn!(%target, error = %e, "UDP send failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 443)
    }

    fn v6(s: &str) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(s.parse::<Ipv6Addr>().unwrap()), 443)
    }

    #[test]
    fn cooldown_admits_first_then_rate_limits_within_window() {
        let map: IpCooldownMap = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        // First call admits.
        assert!(cooldown_check_and_insert(&map, ip, 1000));
        // Same IP within the 1000 ms window: rejected.
        assert!(!cooldown_check_and_insert(&map, ip, 1000));
    }

    #[test]
    fn cooldown_isolates_per_ip() {
        let map: IpCooldownMap = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let a: IpAddr = "203.0.113.7".parse().unwrap();
        let b: IpAddr = "198.51.100.42".parse().unwrap();
        assert!(cooldown_check_and_insert(&map, a, 1000));
        // Different IP must not be rate-limited by A's recent entry.
        assert!(cooldown_check_and_insert(&map, b, 1000));
        // Both individual IPs are now in cooldown.
        assert!(!cooldown_check_and_insert(&map, a, 1000));
        assert!(!cooldown_check_and_insert(&map, b, 1000));
    }

    #[test]
    fn cooldown_zero_window_never_rate_limits() {
        // Cooldown of 0 ms is the production "disabled" sentinel — every call
        // must admit (even though the helper itself isn't gated on the env var;
        // the accept loop short-circuits when the configured cooldown is 0).
        let map: IpCooldownMap = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        // duration_since(last).as_millis() >= 0 always, so window 0 admits all.
        assert!(cooldown_check_and_insert(&map, ip, 0));
        assert!(cooldown_check_and_insert(&map, ip, 0));
        assert!(cooldown_check_and_insert(&map, ip, 0));
    }

    #[test]
    fn block_private_unset_allows_all_targets() {
        // Default behavior: block_private=false → no SSRF guard, everything passes.
        assert!(is_safe_target(&v4(127, 0, 0, 1), false));
        assert!(is_safe_target(&v4(10, 0, 0, 1), false));
        assert!(is_safe_target(&v4(0, 0, 0, 0), false));
        assert!(is_safe_target(&v6("::1"), false));
        assert!(is_safe_target(&v6("fc00::1"), false));
    }

    // Remaining tests pass block_private=true to exercise the SSRF guard itself.

    #[test]
    fn rejects_ipv4_loopback() {
        assert!(!is_safe_target(&v4(127, 0, 0, 1), true));
        assert!(!is_safe_target(&v4(127, 255, 255, 254), true));
    }

    #[test]
    fn rejects_ipv6_loopback() {
        assert!(!is_safe_target(&v6("::1"), true));
    }

    #[test]
    fn rejects_ipv4_multicast() {
        assert!(!is_safe_target(&v4(224, 0, 0, 1), true));
        assert!(!is_safe_target(&v4(239, 255, 255, 255), true));
    }

    #[test]
    fn rejects_ipv6_multicast() {
        assert!(!is_safe_target(&v6("ff00::1"), true));
        assert!(!is_safe_target(&v6("ff02::1"), true));
    }

    #[test]
    fn rejects_ipv4_unspecified() {
        assert!(!is_safe_target(&v4(0, 0, 0, 0), true));
    }

    #[test]
    fn rejects_ipv6_unspecified() {
        assert!(!is_safe_target(&v6("::"), true));
    }

    #[test]
    fn rejects_rfc1918_ten_dot() {
        assert!(!is_safe_target(&v4(10, 0, 0, 1), true));
        assert!(!is_safe_target(&v4(10, 255, 255, 255), true));
    }

    #[test]
    fn rejects_rfc1918_172_16_through_172_31() {
        assert!(!is_safe_target(&v4(172, 16, 0, 0), true));
        assert!(!is_safe_target(&v4(172, 31, 255, 255), true));
    }

    #[test]
    fn accepts_172_just_below_rfc1918_range() {
        // 172.15.x.x is public, not RFC 1918.
        assert!(is_safe_target(&v4(172, 15, 0, 1), true));
    }

    #[test]
    fn accepts_172_just_above_rfc1918_range() {
        // 172.32.x.x is public, not RFC 1918.
        assert!(is_safe_target(&v4(172, 32, 0, 1), true));
    }

    #[test]
    fn rejects_rfc1918_192_168() {
        assert!(!is_safe_target(&v4(192, 168, 0, 1), true));
        assert!(!is_safe_target(&v4(192, 168, 255, 255), true));
    }

    #[test]
    fn rejects_ipv4_link_local() {
        assert!(!is_safe_target(&v4(169, 254, 0, 1), true));
        assert!(!is_safe_target(&v4(169, 254, 255, 254), true));
    }

    #[test]
    fn rejects_ipv4_broadcast() {
        assert!(!is_safe_target(&v4(255, 255, 255, 255), true));
    }

    #[test]
    fn rejects_this_host_zero_slash_eight() {
        // 0.0.0.0/8 — "this host on this network" (RFC 1122).
        assert!(!is_safe_target(&v4(0, 1, 2, 3), true));
        assert!(!is_safe_target(&v4(0, 255, 255, 255), true));
    }

    #[test]
    fn rejects_cgnat_lower_bound() {
        // 100.64.0.0/10 — CGNAT (RFC 6598).
        assert!(!is_safe_target(&v4(100, 64, 0, 0), true));
    }

    #[test]
    fn rejects_ietf_protocol_assignments_192_0_0() {
        // 192.0.0.0/24 — IETF Protocol Assignments (RFC 6890).
        assert!(!is_safe_target(&v4(192, 0, 0, 0), true));
        assert!(!is_safe_target(&v4(192, 0, 0, 255), true));
    }

    #[test]
    fn accepts_just_outside_ietf_assignments_range() {
        // 192.0.1.0 is just outside /24, must pass.
        assert!(is_safe_target(&v4(192, 0, 1, 0), true));
        // 191.255.255.255 just below, must pass.
        assert!(is_safe_target(&v4(191, 255, 255, 255), true));
    }

    #[test]
    fn rejects_cgnat_upper_bound() {
        assert!(!is_safe_target(&v4(100, 127, 255, 255), true));
    }

    #[test]
    fn accepts_just_below_cgnat_range() {
        assert!(is_safe_target(&v4(100, 63, 255, 255), true));
    }

    #[test]
    fn accepts_just_above_cgnat_range() {
        assert!(is_safe_target(&v4(100, 128, 0, 0), true));
    }

    #[test]
    fn rejects_ipv6_unique_local_fc00() {
        assert!(!is_safe_target(&v6("fc00::1"), true));
    }

    #[test]
    fn rejects_ipv6_unique_local_fd00() {
        // fd00::/8 falls inside fc00::/7.
        assert!(!is_safe_target(&v6("fd12:3456:789a::1"), true));
    }

    #[test]
    fn rejects_ipv6_link_local_fe80() {
        assert!(!is_safe_target(&v6("fe80::1"), true));
        assert!(!is_safe_target(&v6("febf:ffff::1"), true));
    }

    #[test]
    fn rejects_ipv4_mapped_loopback() {
        // C-1: ::ffff:127.0.0.1 must unwrap and re-apply IPv4 rules.
        assert!(!is_safe_target(&v6("::ffff:127.0.0.1"), true));
    }

    #[test]
    fn rejects_ipv4_mapped_private() {
        assert!(!is_safe_target(&v6("::ffff:192.168.1.1"), true));
        assert!(!is_safe_target(&v6("::ffff:10.0.0.1"), true));
    }

    #[test]
    fn rejects_ipv4_mapped_cgnat() {
        assert!(!is_safe_target(&v6("::ffff:100.64.0.1"), true));
    }

    #[test]
    fn accepts_ipv4_mapped_public() {
        // C-1: ::ffff:8.8.8.8 must unwrap to a public IPv4 and pass.
        assert!(is_safe_target(&v6("::ffff:8.8.8.8"), true));
    }

    #[test]
    fn accepts_public_ipv4() {
        assert!(is_safe_target(&v4(8, 8, 8, 8), true));
        assert!(is_safe_target(&v4(1, 1, 1, 1), true));
    }

    #[test]
    fn accepts_public_ipv6() {
        assert!(is_safe_target(&v6("2606:4700:4700::1111"), true));
        assert!(is_safe_target(&v6("2001:4860:4860::8888"), true));
    }

    // Egress address-family selection now lives in `snell::resolver`; its
    // pick_addr/build_custom unit tests are in src/resolver.rs.
}
