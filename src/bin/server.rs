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

use anyhow::{bail, Result};
use rand::RngCore;
use snell::cipher::{SnellCipher, SALT_LEN};
use snell::quic::{gc_sessions, new_session_table, SessionTable, SessionToken, UdpSession};
use snell::relay::copy_t2c_adaptive;
use snell::snell::{
    parse_request, read_chunk, CMD_CONNECT, CMD_CONNECT_UDP, CMD_CONNECT_V2, CMD_PING, RESP_ERROR,
    RESP_PONG, RESP_TUNNEL,
};
use std::sync::atomic::Ordering;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::interval;
use tokio_rustls::{rustls, TlsAcceptor};

#[cfg(unix)]
use std::os::unix::io::RawFd;

const HANDSHAKE_TIMEOUT_SECS: u64 = 30;
const MAX_CONCURRENT_CONNS: usize = 4096;
const MAX_UDP_SESSIONS: usize = 10_000;

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
        anyhow::bail!(
            "PSK must be at least 16 characters (got {})",
            psk_str.len()
        );
    }
    let psk = Arc::new(psk_str.into_bytes());

    let egress_iface: Option<Arc<String>> = std::env::var("EGRESS_INTERFACE").ok().map(Arc::new);
    let quic_enabled = std::env::var("QUIC").map(|v| v == "1").unwrap_or(false);
    let tls_acceptor = Arc::new(make_tls_acceptor()?);
    let session_table = new_session_table();
    let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS));

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
            if quic_enabled {
                if let Some(&udp_fd) = activation_fds_i32.get(1) {
                    let udp_sock = snell::activation::into_udp_socket(udp_fd)?;
                    spawn_udp_listener(udp_sock, session_table.clone());
                }
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
            spawn_udp_listener(udp_sock, session_table.clone());
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
        let sessions = session_table.clone();
        tokio::spawn(async move {
            let _permit = permit; // released on drop
            let result = tokio::time::timeout(
                Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
                dispatch(
                    conn,
                    &psk,
                    &tls_acceptor,
                    iface.as_deref().map(String::as_str),
                    &sessions,
                ),
            )
            .await;
            if result.is_err() {
                eprintln!("[{peer}] handshake timeout");
            } else if let Ok(Err(e)) = result {
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

fn spawn_udp_listener(sock: tokio::net::UdpSocket, table: SessionTable) {
    let sock = Arc::new(sock);
    tokio::spawn(async move {
        if let Err(e) = run_udp_relay(sock, table).await {
            eprintln!("[QUIC UDP] {e}");
        }
    });
}

/// UDP relay loop: route datagrams via session token.
async fn run_udp_relay(sock: Arc<tokio::net::UdpSocket>, table: SessionTable) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        if n < 8 {
            continue;
        }

        let token_bytes: [u8; 8] = match buf[..8].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let token = snell::quic::SessionToken(token_bytes);
        let payload = buf[8..n].to_vec();

        let session = {
            let guard = table.lock().await;
            match guard.get(&token) {
                Some(s) => s.clone(),
                None => continue,
            }
        };

        session.touch();

        // First-datagram bootstrap: discover client_addr, spawn target→client task once.
        {
            let mut addr_lock = session.client_addr.lock().await;
            if addr_lock.is_none() {
                *addr_lock = Some(src);
                if !session.recv_started.swap(true, Ordering::SeqCst) {
                    let session_clone = session.clone();
                    let sock_clone = sock.clone();
                    let token_b = *session.token.as_bytes();
                    tokio::spawn(async move {
                        target_to_client_loop(session_clone, sock_clone, token_b).await;
                    });
                }
            }
        }

        // Forward client → target
        if snell::quic::is_quic_initial(&payload) {
            match snell::quic::decrypt_with(&session.init_cipher, &payload) {
                Ok(plain) => {
                    let _ = session.target_sock.send(&plain).await;
                }
                Err(_) => continue, // drop malformed/forged
            }
        } else {
            let _ = session.target_sock.send(&payload).await;
        }
    }
}

async fn target_to_client_loop(
    session: Arc<UdpSession>,
    sock: Arc<tokio::net::UdpSocket>,
    token_bytes: [u8; 8],
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let n = match session.target_sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => break,
        };
        let data = &buf[..n];
        let dst = match *session.client_addr.lock().await {
            Some(a) => a,
            None => break, // shouldn't happen — task started after addr was set
        };
        let mut out =
            Vec::with_capacity(8 + data.len() + snell::quic::QUIC_INIT_OVERHEAD);
        out.extend_from_slice(&token_bytes);
        if snell::quic::is_quic_initial(data) {
            match snell::quic::encrypt_with(&session.init_cipher, data) {
                Ok(enc) => out.extend_from_slice(&enc),
                Err(_) => continue,
            }
        } else {
            out.extend_from_slice(data);
        }
        let _ = sock.send_to(&out, dst).await;
        session.touch();
    }
}

/// Returns false for addresses that should never be proxy targets (SSRF guard).
/// Set ALLOW_PRIVATE_TARGETS=1 to bypass (for local testing only).
fn is_safe_target(addr: &SocketAddr) -> bool {
    let allow_private = std::env::var("ALLOW_PRIVATE_TARGETS")
        .map(|v| v == "1")
        .unwrap_or(false);
    if allow_private {
        return true;
    }
    let ip = addr.ip();
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_private() && !v4.is_link_local() && !v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !((v6.segments()[0] & 0xfe00) == 0xfc00) // unique local fc00::/7
                && !((v6.segments()[0] & 0xffc0) == 0xfe80) // link local fe80::/10
        }
    }
}

async fn dispatch(
    mut conn: TcpStream,
    psk: &[u8],
    tls: &TlsAcceptor,
    iface: Option<&str>,
    sessions: &SessionTable,
) -> Result<()> {
    let mut first = [0u8; 1];
    conn.peek(&mut first).await?;
    match first[0] {
        0x16 => {
            let stream = tls.accept(conn).await?;
            handle(stream, psk, iface, sessions).await
        }
        b'G' => {
            absorb_http_request(&mut conn).await?;
            conn.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\r\n",
            )
            .await?;
            handle(conn, psk, iface, sessions).await
        }
        _ => handle(conn, psk, iface, sessions).await,
    }
}

async fn absorb_http_request(conn: &mut TcpStream) -> Result<()> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        conn.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            bail!("HTTP obfs request too large");
        }
    }
    Ok(())
}

async fn handle<S>(
    mut conn: S,
    psk: &[u8],
    iface: Option<&str>,
    sessions: &SessionTable,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_salt = [0u8; SALT_LEN];
    conn.read_exact(&mut client_salt).await?;
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

        // ── QUIC UDP connect ──────────────────────────────────────────────────
        if req.command == CMD_CONNECT_UDP {
            let target_addr: SocketAddr =
                tokio::net::lookup_host(format!("{}:{}", req.host, req.port))
                    .await?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("DNS: no address"))?;

            if !is_safe_target(&target_addr) {
                eprintln!(
                    "[SSRF] blocked QUIC → {}:{} (resolved to {})",
                    req.host, req.port, target_addr
                );
                let mut r = vec![RESP_ERROR, 0u8, 9];
                r.extend_from_slice(b"forbidden");
                conn.write_all(&s2c.seal(&r)?).await?;
                return Ok(());
            }

            {
                let guard = sessions.lock().await;
                if guard.len() >= MAX_UDP_SESSIONS {
                    let mut r = vec![RESP_ERROR, 0u8, 11];
                    r.extend_from_slice(b"too busy now");
                    conn.write_all(&s2c.seal(&r)?).await?;
                    return Ok(());
                }
            }

            let target_sock =
                snell::egress::bind_udp("0.0.0.0:0".parse().expect("static"), iface)?;
            target_sock.connect(target_addr).await?;

            let mut session_salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut session_salt);
            let init_cipher = snell::quic::derive_init_cipher(psk, &session_salt)?;

            let token = SessionToken::new_random();
            let session = Arc::new(UdpSession {
                token,
                client_addr: tokio::sync::Mutex::new(None),
                target_sock: Arc::new(target_sock),
                last_seen: std::sync::atomic::AtomicU64::new(0),
                init_cipher,
                recv_started: std::sync::atomic::AtomicBool::new(false),
            });
            session.touch();
            sessions.lock().await.insert(token, session);

            let mut resp = vec![RESP_TUNNEL];
            resp.extend_from_slice(token.as_bytes());
            resp.extend_from_slice(&session_salt); // client needs salt to derive same cipher
            conn.write_all(&s2c.seal(&resp)?).await?;
            return Ok(());
        }

        // ── Normal TCP CONNECT ────────────────────────────────────────────────
        if req.command != CMD_CONNECT && req.command != CMD_CONNECT_V2 {
            bail!("unknown command {:#04x}", req.command);
        }

        eprintln!("CONNECT → {}:{}", req.host, req.port);

        let target_addr: SocketAddr =
            tokio::net::lookup_host(format!("{}:{}", req.host, req.port))
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("DNS: no address for {}", req.host))?;

        if !is_safe_target(&target_addr) {
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
