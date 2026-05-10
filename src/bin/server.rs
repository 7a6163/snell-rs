//! snell-server — open-source Snell v5 server.
//! Usage: PSK=yourpsk snell-server [listen_addr]
//! Default listen: 0.0.0.0:6180
//!
//! Environment variables:
//!   PSK               Pre-shared key (required)
//!   EGRESS_INTERFACE  Bind outgoing connections to this network interface
//!   QUIC=1            Enable QUIC proxy mode (opens UDP on same port)
//!
//! Obfuscation auto-detected from first byte:
//!   plain    — random Snell salt
//!   obfs=http — 'G' (HTTP GET WebSocket upgrade)
//!   obfs=tls  — 0x16 (TLS ClientHello)

use anyhow::{bail, Result};
use snell::cipher::{SnellCipher, SALT_LEN};
use snell::quic::{
    encrypt_initial, gc_sessions, is_quic_initial, new_session_table, SessionTable, SessionToken,
    UdpSession,
};
use snell::relay::copy_t2c_adaptive;
use snell::snell::{
    parse_request, read_chunk, CMD_CONNECT, CMD_CONNECT_UDP, CMD_CONNECT_V2, CMD_PING, RESP_ERROR,
    RESP_PONG, RESP_TUNNEL,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::interval;
use tokio_rustls::{rustls, TlsAcceptor};

#[tokio::main]
async fn main() -> Result<()> {
    let listen: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:6180".into())
        .parse()?;
    let psk = Arc::new(
        std::env::var("PSK")
            .map_err(|_| anyhow::anyhow!("PSK environment variable is required"))?
            .into_bytes(),
    );
    let egress_iface: Option<Arc<String>> = std::env::var("EGRESS_INTERFACE").ok().map(Arc::new);
    let quic_enabled = std::env::var("QUIC").map(|v| v == "1").unwrap_or(false);
    let tls_acceptor = Arc::new(make_tls_acceptor()?);
    let session_table = new_session_table();

    // systemd socket activation: adopt pre-bound FDs if present.
    #[cfg(unix)]
    let tcp_ln = {
        let fds = snell::activation::take_listener_fds();
        if !fds.is_empty() {
            eprintln!(
                "snell-server: using systemd socket activation (fd {})",
                fds[0]
            );
            let tcp_ln = snell::activation::into_tcp_listener(fds[0])?;
            if quic_enabled {
                if let Some(&udp_fd) = fds.get(1) {
                    let udp_sock = snell::activation::into_udp_socket(udp_fd)?;
                    spawn_udp_listener(udp_sock, psk.clone(), session_table.clone());
                }
            }
            tcp_ln
        } else {
            let ln = TcpListener::bind(listen).await?;
            if quic_enabled {
                let udp_sock = snell::egress::bind_udp(listen, None)?;
                spawn_udp_listener(udp_sock, psk.clone(), session_table.clone());
            }
            ln
        }
    };
    #[cfg(not(unix))]
    let tcp_ln = {
        let ln = TcpListener::bind(listen).await?;
        if quic_enabled {
            let udp_sock = snell::egress::bind_udp(listen, None)?;
            spawn_udp_listener(udp_sock, psk.clone(), session_table.clone());
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
        let psk = psk.clone();
        let tls_acceptor = tls_acceptor.clone();
        let iface: Option<Arc<String>> = egress_iface.clone();
        let sessions = session_table.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatch(
                conn,
                &psk,
                &tls_acceptor,
                iface.as_deref().map(|s| s.as_str()),
                &sessions,
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

fn spawn_udp_listener(sock: tokio::net::UdpSocket, psk: Arc<Vec<u8>>, table: SessionTable) {
    tokio::spawn(async move {
        if let Err(e) = run_udp_relay(sock, &psk, &table).await {
            eprintln!("[QUIC UDP] {e}");
        }
    });
}

/// UDP relay loop: route datagrams via session token, encrypt/pass-through by packet type.
async fn run_udp_relay(
    sock: tokio::net::UdpSocket,
    psk: &[u8],
    table: &SessionTable,
) -> Result<()> {
    use rand::RngCore;
    let mut session_salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut session_salt);
    let sock = Arc::new(sock);

    let mut buf = vec![0u8; 65535];
    loop {
        let (n, _src) = sock.recv_from(&mut buf).await?;
        if n < 8 {
            continue;
        }

        let token = SessionToken(buf[..8].try_into().unwrap());
        let payload = &buf[8..n];

        let guard = table.lock().await;
        let session = match guard.get(&token) {
            Some(s) => s.clone(),
            None => {
                drop(guard);
                continue;
            }
        };
        drop(guard);

        *session.last_seen.lock().await = std::time::Instant::now();

        if is_quic_initial(payload) {
            match encrypt_initial(psk, &session_salt, payload) {
                Ok(enc) => {
                    let _ = session.target_sock.send(&enc).await;
                }
                Err(e) => eprintln!("[QUIC] encrypt Initial: {e}"),
            }
        } else {
            let _ = session.target_sock.send(payload).await;
        }

        let sock_clone = sock.clone();
        let client_addr = session.client_addr;
        let token_bytes = *token.as_bytes();
        let psk_owned = psk.to_vec();
        let salt_copy = session_salt;
        tokio::spawn(async move {
            let mut rbuf = vec![0u8; 65535];
            if let Ok(m) = session.target_sock.recv(&mut rbuf).await {
                let data = &rbuf[..m];
                let mut out = Vec::with_capacity(8 + data.len() + snell::quic::QUIC_INIT_OVERHEAD);
                out.extend_from_slice(&token_bytes);
                if is_quic_initial(data) {
                    match encrypt_initial(&psk_owned, &salt_copy, data) {
                        Ok(enc) => out.extend_from_slice(&enc),
                        Err(_) => return,
                    }
                } else {
                    out.extend_from_slice(data);
                }
                let _ = sock_clone.send_to(&out, client_addr).await;
            }
        });
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
            let target: SocketAddr = format!("{}:{}", req.host, req.port)
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid QUIC target {}:{}", req.host, req.port))?;

            let target_sock = snell::egress::bind_udp("0.0.0.0:0".parse()?, iface)?;
            target_sock.connect(target).await?;

            let token = SessionToken::new_random();
            let session = Arc::new(UdpSession {
                client_addr: "0.0.0.0:0".parse().unwrap(),
                target_addr: target,
                target_sock,
                last_seen: std::time::Instant::now().into(),
                init_cipher: SnellCipher::new(psk, &client_salt)?.into(),
            });
            sessions.lock().await.insert(token, session);

            let mut resp = vec![RESP_TUNNEL];
            resp.extend_from_slice(token.as_bytes());
            conn.write_all(&s2c.seal(&resp)?).await?;
            return Ok(());
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

        let mut target = match snell::egress::connect_tcp(target_addr, iface).await {
            Ok(t) => t,
            Err(e) => {
                let msg = e.to_string();
                let msg_bytes = msg.as_bytes();
                let len = msg_bytes.len().min(250);
                let mut r = vec![RESP_ERROR, 0u8, len as u8];
                r.extend_from_slice(&msg_bytes[..len]);
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
