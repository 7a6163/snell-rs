//! snell-server — open-source Snell v5 server.
//! Usage: PSK=yourpsk snell-server [listen_addr]
//! Default listen: 0.0.0.0:6180
//!
//! Obfuscation mode is auto-detected from the first byte of each connection:
//!   plain    — starts with Snell salt (random bytes)
//!   obfs=http — starts with 'G' (HTTP GET WebSocket upgrade)
//!   obfs=tls  — starts with 0x16 (TLS ClientHello)

use anyhow::{bail, Result};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{rustls, TlsAcceptor};
use snell::cipher::{SnellCipher, SALT_LEN};
use snell::snell::{read_chunk, parse_request, write_chunk,
                   CMD_CONNECT, CMD_CONNECT_V2, CMD_PING,
                   RESP_ERROR, RESP_PONG, RESP_TUNNEL};

#[tokio::main]
async fn main() -> Result<()> {
    let listen: SocketAddr = std::env::args()
        .nth(1).unwrap_or_else(|| "0.0.0.0:6180".into()).parse()?;
    let psk = Arc::new(
        std::env::var("PSK").unwrap_or_else(|_| "changeme".into()).into_bytes()
    );
    let tls_acceptor = Arc::new(make_tls_acceptor()?);

    let ln = TcpListener::bind(listen).await?;
    eprintln!("snell-server v5 listening on {listen}  (plain / obfs=http / obfs=tls)");
    loop {
        let (conn, peer) = ln.accept().await?;
        let psk = psk.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatch(conn, &psk, &tls_acceptor).await {
                eprintln!("[{peer}] {e}");
            }
        });
    }
}

/// Build a TLS acceptor with a fresh self-signed certificate.
/// The cert is only used for obfuscation — Surge does not verify it.
fn make_tls_acceptor() -> Result<TlsAcceptor> {
    let cert = rcgen::generate_simple_self_signed(vec!["snell".to_string()])?;
    let cert_der = cert.serialize_der()?;
    let key_der  = cert.serialize_private_key_der();

    let certs  = vec![rustls::Certificate(cert_der)];
    let key    = rustls::PrivateKey(key_der);
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Peek at the first byte and route to the correct obfuscation handler,
/// then call the generic `handle()` with the unwrapped stream.
async fn dispatch(mut conn: TcpStream, psk: &[u8], tls: &TlsAcceptor) -> Result<()> {
    let mut first = [0u8; 1];
    conn.peek(&mut first).await?;

    match first[0] {
        0x16 => {
            // TLS ClientHello — obfs=tls
            let stream = tls.accept(conn).await?;
            handle(stream, psk).await
        }
        b'G' => {
            // HTTP GET — obfs=http
            absorb_http_request(&mut conn).await?;
            conn.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\r\n",
            ).await?;
            handle(conn, psk).await
        }
        _ => {
            // Plain Snell
            handle(conn, psk).await
        }
    }
}

/// Read and discard an HTTP request up to the blank line.
async fn absorb_http_request(conn: &mut TcpStream) -> Result<()> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        conn.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") { break; }
        if buf.len() > 8192 { bail!("HTTP obfs request too large"); }
    }
    Ok(())
}

/// Core Snell v5 session handler — generic over the transport stream so it
/// works identically for plain TCP, HTTP-obfs TCP, and TLS-obfs TCP.
async fn handle<S>(mut conn: S, psk: &[u8]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read client salt; derive decryption cipher once per TCP connection.
    let mut client_salt = [0u8; SALT_LEN];
    conn.read_exact(&mut client_salt).await?;
    let mut c2s = SnellCipher::new(psk, &client_salt);

    // Generate server salt; derive encryption cipher; send salt once.
    let (server_salt, mut s2c) = SnellCipher::with_random_salt(psk);
    conn.write_all(&server_salt).await?;

    // Connection-reuse loop: one TCP connection may carry many requests.
    loop {
        let Some(payload) = read_chunk(&mut conn, &mut c2s).await? else {
            break; // zero chunk — client closed session
        };
        let req = parse_request(&payload)?;

        if req.command == CMD_PING {
            conn.write_all(&s2c.seal(&[RESP_PONG])).await?;
            continue;
        }
        if req.command != CMD_CONNECT && req.command != CMD_CONNECT_V2 {
            bail!("unknown command {:#04x}", req.command);
        }

        eprintln!("CONNECT → {}:{}", req.host, req.port);

        let mut target = match TcpStream::connect(format!("{}:{}", req.host, req.port)).await {
            Ok(t) => t,
            Err(e) => {
                let msg = e.to_string();
                let mut r = vec![RESP_ERROR, 0u8, msg.len().min(250) as u8];
                r.extend_from_slice(msg.as_bytes());
                conn.write_all(&s2c.seal(&r)).await?;
                continue;
            }
        };

        conn.write_all(&s2c.seal(&[RESP_TUNNEL])).await?;

        if !req.trailing.is_empty() {
            target.write_all(&req.trailing).await?;
        }

        // Use tokio::io::split (owned halves) so we can unsplit conn after
        // relay and reuse it for the next request in this loop.
        let (cr, cw) = tokio::io::split(conn);
        let (mut tr, mut tw) = tokio::io::split(target);

        let c2t = async move {
            let mut cr  = cr;
            let mut c2s = c2s;
            loop {
                match read_chunk(&mut cr, &mut c2s).await? {
                    None    => break,
                    Some(d) => tw.write_all(&d).await?,
                }
            }
            tw.shutdown().await?;
            Ok::<_, anyhow::Error>((cr, c2s))
        };
        let t2c = async move {
            let mut cw  = cw;
            let mut s2c = s2c;
            let mut buf = vec![0u8; 16384];
            loop {
                let n = tr.read(&mut buf).await?;
                if n == 0 { break; }
                write_chunk(&mut cw, &mut s2c, &buf[..n]).await?;
            }
            cw.write_all(&s2c.seal_zero()).await?;
            Ok::<_, anyhow::Error>((cw, s2c))
        };

        let ((cr, c2s_new), (cw, s2c_new)) = tokio::try_join!(c2t, t2c)?;

        c2s  = c2s_new;
        s2c  = s2c_new;
        conn = cr.unsplit(cw);
    }

    Ok(())
}
