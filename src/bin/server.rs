//! snell-server — open-source Snell v5 server.
//! Usage: PSK=yourpsk snell-server [listen_addr]
//! Default listen: 0.0.0.0:6180
//!
//! Obfuscation mode is auto-detected from the first byte of each connection:
//!   plain    — Snell salt (random bytes, not 'G' or 0x16)
//!   obfs=http — 'G' (HTTP GET WebSocket upgrade)
//!   obfs=tls  — 0x16 (TLS ClientHello)

use anyhow::{bail, Result};
use snell::cipher::{SnellCipher, SALT_LEN};
use snell::snell::{
    parse_request, read_chunk, write_chunk, CMD_CONNECT, CMD_CONNECT_V2, CMD_PING, RESP_ERROR,
    RESP_PONG, RESP_TUNNEL,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

async fn dispatch(mut conn: TcpStream, psk: &[u8], tls: &TlsAcceptor) -> Result<()> {
    let mut first = [0u8; 1];
    conn.peek(&mut first).await?;

    match first[0] {
        0x16 => {
            let stream = tls.accept(conn).await?;
            handle(stream, psk).await
        }
        b'G' => {
            absorb_http_request(&mut conn).await?;
            conn.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\r\n",
            )
            .await?;
            handle(conn, psk).await
        }
        _ => handle(conn, psk).await,
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

async fn handle<S>(mut conn: S, psk: &[u8]) -> Result<()>
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
        if req.command != CMD_CONNECT && req.command != CMD_CONNECT_V2 {
            bail!("unknown command {:#04x}", req.command);
        }

        eprintln!("CONNECT → {}:{}", req.host, req.port);

        let mut target = match TcpStream::connect(format!("{}:{}", req.host, req.port)).await {
            Ok(t) => t,
            Err(e) => {
                let msg = e.to_string();
                let msg_bytes = msg.as_bytes();
                let len = msg_bytes.len().min(250);
                let mut r = vec![RESP_ERROR, 0u8, len as u8];
                r.extend_from_slice(&msg_bytes[..len]); // truncate both length AND content
                conn.write_all(&s2c.seal(&r)?).await?;
                continue;
            }
        };

        conn.write_all(&s2c.seal(&[RESP_TUNNEL])?).await?;

        if !req.trailing.is_empty() {
            target.write_all(&req.trailing).await?;
        }

        let (cr, cw) = tokio::io::split(conn);
        let (mut tr, mut tw) = tokio::io::split(target);

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
        let t2c = async move {
            let mut cw = cw;
            let mut s2c = s2c;
            let mut buf = vec![0u8; 16384];
            loop {
                let n = tr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                write_chunk(&mut cw, &mut s2c, &buf[..n]).await?;
            }
            cw.write_all(&s2c.seal_zero()?).await?;
            Ok::<_, anyhow::Error>((cw, s2c))
        };

        let ((cr, c2s_new), (cw, s2c_new)) = tokio::try_join!(c2t, t2c)?;

        c2s = c2s_new;
        s2c = s2c_new;
        conn = cr.unsplit(cw);
    }

    Ok(())
}
