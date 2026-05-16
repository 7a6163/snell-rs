//! snell-client — Snell v5 SOCKS5 proxy client.
//! Usage: PSK=yourpsk SNELL_SERVER=host:port [LISTEN=127.0.0.1:1080] snell-client
//!
//! Optional env vars:
//!   TCP_FASTOPEN=1  Opt the outbound socket to the snell server into
//!                   client-side TFO (Linux >= 4.11 only; no-op on macOS).

use anyhow::{Result, bail};
use snell::cipher::{SALT_LEN, SnellCipher};
use snell::snell::{RESP_TUNNEL, read_chunk, write_chunk};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() -> Result<()> {
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
    let psk = Arc::new(
        std::env::var("PSK")
            .map_err(|_| anyhow::anyhow!("PSK environment variable is required"))?
            .into_bytes(),
    );
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
                eprintln!("error: {e}");
            }
        });
    }
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
            eprintln!("TCP Fast Open connect setsockopt failed ({e}); continuing without TFO");
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
    if req_hdr[1] != 0x01 {
        bail!("unsupported SOCKS5 command {:#04x}", req_hdr[1]);
    }

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

    // Reply: success (bound addr 0.0.0.0:0)
    local
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Connect to Snell server and perform handshake
    let mut remote = connect_server(server, tfo_out).await?;
    let (salt, mut c2s) = SnellCipher::with_random_salt(psk)?;
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
