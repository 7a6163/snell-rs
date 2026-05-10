//! snell-client — Snell v5 SOCKS5 proxy client.
//! Usage: PSK=yourpsk SNELL_SERVER=host:port [LISTEN=127.0.0.1:1080] snell-client

use anyhow::{bail, Result};
use std::{net::SocketAddr, sync::Arc};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use snell::cipher::{SnellCipher, SALT_LEN};
use snell::snell::{read_chunk, write_chunk, RESP_TUNNEL};

#[tokio::main]
async fn main() -> Result<()> {
    let server: SocketAddr = std::env::var("SNELL_SERVER")
        .unwrap_or_else(|_| "127.0.0.1:6180".into()).parse()?;
    let psk = Arc::new(
        std::env::var("PSK").unwrap_or_else(|_| "changeme".into()).into_bytes()
    );
    let listen: SocketAddr = std::env::var("LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:1080".into()).parse()?;

    let ln = TcpListener::bind(listen).await?;
    eprintln!("Snell v5 SOCKS5 proxy  {listen} → {server}");
    loop {
        let (conn, _) = ln.accept().await?;
        let psk = psk.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(conn, server, &psk).await {
                eprintln!("error: {e}");
            }
        });
    }
}

async fn handle(mut local: TcpStream, server: SocketAddr, psk: &[u8]) -> Result<()> {
    let mut buf = vec![0u8; 512];

    // SOCKS5 handshake
    local.read(&mut buf).await?;
    local.write_all(&[0x05, 0x00]).await?; // no-auth

    let n = local.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 { bail!("invalid SOCKS5 request"); }

    let (host, port) = match buf[3] {
        0x01 => {
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            (ip, u16::from_be_bytes([buf[8], buf[9]]))
        }
        0x03 => {
            let len = buf[4] as usize;
            let host = std::str::from_utf8(&buf[5..5 + len])?.to_owned();
            (host, u16::from_be_bytes([buf[5 + len], buf[6 + len]]))
        }
        0x04 => {
            let arr: [u8; 16] = buf[4..20].try_into()?;
            (std::net::Ipv6Addr::from(arr).to_string(), u16::from_be_bytes([buf[20], buf[21]]))
        }
        t => bail!("unsupported ATYP {t:#04x}"),
    };

    local.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    // Connect to Snell server and do handshake
    let mut remote = TcpStream::connect(server).await?;
    let (salt, mut c2s) = SnellCipher::with_random_salt(psk);
    remote.write_all(&salt).await?;

    // Snell v5 handshake: [ver=1][ConnectV2=5][client_id_len=0][host_len][host][port BE]
    let hb = host.as_bytes();
    let mut hs = vec![0x01u8, 0x05, 0x00, hb.len() as u8];
    hs.extend_from_slice(hb);
    hs.push((port >> 8) as u8);
    hs.push((port & 0xff) as u8);
    remote.write_all(&c2s.seal(&hs)).await?;

    // Read server salt + ResponseTunnel
    let mut ss = [0u8; SALT_LEN];
    remote.read_exact(&mut ss).await?;
    let mut s2c = SnellCipher::new(psk, &ss);

    let Some(resp) = read_chunk(&mut remote, &mut s2c).await? else {
        bail!("server closed before response");
    };
    if resp.first() != Some(&RESP_TUNNEL) {
        bail!("expected ResponseTunnel, got {:?}", resp.first());
    }

    // Bidirectional relay
    let (mut lr, mut lw) = local.split();
    let (mut rr, mut rw) = remote.split();

    let up = async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = lr.read(&mut buf).await?;
            if n == 0 { break; }
            write_chunk(&mut rw, &mut c2s, &buf[..n]).await?;
        }
        rw.write_all(&c2s.seal_zero()).await?;
        Ok::<_, anyhow::Error>(())
    };
    let down = async move {
        loop {
            match read_chunk(&mut rr, &mut s2c).await? {
                None    => break,
                Some(d) => lw.write_all(&d).await?,
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(up, down)?;
    Ok(())
}
