//! snell-client — Snell v5 SOCKS5 proxy client.
//! Usage: PSK=yourpsk SNELL_SERVER=host:port [LISTEN=127.0.0.1:1080] snell-client

use anyhow::{bail, Result};
use snell::cipher::{SnellCipher, SALT_LEN};
use snell::snell::{read_chunk, write_chunk, RESP_TUNNEL};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() -> Result<()> {
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
    let mut remote = TcpStream::connect(server).await?;
    let (salt, mut c2s) = SnellCipher::with_random_salt(psk)?;
    remote.write_all(&salt).await?;

    // Snell v5 CONNECT_V2 request: [ver=1][cmd=5][client_id_len=0][host_len][host][port BE]
    let hb = host.as_bytes();
    let mut hs = vec![0x01u8, 0x05, 0x00, hb.len() as u8];
    hs.extend_from_slice(hb);
    hs.push((port >> 8) as u8);
    hs.push((port & 0xff) as u8);
    remote.write_all(&c2s.seal(&hs)?).await?;

    // Read server salt + ResponseTunnel
    let mut ss = [0u8; SALT_LEN];
    remote.read_exact(&mut ss).await?;
    let mut s2c = SnellCipher::new(psk, &ss)?;

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
            if n == 0 {
                break;
            }
            write_chunk(&mut rw, &mut c2s, &buf[..n]).await?;
        }
        rw.write_all(&c2s.seal_zero()?).await?;
        Ok::<_, anyhow::Error>(())
    };
    let down = async move {
        loop {
            match read_chunk(&mut rr, &mut s2c).await? {
                None => break,
                Some(d) => lw.write_all(&d).await?,
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(up, down)?;
    Ok(())
}
