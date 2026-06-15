//! End-to-end UDP-over-TCP test: a real `snell-client` (SOCKS5 UDP ASSOCIATE)
//! tunnels datagrams through a real `snell-server` to a local UDP echo server,
//! exercising the full UoT path (SOCKS5 UDP ↔ Snell datagram framing).

mod common;
use common::*;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// Bind a UDP echo server that bounces every datagram back to its sender.
/// Returns the bound port.
async fn spawn_udp_echo() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    port
}

#[tokio::test]
async fn udp_e2e_socks5_associate_echo() {
    let echo_port = spawn_udp_echo().await;
    let server_port = random_tcp_port();
    let socks_port = random_tcp_port();

    let _server = spawn_server(server_port, false);
    let _client = spawn_client(server_port, socks_port);
    wait_tcp(server_port).await;
    wait_tcp(socks_port).await;

    // ── SOCKS5 greeting + UDP ASSOCIATE on the control connection ─────────────
    let mut ctrl = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    ctrl.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00], "server must select no-auth");

    // UDP ASSOCIATE (cmd 0x03) with a dummy DST of 0.0.0.0:0.
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    ctrl.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        &reply[..4],
        &[0x05, 0x00, 0x00, 0x01],
        "ASSOCIATE reply hdr"
    );
    let relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));

    // ── Send a SOCKS5 UDP datagram targeting the echo server ──────────────────
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"udp-over-tcp-roundtrip";
    // [RSV 0x0000][FRAG 0x00][ATYP 0x01][127.0.0.1][echo_port][payload]
    let mut dg = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    dg.extend_from_slice(&echo_port.to_be_bytes());
    dg.extend_from_slice(payload);
    app.send_to(&dg, relay).await.unwrap();

    // ── Receive the echoed datagram, SOCKS5-UDP-wrapped ───────────────────────
    let mut rbuf = vec![0u8; 65535];
    let (n, _) = timeout(Duration::from_secs(5), app.recv_from(&mut rbuf))
        .await
        .expect("no UDP response within 5s")
        .unwrap();
    let resp = &rbuf[..n];

    // [RSV 0x0000][FRAG 0x00][ATYP 0x01][src ip][src port][data]
    assert_eq!(&resp[..4], &[0x00, 0x00, 0x00, 0x01], "SOCKS5 UDP resp hdr");
    assert_eq!(&resp[4..8], &[127, 0, 0, 1], "source ip echoed");
    assert_eq!(
        u16::from_be_bytes([resp[8], resp[9]]),
        echo_port,
        "source port echoed"
    );
    assert_eq!(&resp[10..], payload, "payload round-trips intact");

    drop(ctrl); // closing the control conn tears down the association
}
