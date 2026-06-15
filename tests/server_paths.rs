//! Server-side path coverage: hand-crafted Snell handshakes (no client binary)
//! that exercise `snell-server`'s request loop — PING, connect-refused error
//! replies, unknown-command rejection, and the UDP-over-TCP relay — plus QUIC
//! resilience to malformed datagrams.

mod common;
use common::*;

use snell::cipher::{SALT_LEN, SnellCipher};
use snell::snell::{
    CMD_CONNECT_UDP, CMD_CONNECT_V2, CMD_PING, RESP_ERROR, RESP_PONG, RESP_TUNNEL,
    encode_udp_request, parse_udp_response, read_chunk, write_chunk,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

/// Perform a plain Snell v5 handshake against the server and return the
/// connection plus the (client→server, server→client) ciphers.
async fn handshake(server_port: u16) -> (TcpStream, SnellCipher, SnellCipher) {
    let psk = PSK.as_bytes();
    let mut conn = TcpStream::connect(("127.0.0.1", server_port))
        .await
        .unwrap();
    // First byte must avoid the obfs auto-detect (0x16 = TLS, 'G' = HTTP).
    let mut salt = [0u8; SALT_LEN];
    salt[0] = 0x01;
    for b in salt.iter_mut().skip(1) {
        *b = rand::random();
    }
    let c2s = SnellCipher::new(psk, &salt).unwrap();
    conn.write_all(&salt).await.unwrap();
    // The server sends its salt up front, before reading the request.
    let mut server_salt = [0u8; SALT_LEN];
    conn.read_exact(&mut server_salt).await.unwrap();
    let s2c = SnellCipher::new(psk, &server_salt).unwrap();
    (conn, c2s, s2c)
}

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
async fn server_replies_pong_to_ping() {
    let server_port = random_tcp_port();
    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    let (mut conn, mut c2s, mut s2c) = handshake(server_port).await;
    write_chunk(&mut conn, &mut c2s, &[0x01, CMD_PING, 0x00])
        .await
        .unwrap();
    let resp = read_chunk(&mut conn, &mut s2c).await.unwrap().unwrap();
    assert_eq!(resp, vec![RESP_PONG]);
}

#[tokio::test]
async fn server_sends_error_when_target_refuses() {
    let server_port = random_tcp_port();
    let closed = random_udp_port(); // bound then dropped → connect is refused
    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    let (mut conn, mut c2s, mut s2c) = handshake(server_port).await;
    let mut req = vec![0x01, CMD_CONNECT_V2, 0x00, 9];
    req.extend_from_slice(b"127.0.0.1");
    req.extend_from_slice(&closed.to_be_bytes());
    write_chunk(&mut conn, &mut c2s, &req).await.unwrap();

    let resp = read_chunk(&mut conn, &mut s2c).await.unwrap().unwrap();
    assert_eq!(resp[0], RESP_ERROR, "expected a generic error reply");
}

#[tokio::test]
async fn server_rejects_unknown_command() {
    let server_port = random_tcp_port();
    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    let (mut conn, mut c2s, mut s2c) = handshake(server_port).await;
    write_chunk(&mut conn, &mut c2s, &[0x01, 0x77, 0x00])
        .await
        .unwrap();
    // The server bails on the unknown command and drops the connection.
    let r = read_chunk(&mut conn, &mut s2c).await;
    assert!(
        r.is_err() || matches!(r, Ok(None)),
        "connection should close"
    );
}

#[tokio::test]
async fn server_udp_relays_datagram_to_echo() {
    let echo_port = spawn_udp_echo().await;
    let server_port = random_tcp_port();
    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    let (mut conn, mut c2s, mut s2c) = handshake(server_port).await;
    // Open the UDP session: empty placeholder target.
    write_chunk(&mut conn, &mut c2s, &[0x01, CMD_CONNECT_UDP, 0, 0, 0, 0])
        .await
        .unwrap();
    let ack = read_chunk(&mut conn, &mut s2c).await.unwrap().unwrap();
    assert_eq!(ack, vec![RESP_TUNNEL]);

    // A malformed datagram must be dropped without killing the session …
    write_chunk(&mut conn, &mut c2s, &[0xff, 0x00])
        .await
        .unwrap();

    // … and a valid one must round-trip through the echo server.
    let frame = encode_udp_request("127.0.0.1", echo_port, b"ping");
    write_chunk(&mut conn, &mut c2s, &frame).await.unwrap();

    let resp = timeout(Duration::from_secs(3), read_chunk(&mut conn, &mut s2c))
        .await
        .expect("no UDP reply within 3s")
        .unwrap()
        .unwrap();
    let (src, payload) = parse_udp_response(&resp).unwrap();
    assert_eq!(src.port(), echo_port, "reply tagged with echo source port");
    assert_eq!(payload, b"ping", "payload round-trips");
}

#[tokio::test]
async fn quic_survives_malformed_init() {
    let server_port = random_tcp_port();
    let _server = spawn_server(server_port, true);
    wait_tcp(server_port).await;
    sleep(Duration::from_millis(200)).await;

    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = ("127.0.0.1", server_port);

    // Init-classified but too short, then Init-classified garbage that fails to
    // decrypt — both must be dropped without crashing the relay loop.
    cli.send_to(&[0x20, 0x00, 0x01], dst).await.unwrap();
    cli.send_to(&[0x20; 80], dst).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    // The server is still alive and accepting TCP after the bad UDP input.
    wait_tcp(server_port).await;
}
