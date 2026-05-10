//! End-to-end QUIC test: send crafted UDP init+data → snell-rs → echo, verify reply.

mod common;

use common::*;
use snell::cipher::{HDR_CT_LEN, SALT_LEN, SnellCipher};
use snell::quic::{QUIC_CMD_CONNECT, decrypt_init, parse_quic_request};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

fn build_quic_init(psk: &[u8], host: &str, target_port: u16) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    salt[0] = 0x20;
    for b in salt.iter_mut().skip(1) {
        *b = rand::random();
    }
    let mut cipher = SnellCipher::new(psk, &salt).unwrap();
    let host_bytes = host.as_bytes();
    let mut inner = vec![QUIC_CMD_CONNECT, 0u8, host_bytes.len() as u8];
    inner.extend_from_slice(host_bytes);
    inner.extend_from_slice(&target_port.to_be_bytes());
    let chunk = cipher.seal(&inner).unwrap();
    let mut pkt = Vec::with_capacity(SALT_LEN + chunk.len());
    pkt.extend_from_slice(&salt);
    pkt.extend_from_slice(&chunk);
    pkt
}

fn build_quic_data(payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + payload.len());
    p.push(0x40);
    p.extend_from_slice(payload);
    p
}

async fn spawn_udp_echo() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let mut out = Vec::with_capacity(5 + n);
            out.extend_from_slice(b"ECHO:");
            out.extend_from_slice(&buf[..n]);
            let _ = sock.send_to(&out, src).await;
        }
    });
    port
}

#[tokio::test]
async fn quic_packet_roundtrip_lib_only() {
    let pkt = build_quic_init(PSK.as_bytes(), "example.com", 443);
    assert_eq!(pkt.len(), SALT_LEN + HDR_CT_LEN + (3 + 11 + 2) + 16);
    let salt: [u8; SALT_LEN] = pkt[..SALT_LEN].try_into().unwrap();
    let req = decrypt_init(PSK.as_bytes(), &salt, &pkt[SALT_LEN..]).unwrap();
    assert_eq!(req.host, "example.com");
    assert_eq!(req.port, 443);
    assert_eq!(req.user, "");
}

#[tokio::test]
async fn quic_parse_request_rejects_bad_command() {
    let mut bad = vec![0x99u8, 0x00, 0x03];
    bad.extend_from_slice(b"abc\x00\x50");
    assert!(parse_quic_request(&bad).is_err());
}

#[tokio::test]
async fn quic_e2e_init_data_response() {
    let echo_port = spawn_udp_echo().await;
    let server_port = random_tcp_port();

    let _server = spawn_server(server_port, true);
    wait_tcp(server_port).await;
    sleep(Duration::from_millis(200)).await;

    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let init = build_quic_init(PSK.as_bytes(), "127.0.0.1", echo_port);
    cli.send_to(&init, ("127.0.0.1", server_port))
        .await
        .unwrap();

    sleep(Duration::from_millis(300)).await;

    let payload = b"hello-quic-from-test";
    let data_pkt = build_quic_data(payload);
    cli.send_to(&data_pkt, ("127.0.0.1", server_port))
        .await
        .unwrap();

    let mut buf = vec![0u8; 1500];
    let (n, _src) = timeout(Duration::from_secs(3), cli.recv_from(&mut buf))
        .await
        .expect("no reply within 3s")
        .expect("recv error");

    let recv = &buf[..n];
    assert!(
        recv.starts_with(b"ECHO:"),
        "expected ECHO: prefix: {recv:?}"
    );
    assert!(
        recv.windows(payload.len()).any(|w| w == payload),
        "echoed payload missing in {recv:?}",
    );
}
