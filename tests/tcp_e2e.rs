//! End-to-end TCP test: SOCKS5 client → snell-rs server → echo target.

mod common;

use common::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let mut out = Vec::with_capacity(5 + n);
                    out.extend_from_slice(b"ECHO:");
                    out.extend_from_slice(&buf[..n]);
                    if s.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn socks5_connect(socks_port: u16, host: &str, target_port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet_resp = [0u8; 2];
    s.read_exact(&mut greet_resp).await.unwrap();
    assert_eq!(greet_resp, [0x05, 0x00], "SOCKS5 greeting failed");

    let host_bytes = host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut req_resp = [0u8; 10];
    s.read_exact(&mut req_resp).await.unwrap();
    assert_eq!(req_resp[0], 0x05);
    assert_eq!(req_resp[1], 0x00, "SOCKS5 connect rejected");
    s
}

#[tokio::test]
#[serial_test::serial]
async fn tcp_e2e_socks5_to_echo() {
    let echo_port = spawn_echo().await;
    let server_port = random_tcp_port();
    let socks_port = random_tcp_port();

    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;
    let _client = spawn_client(server_port, socks_port);
    wait_tcp(socks_port).await;

    let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
    let payload = b"hello-snell-tcp-roundtrip";
    stream.write_all(payload).await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read failed");
    let recv = &buf[..n];
    assert!(recv.starts_with(b"ECHO:"), "no ECHO: prefix: {recv:?}");
    assert!(recv.windows(payload.len()).any(|w| w == payload));
}

#[tokio::test]
#[serial_test::serial]
async fn tcp_e2e_multiple_requests() {
    let echo_port = spawn_echo().await;
    let server_port = random_tcp_port();
    let socks_port = random_tcp_port();

    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;
    let _client = spawn_client(server_port, socks_port);
    wait_tcp(socks_port).await;

    for i in 0..5 {
        let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port).await;
        let msg = format!("request-{i}");
        stream.write_all(msg.as_bytes()).await.unwrap();
        let mut buf = [0u8; 64];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        assert!(buf[..n].windows(msg.len()).any(|w| w == msg.as_bytes()));
    }
}
