//! CVE-3: server must reject a captured (salt, encrypted-chunk) replay.

mod common;

use common::*;
use snell::cipher::{SALT_LEN, SnellCipher};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Minimal TCP echo target — just enough for snell-server to set up a relay
/// against a real socket without hanging waiting for connect.
async fn spawn_tcp_target() -> u16 {
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
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Build a complete Snell v5 plain-obfs handshake prefix:
/// `[16-byte salt][sealed CONNECT_V2 chunk]` — exactly what a snell-client sends.
fn build_handshake(psk: &[u8], host: &str, target_port: u16) -> (Vec<u8>, [u8; SALT_LEN]) {
    let mut salt = [0u8; SALT_LEN];
    for b in salt.iter_mut() {
        *b = rand::random();
    }
    // dispatch() peeks the first byte and routes 0x16 → TLS obfs, 'G' (0x47) →
    // HTTP obfs, anything else → plain Snell. A random salt has a ~0.78%
    // chance of colliding with one of those prefixes, in which case the
    // server never reaches the salt-cache check and this test times out.
    // Re-roll until the leading byte routes to the plain Snell path.
    while salt[0] == 0x16 || salt[0] == b'G' {
        salt[0] = rand::random();
    }
    let mut cipher = SnellCipher::new(psk, &salt).unwrap();

    // [ver=0x01][cmd=CONNECT_V2=0x05][client_id_len=0][host_len][host][port_be]
    let hb = host.as_bytes();
    let mut hs = vec![0x01u8, 0x05, 0x00, hb.len() as u8];
    hs.extend_from_slice(hb);
    hs.extend_from_slice(&target_port.to_be_bytes());

    let sealed = cipher.seal(&hs).unwrap();
    let mut wire = Vec::with_capacity(SALT_LEN + sealed.len());
    wire.extend_from_slice(&salt);
    wire.extend_from_slice(&sealed);
    (wire, salt)
}

#[tokio::test]
#[serial_test::serial]
async fn tcp_handshake_replay_is_rejected() {
    let target_port = spawn_tcp_target().await;
    let server_port = random_tcp_port();

    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    let (handshake, _salt) = build_handshake(PSK.as_bytes(), "127.0.0.1", target_port);

    // First attempt: cache the salt by completing the salt-read on the server.
    {
        let mut s = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        s.write_all(&handshake).await.unwrap();
        // Give the server a moment to read the salt + insert into cache.
        tokio::time::sleep(Duration::from_millis(150)).await;
        // Close our side without reading the proxied response.
    }

    // Second attempt with the *same* bytes — must be rejected.
    let mut s = TcpStream::connect(("127.0.0.1", server_port))
        .await
        .unwrap();
    s.write_all(&handshake).await.unwrap();

    // Replay rejection => server bails immediately => our read returns 0 (EOF)
    // or errors with a reset. Either is acceptable; a successful non-zero read
    // (or a hang past the timeout) means the guard didn't fire.
    let mut buf = [0u8; 64];
    match timeout(Duration::from_secs(2), s.read(&mut buf)).await {
        Ok(Ok(0)) => {}  // EOF — server closed the replayed connection.
        Ok(Err(_)) => {} // Connection reset — also acceptable.
        Ok(Ok(n)) => panic!("server returned {n} bytes on replay; expected immediate close"),
        Err(_) => panic!("server did not close replay connection within 2s"),
    }
}

/// HTTP-obfs dispatch path: when the first byte is 'G' the server absorbs
/// an HTTP GET request, replies with `101 Switching Protocols`, then handles
/// the rest as a plain Snell handshake. This covers the obfs_budget timeout
/// callsite that the snell-client tests never reach (they go straight to
/// plain Snell).
#[tokio::test]
#[serial_test::serial]
async fn http_obfs_handshake_completes() {
    let target_port = spawn_tcp_target().await;
    let server_port = random_tcp_port();

    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    let mut s = TcpStream::connect(("127.0.0.1", server_port))
        .await
        .unwrap();

    // Send an HTTP GET to trigger the 'G' obfs dispatch arm.
    s.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();

    // Read the server's `101 Switching Protocols` reply (terminator \r\n\r\n).
    let mut accum = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = timeout(Duration::from_secs(2), s.read(&mut buf))
            .await
            .expect("101 reply timeout")
            .expect("101 read failed");
        if n == 0 {
            panic!("server closed before sending 101");
        }
        accum.extend_from_slice(&buf[..n]);
        if accum.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if accum.len() > 1024 {
            panic!("101 response too long without terminator: {:?}", accum);
        }
    }
    assert!(
        accum.starts_with(b"HTTP/1.1 101"),
        "unexpected obfs reply: {:?}",
        accum
    );

    // After the 101, write a plain-Snell handshake against the obfs'd stream.
    // The server is now in handle() expecting [16-byte salt][sealed chunk...].
    let (handshake, _) = build_handshake(PSK.as_bytes(), "127.0.0.1", target_port);
    s.write_all(&handshake).await.unwrap();

    // Brief read window — server should NOT close immediately; it's setting
    // up the relay to the target. Either some bytes or a timeout means alive.
    let mut buf = [0u8; 64];
    match timeout(Duration::from_millis(300), s.read(&mut buf)).await {
        Ok(Ok(0)) => panic!("server closed obfs+handshake connection unexpectedly"),
        Ok(Err(e)) => panic!("server reset obfs+handshake connection: {e}"),
        _ => {}
    }
}

/// Negative control: distinct salts must both be accepted. Without this we
/// can't tell whether the previous test passes because of the salt cache or
/// because the server is broken in general.
#[tokio::test]
#[serial_test::serial]
async fn fresh_salts_both_accepted() {
    let target_port = spawn_tcp_target().await;
    let server_port = random_tcp_port();

    let _server = spawn_server(server_port, false);
    wait_tcp(server_port).await;

    for _ in 0..2 {
        let (handshake, _) = build_handshake(PSK.as_bytes(), "127.0.0.1", target_port);
        let mut s = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        s.write_all(&handshake).await.unwrap();
        // Brief read window — server should NOT close immediately; if the salt
        // is fresh it'll be busy setting up the relay.
        let mut buf = [0u8; 64];
        match timeout(Duration::from_millis(300), s.read(&mut buf)).await {
            Ok(Ok(0)) => panic!("server closed a fresh-salt connection unexpectedly"),
            Ok(Err(e)) => panic!("server reset a fresh-salt connection: {e}"),
            _ => {} // Either some bytes, or timeout — both mean "connection alive".
        }
    }
}
