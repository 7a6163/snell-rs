//! Snell v5 protocol layer — wire format identical to v3.

use crate::cipher::{HDR_CT_LEN, SnellCipher};
use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const CMD_PING: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_CONNECT_V2: u8 = 0x05;
pub const CMD_CONNECT_UDP: u8 = 0x06;
pub const RESP_TUNNEL: u8 = 0x00;
pub const RESP_PONG: u8 = 0x01;
pub const RESP_ERROR: u8 = 0x02;

pub struct SnellRequest {
    pub command: u8,
    pub host: String,
    pub port: u16,
    /// App data bundled with the handshake in the first chunk.
    pub trailing: Vec<u8>,
}

/// Parse a decrypted Snell v5 handshake payload.
pub fn parse_request(data: &[u8]) -> Result<SnellRequest> {
    if data.len() < 3 {
        bail!("request too short");
    }
    if data[0] != 0x01 {
        bail!("unsupported snell version {}", data[0]);
    }
    let command = data[1];
    let client_id_len = data[2] as usize;

    if command == CMD_PING {
        return Ok(SnellRequest {
            command,
            host: String::new(),
            port: 0,
            trailing: vec![],
        });
    }

    if data.len() < 3 + client_id_len {
        bail!("truncated client_id (need {} bytes)", client_id_len);
    }
    let mut pos = 3 + client_id_len;
    if data.len() < pos + 3 {
        bail!("truncated handshake");
    }
    let host_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + host_len + 2 {
        bail!("truncated host");
    }
    let host = String::from_utf8(data[pos..pos + host_len].to_vec())?;
    pos += host_len;
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    Ok(SnellRequest {
        command,
        host,
        port,
        trailing: data[pos..].to_vec(),
    })
}

/// Read and decrypt one complete chunk. Returns `None` on zero chunk.
pub async fn read_chunk<R: AsyncReadExt + Unpin>(
    r: &mut R,
    cipher: &mut SnellCipher,
) -> Result<Option<Vec<u8>>> {
    let mut hdr_ct = [0u8; HDR_CT_LEN];
    r.read_exact(&mut hdr_ct).await?;

    let Some((interleave, payload_len)) = cipher.open_header(&hdr_ct)? else {
        return Ok(None);
    };

    let total = interleave + payload_len + 16;
    let mut buf = vec![0u8; total];
    r.read_exact(&mut buf).await?;

    // Un-interleave: undo the even-byte swap applied by sender
    if interleave > 0 {
        let n = interleave.min(payload_len + 16);
        for i in (0..n).step_by(2) {
            buf.swap(i, interleave + i);
        }
    }

    cipher
        .open_payload(&buf[interleave..interleave + payload_len + 16])
        .map(Some)
}

/// Encrypt `data` as chunks and write to `w` (splits at 16383 bytes if needed).
pub async fn write_chunk<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cipher: &mut SnellCipher,
    data: &[u8],
) -> Result<()> {
    for chunk in data.chunks(0x3fff) {
        w.write_all(&cipher.seal(chunk)?).await?;
    }
    Ok(())
}

/// Like `write_chunk` but limits each chunk to `max_bytes` (used by adaptive sizer).
pub async fn write_chunk_sized<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cipher: &mut SnellCipher,
    data: &[u8],
    max_bytes: usize,
) -> Result<()> {
    let cap = max_bytes.min(0x3fff);
    for chunk in data.chunks(cap) {
        w.write_all(&cipher.seal(chunk)?).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    const TEST_PSK: &[u8] = b"unit-test-psk-with-enough-bytes!";
    const TEST_SALT: [u8; 16] = [0u8; 16];

    fn cipher_pair() -> (SnellCipher, SnellCipher) {
        (
            SnellCipher::new(TEST_PSK, &TEST_SALT).unwrap(),
            SnellCipher::new(TEST_PSK, &TEST_SALT).unwrap(),
        )
    }

    // ---- parse_request -------------------------------------------------------

    #[test]
    fn parse_request_ping_returns_empty_host_and_port() {
        let req = parse_request(&[0x01, CMD_PING, 0]).unwrap();
        assert_eq!(req.command, CMD_PING);
        assert!(req.host.is_empty());
        assert_eq!(req.port, 0);
        assert!(req.trailing.is_empty());
    }

    #[test]
    fn parse_request_connect_v2_with_host_and_port() {
        // version=01, cmd=05, client_id_len=00, host_len=07, "example", port=0x01bb (443)
        let data = b"\x01\x05\x00\x07example\x01\xbb";
        let req = parse_request(data).unwrap();
        assert_eq!(req.command, CMD_CONNECT_V2);
        assert_eq!(req.host, "example");
        assert_eq!(req.port, 443);
        assert!(req.trailing.is_empty());
    }

    #[test]
    fn parse_request_skips_client_id_bytes() {
        // client_id_len=4 ("abcd") must be skipped, not parsed as host.
        let data = b"\x01\x05\x04abcd\x04host\x00\x50";
        let req = parse_request(data).unwrap();
        assert_eq!(req.host, "host");
        assert_eq!(req.port, 80);
    }

    #[test]
    fn parse_request_extracts_trailing_app_data() {
        let data = b"\x01\x05\x00\x04host\x00\x50body";
        let req = parse_request(data).unwrap();
        assert_eq!(req.host, "host");
        assert_eq!(req.port, 80);
        assert_eq!(req.trailing, b"body");
    }

    #[test]
    fn parse_request_rejects_buffer_below_minimum() {
        assert!(parse_request(&[]).is_err());
        assert!(parse_request(&[0x01]).is_err());
        assert!(parse_request(&[0x01, CMD_CONNECT_V2]).is_err());
    }

    #[test]
    fn parse_request_rejects_unsupported_version() {
        assert!(parse_request(&[0x02, CMD_CONNECT_V2, 0]).is_err());
        assert!(parse_request(&[0xff, CMD_CONNECT_V2, 0]).is_err());
    }

    #[test]
    fn parse_request_rejects_truncated_client_id() {
        // claims 10-byte client_id but only 2 bytes follow
        assert!(parse_request(&[0x01, CMD_CONNECT_V2, 10, b'a', b'b']).is_err());
    }

    #[test]
    fn parse_request_rejects_truncated_host_or_port() {
        // host_len=100 but no host bytes follow
        assert!(parse_request(&[0x01, CMD_CONNECT_V2, 0, 100]).is_err());
        // host bytes present but no port bytes
        assert!(parse_request(b"\x01\x05\x00\x04host").is_err());
    }

    #[test]
    fn parse_request_rejects_non_utf8_host() {
        let data: &[u8] = &[
            0x01,
            CMD_CONNECT_V2,
            0,
            4,
            0xff,
            0xfe,
            0xfd,
            0xfc,
            0x00,
            0x50,
        ];
        assert!(parse_request(data).is_err());
    }

    // ---- chunk round-trips ---------------------------------------------------

    #[tokio::test]
    async fn roundtrip_small_payload() {
        let (mut tx, mut rx) = cipher_pair();
        let (mut wend, mut rend) = duplex(64 * 1024);
        let payload = b"hello world";
        write_chunk(&mut wend, &mut tx, payload).await.unwrap();
        let out = read_chunk(&mut rend, &mut rx).await.unwrap();
        assert_eq!(out.as_deref(), Some(&payload[..]));
    }

    #[tokio::test]
    async fn roundtrip_single_byte() {
        let (mut tx, mut rx) = cipher_pair();
        let (mut wend, mut rend) = duplex(64);
        write_chunk(&mut wend, &mut tx, &[0x42]).await.unwrap();
        let out = read_chunk(&mut rend, &mut rx).await.unwrap();
        assert_eq!(out, Some(vec![0x42]));
    }

    #[tokio::test]
    async fn roundtrip_at_max_chunk_boundary() {
        // 0x3fff = 16383 — largest single chunk write_chunk emits.
        let payload = vec![0xABu8; 0x3fff];
        let (mut tx, mut rx) = cipher_pair();
        let (mut wend, mut rend) = duplex(128 * 1024);
        write_chunk(&mut wend, &mut tx, &payload).await.unwrap();
        let out = read_chunk(&mut rend, &mut rx).await.unwrap();
        assert_eq!(out, Some(payload));
    }

    #[tokio::test]
    async fn roundtrip_just_over_max_chunk_splits_into_two() {
        let payload = vec![0xCDu8; 0x3fff + 1];
        let (mut tx, mut rx) = cipher_pair();
        let (mut wend, mut rend) = duplex(128 * 1024);
        write_chunk(&mut wend, &mut tx, &payload).await.unwrap();

        let first = read_chunk(&mut rend, &mut rx).await.unwrap().unwrap();
        let second = read_chunk(&mut rend, &mut rx).await.unwrap().unwrap();
        assert_eq!(first.len(), 0x3fff);
        assert_eq!(second.len(), 1);

        let mut combined = first;
        combined.extend(second);
        assert_eq!(combined, payload);
    }

    #[tokio::test]
    async fn roundtrip_multi_chunk_large_payload() {
        // 50 KiB → 4 chunks (16383, 16383, 16383, 851).
        let payload: Vec<u8> = (0..50 * 1024).map(|i| (i & 0xff) as u8).collect();
        let (mut tx, mut rx) = cipher_pair();
        let (mut wend, mut rend) = duplex(128 * 1024);
        write_chunk(&mut wend, &mut tx, &payload).await.unwrap();
        let mut got = Vec::with_capacity(payload.len());
        while got.len() < payload.len() {
            let chunk = read_chunk(&mut rend, &mut rx).await.unwrap().unwrap();
            got.extend(chunk);
        }
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn write_chunk_with_empty_input_emits_no_bytes() {
        let mut tx = SnellCipher::new(TEST_PSK, &TEST_SALT).unwrap();
        let (mut wend, mut rend) = duplex(64);
        write_chunk(&mut wend, &mut tx, &[]).await.unwrap();
        drop(wend);
        let mut buf = [0u8; 32];
        let n = rend.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "empty payload must produce zero on-wire bytes");
    }

    #[tokio::test]
    async fn zero_chunk_surfaces_as_none() {
        let (mut tx, mut rx) = cipher_pair();
        let (mut wend, mut rend) = duplex(64);
        let zero = tx.seal_zero().unwrap();
        wend.write_all(&zero).await.unwrap();
        let out = read_chunk(&mut rend, &mut rx).await.unwrap();
        assert!(out.is_none(), "zero-length chunk must surface as None");
    }

    #[tokio::test]
    async fn write_chunk_sized_with_small_cap_splits_into_many() {
        // cap = 4 — each chunk holds at most 4 plaintext bytes.
        let payload: Vec<u8> = (0..16u8).collect();
        let (mut tx, mut rx) = cipher_pair();
        let (mut wend, mut rend) = duplex(64 * 1024);
        write_chunk_sized(&mut wend, &mut tx, &payload, 4)
            .await
            .unwrap();
        let mut got = Vec::new();
        for _ in 0..4 {
            let chunk = read_chunk(&mut rend, &mut rx).await.unwrap().unwrap();
            assert!(chunk.len() <= 4);
            got.extend(chunk);
        }
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn write_chunk_sized_clamps_cap_to_protocol_max() {
        // Requesting 1 MiB cap must be clamped to 0x3fff.
        let payload = vec![0x5Au8; 0x3fff + 1];
        let (mut tx, mut rx) = cipher_pair();
        let (mut wend, mut rend) = duplex(128 * 1024);
        write_chunk_sized(&mut wend, &mut tx, &payload, 1024 * 1024)
            .await
            .unwrap();
        let first = read_chunk(&mut rend, &mut rx).await.unwrap().unwrap();
        let second = read_chunk(&mut rend, &mut rx).await.unwrap().unwrap();
        assert_eq!(first.len(), 0x3fff);
        assert_eq!(second.len(), 1);
    }
}
