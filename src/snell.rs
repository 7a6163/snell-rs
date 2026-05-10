//! Snell v5 protocol layer — wire format identical to v3.

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::cipher::{SnellCipher, HDR_CT_LEN};

pub const CMD_PING:       u8 = 0x00;
pub const CMD_CONNECT:    u8 = 0x01;
pub const CMD_CONNECT_V2: u8 = 0x05;
pub const RESP_TUNNEL:    u8 = 0x00;
pub const RESP_PONG:      u8 = 0x01;
pub const RESP_ERROR:     u8 = 0x02;

pub struct SnellRequest {
    pub command:  u8,
    pub host:     String,
    pub port:     u16,
    /// App data bundled with the handshake in the first chunk.
    pub trailing: Vec<u8>,
}

/// Parse a decrypted Snell v5 handshake payload.
pub fn parse_request(data: &[u8]) -> Result<SnellRequest> {
    if data.len() < 3 { bail!("request too short"); }
    if data[0] != 0x01 { bail!("unsupported snell version {}", data[0]); }
    let command       = data[1];
    let client_id_len = data[2] as usize;

    if command == CMD_PING {
        return Ok(SnellRequest { command, host: String::new(), port: 0, trailing: vec![] });
    }

    let mut pos = 3 + client_id_len;
    if data.len() < pos + 3 { bail!("truncated handshake"); }
    let host_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + host_len + 2 { bail!("truncated host"); }
    let host = String::from_utf8(data[pos..pos + host_len].to_vec())?;
    pos += host_len;
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    Ok(SnellRequest { command, host, port, trailing: data[pos..].to_vec() })
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
        for i in (0..n).step_by(2) { buf.swap(i, interleave + i); }
    }

    cipher.open_payload(&buf[interleave..interleave + payload_len + 16]).map(Some)
}

/// Encrypt `data` as chunks and write to `w` (splits at 16383 bytes if needed).
pub async fn write_chunk<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cipher: &mut SnellCipher,
    data: &[u8],
) -> Result<()> {
    for chunk in data.chunks(0x3fff) {
        w.write_all(&cipher.seal(chunk)).await?;
    }
    Ok(())
}
