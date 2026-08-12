//! Async wire IO for the v6 `default` (shaped) and `unsafe-raw` (plaintext) modes.
//!
//! `default`: every AEAD chunk is a [`seal_record`](super::seal_record)-style
//! record — a per-chunk PSK-derived prefix (which is also the header AEAD AAD)
//! followed by the v5 chunk. A per-direction chunk counter drives `prefix_len`.
//! Session end is a prefixed zero record.
//!
//! `unsafe-raw`: plaintext [`encode_unsafe_raw`](super::unsafe_raw::encode_unsafe_raw)
//! frames — no salt, KDF, or cipher. Session end is a zero-length frame.
//!
//! The crypto (AES-128-GCM, argon2id KDF) is unchanged from v5; these helpers
//! only add the v6 framing verified byte-exact in `tests/v6_test_vectors.json`.

use anyhow::{Result, bail};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Profile;
use super::seal_record;
use super::unsafe_raw::encode_unsafe_raw;
use crate::cipher::{HDR_CT_LEN, SnellCipher};

/// Protocol chunk-size ceiling (matches v5 `write_chunk`).
const MAX_CHUNK: usize = 0x3fff;

// ── default mode: prefixed records ───────────────────────────────────────────

/// Read one `default`-mode record. Returns `None` on a zero record (session
/// EOF). Advances `chunk` (the per-direction record index) on every call.
pub async fn read_record<R: AsyncReadExt + Unpin>(
    r: &mut R,
    cipher: &mut SnellCipher,
    profile: &Profile,
    chunk: &mut u64,
) -> Result<Option<Vec<u8>>> {
    let mut prefix = vec![0u8; profile.prefix_len(*chunk)];
    r.read_exact(&mut prefix).await?;

    let mut hdr = [0u8; HDR_CT_LEN];
    r.read_exact(&mut hdr).await?;
    let opened = cipher.open_header_with_aad(&hdr, &prefix)?;
    *chunk += 1;
    let Some((interleave, payload_len)) = opened else {
        return Ok(None);
    };

    let mut buf = vec![0u8; interleave + payload_len + 16];
    r.read_exact(&mut buf).await?;
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

/// Seal `data` as one or more `default`-mode records (split at `MAX_CHUNK`),
/// each with a fresh random prefix of the PSK-derived length. Advances `chunk`.
pub async fn write_records<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cipher: &mut SnellCipher,
    profile: &Profile,
    chunk: &mut u64,
    data: &[u8],
) -> Result<()> {
    for part in data.chunks(MAX_CHUNK) {
        let mut prefix = vec![0u8; profile.prefix_len(*chunk)];
        rand::thread_rng().fill_bytes(&mut prefix);
        w.write_all(&seal_record(cipher, part, &prefix)?).await?;
        *chunk += 1;
    }
    Ok(())
}

/// Write the session-terminating zero record (prefix + zero header CT).
pub async fn write_zero_record<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cipher: &mut SnellCipher,
    profile: &Profile,
    chunk: &mut u64,
) -> Result<()> {
    let mut prefix = vec![0u8; profile.prefix_len(*chunk)];
    rand::thread_rng().fill_bytes(&mut prefix);
    let mut out = Vec::with_capacity(prefix.len() + HDR_CT_LEN);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&cipher.seal_zero_with_aad(&prefix)?);
    w.write_all(&out).await?;
    *chunk += 1;
    Ok(())
}

// ── unsafe-raw mode: plaintext frames ────────────────────────────────────────

/// Read one `unsafe-raw` plaintext frame. Returns `None` on a zero-length frame
/// or a clean EOF (both signal session end).
pub async fn read_unsafe_raw<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; 5];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if hdr[0] != 0x04 {
        bail!("bad unsafe-raw type {:#04x}", hdr[0]);
    }
    let interleave = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
    let payload_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if payload_len == 0 {
        return Ok(None);
    }
    let mut body = vec![0u8; interleave + payload_len];
    r.read_exact(&mut body).await?;
    // Un-interleave: undo the even-byte swap the sender applied.
    if interleave > 0 {
        let n = interleave.min(payload_len);
        for i in (0..n).step_by(2) {
            body.swap(i, interleave + i);
        }
    }
    Ok(Some(body[interleave..].to_vec()))
}

/// Write `data` as one or more `unsafe-raw` plaintext frames (split at `MAX_CHUNK`).
pub async fn write_unsafe_raw<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    for part in data.chunks(MAX_CHUNK) {
        w.write_all(&encode_unsafe_raw(part)).await?;
    }
    Ok(())
}

/// Write the session-terminating zero-length `unsafe-raw` frame.
pub async fn write_unsafe_raw_zero<W: AsyncWriteExt + Unpin>(w: &mut W) -> Result<()> {
    w.write_all(&encode_unsafe_raw(&[])).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    const PSK: &[u8] = b"io-test-psk-0123456789abcdef";

    #[tokio::test]
    async fn default_records_round_trip_with_prefixes() {
        let profile = Profile::derive(PSK);
        let salt = [7u8; 16];
        let (mut a, mut b) = duplex(65536);

        // writer side
        let profile_w = profile.clone();
        let writer = tokio::spawn(async move {
            let mut tx = SnellCipher::new(PSK, &salt).unwrap();
            let mut k = 0u64;
            write_records(&mut a, &mut tx, &profile_w, &mut k, b"first")
                .await
                .unwrap();
            write_records(&mut a, &mut tx, &profile_w, &mut k, b"second-chunk")
                .await
                .unwrap();
            write_zero_record(&mut a, &mut tx, &profile_w, &mut k)
                .await
                .unwrap();
        });

        let mut rx = SnellCipher::new(PSK, &salt).unwrap();
        let mut k = 0u64;
        assert_eq!(
            read_record(&mut b, &mut rx, &profile, &mut k)
                .await
                .unwrap()
                .unwrap(),
            b"first"
        );
        assert_eq!(
            read_record(&mut b, &mut rx, &profile, &mut k)
                .await
                .unwrap()
                .unwrap(),
            b"second-chunk"
        );
        assert!(
            read_record(&mut b, &mut rx, &profile, &mut k)
                .await
                .unwrap()
                .is_none()
        );
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn unsafe_raw_frames_round_trip() {
        let (mut a, mut b) = duplex(65536);
        let writer = tokio::spawn(async move {
            write_unsafe_raw(&mut a, b"plaintext-one").await.unwrap();
            write_unsafe_raw(&mut a, b"two").await.unwrap();
            write_unsafe_raw_zero(&mut a).await.unwrap();
        });
        assert_eq!(
            read_unsafe_raw(&mut b).await.unwrap().unwrap(),
            b"plaintext-one"
        );
        assert_eq!(read_unsafe_raw(&mut b).await.unwrap().unwrap(), b"two");
        assert!(read_unsafe_raw(&mut b).await.unwrap().is_none());
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn unsafe_raw_read_treats_eof_as_end() {
        let (a, mut b) = duplex(64);
        drop(a); // immediate EOF
        assert!(read_unsafe_raw(&mut b).await.unwrap().is_none());
    }
}
