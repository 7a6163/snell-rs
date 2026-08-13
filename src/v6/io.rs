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
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Profile;
use super::seal_record_shaped;
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
    let k = *chunk;
    let mut prefix = vec![0u8; profile.prefix_len(k)];
    r.read_exact(&mut prefix).await?;

    let mut hdr = [0u8; HDR_CT_LEN];
    r.read_exact(&mut hdr).await?;
    let (interleave, payload_len) = cipher.open_header_raw_with_aad(&hdr, &prefix)?;
    *chunk += 1;

    if payload_len == 0 {
        // A zero record still carries its junk region; leaving it on the wire
        // desynchronises the stream against a peer that padded its terminator.
        r.read_exact(&mut vec![0u8; interleave]).await?;
        return Ok(None);
    }

    let mut body = vec![0u8; interleave + payload_len + 16];
    r.read_exact(&mut body).await?;
    let (junk, ct) = body.split_at_mut(interleave);
    if interleave > 0 {
        profile.mix(k, junk, ct);
    }
    cipher.open_payload_with_aad(ct, junk).map(Some)
}

/// Seal `data` as one or more `default`-mode records (split at `MAX_CHUNK`),
/// each with a PSK-derived prefix and a PSK-sized junk region. The prefix and
/// junk bytes are produced by the official filler generator (fn `0x417c8`),
/// and the junk is mixed into the payload ciphertext (fn `0x41200`). Advances
/// `chunk`.
pub async fn write_records<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cipher: &mut SnellCipher,
    profile: &Profile,
    chunk: &mut u64,
    data: &[u8],
) -> Result<()> {
    for part in data.chunks(MAX_CHUNK) {
        let k = *chunk;
        let first = k == 0;
        let il = profile.plan_interleave(k, part.len(), first);
        let mut prefix = vec![0u8; profile.prefix_len(k)];
        let mut junk = vec![0u8; il];
        profile.fill_filler(k, &mut prefix);
        profile.fill_filler(k, &mut junk);
        w.write_all(&seal_record_shaped(
            cipher, profile, k, part, &prefix, &junk,
        )?)
        .await?;
        *chunk += 1;
    }
    Ok(())
}

/// Write the session-terminating zero record: `prefix || zero_header_CT || junk`.
/// The zero record carries its own junk region, which the peer must drain.
pub async fn write_zero_record<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cipher: &mut SnellCipher,
    profile: &Profile,
    chunk: &mut u64,
) -> Result<()> {
    let k = *chunk;
    let first = k == 0;
    let il = profile.plan_interleave(k, 0, first);
    let mut prefix = vec![0u8; profile.prefix_len(k)];
    let mut junk = vec![0u8; il];
    profile.fill_filler(k, &mut prefix);
    profile.fill_filler(k, &mut junk);
    let mut out = Vec::with_capacity(prefix.len() + HDR_CT_LEN + il);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&cipher.seal_zero_with_junk(&prefix, il)?);
    out.extend_from_slice(&junk);
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
    // The junk region is inert in this mode (see `unsafe_raw`): no AAD, no mix.
    let mut body = vec![0u8; interleave + payload_len];
    r.read_exact(&mut body).await?;
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
    use crate::v6::seal_record_shaped;
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

    /// The reader's shaped path (un-mix + payload AAD) is pinned by the captured
    /// Surge fixtures; this pins our own sealer against it across junk sizes,
    /// including the degenerate ones where the mix can only touch part of a region.
    #[tokio::test]
    async fn shaped_records_with_junk_round_trip() {
        let profile = Profile::derive(PSK);
        let salt = [9u8; 16];
        let payloads: [&[u8]; 5] = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"];
        let junk_lens = [0usize, 1, 879, 3, 4096];
        let (mut a, mut b) = duplex(1 << 16);

        let profile_w = profile.clone();
        let writer = tokio::spawn(async move {
            let mut tx = SnellCipher::new(PSK, &salt).unwrap();
            let mut k = 0u64;
            for (payload, &jl) in payloads.iter().zip(junk_lens.iter()) {
                let prefix = vec![0xABu8; profile_w.prefix_len(k)];
                let junk: Vec<u8> = (0..jl).map(|i| (i * 31 + 7) as u8).collect();
                let rec =
                    seal_record_shaped(&mut tx, &profile_w, k, payload, &prefix, &junk).unwrap();
                a.write_all(&rec).await.unwrap();
                k += 1;
            }
            write_zero_record(&mut a, &mut tx, &profile_w, &mut k)
                .await
                .unwrap();
        });

        let mut rx = SnellCipher::new(PSK, &salt).unwrap();
        let mut k = 0u64;
        for payload in payloads {
            let got = read_record(&mut b, &mut rx, &profile, &mut k)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, payload);
        }
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
