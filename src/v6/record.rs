//! v6 record layer: every v5-style AEAD chunk is preceded by `prefix_len(k)`
//! PSK-derived bytes, and those prefix bytes are the header chunk's AEAD AAD.
//!
//!   record(k) = [prefix: prefix_len(k) bytes]
//!               [header CT: 23B, AAD = prefix]
//!               [interleave bytes]
//!               [payload CT: plen + 16]
//!
//! `k` is the per-direction chunk index (0,1,2,...). The crypto (AES-128-GCM,
//! 12-byte LE counter nonce: header = 2k, payload = 2k+1) is unchanged from v5,
//! so this reuses [`SnellCipher`]; the only addition is the prefix + header AAD.

use anyhow::Result;

use super::profile::{HI_CAP, Profile};
use crate::cipher::{HDR_CT_LEN, SnellCipher};

/// Maximum bytes a single record may be inflated by (fn `0x41b00`).
const PAD_CAP: u32 = 730;

impl Profile {
    /// Prefix length lower bound, clamped against [`prefix_hi`](Self::prefix_hi).
    pub(crate) fn prefix_lo(&self) -> u32 {
        self.param(14, 0, 8, 80).min(self.prefix_hi())
    }

    /// Prefix length upper bound, clamped to HI_CAP (profile init epilogue `0x42520`).
    pub(crate) fn prefix_hi(&self) -> u32 {
        (self.param(14, 0, 8, 80) + self.param(15, 0, 16, 160)).min(HI_CAP)
    }

    /// Per-chunk PSK-derived prefix byte count (fn `0x41600`).
    pub fn prefix_len(&self, chunk: u64) -> usize {
        self.bound(
            self.draw_b(33, chunk, 0),
            self.prefix_lo(),
            self.prefix_hi(),
        ) as usize
    }

    // ── interleave sizing ───────────────────────────────────────────────────

    /// Interleave length upper bound, clamped to [`PAD_CAP`] (profile+0x50).
    fn inter_hi(&self) -> u32 {
        (self.param(7, 0, 24, 160) + self.param(8, 0, 160, 960)).min(PAD_CAP)
    }

    /// Interleave length lower bound, clamped against [`inter_hi`](Self::inter_hi).
    fn inter_lo(&self) -> u32 {
        self.param(7, 0, 24, 160).min(self.inter_hi())
    }

    /// fn `0x41630`: whether this record should carry a junk region.
    fn should_interleave(&self, chunk: u32, payload_len: u32) -> bool {
        if self.param(9, 0, 2, 8) > chunk {
            return true;
        }
        if payload_len != 0 && self.param(11, 0, 96, 768) >= payload_len {
            return true;
        }
        let d = self.param(10, 0, 2, 11);
        d != 0 && chunk.is_multiple_of(d)
    }

    /// fn `0x41680`: base interleave length before target-size padding.
    fn interleave_len(&self, chunk: u32, payload_len: u32) -> u32 {
        if !self.should_interleave(chunk, payload_len) {
            return 0;
        }
        self.bound(
            self.draw_b(34, chunk as u64, payload_len as u64),
            self.inter_lo(),
            self.inter_hi(),
        )
    }

    /// fn `0x41b08`: pick a plausible packet size to pad toward.
    fn target_size(&self, chunk: u32, total: u64) -> u32 {
        if total > 1459 {
            return if total <= 0xfffe {
                total as u32
            } else {
                0xffff
            };
        }
        let tbl_a = |i: u32| self.param(30, i as u64, 320, 1460);
        let n_a = 8u32;
        let n_c = self.param(29, 0, 4, 8);

        // Base pick: per-chunk table for early chunks, shared table otherwise.
        let mut cur = if n_c > chunk {
            self.param(31, chunk as u64, 360, 1460)
        } else {
            tbl_a(self.draw_b(35, chunk as u64, total) % n_a)
        };

        // Inflation ceiling: pct% of total, capped at PAD_CAP.
        let pct = self.param(28, 0x504c, 8, 48) as u64;
        let mut ceiling = (pct * total / 100).min(PAD_CAP as u64) as u32;
        let odd = self.draw_b(35, chunk as u64, ceiling as u64) & 1;

        // Mode-2 jitter: symmetric ±j wobble.
        if self.draw(28, 0) % 3 == 2 {
            let j = self.param(32, 0, 8, 96);
            let r = self.draw_b(36, chunk as u64, 0) % (2 * j + 1);
            let v = cur as i64 + r as i64 - j as i64;
            cur = if v <= 0 { 1 } else { (v as u32) & 0xffff };
        }

        // Inflate or deflate on one PRF bit.
        if odd != 0 {
            ceiling >>= 1;
            if ceiling < cur {
                cur = (cur - ceiling) & 0xffff;
            }
        } else {
            cur = (cur + ceiling).min(0xffff);
        }

        // Grow until the target covers the record.
        while total > cur as u64 {
            let t = tbl_a(self.draw_b(37, chunk as u64, cur as u64) % n_a);
            cur = if cur >= t {
                (cur + self.inter_hi()).min(0xffff)
            } else {
                t
            };
        }
        cur & 0xffff
    }

    /// fn `0x41cd0`: raise the first record's interleave so the combined
    /// frame + record meets a minimum wire size. Divisor is exactly 75.
    fn first_record_floor(
        &self,
        frame_body: u32,
        prefix: u32,
        interleave: u32,
        payload_len: u64,
    ) -> u32 {
        let x = payload_len + if payload_len != 0 { 55 } else { 39 };
        let floor = (25 * x).div_ceil(75).max(192);
        let seen = interleave as u64 + prefix as u64 + frame_body as u64;
        if seen >= floor {
            return interleave;
        }
        let need = (floor - seen + interleave as u64).min(self.inter_hi() as u64 + PAD_CAP as u64);
        if need <= 0xfffe { need as u32 } else { 0xffff }
    }

    /// Compute the interleave length for a record (fn `0x43320` sizing path).
    ///
    /// `chunk` is the per-direction record index. `first_record` should be
    /// true when `chunk == 0` (the first record after the handshake frame);
    /// it adds the frame length to the sizing total and applies the
    /// first-record floor.
    pub(crate) fn plan_interleave(
        &self,
        chunk: u64,
        payload_len: usize,
        first_record: bool,
    ) -> usize {
        let chunk = chunk as u32;
        let pl = payload_len as u32;
        let frame_len = if first_record { self.frame_len() } else { 0 };
        let prefix = self.prefix_len(chunk as u64) as u64;
        let mut inter = self.interleave_len(chunk, pl) as u64;
        let total = frame_len as u64
            + prefix
            + HDR_CT_LEN as u64
            + inter
            + pl as u64
            + if pl != 0 { 16 } else { 0 };

        let target = self.target_size(chunk, total) as u64;
        if target > total {
            let add = (target - total).min(PAD_CAP as u64) as u32;
            inter += add as u64;
        }

        if first_record {
            let raised = self.first_record_floor(
                (frame_len - 16) as u32,
                prefix as u32,
                inter as u32,
                pl as u64,
            ) as u64;
            inter = raised;
        }

        inter as usize
    }
}

/// Seal one v6 record: `prefix || header_CT(AAD=prefix) || payload_CT`.
///
/// `prefix` must be `prefix_len(k)` bytes for the chunk index `k` being sealed;
/// its content is arbitrary (random on the wire, zero-filled in the golden
/// vectors). The caller advances `cipher`'s nonce by sealing in chunk order.
pub fn seal_record(cipher: &mut SnellCipher, plaintext: &[u8], prefix: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(prefix.len() + HDR_CT_LEN + plaintext.len() + 16);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&cipher.seal_with_aad(plaintext, prefix)?);
    Ok(out)
}

/// Seal one v6 record carrying a junk region:
/// `prefix || header_CT(AAD=prefix) || junk || payload_CT(AAD=junk)`, with the
/// profile mix applied across the junk and payload regions.
///
/// `chunk` is the record index `k` being sealed, and must match the `prefix`
/// length. An empty `junk` reproduces [`seal_record`] byte for byte.
pub fn seal_record_shaped(
    cipher: &mut SnellCipher,
    profile: &Profile,
    chunk: u64,
    plaintext: &[u8],
    prefix: &[u8],
    junk: &[u8],
) -> Result<Vec<u8>> {
    let mut body = cipher.seal_with_junk(plaintext, prefix, junk)?;
    if !junk.is_empty() {
        let (j, ct) = body[HDR_CT_LEN..].split_at_mut(junk.len());
        profile.mix(chunk, j, ct);
    }
    let mut out = Vec::with_capacity(prefix.len() + body.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK_A: &[u8] = b"test-psk-0123456789abcdef";

    #[test]
    fn prefix_fields_match_reference_psk_a() {
        let p = Profile::derive(PSK_A);
        assert_eq!(p.prefix_lo(), 78);
        assert_eq!(p.prefix_hi(), 128);
        assert_eq!(p.prefix_len(0), 107);
    }

    /// An empty junk region must leave the wire bytes exactly as the junkless
    /// sealer produces them, or the committed v6 golden vectors would shift.
    #[test]
    fn empty_junk_matches_the_plain_record() {
        let p = Profile::derive(PSK_A);
        let prefix = vec![0u8; p.prefix_len(0)];
        let mut c1 = SnellCipher::new(PSK_A, &[3u8; 16]).unwrap();
        let mut c2 = SnellCipher::new(PSK_A, &[3u8; 16]).unwrap();
        assert_eq!(
            seal_record_shaped(&mut c1, &p, 0, b"payload", &prefix, &[]).unwrap(),
            seal_record(&mut c2, b"payload", &prefix).unwrap()
        );
    }

    /// PSK A mixes with `mode 1, rounds 1, block 51`, so a record with enough
    /// junk must come out permuted — otherwise the writer is silently skipping
    /// the mix and would only interoperate with itself.
    #[test]
    fn shaped_record_permutes_junk_and_ciphertext() {
        let p = Profile::derive(PSK_A);
        let prefix = vec![0u8; p.prefix_len(0)];
        let junk: Vec<u8> = (0..879u32).map(|i| (i % 251) as u8).collect();
        let mut cipher = SnellCipher::new(PSK_A, &[3u8; 16]).unwrap();
        let rec = seal_record_shaped(&mut cipher, &p, 0, &[0u8; 86], &prefix, &junk).unwrap();

        let body = &rec[prefix.len() + HDR_CT_LEN..];
        assert_eq!(body.len(), junk.len() + 86 + 16);
        assert_ne!(&body[..junk.len()], &junk[..], "junk region was not mixed");
        // The mix only moves the first 51 bytes of either region for this profile.
        assert_eq!(&body[51..junk.len()], &junk[51..]);
    }

    /// The sizing pipeline must reproduce the exact interleave lengths from
    /// captured Surge traffic. PSK A saturates the +730 pad cap; PSK B does
    /// not, making it a discriminating oracle on `target_size`.
    #[test]
    fn plan_interleave_matches_captures() {
        let a = Profile::derive(b"test-psk-0123456789abcdef");
        assert_eq!(a.plan_interleave(0, 86, true), 879, "PSK A interleave");

        let b = Profile::derive(b"test-psk-fedcba9876543210");
        assert_eq!(b.plan_interleave(0, 86, true), 1022, "PSK B interleave");
    }
}
