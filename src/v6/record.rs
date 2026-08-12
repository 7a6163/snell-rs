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

impl Profile {
    /// Prefix length lower bound (profile+188).
    pub(crate) fn prefix_lo(&self) -> u32 {
        self.param(14, 0, 8, 80)
    }

    /// Prefix length upper bound (profile+90), clamped to HI_CAP.
    pub(crate) fn prefix_hi(&self) -> u32 {
        (self.prefix_lo() + self.param(15, 0, 16, 160)).min(HI_CAP)
    }

    /// Per-chunk PSK-derived prefix byte count (the chunk index drives PRF `b`).
    pub fn prefix_len(&self, chunk: u64) -> usize {
        let (lo, hi) = (self.prefix_lo(), self.prefix_hi());
        (lo + self.draw_b(33, chunk, 0) % (hi - lo + 1)) as usize
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_fields_match_reference_psk_a() {
        let p = Profile::derive(b"test-psk-0123456789abcdef");
        assert_eq!(p.prefix_lo(), 78);
        assert_eq!(p.prefix_hi(), 128);
        assert_eq!(p.prefix_len(0), 107);
    }
}
