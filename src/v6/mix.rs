//! v6 `default`-mode junk/ciphertext mix — official fn `0x41200` (aarch64 b2 and
//! rc2, byte-identical; amd64 `0x39ef0`).
//!
//! When a record carries a non-empty junk region, the sender swaps individual
//! bytes between that region and the payload ciphertext *after* sealing. The
//! permutation is PSK-derived and self-inverse, so the receiver undoes it by
//! calling the same routine *before* authenticating the payload — at which point
//! the restored junk bytes are the payload's AEAD AAD.
//!
//! Verified against captured Surge traffic: two PSKs exercising `mode == 1,
//! rounds == 1` and `mode == 2, rounds == 2` both recover a tag-valid payload.

use super::profile::Profile;

impl Profile {
    /// Mix variant selector (profile+0x70).
    fn mix_mode(&self) -> u32 {
        self.draw(16, 0) % 3
    }

    /// Mix round count, 1..=3 (profile+0xd2).
    fn mix_rounds(&self) -> u32 {
        self.param(17, 0, 1, 3)
    }

    /// Stride base for the strided variants, 2..=13 (profile+0x94).
    fn mix_stride_base(&self) -> u32 {
        self.param(18, 0, 2, 13)
    }

    /// Start-offset base for the strided variants, 0..=15 (profile+0xd4).
    fn mix_start_base(&self) -> u32 {
        self.param(19, 0, 0, 15)
    }

    /// Block size for the block variant, 8..=64 (profile+0xa2).
    fn mix_block(&self) -> u32 {
        self.param(20, 0, 8, 64)
    }

    /// Swap bytes between a record's junk region and its payload ciphertext.
    ///
    /// Self-inverse, so sender and receiver call it identically. Only the first
    /// `min(junk.len(), ct.len())` bytes of either region can move.
    pub(crate) fn mix(&self, chunk: u64, junk: &mut [u8], ct: &mut [u8]) {
        let n = junk.len().min(ct.len());
        if n == 0 {
            return;
        }
        let mode = self.mix_mode();
        for r in 0..self.mix_rounds() {
            if mode == 1 {
                // param(20,..) is at least 8, so the block size is never zero.
                let bs = self.mix_block() as usize;
                let nblocks = n / bs;
                // Round parity picks alternating blocks: one round moves the even
                // blocks, a second round moves the odd ones (and so undoes nothing).
                let mut blk = (r & 1) as usize;
                while blk < nblocks {
                    let base = blk * bs;
                    junk[base..base + bs].swap_with_slice(&mut ct[base..base + bs]);
                    blk += 2;
                }
            } else {
                let stride = self.mix_stride_base().wrapping_add(r % 3).max(1);
                let base = self.mix_start_base();
                let start = if mode == 2 {
                    base.wrapping_add(self.draw_b(3, chunk, u64::from(r))) % stride
                } else {
                    base % stride
                };
                let mut o = start as usize;
                while o < n {
                    std::mem::swap(&mut junk[o], &mut ct[o]);
                    o += stride as usize;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader only recovers the plaintext because the sender's mix is its own
    /// inverse; if that ever stops holding, every shaped record breaks.
    #[test]
    fn mix_is_an_involution_across_profiles_and_shapes() {
        for i in 0..64u32 {
            let p = Profile::derive(format!("involution-psk-{i:04}").as_bytes());
            for (jl, cl) in [
                (0, 0),
                (1, 1),
                (7, 130),
                (879, 102),
                (1022, 102),
                (300, 4096),
            ] {
                for chunk in 0..3u64 {
                    let junk0: Vec<u8> = (0..jl).map(|x| (x * 7 + 1) as u8).collect();
                    let ct0: Vec<u8> = (0..cl).map(|x| (x * 13 + 5) as u8).collect();
                    let (mut junk, mut ct) = (junk0.clone(), ct0.clone());
                    p.mix(chunk, &mut junk, &mut ct);
                    p.mix(chunk, &mut junk, &mut ct);
                    assert_eq!(junk, junk0, "junk psk={i} shape=({jl},{cl}) chunk={chunk}");
                    assert_eq!(ct, ct0, "ct psk={i} shape=({jl},{cl}) chunk={chunk}");
                }
            }
        }
    }

    /// A no-op mix would make the involution test pass vacuously. Sized so every
    /// block size (at most 64) yields many blocks: with only one block, `mode 1`
    /// with 3 rounds legitimately swaps it back and is the identity.
    #[test]
    fn mix_actually_moves_bytes() {
        for i in 0..64u32 {
            let p = Profile::derive(format!("involution-psk-{i:04}").as_bytes());
            let mut junk = vec![0xAAu8; 4096];
            let mut ct = vec![0x55u8; 4096];
            p.mix(0, &mut junk, &mut ct);
            assert!(
                ct.iter().any(|&b| b != 0x55),
                "psk {i} left the record untouched"
            );
        }
    }

    /// The two mix parameter sets that captured Surge traffic pinned down.
    #[test]
    fn mix_fields_match_reference_psks() {
        let a = Profile::derive(b"test-psk-0123456789abcdef");
        assert_eq!((a.mix_mode(), a.mix_rounds(), a.mix_block()), (1, 1, 51));
        assert_eq!((a.mix_stride_base(), a.mix_start_base()), (8, 10));

        let b = Profile::derive(b"test-psk-fedcba9876543210");
        assert_eq!((b.mix_mode(), b.mix_rounds(), b.mix_block()), (2, 2, 30));
    }
}
