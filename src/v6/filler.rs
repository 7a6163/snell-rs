//! v6 wire-filler generator — official fn `0x417c8`. Produces the
//! popcount-shaped bytes that pad the first frame, the per-record prefix, and
//! the per-record junk region.
//!
//! All official filler consists of bytes from a single popcount row of
//! [`POPTBL`], rotated by a per-position amount. Both test PSKs select row 4
//! (popcount 4), which is why every filler byte in the captures has exactly
//! four bits set. The generator is PSK-derived and session-independent: two
//! sessions with the same PSK produce byte-identical filler.
//!
//! Verified byte-exact against captured Surge traffic for both test PSKs
//! across all six oracle regions (prefix, junk, first-frame filler × 2 PSKs).

use super::profile::{GOLDEN, MUL, Profile, fmix64};

/// rodata `0x1b84f0`: row `k` holds 16 rotation representatives of popcount `k`.
/// Only rows 0..=7 are reachable; row 4 is the 16-entry table previously found
/// at file offset `0x1fd000`.
const POPTBL: [[u8; 16]; 8] = [
    [0x00; 16],
    [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80,
    ],
    [
        0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18,
        0x24,
    ],
    [
        0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70,
        0xe0,
    ],
    [
        0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78,
        0xf0,
    ],
    [
        0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f,
        0x1f,
    ],
    [
        0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7,
        0xdb,
    ],
    [
        0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf,
        0x7f,
    ],
];

// fn 0x41090 state-mixing constants.
const PRF_LEN_MUL: u64 = 0x165667B19E3779F9;
const PRF_LEN_ADD: u64 = 0x0D4CD3E7B14A36D7;
const PRF_C_ADD: u64 = 0xB57DE1F3F82CB33F;
const PRF_CAT_MUL: u64 = 0xA24BAED4963EE407;

/// fn `0x411d8`: byte-domain bound. `lo + v % (hi - lo + 1)`, all u8 arithmetic.
fn byte_bound(v: u8, lo: u8, hi: u8) -> u8 {
    lo.wrapping_add(v % hi.wrapping_sub(lo).wrapping_add(1))
}

impl Profile {
    /// fn `0x41090`: raw filler PRF. The output length is part of the state, so
    /// two regions with the same `(cat, c)` but different lengths produce
    /// unrelated streams — this is why the prefix and junk of the same record
    /// differ despite sharing `chunk`.
    fn filler_prf(&self, cat: u64, c: u64, out: &mut [u8]) {
        if out.is_empty() {
            return;
        }
        let mut block = (out.len() as u64)
            .wrapping_mul(PRF_LEN_MUL)
            .wrapping_add(PRF_LEN_ADD)
            ^ self.state_loader(cat)
            ^ c.wrapping_mul(MUL).wrapping_add(PRF_C_ADD)
            ^ cat.wrapping_mul(PRF_CAT_MUL);
        for chunk in out.chunks_mut(8) {
            block = block.wrapping_add(GOLDEN);
            let z = fmix64(block);
            for (k, b) in chunk.iter_mut().enumerate() {
                *b = (z >> (8 * k)) as u8;
            }
        }
    }

    /// fn `0x417c8`: fill `out` with PSK-derived filler bytes.
    ///
    /// `chunk` is the record index, or `u32::MAX` (`0xffff_ffff`) for the
    /// first-frame filler (the handshake frame, sent before any record).
    pub fn fill_filler(&self, chunk: u64, out: &mut [u8]) {
        if out.is_empty() {
            return;
        }
        self.filler_prf(0, chunk, out);
        match self.draw(6, 0) & 3 {
            // Arm 0 (fn 0x4195c): popcount-shaped. Oracle-verified for both PSKs.
            0 => {
                let sel = self.bound(
                    self.draw_b(1, chunk, 0),
                    self.param(12, 0, 24, 41),
                    self.param(13, 0, 58, 76),
                );
                let x = (sel & 0xff) << 3;
                let row = if x <= 0x31 {
                    1
                } else if x < 750 {
                    ((x + 50) / 100) as usize
                } else {
                    7
                };
                for (i, b) in out.iter_mut().enumerate() {
                    let raw = *b;
                    let t = raw.wrapping_add(i as u8);
                    let idx = ((raw ^ t) & 0x0f) as usize;
                    *b = POPTBL[row][idx].rotate_left(((t ^ (raw >> 4)) & 7) as u32);
                }
            }
            // Arm 1 (fn 0x419b4): UTF-8-shaped. Disassembly-only.
            1 => {
                let (b6, e7, s74) = (
                    self.param(6, 1, 24, 128),
                    self.param(6, 2, 16, 96),
                    self.param(6, 3, 16, 96),
                );
                let m = s74 + b6 + e7;
                for (i, b) in out.iter_mut().enumerate() {
                    let raw = *b;
                    let ii = i as u8;
                    let r = (raw as u32) % m;
                    *b = if r < b6 {
                        byte_bound(raw.wrapping_add(ii), 32, 126)
                    } else if r >= b6 + e7 {
                        byte_bound(raw.wrapping_add(ii.wrapping_mul(7)), 0xc0, 0xff)
                    } else {
                        byte_bound(raw ^ ii, 0x80, 0xbf)
                    };
                }
            }
            // Arm 2 (fn 0x418fc): packed-BCD-ish. Disassembly-only.
            2 => {
                let d6 = self.param(6, 4, 0, 9);
                for (i, b) in out.iter_mut().enumerate() {
                    let raw = *b;
                    let lo = ((raw & 0x0f) as u64 + d6 as u64 + (i as u64 & 1)) % 10;
                    let hi = ((raw >> 4) as u32 + 3 + (i as u32 & 3)) & 0x0f;
                    *b = ((hi << 4) as u8) | lo as u8;
                }
            }
            // Arm 3 (fn 0x4181c): 32-byte-key XOR + digits. Disassembly-only.
            _ => {
                let mut key = [0u8; 32];
                self.filler_prf(2, chunk, &mut key);
                let a4 = self.param(6, 5, 1, 8);
                let w = a4 << 2;
                let period = if w > 3 {
                    if w < 0x21 { w as usize } else { 32 }
                } else {
                    4
                };
                let d = self.param(6, 6, 7, 23).max(5) as usize;
                for (i, b) in out.iter_mut().enumerate() {
                    let r = i % d;
                    if r < d - 3 {
                        *b = ((a4 + 3).wrapping_mul(i as u32) as u8) ^ key[i % period];
                    } else if r < d - 1 {
                        *b = b'0' + *b % 10;
                    }
                    // r >= d - 1: leave the raw PRF byte
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The filler generator must reproduce the exact prefix bytes from both
    /// captured Surge sessions. These are raw generator output (no mix involved).
    #[test]
    fn filler_matches_captured_prefixes() {
        let cap_a = include_bytes!("../../tests/data/surge_v6_default_pska_1.bin");
        let cap_b = include_bytes!("../../tests/data/surge_v6_default_pskb.bin");
        let prof_a = Profile::derive(b"test-psk-0123456789abcdef");
        let prof_b = Profile::derive(b"test-psk-fedcba9876543210");

        let pl_a = prof_a.prefix_len(0);
        let pl_b = prof_b.prefix_len(0);
        let fl_a = prof_a.frame_len();
        let fl_b = prof_b.frame_len();

        let mut prefix = vec![0u8; pl_a];
        prof_a.fill_filler(0, &mut prefix);
        assert_eq!(&prefix, &cap_a[fl_a..fl_a + pl_a], "PSK A prefix mismatch");

        let mut prefix = vec![0u8; pl_b];
        prof_b.fill_filler(0, &mut prefix);
        assert_eq!(&prefix, &cap_b[fl_b..fl_b + pl_b], "PSK B prefix mismatch");
    }

    /// The filler generator must reproduce the exact junk bytes from both
    /// captures after un-mixing. The junk region is the payload's AEAD AAD, so
    /// a wrong byte here would break decryption even if the mix were correct.
    #[test]
    fn filler_matches_captured_junk_after_unmix() {
        let cap_a = include_bytes!("../../tests/data/surge_v6_default_pska_1.bin");
        let cap_b = include_bytes!("../../tests/data/surge_v6_default_pskb.bin");
        let prof_a = Profile::derive(b"test-psk-0123456789abcdef");
        let prof_b = Profile::derive(b"test-psk-fedcba9876543210");

        // PSK A: mode 1, rounds 1, block 51 → swaps body[0..51] with body[879..930].
        let fl_a = prof_a.frame_len();
        let pl_a = prof_a.prefix_len(0);
        let body_a = &cap_a[fl_a + pl_a + 23..];
        let mut junk = body_a[..879].to_vec();
        let mut ct = body_a[879..].to_vec();
        prof_a.mix(0, &mut junk, &mut ct);
        let mut expected = vec![0u8; 879];
        prof_a.fill_filler(0, &mut expected);
        assert_eq!(&junk, &expected, "PSK A junk mismatch after unmix");

        // PSK B: mode 2, rounds 2, block 30 → strided swap.
        let fl_b = prof_b.frame_len();
        let pl_b = prof_b.prefix_len(0);
        let body_b = &cap_b[fl_b + pl_b + 23..];
        let mut junk = body_b[..1022].to_vec();
        let mut ct = body_b[1022..].to_vec();
        prof_b.mix(0, &mut junk, &mut ct);
        let mut expected = vec![0u8; 1022];
        prof_b.fill_filler(0, &mut expected);
        assert_eq!(&junk, &expected, "PSK B junk mismatch after unmix");
    }

    /// The first-frame filler uses chunk = 0xffffffff and must reproduce the
    /// non-salt bytes of the captured handshake frame.
    #[test]
    fn filler_matches_first_frame() {
        for (cap, psk) in [
            (
                &include_bytes!("../../tests/data/surge_v6_default_pska_1.bin")[..],
                b"test-psk-0123456789abcdef",
            ),
            (
                &include_bytes!("../../tests/data/surge_v6_default_pskb.bin")[..],
                b"test-psk-fedcba9876543210",
            ),
        ] {
            let prof = Profile::derive(psk);
            let fl = prof.frame_len();
            let mut filler = vec![0u8; fl];
            prof.fill_filler(u64::from(u32::MAX), &mut filler);

            // Overwrite the salt positions with the keystream-XOR-salt values
            // the encode step would apply, then compare the remaining bytes.
            let perm = prof.perm();
            let ks = prof.keystream();
            let salt = prof.decode_first_frame(&cap[..fl]).unwrap();
            for i in 0..16 {
                filler[perm[i]] = ks[i] ^ salt[i];
            }
            assert_eq!(&filler, &cap[..fl], "first-frame filler mismatch");
        }
    }
}
