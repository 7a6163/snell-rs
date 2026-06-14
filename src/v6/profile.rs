//! v6 per-connection "shaping profile" derived deterministically from the PSK.
//!
//! Faithful port of `reference/v6_seed.py` (reverse-engineered from the official
//! snell-server v6.0.0b2 binary, validated byte-exact against live gdb captures
//! and end-to-end against the live server). Every formula here is gated by the
//! golden vectors in `tests/v6_test_vectors.json`.
//!
//! All u64 arithmetic is wrapping. The pipeline:
//!   master32 = blake2b-256(CONST24 || psk)
//!   m0..m3   = little-endian u64 words of master32
//!   seed(idx,k64) = fmix64(...)               # 7 category seeds at fixed offsets
//!   draw_b(cat,b,c) = fold32(fmix64(...))     # PSK-derived PRF
//!   param(cat,c,lo,hi) = lo + draw(cat,c) % (hi-lo+1)

use blake2::Blake2b;
use blake2::Digest;
use blake2::digest::consts::U32;

type Blake2b256 = Blake2b<U32>;

// splitmix64 fmix constants.
pub(crate) const C1: u64 = 0xBF58476D1CE4E5B9;
pub(crate) const C2: u64 = 0x94D049BB133111EB;
pub(crate) const GOLDEN: u64 = 0x9E3779B97F4A7C15;
const MUL: u64 = 0xD6E8FEB86659FD93;
const ADD: u64 = 0xA0761D6478BD642F;
pub(crate) const K7: u64 = 0x8F3907F7B2B80C35;
pub(crate) const K8: u64 = 0xE7037ED1A0B428DB;
pub(crate) const K5: u64 = 0x589965CC75374CC3;
pub(crate) const K4: u64 = 0x33A213EC50FFE2E9;
pub(crate) const SHUF_SALT: u64 = 0xDAA66D2C7DDF743F;

/// profile+208 / prefix_hi are both clamped to 0x80 at connection time.
pub(crate) const HI_CAP: u32 = 128;

/// BLAKE2b personalization prefix hashed with the PSK to derive `master32`.
const CONST24: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

/// rodata 0x1b3390: category index -> routing byte (40 entries).
const CATMAP: [u8; 40] = [
    0x00, 0x00, 0x02, 0x04, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0x00, 0x00,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0xf8, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x00, 0x00, 0x08, 0x08, 0x08, 0x06, 0x06,
];

/// Category-seed table: struct offset -> (idx, k64). From seeder fn 0x41cc0.
const SEEDDEF: [(u16, u64, u64); 7] = [
    (0, 16, 0xC9F4260B7D1E835A),
    (72, 0, 0x5D9217C083E64AB9),
    (96, 5, 0xB46C2E7D9A1538F1),
    (136, 3, 0x3E8A91B52740F6CD),
    (168, 21, 0x62D0B5E19C4A783F),
    (192, 2, 0xA71F0C54D8396E2B),
    (216, 28, 0x917B3C48E6A205D4),
];

/// splitmix64 finalizer.
pub(crate) fn fmix64(mut z: u64) -> u64 {
    z ^= z >> 30;
    z = z.wrapping_mul(C1);
    z ^= z >> 27;
    z = z.wrapping_mul(C2);
    z ^= z >> 31;
    z
}

/// Fold a u64 to u32 by XOR-ing its halves.
pub(crate) fn fold32(z: u64) -> u32 {
    (z ^ (z >> 32)) as u32
}

/// rodata 0x1b3390 routing byte -> seed struct offset.
fn route(b: u8) -> u16 {
    match b {
        0x00 => 72,
        0x02 => 192,
        0x04 => 0,
        0x06 => 168,
        0x08 => 216,
        // 0xf8 and any unmapped byte fall back to the +96 seed.
        _ => 96,
    }
}

fn master32(psk: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(CONST24);
    h.update(psk);
    let out = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

fn seed(idx: u64, k64: u64, m: &[u64; 4]) -> u64 {
    let t = idx.wrapping_mul(MUL)
        ^ k64.wrapping_add(ADD)
        ^ (m[1].wrapping_add(GOLDEN) ^ m[2].rotate_right(47))
        ^ (m[0] ^ m[3].rotate_right(11));
    fmix64(t)
}

/// PSK-derived shaping profile. Cheap to derive; derive once per connection.
pub struct Profile {
    seeds: [(u16, u64); 7],
}

impl Profile {
    /// Derive the profile from the PSK (one BLAKE2b + 7 fmix64s).
    pub fn derive(psk: &[u8]) -> Self {
        let mb = master32(psk);
        let m = [
            u64::from_le_bytes(mb[0..8].try_into().expect("8 bytes")),
            u64::from_le_bytes(mb[8..16].try_into().expect("8 bytes")),
            u64::from_le_bytes(mb[16..24].try_into().expect("8 bytes")),
            u64::from_le_bytes(mb[24..32].try_into().expect("8 bytes")),
        ];
        let mut seeds = [(0u16, 0u64); 7];
        for (slot, &(off, idx, k64)) in seeds.iter_mut().zip(SEEDDEF.iter()) {
            *slot = (off, seed(idx, k64, &m));
        }
        Self { seeds }
    }

    /// Look up a category seed by its struct offset (offsets are fixed at derive).
    pub(crate) fn seed_at(&self, off: u16) -> u64 {
        self.seeds
            .iter()
            .find_map(|&(o, v)| (o == off).then_some(v))
            .expect("seed offset present by construction")
    }

    fn state_loader(&self, cat: u64) -> u64 {
        if cat > 39 {
            self.seed_at(96)
        } else {
            self.seed_at(route(CATMAP[cat as usize]))
        }
    }

    /// PSK-derived PRF with explicit `b` (chunk index) and `c` (call counter).
    pub(crate) fn draw_b(&self, cat: u64, b: u64, c: u64) -> u32 {
        let s = self.state_loader(cat);
        let h = fmix64(
            cat.wrapping_mul(GOLDEN)
                ^ b.wrapping_mul(K8).wrapping_add(K7)
                ^ c.wrapping_mul(K5).wrapping_add(K4)
                ^ s,
        );
        fold32(h)
    }

    /// `draw(cat,c) == draw_b(cat, 0, c)`.
    pub(crate) fn draw(&self, cat: u64, c: u64) -> u32 {
        self.draw_b(cat, 0, c)
    }

    /// Bounded parameter: `lo + draw(cat,c) % (hi-lo+1)` (or `lo` if `hi <= lo`).
    pub(crate) fn param(&self, cat: u64, c: u64, lo: u32, hi: u32) -> u32 {
        if hi > lo {
            lo + self.draw(cat, c) % (hi - lo + 1)
        } else {
            lo
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_matches_reference_psk_a() {
        let p = Profile::derive(b"test-psk-0123456789abcdef");
        assert_eq!(p.seed_at(0), 0xecad11149a98ae33);
        assert_eq!(p.seed_at(136), 0x3949ad7f58be7803);
    }

    #[test]
    fn f_field_param_matches_reference() {
        let p = Profile::derive(b"test-psk-0123456789abcdef");
        // F_field = param(18, 0x51A7, 17, 251) -> 251 for PSK A.
        assert_eq!(p.param(18, 0x51A7, 17, 251), 251);
    }

    #[test]
    fn draw_covers_all_route_arms_and_high_category() {
        let p = Profile::derive(b"test-psk-0123456789abcdef");
        // Each cat maps through CATMAP to a distinct ROUTE arm.
        let _ = p.draw(2, 0); //  CATMAP[2]=0x02 -> seed+192
        let _ = p.draw(21, 0); // CATMAP[21]=0x06 -> seed+168
        let _ = p.draw(28, 0); // CATMAP[28]=0x08 -> seed+216
        let _ = p.draw(4, 0); //  CATMAP[4]=0xf8 -> seed+96 fallback
        let _ = p.draw(40, 0); // cat > 39 -> seed+96 (out-of-range branch)
        // Deterministic for identical inputs.
        assert_eq!(p.draw(2, 0), p.draw(2, 0));
    }

    #[test]
    fn param_returns_lo_when_hi_not_greater() {
        let p = Profile::derive(b"test-psk-0123456789abcdef");
        assert_eq!(p.param(0, 0, 5, 5), 5); // hi == lo
        assert_eq!(p.param(0, 0, 9, 3), 9); // hi < lo
    }
}
