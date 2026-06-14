//! v6 handshake first frame: the 16-byte session salt is scattered across a
//! PSK-sized frame at PSK-derived permuted positions, each byte XORed with a
//! PSK-derived keystream. (The entire v6 handshake delta vs v5.)
//!
//!   encode (client): wire[perm[i]] = ks(i) ^ salt[i]   for i in 0..16
//!   decode (server): salt[i]       = ks(i) ^ wire[perm[i]]
//!
//! Non-salt wire bytes are random filler (the peer reads only perm[0..16]).

use anyhow::{Result, bail};

use super::profile::{GOLDEN, HI_CAP, K4, K5, K7, K8, Profile, SHUF_SALT, fmix64, fold32};

/// PRF `c` argument used by the keystream and permutation (fn 0x41a98 / 0x42988).
const F_C: u64 = 0x51A7;
const SALT_LEN: usize = 16;

impl Profile {
    /// First-frame size field `S+226 = param(18, 0x51A7, 17, 251)`.
    pub(crate) fn f_field(&self) -> u32 {
        self.param(18, F_C, 17, 251)
    }

    /// Number of Fisher-Yates passes for the permutation (profile+178).
    pub(crate) fn shuffle_rounds(&self) -> u32 {
        self.param(17, F_C, 1, 4)
    }

    /// First-frame length lower bound (profile+108).
    pub(crate) fn frame_lo(&self) -> u32 {
        self.param(14, 0x7053, 16, 96)
    }

    /// First-frame length upper bound (profile+208), clamped to HI_CAP.
    pub(crate) fn frame_hi(&self) -> u32 {
        (self.frame_lo() + self.param(15, 0x7053, 16, 160)).min(HI_CAP)
    }

    /// Total first-frame byte count = `16 + param(33, 0x7053, lo, hi)`.
    pub fn frame_len(&self) -> usize {
        let (lo, hi) = (self.frame_lo(), self.frame_hi());
        (16 + self.param(33, 0x7053, lo, hi)) as usize
    }

    /// 16-byte keystream: `ks(i) = ((i*F) ^ fold32(fmix64(...))) & 0xFF`.
    pub(crate) fn keystream(&self) -> [u8; SALT_LEN] {
        let seed = self.seed_at(136);
        let f = self.f_field() as u64;
        let mut out = [0u8; SALT_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            let i = i as u64;
            let prf = fmix64(
                2u64.wrapping_mul(GOLDEN)
                    ^ F_C.wrapping_mul(K8).wrapping_add(K7)
                    ^ i.wrapping_mul(K5).wrapping_add(K4)
                    ^ seed,
            );
            *b = ((i.wrapping_mul(f) ^ fold32(prf) as u64) & 0xFF) as u8;
        }
        out
    }

    /// PSK-derived index permutation over `[0, frame_len)` (fn 0x42a10).
    pub(crate) fn perm(&self) -> Vec<usize> {
        let seed = self.seed_at(136);
        let n = self.frame_len();
        let rounds = self.shuffle_rounds();
        let mut p: Vec<usize> = (0..n).collect();
        for r in 0..rounds as u64 {
            let ctr = (F_C + r) & 0xFFFF;
            for i in 0..n {
                let span = (n - i) as u64;
                let j = i + (shuffle_prf(seed, ctr, i as u64) as u64 % span) as usize;
                p.swap(i, j);
            }
        }
        p
    }

    /// Build the `frame_len`-byte first frame carrying `salt`. `filler` (if given)
    /// supplies the non-salt bytes and must be exactly `frame_len` long; `None`
    /// uses zero filler (matches the golden vectors).
    pub fn encode_first_frame(
        &self,
        salt: &[u8; SALT_LEN],
        filler: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let n = self.frame_len();
        let mut buf = match filler {
            Some(f) if f.len() == n => f.to_vec(),
            Some(f) => bail!("filler length {} != frame_len {n}", f.len()),
            None => vec![0u8; n],
        };
        let perm = self.perm();
        let ks = self.keystream();
        for i in 0..SALT_LEN {
            buf[perm[i]] = ks[i] ^ salt[i];
        }
        Ok(buf)
    }

    /// Recover the 16-byte salt from a `frame_len`-byte first frame (server side).
    pub fn decode_first_frame(&self, wire: &[u8]) -> Result<[u8; SALT_LEN]> {
        let n = self.frame_len();
        if wire.len() != n {
            bail!("first frame length {} != expected {n}", wire.len());
        }
        let perm = self.perm();
        let ks = self.keystream();
        let mut salt = [0u8; SALT_LEN];
        for i in 0..SALT_LEN {
            salt[i] = ks[i] ^ wire[perm[i]];
        }
        Ok(salt)
    }
}

/// Shuffle PRF (fn 0x42988): `fold32(fmix64((ctr*K8+K7) ^ seed ^ ((idx*K5+K4) ^ SHUF_SALT)))`.
fn shuffle_prf(seed: u64, ctr: u64, idx: u64) -> u32 {
    let t = ctr.wrapping_mul(K8).wrapping_add(K7)
        ^ seed
        ^ (idx.wrapping_mul(K5).wrapping_add(K4) ^ SHUF_SALT);
    fold32(fmix64(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_fields_match_reference_psk_a() {
        let p = Profile::derive(b"test-psk-0123456789abcdef");
        assert_eq!(p.f_field(), 251);
        assert_eq!(p.shuffle_rounds(), 4);
        assert_eq!(p.frame_lo(), 65);
        assert_eq!(p.frame_hi(), 128);
        assert_eq!(p.frame_len(), 120);
        assert_eq!(hex(&p.keystream()), "b2095ec2e8d0fb88c863a972cf7e2a5c");
    }

    #[test]
    fn salt_round_trips_through_frame() {
        let p = Profile::derive(b"test-psk-fedcba9876543210");
        let salt = [
            0x01, 0x0e, 0x1b, 0x28, 0x35, 0x42, 0x4f, 0x5c, 0x69, 0x76, 0x83, 0x90, 0x9d, 0xaa,
            0xb7, 0xc4,
        ];
        let frame = p.encode_first_frame(&salt, None).unwrap();
        assert_eq!(frame.len(), p.frame_len());
        assert_eq!(p.decode_first_frame(&frame).unwrap(), salt);
    }

    #[test]
    fn encode_accepts_correct_length_filler_and_rejects_wrong() {
        let p = Profile::derive(b"test-psk-0123456789abcdef");
        let salt = [0u8; 16];
        let n = p.frame_len();
        // Correct-length filler is accepted and still round-trips the salt.
        let frame = p.encode_first_frame(&salt, Some(&vec![0xAB; n])).unwrap();
        assert_eq!(frame.len(), n);
        assert_eq!(p.decode_first_frame(&frame).unwrap(), salt);
        // Wrong-length filler is rejected.
        assert!(p.encode_first_frame(&salt, Some(&[0u8; 3])).is_err());
    }

    #[test]
    fn decode_rejects_wrong_length_frame() {
        let p = Profile::derive(b"test-psk-0123456789abcdef");
        assert!(p.decode_first_frame(&[0u8; 5]).is_err());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
