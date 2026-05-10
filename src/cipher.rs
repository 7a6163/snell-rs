//! Snell v5 encryption layer.
//!
//! Discovered via binary analysis of snell-server v5.0.1 (Nov 2025):
//!   - Salt:   16 random bytes, sent first by each side
//!   - KDF:    argon2id(psk, salt, t=3, m=8KiB, p=1) → 32B, take first 16B
//!   - Cipher: AES-128-GCM, 12-byte LE nonce counter starting at 0
//!   - Chunk:  [23B header CT] [interleave bytes] [payload_len+16 payload CT]
//!     Header plaintext: [0x04][0x00][0x00][interleave_size BE 2B][payload_len BE 2B]

use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use anyhow::{bail, Result};

pub const SALT_LEN:    usize = 16;
pub const HDR_CT_LEN:  usize = 23; // 7 plaintext + 16 GCM tag

pub struct SnellCipher {
    aead:  Aes128Gcm,
    nonce: [u8; 12],
}

impl SnellCipher {
    /// Derive AES-128-GCM key from PSK + salt using argon2id.
    pub fn new(psk: &[u8], salt: &[u8]) -> Self {
        let params = Params::new(8, 3, 1, Some(32)).expect("argon2 params");
        let mut key_mat = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(psk, salt, &mut key_mat)
            .expect("argon2id");
        let key = Key::<Aes128Gcm>::from_slice(&key_mat[..16]);
        Self { aead: Aes128Gcm::new(key), nonce: [0u8; 12] }
    }

    /// Generate a fresh random salt and derive the cipher from it.
    pub fn with_random_salt(psk: &[u8]) -> ([u8; SALT_LEN], Self) {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        (salt, Self::new(psk, &salt))
    }

    fn inc(&mut self) {
        for b in &mut self.nonce {
            *b = b.wrapping_add(1);
            if *b != 0 { break; }
        }
    }

    /// Seal plaintext into a v5 chunk (interleave_size = 0).
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        assert!(plaintext.len() <= 0xffff);
        let n = plaintext.len();
        // [0x04][pad 0x00 0x00][interleave_size=0x0000][payload_len BE]
        let hdr = [0x04u8, 0, 0, 0, 0, (n >> 8) as u8, (n & 0xff) as u8];
        let hdr_ct = self.aead.encrypt(Nonce::from_slice(&self.nonce), hdr.as_slice()).unwrap();
        self.inc();
        let pay_ct = self.aead.encrypt(Nonce::from_slice(&self.nonce), plaintext).unwrap();
        self.inc();
        [hdr_ct, pay_ct].concat()
    }

    /// Zero chunk — signals end of a multiplexed session.
    pub fn seal_zero(&mut self) -> Vec<u8> {
        let hdr = [0x04u8, 0, 0, 0, 0, 0, 0];
        let ct = self.aead.encrypt(Nonce::from_slice(&self.nonce), hdr.as_slice()).unwrap();
        self.inc();
        ct
    }

    /// Decrypt 23-byte header CT → (interleave_size, payload_len).
    /// Returns `None` for a zero chunk (payload_len == 0).
    pub fn open_header(&mut self, ct: &[u8; HDR_CT_LEN]) -> Result<Option<(usize, usize)>> {
        let pt = self.aead
            .decrypt(Nonce::from_slice(&self.nonce), ct.as_slice())
            .map_err(|_| anyhow::anyhow!("header authentication failed"))?;
        self.inc();
        if pt.len() != 7 || pt[0] != 0x04 {
            bail!("invalid chunk header type={:#04x}", pt.first().copied().unwrap_or(0));
        }
        let interleave  = u16::from_be_bytes([pt[3], pt[4]]) as usize;
        let payload_len = u16::from_be_bytes([pt[5], pt[6]]) as usize;
        if payload_len == 0 { return Ok(None); }
        Ok(Some((interleave, payload_len)))
    }

    /// Decrypt payload ciphertext (payload_len + 16 tag bytes).
    pub fn open_payload(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        self.aead
            .decrypt(Nonce::from_slice(&self.nonce), ct)
            .map_err(|_| anyhow::anyhow!("payload authentication failed"))
            .inspect(|_| self.inc())
    }
}
