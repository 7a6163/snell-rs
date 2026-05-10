//! Snell v5 encryption layer.
//!
//! - Salt:   16 random bytes, sent first by each side
//! - KDF:    argon2id(psk, salt, t=3, m=8KiB, p=1) → 32B, take first 16B
//! - Cipher: AES-128-GCM, 12-byte LE nonce counter starting at 0
//! - Chunk:  [23B header CT] [interleave bytes] [payload_len+16 payload CT]
//!   Header plaintext: [0x04][0x00][0x00][interleave_size BE 2B][payload_len BE 2B]

use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

pub const SALT_LEN: usize = 16;
pub const HDR_CT_LEN: usize = 23; // 7-byte header PT + 16-byte GCM tag

pub struct SnellCipher {
    aead: Aes128Gcm,
    nonce: [u8; 12],
}

impl SnellCipher {
    /// Derive AES-128-GCM key from PSK + salt using argon2id.
    pub fn new(psk: &[u8], salt: &[u8]) -> Result<Self> {
        // Params::new(m_cost=8, t_cost=3, p_cost=1, output=32) — static values, infallible.
        let params = Params::new(8, 3, 1, Some(32)).expect("argon2 static params");
        let mut key_mat = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(psk, salt, &mut key_mat)
            .map_err(|e| anyhow::anyhow!("argon2id KDF: {e}"))?;
        let key = Key::<Aes128Gcm>::from_slice(&key_mat[..16]); // protocol uses first 16B only
        Ok(Self {
            aead: Aes128Gcm::new(key),
            nonce: [0u8; 12],
        })
    }

    /// Generate a fresh random salt and derive the cipher from it.
    pub fn with_random_salt(psk: &[u8]) -> Result<([u8; SALT_LEN], Self)> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Ok((salt, Self::new(psk, &salt)?))
    }

    // 12-byte little-endian nonce increment (LE carry propagation).
    fn inc(&mut self) {
        for b in &mut self.nonce {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    /// Seal plaintext into a v5 chunk (interleave_size = 0).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > 0xffff {
            bail!("plaintext too large: {} bytes (max 65535)", plaintext.len());
        }
        let n = plaintext.len();
        let hdr = [0x04u8, 0, 0, 0, 0, (n >> 8) as u8, (n & 0xff) as u8];

        // Single pre-allocated buffer — avoids two intermediate Vec allocations.
        let mut out = Vec::with_capacity(HDR_CT_LEN + n + 16);
        out.extend_from_slice(
            &self
                .aead
                .encrypt(Nonce::from_slice(&self.nonce), hdr.as_slice())
                .map_err(|_| anyhow::anyhow!("header AEAD encrypt"))?,
        );
        self.inc();
        out.extend_from_slice(
            &self
                .aead
                .encrypt(Nonce::from_slice(&self.nonce), plaintext)
                .map_err(|_| anyhow::anyhow!("payload AEAD encrypt"))?,
        );
        self.inc();
        Ok(out)
    }

    /// Zero chunk — signals end of a multiplexed session.
    pub fn seal_zero(&mut self) -> Result<Vec<u8>> {
        let hdr = [0x04u8, 0, 0, 0, 0, 0, 0];
        let ct = self
            .aead
            .encrypt(Nonce::from_slice(&self.nonce), hdr.as_slice())
            .map_err(|_| anyhow::anyhow!("zero-chunk AEAD encrypt"))?;
        self.inc();
        Ok(ct)
    }

    /// Decrypt 23-byte header CT → (interleave_size, payload_len).
    /// Returns `None` for a zero chunk (payload_len == 0).
    /// Nonce is incremented only on successful decryption.
    pub fn open_header(&mut self, ct: &[u8; HDR_CT_LEN]) -> Result<Option<(usize, usize)>> {
        let pt = self
            .aead
            .decrypt(Nonce::from_slice(&self.nonce), ct.as_slice())
            .map_err(|_| anyhow::anyhow!("header authentication failed"))?;
        self.inc();
        if pt.len() != 7 || pt[0] != 0x04 {
            bail!(
                "invalid chunk header type={:#04x}",
                pt.first().copied().unwrap_or(0)
            );
        }
        let interleave = u16::from_be_bytes([pt[3], pt[4]]) as usize;
        let payload_len = u16::from_be_bytes([pt[5], pt[6]]) as usize;
        if payload_len == 0 {
            return Ok(None);
        }
        Ok(Some((interleave, payload_len)))
    }

    /// Decrypt payload ciphertext (payload_len + 16 tag bytes).
    /// Nonce is incremented only on successful decryption.
    pub fn open_payload(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        self.aead
            .decrypt(Nonce::from_slice(&self.nonce), ct)
            .map_err(|_| anyhow::anyhow!("payload authentication failed"))
            .inspect(|_| self.inc())
    }
}
