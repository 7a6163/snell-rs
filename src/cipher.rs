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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PSK: &[u8] = b"unit-test-psk-with-enough-bytes!";
    const TEST_SALT: [u8; SALT_LEN] = [0u8; SALT_LEN];

    fn cipher_pair() -> (SnellCipher, SnellCipher) {
        (
            SnellCipher::new(TEST_PSK, &TEST_SALT).unwrap(),
            SnellCipher::new(TEST_PSK, &TEST_SALT).unwrap(),
        )
    }

    /// Split a sealed chunk into its 23-byte header CT and payload+tag CT.
    fn split(sealed: &[u8]) -> ([u8; HDR_CT_LEN], Vec<u8>) {
        let mut hdr = [0u8; HDR_CT_LEN];
        hdr.copy_from_slice(&sealed[..HDR_CT_LEN]);
        (hdr, sealed[HDR_CT_LEN..].to_vec())
    }

    #[test]
    fn seal_open_roundtrip_basic() {
        let (mut tx, mut rx) = cipher_pair();
        let plaintext = b"hello cipher";
        let sealed = tx.seal(plaintext).unwrap();
        let (hdr, body) = split(&sealed);

        let (interleave, payload_len) = rx.open_header(&hdr).unwrap().unwrap();
        assert_eq!(interleave, 0, "seal() always emits interleave=0");
        assert_eq!(payload_len, plaintext.len());
        assert_eq!(body.len(), payload_len + 16);

        let pt = rx.open_payload(&body).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn seal_zero_open_header_returns_none() {
        let (mut tx, mut rx) = cipher_pair();
        let zero = tx.seal_zero().unwrap();
        assert_eq!(zero.len(), HDR_CT_LEN, "zero chunk is header-only");
        let hdr: [u8; HDR_CT_LEN] = zero.try_into().unwrap();
        let out = rx.open_header(&hdr).unwrap();
        assert!(out.is_none(), "zero chunk must surface as None");
    }

    /// Nonce invariant: failed open_header MUST NOT advance the nonce counter.
    /// We prove non-advancement by: tamper → Err → real header → Ok.
    /// If the failed decrypt had advanced the nonce, the real header would
    /// then decrypt with the wrong nonce and fail.
    #[test]
    fn failed_open_header_does_not_advance_nonce() {
        let (mut tx, mut rx) = cipher_pair();
        let sealed = tx.seal(b"witness").unwrap();
        let (hdr, body) = split(&sealed);

        // Flip one byte in the header CT — authentication tag must reject it.
        let mut tampered = hdr;
        tampered[0] ^= 0xff;
        assert!(rx.open_header(&tampered).is_err());

        // Real header must still decrypt — proves nonce was preserved.
        let opened = rx.open_header(&hdr).unwrap().unwrap();
        assert_eq!(opened.1, b"witness".len());
        let pt = rx.open_payload(&body).unwrap();
        assert_eq!(pt, b"witness");
    }

    /// Nonce invariant: failed open_payload MUST NOT advance the nonce counter.
    #[test]
    fn failed_open_payload_does_not_advance_nonce() {
        let (mut tx, mut rx) = cipher_pair();
        let sealed = tx.seal(b"payload-witness").unwrap();
        let (hdr, body) = split(&sealed);

        rx.open_header(&hdr).unwrap().unwrap();

        // Flip one byte in the payload CT — AEAD tag must reject.
        let mut tampered = body.clone();
        tampered[0] ^= 0xff;
        assert!(rx.open_payload(&tampered).is_err());

        // Real payload must still decrypt with the same nonce.
        let pt = rx.open_payload(&body).unwrap();
        assert_eq!(pt, b"payload-witness");
    }

    #[test]
    fn plaintext_above_protocol_limit_is_rejected() {
        let mut c = SnellCipher::new(TEST_PSK, &TEST_SALT).unwrap();
        // 0xffff is the largest accepted plaintext; 0x10000 must bail.
        let oversize = vec![0u8; 0x10000];
        assert!(c.seal(&oversize).is_err());

        // The exact boundary 0xffff is accepted.
        let at_limit = vec![0u8; 0xffff];
        assert!(c.seal(&at_limit).is_ok());
    }

    #[test]
    fn wrong_psk_fails_decryption() {
        let mut tx = SnellCipher::new(TEST_PSK, &TEST_SALT).unwrap();
        let mut rx = SnellCipher::new(b"different-psk-also-long-enough!!", &TEST_SALT).unwrap();
        let sealed = tx.seal(b"secret").unwrap();
        let (hdr, _) = split(&sealed);
        assert!(rx.open_header(&hdr).is_err());
    }

    #[test]
    fn wrong_salt_fails_decryption() {
        let mut tx = SnellCipher::new(TEST_PSK, &TEST_SALT).unwrap();
        let alt_salt = [0xAAu8; SALT_LEN];
        let mut rx = SnellCipher::new(TEST_PSK, &alt_salt).unwrap();
        let sealed = tx.seal(b"secret").unwrap();
        let (hdr, _) = split(&sealed);
        assert!(rx.open_header(&hdr).is_err());
    }

    /// Chunks are tied to nonce ordering — opening the second chunk's header
    /// before the first must fail.
    #[test]
    fn chunks_must_be_opened_in_order() {
        let (mut tx, mut rx) = cipher_pair();
        let _ct1 = tx.seal(b"first").unwrap();
        let ct2 = tx.seal(b"second").unwrap();
        let (hdr2, _) = split(&ct2);
        // rx is still at nonce 0; ct2's header was sealed at nonce 2.
        assert!(rx.open_header(&hdr2).is_err());
    }

    #[test]
    fn with_random_salt_produces_usable_cipher() {
        let (salt, mut tx) = SnellCipher::with_random_salt(TEST_PSK).unwrap();
        assert_eq!(salt.len(), SALT_LEN);
        // A receiver derived from the same psk+salt can decrypt.
        let mut rx = SnellCipher::new(TEST_PSK, &salt).unwrap();
        let sealed = tx.seal(b"derived").unwrap();
        let (hdr, body) = split(&sealed);
        let (_, payload_len) = rx.open_header(&hdr).unwrap().unwrap();
        assert_eq!(payload_len, b"derived".len());
        let pt = rx.open_payload(&body).unwrap();
        assert_eq!(pt, b"derived");
    }
}
