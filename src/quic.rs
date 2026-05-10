//! QUIC Proxy Mode — UDP relay with selective encryption.
//!
//! Design (Option A): client signals QUIC intent via CMD_CONNECT_UDP=0x06
//! over the existing TCP control channel. Server creates a UDP session keyed
//! by a random 8-byte token, returns the token in the RESP_TUNNEL response.
//! The client then sends UDP datagrams prefixed with the token.
//!
//! Encryption policy (per Snell v5 spec):
//!   - QUIC Initial packets  → AES-128-GCM AEAD with random 12-byte nonce
//!   - All other QUIC packets → forwarded raw (already encrypted by QUIC)
//!
//! This preserves QUIC's PMTU probing (no extra bytes on data packets) and
//! avoids double-encryption overhead on the bulk data path.

use anyhow::Result;
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::cipher::SnellCipher;

// ── QUIC Initial packet detection ────────────────────────────────────────────

/// Returns `true` if `b` looks like a QUIC Initial packet.
///
/// Criteria (RFC 9000):
///   - Long Header form: bit 7 = 1, bit 6 = 1 (Fixed Bit)
///   - Packet type bits 5-4 = 0b00 (Initial)
///   - Version (bytes 1-4) != 0x00000000 (not Version Negotiation)
pub fn is_quic_initial(b: &[u8]) -> bool {
    if b.len() < 5 {
        return false;
    }
    if b[0] & 0xC0 != 0xC0 {
        return false;
    }
    if b[0] & 0x30 != 0x00 {
        return false;
    }
    let version = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
    version != 0
}

// ── Session token ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionToken(pub [u8; 8]);

impl SessionToken {
    pub fn new_random() -> Self {
        let mut token = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut token);
        Self(token)
    }

    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl std::fmt::Display for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// ── Session table ─────────────────────────────────────────────────────────────

pub struct UdpSession {
    pub client_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub target_sock: UdpSocket,
    pub last_seen: Mutex<Instant>,
    /// Per-session cipher used only for QUIC Initial packets.
    pub init_cipher: Mutex<SnellCipher>,
}

pub type SessionTable = Arc<Mutex<HashMap<SessionToken, Arc<UdpSession>>>>;

pub fn new_session_table() -> SessionTable {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Remove sessions idle for more than `timeout_secs` seconds.
pub async fn gc_sessions(table: &SessionTable, timeout_secs: u64) {
    let deadline = Instant::now()
        .checked_sub(std::time::Duration::from_secs(timeout_secs))
        .unwrap_or(Instant::now());
    let mut guard = table.lock().await;
    guard.retain(|_, session| {
        let last = session
            .last_seen
            .try_lock()
            .map(|g| *g)
            .unwrap_or(Instant::now());
        last >= deadline
    });
}

// ── Selective encryption helpers ──────────────────────────────────────────────

/// Overhead added to encrypted Initial packets: 12-byte nonce prefix + 16-byte GCM tag.
pub const QUIC_INIT_OVERHEAD: usize = 12 + 16;

/// Encrypt a QUIC Initial packet with a fresh random nonce.
/// Wire format: [12-byte nonce][AES-128-GCM ciphertext+tag].
pub fn encrypt_initial(psk: &[u8], salt: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce as GcmNonce};
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(8, 3, 1, Some(32)).expect("argon2 static params");
    let mut key_mat = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(psk, salt, &mut key_mat)
        .map_err(|e| anyhow::anyhow!("argon2id: {e}"))?;
    let cipher =
        Aes128Gcm::new_from_slice(&key_mat[..16]).map_err(|_| anyhow::anyhow!("AES key"))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = GcmNonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("QUIC Initial AEAD encrypt"))?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a QUIC Initial packet from `[12-byte nonce][ciphertext+tag]` format.
pub fn decrypt_initial(psk: &[u8], salt: &[u8], wire: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce as GcmNonce};
    use argon2::{Algorithm, Argon2, Params, Version};

    if wire.len() < QUIC_INIT_OVERHEAD {
        anyhow::bail!("QUIC Initial datagram too short");
    }
    let (nonce_bytes, ct) = wire.split_at(12);

    let params = Params::new(8, 3, 1, Some(32)).expect("argon2 static params");
    let mut key_mat = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(psk, salt, &mut key_mat)
        .map_err(|e| anyhow::anyhow!("argon2id: {e}"))?;
    let cipher =
        Aes128Gcm::new_from_slice(&key_mat[..16]).map_err(|_| anyhow::anyhow!("AES key"))?;

    cipher
        .decrypt(GcmNonce::from_slice(nonce_bytes), ct)
        .map_err(|_| anyhow::anyhow!("QUIC Initial AEAD decrypt"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_quic_initial() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0xC0;
        pkt[1] = 0x00;
        pkt[2] = 0x00;
        pkt[3] = 0x00;
        pkt[4] = 0x01;
        assert!(is_quic_initial(&pkt));
    }

    #[test]
    fn rejects_short_packet() {
        assert!(!is_quic_initial(&[0xC0, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn rejects_short_header() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x40;
        assert!(!is_quic_initial(&pkt));
    }

    #[test]
    fn rejects_non_initial_type() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0xD0;
        pkt[1..5].copy_from_slice(&[0, 0, 0, 1]);
        assert!(!is_quic_initial(&pkt));
    }

    #[test]
    fn rejects_version_negotiation() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0xC0;
        pkt[1..5].copy_from_slice(&[0, 0, 0, 0]);
        assert!(!is_quic_initial(&pkt));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let psk = b"testpsk";
        let salt = [1u8; 16];
        let plain = b"QUIC Initial payload";
        let wire = encrypt_initial(psk, &salt, plain).unwrap();
        let back = decrypt_initial(psk, &salt, &wire).unwrap();
        assert_eq!(&back, plain);
    }

    #[test]
    fn token_roundtrip() {
        let t = SessionToken::new_random();
        assert_eq!(t.as_bytes().len(), 8);
        let display = format!("{t}");
        assert_eq!(display.len(), 16);
    }
}
