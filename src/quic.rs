//! QUIC Proxy Mode — UDP relay with selective encryption.

use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce as GcmNonce};
use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Returns `true` if `b` looks like a QUIC v1 Initial packet (RFC 9000).
pub fn is_quic_initial(b: &[u8]) -> bool {
    if b.len() < 5 {
        return false;
    }
    if b[0] & 0xC0 != 0xC0 {
        return false;
    } // Long Header + Fixed Bit
    if b[0] & 0x30 != 0x00 {
        return false;
    } // Initial type
    let version = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
    version != 0
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionToken(pub [u8; 8]);

impl SessionToken {
    pub fn new_random() -> Self {
        let mut t = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut t);
        Self(t)
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

/// Pre-derive an AES-128-GCM cipher once for QUIC Initial packets.
/// Avoids per-packet argon2id (DoS mitigation).
pub fn derive_init_cipher(psk: &[u8], salt: &[u8]) -> Result<Aes128Gcm> {
    let params = Params::new(8, 3, 1, Some(32)).expect("argon2 static params");
    let mut key_mat = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(psk, salt, &mut key_mat)
        .map_err(|e| anyhow::anyhow!("argon2id: {e}"))?;
    Aes128Gcm::new_from_slice(&key_mat[..16]).map_err(|_| anyhow::anyhow!("AES key"))
}

/// Wire format: [12-byte random nonce][AES-GCM CT + 16-byte tag].
pub const QUIC_INIT_OVERHEAD: usize = 12 + 16;

pub fn encrypt_with(cipher: &Aes128Gcm, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(GcmNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("AEAD encrypt"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_with(cipher: &Aes128Gcm, wire: &[u8]) -> Result<Vec<u8>> {
    if wire.len() < QUIC_INIT_OVERHEAD {
        anyhow::bail!("QUIC Initial too short");
    }
    let (nonce, ct) = wire.split_at(12);
    cipher
        .decrypt(GcmNonce::from_slice(nonce), ct)
        .map_err(|_| anyhow::anyhow!("AEAD decrypt"))
}

pub struct UdpSession {
    pub token: SessionToken,
    /// Discovered from the first UDP datagram. None until then.
    pub client_addr: Mutex<Option<SocketAddr>>,
    pub target_sock: Arc<UdpSocket>,
    /// epoch nanos — atomic so updates don't lock.
    pub last_seen: AtomicU64,
    /// Pre-derived once; per-session salt prevents key sharing across sessions.
    pub init_cipher: Aes128Gcm,
    /// Ensures the target→client recv task is spawned exactly once.
    pub recv_started: AtomicBool,
}

impl UdpSession {
    pub fn touch(&self) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        self.last_seen.store(nanos, Ordering::Relaxed);
    }
}

pub type SessionTable = Arc<Mutex<HashMap<SessionToken, Arc<UdpSession>>>>;

pub fn new_session_table() -> SessionTable {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Remove sessions idle for more than `timeout_secs` seconds.
pub async fn gc_sessions(table: &SessionTable, timeout_secs: u64) {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let cutoff = now_nanos.saturating_sub(timeout_secs * 1_000_000_000);
    let mut guard = table.lock().await;
    guard.retain(|_, s| s.last_seen.load(Ordering::Relaxed) >= cutoff);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_quic_initial() {
        let mut p = vec![0u8; 20];
        p[0] = 0xC0;
        p[4] = 0x01;
        assert!(is_quic_initial(&p));
    }

    #[test]
    fn rejects_short() {
        assert!(!is_quic_initial(&[0xC0, 0, 0, 0]));
    }

    #[test]
    fn rejects_short_header_byte() {
        let mut p = vec![0u8; 20];
        p[0] = 0x40;
        assert!(!is_quic_initial(&p));
    }

    #[test]
    fn rejects_non_initial() {
        let mut p = vec![0u8; 20];
        p[0] = 0xD0;
        p[4] = 1;
        assert!(!is_quic_initial(&p));
    }

    #[test]
    fn rejects_version_negotiation() {
        let mut p = vec![0u8; 20];
        p[0] = 0xC0;
        assert!(!is_quic_initial(&p));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let cipher = derive_init_cipher(b"psk", &[1u8; 16]).unwrap();
        let pt = b"QUIC Initial";
        let wire = encrypt_with(&cipher, pt).unwrap();
        let back = decrypt_with(&cipher, &wire).unwrap();
        assert_eq!(&back, pt);
    }

    #[test]
    fn token_roundtrip() {
        let t = SessionToken::new_random();
        assert_eq!(t.as_bytes().len(), 8);
        assert_eq!(format!("{t}").len(), 16);
    }
}
