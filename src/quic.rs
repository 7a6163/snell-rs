//! Snell v5 QUIC Proxy Mode — verified wire format.
//!
//! Wire format (per UDP datagram):
//!   [16B per-packet salt]
//!   [23B AES-128-GCM(header_pt, key, nonce=0)]
//!   [interleave_size bytes]
//!   [payload_len + 16B AES-128-GCM(inner_pt, key, nonce=1)]
//!
//! KDF: argon2id(PSK, packet[:16], t=3, m=8KiB, p=1) -> 32B, take first 16B
//! Cipher: AES-128-GCM, 12-byte LE nonce counter starting at 0
//! Sessions: keyed by source sockaddr (IP:port)
//!
//! Packet classification (server-side, by byte[0] of full datagram):
//!   byte[0] in [0x40..0x7F] or > 0xBF  -> DATA packet (raw forward)
//!   byte[0] in [0x00..0x3F] or [0x80..0xBF] -> INIT (decrypt + create session)

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::cipher::{SnellCipher, SALT_LEN, HDR_CT_LEN};

/// QUIC mode CONNECT command — fixed to 0x01, no version byte.
pub const QUIC_CMD_CONNECT: u8 = 0x01;

/// Parsed QUIC init payload (different format from TCP — no version byte,
/// no client_id, has user/SNI string instead).
#[derive(Debug)]
pub struct QuicRequest {
    pub user:     String,
    pub host:     String,
    pub port:     u16,
    /// App data following the CONNECT header.
    pub trailing: Vec<u8>,
}

/// Parse a decrypted QUIC init payload.
/// Format: [0x01][user_len][user][host_len][host][port BE u16][trailing...]
pub fn parse_quic_request(data: &[u8]) -> anyhow::Result<QuicRequest> {
    if data.len() < 2 { anyhow::bail!("QUIC payload too short"); }
    if data[0] != QUIC_CMD_CONNECT {
        anyhow::bail!("QUIC command must be 0x01, got {:#04x}", data[0]);
    }
    let user_len = data[1] as usize;
    if data.len() < 2 + user_len + 1 { anyhow::bail!("truncated user"); }
    let user = std::str::from_utf8(&data[2..2 + user_len])?.to_owned();
    let mut pos = 2 + user_len;
    let host_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + host_len + 2 { anyhow::bail!("truncated host"); }
    let host = std::str::from_utf8(&data[pos..pos + host_len])?.to_owned();
    pos += host_len;
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    Ok(QuicRequest { user, host, port, trailing: data[pos..].to_vec() })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind { Init, Data }

/// Classify a UDP datagram by its first byte (matches snell-server v5 classifier).
pub fn classify(packet: &[u8]) -> Option<PacketKind> {
    if packet.is_empty() { return None; }
    let b = packet[0];
    if (0x40..=0x7F).contains(&b) || b > 0xBF {
        Some(PacketKind::Data)
    } else {
        Some(PacketKind::Init)
    }
}

pub struct UdpSession {
    pub client_addr: SocketAddr,
    pub target_sock: Arc<UdpSocket>,
    pub last_seen:   AtomicU64,
}

impl UdpSession {
    pub fn touch(&self) {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64).unwrap_or(0);
        self.last_seen.store(nanos, Ordering::Relaxed);
    }
}

pub type SessionTable = Arc<Mutex<HashMap<SocketAddr, Arc<UdpSession>>>>;

pub fn new_session_table() -> SessionTable {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Remove sessions idle for more than `timeout_secs` seconds.
pub async fn gc_sessions(table: &SessionTable, timeout_secs: u64) {
    let now_nanos = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64).unwrap_or(0);
    let cutoff = now_nanos.saturating_sub(timeout_secs.saturating_mul(1_000_000_000));
    table.lock().await.retain(|_, s| s.last_seen.load(Ordering::Relaxed) >= cutoff);
}

/// Decrypt the init datagram payload after stripping the 16-byte salt.
/// Returns the parsed Snell request from the first chunk.
///
/// `data_after_salt` is the bytes AFTER the 16-byte salt. It must contain at
/// least one full chunk: [23B header CT][interleave bytes][payload_len + 16B].
pub fn decrypt_init(psk: &[u8], salt: &[u8; SALT_LEN], data_after_salt: &[u8])
    -> Result<QuicRequest>
{
    let mut cipher = SnellCipher::new(psk, salt)?;
    if data_after_salt.len() < HDR_CT_LEN { bail!("init datagram too short"); }
    let hdr_ct: [u8; HDR_CT_LEN] = data_after_salt[..HDR_CT_LEN].try_into().unwrap();
    let (interleave, payload_len) = match cipher.open_header(&hdr_ct)? {
        Some(t) => t,
        None    => bail!("zero chunk as init handshake"),
    };
    let payload_start = HDR_CT_LEN + interleave;
    let payload_end   = payload_start + payload_len + 16;
    if data_after_salt.len() < payload_end { bail!("init datagram truncated"); }
    let payload_pt = cipher.open_payload(&data_after_salt[payload_start..payload_end])?;
    parse_quic_request(&payload_pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_data_short_header() {
        let mut p = vec![0u8; 20]; p[0] = 0x55;
        assert_eq!(classify(&p), Some(PacketKind::Data));
    }

    #[test]
    fn classify_data_long_header_not_initial() {
        let mut p = vec![0u8; 20]; p[0] = 0xD0;
        assert_eq!(classify(&p), Some(PacketKind::Data));
    }

    #[test]
    fn classify_init() {
        let mut p = vec![0u8; 20]; p[0] = 0x20;
        assert_eq!(classify(&p), Some(PacketKind::Init));
    }

    #[test]
    fn classify_init_high_range() {
        let mut p = vec![0u8; 20]; p[0] = 0xA0;
        assert_eq!(classify(&p), Some(PacketKind::Init));
    }

    #[test]
    fn classify_empty() {
        assert_eq!(classify(&[]), None);
    }
}
