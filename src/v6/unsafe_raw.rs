//! v6.0.0b3 `unsafe-raw` mode — plaintext snell chunks (no salt, KDF, or AEAD).
//!
//! Wire format (see `PORTING_v6_b3.md`): a 5-byte plaintext header followed by
//! the optional interleave scratch and the plaintext payload.
//!
//! ```text
//! [0x04][interleave: u16 BE][payload_len: u16 BE][interleave bytes][payload]
//! ```
//!
//! There is no 16-byte AEAD tag and the header is 5 bytes (not the 7-byte
//! AEAD-plaintext layout of the encrypted modes). The interleave scratch is the
//! same even-byte-swap scheme the AEAD modes use; `encode` emits zero interleave
//! and `decode` undoes any interleave it is given.

/// Encode one plaintext chunk with zero interleave.
pub fn encode_unsafe_raw(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0x04);
    out.extend_from_slice(&0u16.to_be_bytes()); // interleave = 0
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode one plaintext chunk from the front of `buf`, returning the payload and
/// the number of bytes consumed. Returns `None` on a bad type byte or a buffer
/// too short to hold the framed chunk.
pub fn decode_unsafe_raw(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 5 || buf[0] != 0x04 {
        return None;
    }
    let interleave = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total = 5 + interleave + payload_len;
    if buf.len() < total {
        return None;
    }
    let mut body = buf[5..total].to_vec();
    // Undo the even-byte swap the sender applied across the interleave prefix.
    if interleave > 0 {
        let n = interleave.min(payload_len);
        for i in (0..n).step_by(2) {
            body.swap(i, interleave + i);
        }
    }
    Some((body[interleave..].to_vec(), total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Golden vector from `PORTING_v6_b3.md` — CONNECT 127.0.0.1:12345.
    #[test]
    fn unsafe_raw_matches_golden_blob() {
        let request = unhex("010100093132372e302e302e313039");
        let blob = encode_unsafe_raw(&request);
        assert_eq!(hex(&blob), "040000000f010100093132372e302e302e313039");
        assert_eq!(blob.len(), 20);
    }

    #[test]
    fn unsafe_raw_roundtrips() {
        let payload = b"hello unsafe-raw world";
        let wire = encode_unsafe_raw(payload);
        let (got, consumed) = decode_unsafe_raw(&wire).unwrap();
        assert_eq!(got, payload);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn decode_rejects_bad_type_and_truncation() {
        assert!(decode_unsafe_raw(&[0x05, 0, 0, 0, 1, 0xaa]).is_none()); // bad type
        assert!(decode_unsafe_raw(&[0x04, 0, 0]).is_none()); // header too short
        assert!(decode_unsafe_raw(&[0x04, 0, 0, 0, 9, 1, 2]).is_none()); // body truncated
    }

    #[test]
    fn decode_undoes_interleave() {
        // Hand-craft a chunk with interleave=2: body = [scratch:2][payload].
        // The sender swap (even indices) is its own inverse, so building the wire
        // by applying that swap lets decode recover the original payload.
        let payload = b"abcd";
        let interleave = 2usize;
        let mut body = vec![0u8; interleave];
        body.extend_from_slice(payload);
        let n = interleave.min(payload.len());
        for i in (0..n).step_by(2) {
            body.swap(i, interleave + i);
        }
        let mut wire = vec![0x04];
        wire.extend_from_slice(&(interleave as u16).to_be_bytes());
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(&body);

        let (got, consumed) = decode_unsafe_raw(&wire).unwrap();
        assert_eq!(got, payload);
        assert_eq!(consumed, wire.len());
    }
}
