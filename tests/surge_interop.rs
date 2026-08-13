//! Interoperability regression against real captured Surge v6 `default`-mode
//! traffic.
//!
//! Each fixture is the complete first client flight of a live Surge session
//! (first frame + one shaped record) recorded against a known test PSK. They
//! exercise the parts of the record layer that only a real peer produces:
//! a non-zero junk region, the payload AEAD authenticating over that junk, and
//! the PSK-derived junk/ciphertext mix.
//!
//! The two PSKs deliberately land on different mix variants — PSK A on
//! `mode 1, rounds 1` (block swap) and PSK B on `mode 2, rounds 2` (strided
//! swap) — so a regression in either arm fails here.

use snell::cipher::SnellCipher;
use snell::v6::{Profile, read_record};

const PSK_A: &[u8] = b"test-psk-0123456789abcdef";
const PSK_B: &[u8] = b"test-psk-fedcba9876543210";

/// The CONNECT request every capture carries: Snell v6 CONNECT to `bing.com:80`
/// with an HTTP HEAD as the initial payload.
const EXPECTED: &[u8] = b"\x01\x05\x00\x08bing.com\x00\x50\
HEAD / HTTP/1.1\r\nHost: bing.com\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n";

async fn decode_first_record(capture: &[u8], psk: &[u8]) -> Vec<u8> {
    let profile = Profile::derive(psk);
    let (frame, rest) = capture.split_at(profile.frame_len());
    let salt = profile
        .decode_first_frame(frame)
        .expect("first frame should yield the session salt");
    let mut cipher = SnellCipher::new(psk, &salt).expect("cipher init");
    let mut chunk = 0u64;
    let mut reader = rest;
    read_record(&mut reader, &mut cipher, &profile, &mut chunk)
        .await
        .expect("record should decode")
        .expect("record should carry a payload")
}

#[tokio::test]
async fn decodes_surge_record_with_block_mix() {
    for capture in [
        &include_bytes!("data/surge_v6_default_pska_1.bin")[..],
        &include_bytes!("data/surge_v6_default_pska_2.bin")[..],
    ] {
        assert_eq!(decode_first_record(capture, PSK_A).await, EXPECTED);
    }
}

#[tokio::test]
async fn decodes_surge_record_with_strided_mix() {
    let capture = &include_bytes!("data/surge_v6_default_pskb.bin")[..];
    assert_eq!(decode_first_record(capture, PSK_B).await, EXPECTED);
}

/// The fixtures must actually cover a junked record, or they would pass even
/// with the junk handling removed.
#[tokio::test]
async fn fixtures_carry_a_non_empty_junk_region() {
    for (capture, psk) in [
        (
            &include_bytes!("data/surge_v6_default_pska_1.bin")[..],
            PSK_A,
        ),
        (&include_bytes!("data/surge_v6_default_pskb.bin")[..], PSK_B),
    ] {
        let profile = Profile::derive(psk);
        let salt = profile
            .decode_first_frame(&capture[..profile.frame_len()])
            .expect("first frame");
        let mut cipher = SnellCipher::new(psk, &salt).unwrap();
        let off = profile.frame_len() + profile.prefix_len(0);
        let prefix = &capture[profile.frame_len()..off];
        let hdr: [u8; 23] = capture[off..off + 23].try_into().unwrap();
        let (interleave, payload_len) = cipher.open_header_raw_with_aad(&hdr, prefix).unwrap();
        assert!(interleave > 0, "fixture has no junk to exercise the mix");
        // The capture must be exactly one whole record, or the offsets above are
        // being interpreted wrongly and still happening to decrypt.
        assert_eq!(off + 23 + interleave + payload_len + 16, capture.len());
    }
}
