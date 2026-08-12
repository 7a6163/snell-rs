//! Golden-vector conformance: every v6 layer must reproduce
//! `tests/v6_test_vectors.json` byte-for-byte. The JSON is the live-server
//! oracle (see PORTING_v6.md); each gate below depends on the previous one.

use super::{Profile, seal_record};
use crate::cipher::SnellCipher;
use serde_json::Value;

const VECTORS: &str = include_str!("../../tests/v6_test_vectors.json");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn argon2_key(psk: &[u8], salt: &[u8]) -> [u8; 16] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(8, 3, 1, Some(32)).expect("static params");
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(psk, salt, &mut out)
        .expect("argon2id");
    let mut k = [0u8; 16];
    k.copy_from_slice(&out[..16]);
    k
}

#[test]
fn all_v6_vectors_match() {
    let root: Value = serde_json::from_str(VECTORS).expect("parse vectors json");
    let vectors = root["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "no vectors to check");

    for v in vectors {
        let psk = v["psk"].as_str().unwrap().as_bytes();
        let label = v["psk"].as_str().unwrap();
        let p = Profile::derive(psk);

        // 1. profile seeds (gate everything else)
        for (off, val) in v["seeds"].as_object().unwrap() {
            let off: u16 = off.parse().unwrap();
            let want = u64::from_str_radix(val.as_str().unwrap(), 16).unwrap();
            assert_eq!(p.seed_at(off), want, "seed+{off} ({label})");
        }
        let want136 = u64::from_str_radix(v["seed136"].as_str().unwrap(), 16).unwrap();
        assert_eq!(p.seed_at(136), want136, "seed136 ({label})");

        // 2. frame size fields
        assert_eq!(
            p.f_field(),
            v["F_field"].as_u64().unwrap() as u32,
            "F ({label})"
        );
        assert_eq!(
            p.shuffle_rounds(),
            v["shuffle_rounds"].as_u64().unwrap() as u32,
            "rounds ({label})"
        );
        assert_eq!(
            p.frame_lo(),
            v["frame_lo"].as_u64().unwrap() as u32,
            "lo ({label})"
        );
        assert_eq!(
            p.frame_hi(),
            v["frame_hi"].as_u64().unwrap() as u32,
            "hi ({label})"
        );
        assert_eq!(
            p.frame_len(),
            v["frame_len"].as_u64().unwrap() as usize,
            "len ({label})"
        );

        // 3. keystream + permutation
        assert_eq!(
            hex(&p.keystream()),
            v["keystream_hex"].as_str().unwrap(),
            "keystream ({label})"
        );
        let want_perm: Vec<usize> = v["perm"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(p.perm(), want_perm, "perm ({label})");

        // 4. first frame encode (zero filler) + decode round-trip
        let salt: [u8; 16] = unhex(v["salt_hex"].as_str().unwrap())
            .as_slice()
            .try_into()
            .unwrap();
        let frame = p.encode_first_frame(&salt, None).unwrap();
        assert_eq!(
            hex(&frame),
            v["first_frame_hex"].as_str().unwrap(),
            "first_frame ({label})"
        );
        assert_eq!(
            p.decode_first_frame(&frame).unwrap(),
            salt,
            "decode ({label})"
        );

        // 5. record prefix bounds
        assert_eq!(
            p.prefix_lo(),
            v["prefix_lo"].as_u64().unwrap() as u32,
            "prefix_lo ({label})"
        );
        assert_eq!(
            p.prefix_hi(),
            v["prefix_hi"].as_u64().unwrap() as u32,
            "prefix_hi ({label})"
        );
        assert_eq!(
            p.prefix_len(0),
            v["prefix_len_chunk0"].as_u64().unwrap() as usize,
            "prefix_len0 ({label})"
        );

        // 6. argon2id session key (KDF params unchanged from v5)
        assert_eq!(
            hex(&argon2_key(psk, &salt)),
            v["argon2_key_hex"].as_str().unwrap(),
            "argon2_key ({label})"
        );

        // 7. first record + full blob (zero prefix) — exactly what the live server accepted
        let req = unhex(v["snell_request_hex"].as_str().unwrap());
        let prefix = vec![0u8; p.prefix_len(0)];
        let mut cipher = SnellCipher::new(psk, &salt).unwrap();
        let record = seal_record(&mut cipher, &req, &prefix).unwrap();
        assert_eq!(
            hex(&record),
            v["first_record_hex"].as_str().unwrap(),
            "first_record ({label})"
        );
        let blob = [frame, record].concat();
        assert_eq!(
            hex(&blob),
            v["full_blob_hex"].as_str().unwrap(),
            "full_blob ({label})"
        );
    }
}
