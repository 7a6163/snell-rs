//! v6.0.0b3 `mode` setting — selects the encryption / obfuscation mode.
//!
//! Out-of-band configuration: the server and client `mode` must match, as there
//! is **no on-wire negotiation**. See `PORTING_v6_b3.md`.

/// v6 encryption mode. Numeric discriminants match the official server's
/// internal enum (`default=0, unshaped=1, unsafe-raw=2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Shaped (b2/b3 default): scattered salt first-frame + per-chunk prefix
    /// that doubles as the header AEAD AAD. See `PORTING_v6.md`.
    #[default]
    Default = 0,
    /// Raw 16-byte salt + v5 AEAD chunks with an empty header AAD. Byte-for-byte
    /// identical to the v5 wire format this crate already implements — see
    /// [`crate::cipher::SnellCipher`] / [`crate::snell`].
    Unshaped = 1,
    /// Plaintext 5-byte-header chunks: no salt, no KDF, no cipher.
    /// See [`crate::v6::unsafe_raw`].
    UnsafeRaw = 2,
}

impl Mode {
    /// Parse a `mode` config value. Unknown strings return `None`.
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim() {
            "default" => Some(Mode::Default),
            "unshaped" => Some(Mode::Unshaped),
            "unsafe-raw" => Some(Mode::UnsafeRaw),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::SnellCipher;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn mode_parse_and_discriminants() {
        assert_eq!(Mode::parse("default"), Some(Mode::Default));
        assert_eq!(Mode::parse("unshaped"), Some(Mode::Unshaped));
        assert_eq!(Mode::parse(" unsafe-raw "), Some(Mode::UnsafeRaw));
        assert_eq!(Mode::parse("bogus"), None);
        assert_eq!(Mode::default(), Mode::Default);
        assert_eq!(Mode::Default as u8, 0);
        assert_eq!(Mode::Unshaped as u8, 1);
        assert_eq!(Mode::UnsafeRaw as u8, 2);
    }

    /// Unshaped mode is byte-identical to v5: raw salt followed by a single
    /// `SnellCipher` chunk (interleave 0, empty AAD). Golden vector from
    /// `PORTING_v6_b3.md` (PSK `test-psk-0123456789abcdef`, CONNECT 127.0.0.1:12345).
    #[test]
    fn unshaped_matches_v5_golden_blob() {
        let psk = b"test-psk-0123456789abcdef";
        let salt = unhex("010e1b2835424f5c697683909daab7c4");
        let request = unhex("010100093132372e302e302e313039");

        let mut cipher = SnellCipher::new(psk, &salt).unwrap();
        let mut blob = salt.clone();
        blob.extend_from_slice(&cipher.seal(&request).unwrap());

        // Raw salt (16) + header CT (23) + payload CT (15 + 16) = 70 bytes.
        assert_eq!(blob.len(), 70);
        let expected = "010e1b2835424f5c697683909daab7c4\
            de5154218416c120ec34987ffadda9fe3656638\
            2a117cfbc0c58ca7c0e612e948a7512f55fcf9ca421fca490d444e46f166f229b7afb";
        assert_eq!(hex(&blob), expected);
    }
}
