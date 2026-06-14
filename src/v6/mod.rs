//! Snell v6.0.0b2 shaping layer (opt-in; v5 remains the default).
//!
//! v6 keeps v5's crypto unchanged (argon2id KDF + AES-128-GCM, 12-byte LE
//! counter nonce) and layers on two PSK-derived obfuscations, both driven by a
//! per-connection [`Profile`]:
//!
//! 1. **Handshake first frame** — the 16-byte session salt is scattered into a
//!    PSK-sized frame at permuted positions, each XORed with a keystream byte
//!    ([`Profile::encode_first_frame`] / [`Profile::decode_first_frame`]).
//! 2. **Per-chunk prefix** — every AEAD chunk is preceded by `prefix_len(k)`
//!    PSK-derived bytes that double as the header chunk's AEAD AAD
//!    ([`Profile::prefix_len`] / [`seal_record`]).
//!
//! All formulas are verified byte-exact against `tests/v6_test_vectors.json`
//! (see the in-crate `vectors` test), which was validated end-to-end against the
//! live official server.

mod frame;
mod profile;
mod record;

pub use profile::Profile;
pub use record::seal_record;

#[cfg(test)]
mod vectors;
