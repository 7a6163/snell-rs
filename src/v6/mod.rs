//! Snell v6.0.0b2 shaping layer (opt-in; v5 remains the default).
//!
//! v6 keeps v5's crypto unchanged (argon2id KDF + AES-128-GCM, 12-byte LE
//! counter nonce) and layers on PSK-derived obfuscations driven by a
//! per-connection [`Profile`]:
//!
//! 1. **Handshake first frame** — the 16-byte session salt is scattered into a
//!    PSK-sized frame at permuted positions, each XORed with a keystream byte
//!    ([`Profile::encode_first_frame`] / [`Profile::decode_first_frame`]).
//! 2. **Per-chunk prefix** — every AEAD chunk is preceded by `prefix_len(k)`
//!    PSK-derived filler bytes that double as the header chunk's AEAD AAD
//!    ([`Profile::prefix_len`] / [`seal_record`]).
//! 3. **Junk region** — records carry a PSK-sized junk region between the
//!    header and payload CT; it is the payload's AEAD AAD and is byte-swapped
//!    with the payload CT by a PSK-derived involution ([`Profile::mix`]).
//! 4. **Filler generator** — all wire padding (prefix, junk, first-frame
//!    filler) is produced by fn `0x417c8`: popcount-shaped bytes from a
//!    PSK-derived PRF, indistinguishable from the official server's traffic
//!    ([`Profile::fill_filler`]).
//!
//! All formulas are verified byte-exact against `tests/v6_test_vectors.json`
//! and against real captured Surge traffic in `tests/surge_interop.rs`.

mod filler;
mod frame;
pub mod io;
mod mix;
mod mode;
mod profile;
mod record;
pub mod unsafe_raw;

pub use io::{
    read_record, read_unsafe_raw, write_records, write_unsafe_raw, write_unsafe_raw_zero,
    write_zero_record,
};
pub use mode::Mode;
pub use profile::Profile;
pub use record::{seal_record, seal_record_shaped};
pub use unsafe_raw::{decode_unsafe_raw, encode_unsafe_raw};

#[cfg(test)]
mod vectors;
