# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.2.1] - 2026-08-14

### Fixed

- A peer that opened a connection and went away was reported as
  `ERROR connection failed ... error=early eof`. Nothing had failed: reachability
  probes and port scanners connect and close without speaking, and clients abort
  established sessions instead of sending the authenticated zero record. Both
  reach the same EOF out of a `read_exact`. On a public listener this is
  continuous, and it buried the failures an operator can act on — a passing Surge
  test alongside a log full of `ERROR` reads as a broken server.

  A connection that closes before sending a byte is now logged at `debug` as
  `connection closed early`, and a hang-up after the tunnel is established ends
  the session normally. The classification is by connection *phase*, not by io
  error kind: throughout the handshake window an EOF or reset keeps its `ERROR`
  level and its PSK/`MODE` hint, because that is how a wrong PSK or a `MODE`
  mismatch presents on a peer that hangs up instead of waiting for a reply.
  Matching on error kind alone would have silenced those too.

### Added

- End-to-end coverage for disconnects in `default` mode: a bare connect and
  close, a truncated first frame, and a live session torn down mid-stream without
  a zero record, each followed by asserting the server still serves a fresh
  connection. Plus assertions on the server's own log output, so that a genuine
  `MODE` mismatch is still reported at `ERROR` while a silent probe is not —
  the classification, not just the framing, is now pinned.

## [6.2.0] - 2026-08-13

### Fixed

- **v6 `default` (shaped) mode could not talk to a real client at all.** Any
  record carrying a junk region failed with `payload authentication failed`,
  which is every record a Surge client sends. Two things were wrong, both
  recovered by reverse-engineering the official binaries against captured
  traffic:
  - The payload AEAD authenticates over the record's junk region. We passed an
    empty AAD.
  - After sealing, the sender applies a PSK-derived self-inverse permutation
    (official fn `0x41200`) that swaps bytes between the junk region and the
    payload ciphertext; the receiver must undo it before opening. We instead had
    an invented even-byte swap that matched nothing.

  The header layer was always correct, which is why the failure surfaced as a
  payload error and looked like a key problem.
- A `default`-mode zero record carries its own junk region. The reader returned
  end-of-session without draining those bytes, desynchronising the stream
  against a peer that padded its terminator.
- `unsafe-raw` carried the same invented even-byte swap, which would have
  silently corrupted any frame a peer sent with a non-empty interleave. The junk
  region is inert in that mode: the official binary reaches both the junk
  generator and the mix only from the AEAD record writer and reader. Its
  round-trip test was tautological — it built the wire with the same swap it was
  meant to verify — and has been replaced.
- `prefix_lo` was not clamped against `prefix_hi`. The official profile-init
  epilogue (`0x42520`) clamps each lower bound against its upper bound; our port
  missed it. No test PSK was affected (the clamp is a no-op when `lo ≤ 80 < 128
  ≤ hi`), but the missing clamp would bite a PSK whose `prefix_hi` is clamped
  down to 128 while `prefix_lo` exceeds it.

### Added

- **Wire-filler generator** (official fn `0x417c8`): all v6 padding — the
  per-record prefix, the junk region, and the first-frame filler — is now
  produced by the official PRF plus a popcount-table byte shaper. Every filler
  byte has a PSK-derived popcount (4 for both test PSKs), making our traffic
  byte-indistinguishable from the official server's at the byte-distribution
  level. Previously the writer used `rand::thread_rng().fill_bytes()`, producing
  uniformly random bytes that are trivially distinguishable from official
  traffic by DPI.
- **Interleave sizing pipeline** (fns `0x41630`/`0x41680`/`0x41b08`/`0x41cd0`):
  the writer now computes the same junk-region sizes the official server
  produces, including the target-size padding toward plausible packet sizes and
  the first-record floor. Verified against both captured PSKs: PSK A produces
  `interleave=879` (saturating the +730 pad cap), PSK B produces
  `interleave=1022` (non-saturating, discriminating on `target_size`).
- The writer now emits shaped records with junk and applies the mix, matching
  the official wire format. Previously the writer always sent `interleave=0`,
  which is conforming but defeats the DPI-resistance purpose of shaped mode.
- `tests/surge_interop.rs` plus three fixtures of real captured Surge
  `default`-mode traffic. The two PSKs land on different mix variants
  (`mode 1, rounds 1` block swap and `mode 2, rounds 2` strided swap), so a
  regression in either arm fails the suite. These are the first tests in the
  repo that pin the v6 record layer against a real peer rather than against
  ourselves.
- `seal_record_shaped` and `SnellCipher::seal_with_junk` for emitting records
  that carry a junk region, with round-trip coverage across junk sizes.

## [6.1.0] - 2026-08-13

### Changed

- **BREAKING:** an unset `MODE` now means `default` (v6 shaped) instead of
  `unshaped`, matching official snell-server, whose help text reads
  "Default: default." and whose `default` is the zero-valued enum variant a
  zero-initialised config yields. **Serving a v5 client now requires an explicit
  `MODE=unshaped`.** Deviating from the reference implementation on its most
  visible default was a wart, and it cost real debugging time: a Surge client on
  v6 against an unset-`MODE` server fails with `header authentication failed`,
  which reads like a PSK problem.
- `MODE` parsing is now ASCII case-insensitive, matching the official server's
  `strcasecmp`. `MODE=Default` used to abort startup.

### Added

- The startup banner now reports the crate version, so a running container's
  build is legible from the first line of its log:
  `snell-server 6.1.0 listening on 0.0.0.0:6180  [v6/default (shaped)]`.
- A failed handshake now names `MODE` as a suspect alongside the PSK. The two are
  indistinguishable on the wire — both derive the wrong key and fail the same
  AEAD open — so the log spells out which mode the server is in and which peers
  cannot authenticate against it.
- `compose.yml` now passes through every environment variable the README
  documents; `MODE` and `DNS_IP_PREFERENCE` were previously unreachable for
  Compose users, making the new v6 features impossible to enable that way.

## [6.0.0] - 2026-08-13

### Changed

- Align server with official v6.0.0rc2: clear error for literal targets blocked
  by IP policy; official error codes; five-state dns-ip-preference model.

### Security

- Bumped `lru` to 0.18.2 for RUSTSEC-2026-0253 (`LruCache::pop()` was not
  panic-safe). The salt cache was never exposed to it — its key is `[u8; 16]`,
  which has no `Drop`, and the advisory needs a panicking key `Drop` caught by
  `catch_unwind` — but the audit gate has to stay clean.

## [6.0.0-rc.1] - 2026-07-21

### Added

- **v6 encryption modes** (`MODE`): the server and client now speak all three
  official snell-server v6 modes, selected out-of-band and validated
  byte-exact against the v6.0.0rc-1 binaries (amd64 / i386 / aarch64).
  - `default` (shaped) — the 16-byte session salt is scattered into a
    PSK-sized first frame at PSK-derived permuted positions, each XORed with a
    PSK-derived keystream; every AEAD chunk is preceded by a PSK-derived prefix
    that doubles as the header AEAD AAD. Surge's default mode; DPI-resistant.
  - `unshaped` — raw 16-byte salt + v5 AEAD chunks with an empty header AAD.
    Byte-identical to the v5 wire this crate has always spoken, so it remains
    the default when `MODE` is unset (existing v5 deployments are unaffected).
  - `unsafe-raw` — plaintext 5-byte-header framing: no salt, KDF, or cipher.
    Only for use behind an already-secure outer channel.
  The crypto (argon2id KDF, AES-128-GCM, 12-byte LE counter nonce) is unchanged
  from v5 across all three modes. See `src/v6/` and `tests/v6_test_vectors.json`.
- `MODE` env var on both `snell-server` and `snell-client` (must match; not
  negotiated on the wire).

### Changed

- Crate version bumped to `6.0.0-rc.1`; description now "Open-source Snell
  v5/v6 proxy protocol implementation".
- The server startup banner and client banner report the active mode.
- `v6` module is now wired into both binaries (previously a standalone,
  byte-verified library not reachable from the running server/client).

### Notes

- `obfs=http` / `obfs=tls` auto-detect and UDP-over-TCP relay continue to apply
  only on the `unshaped` (v5) wire. `default` and `unsafe-raw` cover TCP CONNECT.
- rc-1's TCP CONNECT wire format is identical to v6.0.0b4; the `src/v6/`
  golden vectors remain a valid oracle.

## [5.6.0] - 2026-06-15

### Added

- **IPv6 outbound toggle** (`IPV6`): default off = IPv4-only egress, matching the
  official snell-server `ipv6=false`; set `IPV6=1` to allow IPv6 targets. Applies
  to both the TCP and QUIC resolution paths.
- **Custom DNS resolver** (`DNS`): a comma-separated list of upstream nameserver
  IPs (e.g. `DNS=1.1.1.1,8.8.8.8`), queried over UDP+TCP port 53 via
  hickory-resolver, replacing the system resolver for target hostnames. Unset
  keeps the system resolver. Honors the `IPV6` toggle.
- **UDP-over-TCP relay** (`CMD_CONNECT_UDP`): UDP datagrams are framed and
  relayed inside the encrypted TCP tunnel (one datagram per Snell chunk), on both
  the server and the client. `snell-client` exposes this via SOCKS5 UDP
  ASSOCIATE. Server-side targets honor the DNS resolver, IPv6 toggle, SSRF guard,
  and egress interface binding.
- MIT license.

> Note: the UDP-over-TCP wire format was implemented clean-room from the
> behaviour of the open-source `opensnell` project and verified with an internal
> round-trip test; it has not been validated byte-for-byte against an official
> Surge capture.

## [5.5.0] - 2026-05-19

### Added

- Structured logging via `tracing` + `tracing-subscriber` (`RUST_LOG`,
  `LOG_FORMAT=json`).
- PSK wrapped in `zeroize::Zeroizing` for scrub-on-drop (best-effort defense
  against core dumps / swap).

### Changed

- Split the handshake timeout into per-phase budgets to limit slowloris-style
  squatting.

## [5.4.0] - 2026-05-17

### Added

- Per-source-IP TCP handshake cooldown (`TCP_HANDSHAKE_COOLDOWN_MS`) to bound
  argon2id DoS from a single IP.
- CI `cargo audit` + `cargo deny check advisories` gate.

### Changed

- Tuned the release profile (LTO, codegen-units, panic=abort, strip) for runtime
  performance and smaller binaries.

### Fixed

- Re-roll the `snell-client` handshake salt to avoid colliding with the server's
  obfs auto-detect first byte.

## [5.3.0] - 2026-05-16

### Added

- TCP Fast Open: enabled server-side by default; opt-in for server egress and the
  client (`TCP_FASTOPEN` / `TCP_FASTOPEN_OUT`), with a `tfo` setsockopt module.

## [5.2.1] - 2026-05-12

### Added

- i686 and armv7l musl binaries plus armv7 Docker architecture.

## [5.2.0] - 2026-05-12

### Changed

- **Breaking:** flipped the SSRF guard default — private/LAN targets are now
  allowed by default (`BLOCK_PRIVATE_TARGETS=1` to re-enable the strict guard),
  matching shadowsocks / v2ray / trojan behaviour.

### Security

- Added salt replay protection (CVE-3).

## [5.1.0] - 2026-05-11

### Added

- SIGTERM/SIGINT graceful shutdown for both binaries.
- `compose.yml` + `.env.example` for env-driven configuration.
- Code-coverage upload to Codecov (`cargo-llvm-cov`).

### Changed

- AEAD in-place sealing and expanded SSRF coverage.

## [5.0.0] - 2026-05-10

### Added

- Initial open-source Snell v5 server and client in Rust: plain / `obfs=http` /
  `obfs=tls` (auto-detected), connection reuse, dynamic record sizing, QUIC proxy
  mode, egress interface binding, and systemd socket activation.
- End-to-end integration tests for TCP and QUIC; CI with static musl binaries and
  a multi-arch Docker image.

[6.1.0]: https://github.com/7a6163/snell-rs/compare/v6.0.0...v6.1.0
[6.0.0]: https://github.com/7a6163/snell-rs/compare/v5.6.0...v6.0.0
[6.0.0-rc.1]: https://github.com/7a6163/snell-rs/compare/v5.6.0...v6.0.0-rc.1
[5.6.0]: https://github.com/7a6163/snell-rs/compare/v5.5.0...v5.6.0
[5.5.0]: https://github.com/7a6163/snell-rs/compare/v5.4.0...v5.5.0
[5.4.0]: https://github.com/7a6163/snell-rs/compare/v5.3.0...v5.4.0
[5.3.0]: https://github.com/7a6163/snell-rs/compare/v5.2.1...v5.3.0
[5.2.1]: https://github.com/7a6163/snell-rs/compare/v5.2.0...v5.2.1
[5.2.0]: https://github.com/7a6163/snell-rs/compare/v5.1.0...v5.2.0
[5.1.0]: https://github.com/7a6163/snell-rs/compare/v5.0.0...v5.1.0
[5.0.0]: https://github.com/7a6163/snell-rs/releases/tag/v5.0.0
