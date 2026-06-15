# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[5.6.0]: https://github.com/7a6163/snell-rs/compare/v5.5.0...v5.6.0
[5.5.0]: https://github.com/7a6163/snell-rs/compare/v5.4.0...v5.5.0
[5.4.0]: https://github.com/7a6163/snell-rs/compare/v5.3.0...v5.4.0
[5.3.0]: https://github.com/7a6163/snell-rs/compare/v5.2.1...v5.3.0
[5.2.1]: https://github.com/7a6163/snell-rs/compare/v5.2.0...v5.2.1
[5.2.0]: https://github.com/7a6163/snell-rs/compare/v5.1.0...v5.2.0
[5.1.0]: https://github.com/7a6163/snell-rs/compare/v5.0.0...v5.1.0
[5.0.0]: https://github.com/7a6163/snell-rs/releases/tag/v5.0.0
