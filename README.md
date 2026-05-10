# snell-rs

Open-source Rust implementation of the [Snell v5](https://manual.nssurge.com/others/snell.html) proxy protocol, reverse-engineered from the closed-source `snell-server v5.0.1` (Nov 2025).

Compatible with [Surge](https://nssurge.com) as a drop-in Snell v5 server.

## Features

- **Snell v5 protocol** — argon2id KDF + AES-128-GCM, 23-byte chunk header with interleave
- **Connection reuse** — single TCP connection carries multiple requests
- **Obfuscation** — plain / `obfs=http` / `obfs=tls` auto-detected per connection
- **Dynamic record sizing** — adaptive 1–16 KB chunks, reduces latency under packet loss
- **QUIC proxy mode** — UDP relay with selective encryption of QUIC Initial packets
- **Egress control** — bind outgoing connections to a specific network interface
- **systemd socket activation** — inherit pre-bound file descriptors

## Build

```bash
# Requires Rust 1.85+ (edition 2024)
cargo build --release

# Binaries output to:
./target/release/snell-server
./target/release/snell-client   # local SOCKS5 → Snell proxy for testing
```

## Quick Start

**Server:**

```bash
PSK=your-preshared-key ./snell-server 0.0.0.0:6180
```

**Surge proxy entry:**

```ini
[Proxy]
my-server = snell, your-server-ip, 6180, psk=your-preshared-key, version=5
```

**Local test via SOCKS5 client:**

```bash
PSK=your-preshared-key \
SNELL_SERVER=your-server-ip:6180 \
LISTEN=127.0.0.1:1080 \
./snell-client

curl --socks5 127.0.0.1:1080 https://example.com
```

## Configuration

All configuration is via environment variables.

### Server

| Variable | Required | Default | Description |
|---|---|---|---|
| `PSK` | ✅ | — | Pre-shared key (required, no default) |
| `EGRESS_INTERFACE` | — | system default | Bind outgoing connections to this interface (e.g. `eth0`) |
| `QUIC` | — | `0` | Set to `1` to enable QUIC proxy mode (opens UDP on the same port) |

```bash
# Full-featured server launch
PSK=your-key QUIC=1 EGRESS_INTERFACE=eth0 ./snell-server 0.0.0.0:6180
```

### Client

| Variable | Required | Default | Description |
|---|---|---|---|
| `PSK` | ✅ | — | Pre-shared key (required) |
| `SNELL_SERVER` | — | `127.0.0.1:6180` | Snell server address |
| `LISTEN` | — | `127.0.0.1:1080` | Local SOCKS5 listen address |

## Obfuscation

The server **auto-detects** the obfuscation mode from the first byte of each incoming connection — no server-side configuration needed.

| Mode | Surge setting | Detection | Description |
|---|---|---|---|
| Plain | `obfs=off` | random bytes | Raw Snell v5 |
| HTTP | `obfs=http` | `G` (HTTP GET) | Fake WebSocket upgrade handshake |
| TLS | `obfs=tls` | `0x16` (TLS ClientHello) | Self-signed TLS 1.3 wrapper |

```ini
# Surge — HTTP obfuscation
my-server = snell, your-server-ip, 6180, psk=your-key, version=5, obfs=http, obfs-host=example.com

# Surge — TLS obfuscation
my-server = snell, your-server-ip, 6180, psk=your-key, version=5, obfs=tls, obfs-host=example.com
```

## QUIC Proxy Mode

Enable with `QUIC=1`. The server binds a UDP socket on the same port as TCP.

- **QUIC Initial packets** are encrypted with PSK-derived AES-128-GCM (protects SNI and target hostname)
- **QUIC data packets** are forwarded raw — no extra bytes added, PMTU probing is preserved

> **Note:** QUIC proxy uses a custom `CMD_CONNECT_UDP` handshake over the TCP control channel. Compatibility with unmodified Surge clients has not been verified — capture real traffic before production deployment.

## Egress Interface

Bind all outgoing connections to a specific network interface. Requires `CAP_NET_RAW` on Linux or root on macOS.

```bash
# Linux — grant capability without running as root
sudo setcap cap_net_raw+ep ./snell-server

PSK=your-key EGRESS_INTERFACE=eth0 ./snell-server
```

## systemd Socket Activation

The server supports `sd_listen_fds` — it will adopt pre-bound file descriptors passed by systemd instead of binding its own port.

```ini
# /etc/systemd/system/snell.socket
[Socket]
ListenStream=6180
ListenDatagram=6180   # optional, for QUIC mode

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/snell.service
[Unit]
Requires=snell.socket

[Service]
ExecStart=/usr/local/bin/snell-server
Environment=PSK=your-key
Environment=QUIC=1
```

```bash
systemctl enable --now snell.socket
```

## Protocol

Snell v5 was reverse-engineered from `snell-server v5.0.1` via Ghidra static analysis and live traffic decryption.

**Encryption:**

```
Salt:   16 random bytes per direction, exchanged in plaintext at connection start
KDF:    argon2id(PSK, salt, t=3, m=8 KiB, p=1) → 32 bytes, first 16 used as key
Cipher: AES-128-GCM, 12-byte little-endian nonce counter (incremented per AEAD op)
```

**Chunk format:**

```
[23-byte header CT] [interleave bytes] [payload_len + 16 payload CT]

Header plaintext (7 bytes):
  [0x04][0x00][0x00][interleave_size BE u16][payload_len BE u16]
```

## Project Structure

```
src/
├── lib.rs          module declarations
├── cipher.rs       SnellCipher — argon2id KDF + AES-128-GCM seal/open
├── snell.rs        read_chunk, write_chunk, parse_request, protocol constants
├── relay.rs        AdaptiveSizer — dynamic record sizing for t2c relay
├── egress.rs       interface binding (SO_BINDTODEVICE / IP_BOUND_IF)
├── activation.rs   systemd socket activation (sd_listen_fds)
├── quic.rs         QUIC Initial detection, session table, selective encryption
└── bin/
    ├── server.rs   Snell v5 server — all features wired together
    └── client.rs   SOCKS5 → Snell v5 client for local testing
```

## Security

- `PSK` is **required** — the server exits with an error if unset
- argon2id (t=3, m=8 KiB) protects against GPU-accelerated brute-force on the PSK
- AES-128-GCM provides authenticated encryption — any tampered packet closes the connection
- Each connection derives independent keys from unique random salts (forward secrecy per connection)

Generate a strong PSK:

```bash
openssl rand -base64 32
```

## Tested With

- Surge for macOS (Snell v5, plain / obfs=http / obfs=tls)
- curl via local SOCKS5 client (HTTP + HTTPS)

## Disclaimer

This project was produced by reverse-engineering the Snell binary for research and interoperability purposes. Snell is a proprietary protocol developed by the [Surge](https://nssurge.com) team. This implementation is not affiliated with or endorsed by Surge.
