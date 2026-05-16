# snell-rs

[![codecov](https://codecov.io/gh/7a6163/snell-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/7a6163/snell-rs)

Open-source Snell v5 proxy server and client, written in Rust.

Compatible with [Surge](https://nssurge.com) as a Snell v5 server.

## Features

- Snell v5 protocol support
- Connection reuse
- Obfuscation: plain / `obfs=http` / `obfs=tls` (auto-detected)
- Dynamic record sizing — adaptive chunk sizes for better performance under packet loss
- QUIC proxy mode — UDP relay with selective encryption
- Egress interface binding
- systemd socket activation

## Build

```bash
# Requires Rust 1.95+ (pinned via rust-toolchain.toml)
cargo build --release
```

Binaries:

```
./target/release/snell-server
./target/release/snell-client   # local SOCKS5 proxy for testing
```

## Quick Start

**Start the server:**

```bash
PSK=your-preshared-key ./snell-server 0.0.0.0:6180
```

**Surge configuration:**

```ini
[Proxy]
my-server = snell, your-server-ip, 6180, psk=your-preshared-key, version=5
```

**Test locally with the SOCKS5 client:**

```bash
PSK=your-preshared-key \
SNELL_SERVER=your-server-ip:6180 \
LISTEN=127.0.0.1:1080 \
./snell-client

curl --socks5 127.0.0.1:1080 https://example.com
```

## Configuration

### Server

| Variable | Required | Default | Description |
|---|---|---|---|
| `PSK` | ✅ | — | Pre-shared key |
| `EGRESS_INTERFACE` | — | system default | Bind outgoing connections to this interface |
| `QUIC` | — | `0` | Set to `1` to enable QUIC proxy mode |
| `TCP_FASTOPEN` | — | `1` | Server-side TFO. Set to `0` to disable. See [TCP Fast Open](#tcp-fast-open) |
| `TCP_FASTOPEN_OUT` | — | `0` | Set to `1` to opt outbound CONNECT sockets into client-side TFO |

```bash
PSK=your-key QUIC=1 EGRESS_INTERFACE=eth0 ./snell-server 0.0.0.0:6180
```

### Client

`snell-client` is a local SOCKS5 proxy that tunnels traffic to a Snell server. Useful for routing specific apps through a Snell server, or for verifying a `snell-server` deployment without a Surge license.

| Variable | Required | Default | Description |
|---|---|---|---|
| `PSK` | ✅ | — | Must match the server's PSK |
| `SNELL_SERVER` | — | `127.0.0.1:6180` | Snell server `host:port` |
| `LISTEN` | — | `127.0.0.1:1080` | Local SOCKS5 bind address |
| `TCP_FASTOPEN` | — | `0` | Set to `1` to opt the outbound socket to the snell server into client-side TFO |

**Run:**

```bash
PSK=your-preshared-key \
SNELL_SERVER=your-server-ip:6180 \
LISTEN=127.0.0.1:1080 \
./snell-client
```

**Examples:**

```bash
# curl through the proxy (use --socks5-hostname so DNS goes through the tunnel)
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me

# Route a single app via proxychains
proxychains4 -q ./your-app

# System-wide SOCKS5 on macOS
networksetup -setsocksfirewallproxy "Wi-Fi" 127.0.0.1 1080

# Disable when done
networksetup -setsocksfirewallproxystate "Wi-Fi" off
```

**Notes:**

- Plain Snell only — no client-side obfuscation. If the server is reached via `obfs=http` or `obfs=tls`, use Surge as the client instead.
- Supports Snell v5 connection reuse for lower per-request latency.

## Obfuscation

The server auto-detects the obfuscation mode — no server-side configuration needed.

| Mode | Surge setting |
|---|---|
| Plain | `obfs=off` |
| HTTP | `obfs=http` |
| TLS | `obfs=tls` |

```ini
# HTTP obfuscation
my-server = snell, your-server-ip, 6180, psk=your-key, version=5, obfs=http, obfs-host=example.com

# TLS obfuscation
my-server = snell, your-server-ip, 6180, psk=your-key, version=5, obfs=tls, obfs-host=example.com
```

## QUIC Proxy Mode

Enable with `QUIC=1`. The server opens a UDP socket on the same port as TCP.

> **Note:** QUIC proxy mode is experimental. Compatibility with unmodified Surge clients has not been fully verified.

## Egress Interface

Requires `CAP_NET_RAW` on Linux or root on macOS.

```bash
# Linux — without running as root
sudo setcap cap_net_raw+ep ./snell-server

PSK=your-key EGRESS_INTERFACE=eth0 ./snell-server
```

## TCP Fast Open

Server-side TFO is on by default and the server prints
`<NOTIFY> TCP Fast Open enabled` at startup when the `setsockopt`
succeeds. The kernel still needs the server bit:

```bash
# Linux — enable both client (1) and server (2) bits
sudo sysctl -w net.ipv4.tcp_fastopen=3
# Persist
echo 'net.ipv4.tcp_fastopen=3' | sudo tee /etc/sysctl.d/99-tfo.conf

# macOS
sudo sysctl -w net.inet.tcp.fastopen=3
```

In Docker the host sysctl applies — the container can't change it.
Set `--sysctl net.ipv4.tcp_fastopen=3` on `docker run` or rely on the
host's value.

Set `TCP_FASTOPEN=0` to skip the setsockopt entirely.

Outbound TFO (`TCP_FASTOPEN_OUT=1` on server, `TCP_FASTOPEN=1` on the
client binary) is opt-in. Linux >= 4.11 only; the macOS client-side
path requires `connectx()` and is currently a no-op.

## systemd Socket Activation

```ini
# /etc/systemd/system/snell.socket
[Socket]
ListenStream=6180
ListenDatagram=6180

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

## Security

- `PSK` is required — the server exits with an error if unset
- Generate a strong PSK: `openssl rand -base64 32`

## Disclaimer

Snell is a proprietary protocol developed by the [Surge](https://nssurge.com) team. This project is an independent open-source implementation for interoperability purposes and is not affiliated with or endorsed by Surge.
