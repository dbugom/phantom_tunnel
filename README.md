# Phantom Tunnel

A secure, censorship-resistant tunneling protocol built in Rust.

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## Features

- **End-to-end encryption** using Noise Protocol (IK pattern) with ChaCha20-Poly1305
- **TLS fingerprint mimicry** - Traffic looks like Chrome, Firefox, or Safari
- **Stream multiplexing** - Multiple connections over a single tunnel
- **SOCKS5 & HTTP proxy** - Works with any application
- **DNS tunneling** - Fallback for heavily censored networks
- **Traffic obfuscation** - Padding and timing randomization

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.70 or later

### Installation

```bash
# Clone the repository
git clone https://github.com/dbugom/phantom_tunnel.git
cd phantom_tunnel

# Build
cargo build --release

# Binaries are in target/release/
```

### Server Setup

```bash
# 1. Create config file
cp examples/server.config.toml config.toml

# 2. Start server (keys auto-generate on first run)
./target/release/phantom-server -c config.toml
```

On first run, the server will:
- Generate a keypair automatically
- Save it to your config file
- Print the public key to share with clients

### Client Setup

```bash
# 1. Create config file
cp examples/client.config.toml config.toml

# 2. Add server's public key to config.toml
#    server_public_key = "KEY_FROM_SERVER"

# 3. Start client (keys auto-generate on first run)
./target/release/phantom-client -c config.toml
```

The client starts local proxies:
- **SOCKS5**: `127.0.0.1:1080`
- **HTTP**: `127.0.0.1:8080`

### Configure Your Applications

**Browser (Firefox):**
1. Settings → Network Settings → Manual proxy
2. SOCKS Host: `127.0.0.1`, Port: `1080`
3. Check "SOCKS v5" and "Proxy DNS"

**Command line:**
```bash
# Using SOCKS5
curl --socks5-hostname 127.0.0.1:1080 https://example.com

# Using HTTP proxy
curl -x http://127.0.0.1:8080 https://example.com
```

## Configuration

### Server (`config.toml`)

```toml
[server]
listen = "0.0.0.0:443"
private_key = ""  # Auto-generated on first run
public_key = ""   # Auto-generated on first run
allowed_clients = [
    # Add client public keys here
]
max_connections = 1000

[logging]
level = "info"
```

### Client (`config.toml`)

```toml
[client]
server = "your-server.com:443"
server_public_key = "SERVER_PUBLIC_KEY_HERE"
private_key = ""  # Auto-generated on first run
public_key = ""   # Auto-generated on first run
socks5_listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"
tls_profile = "chrome"  # chrome, firefox, safari, random
enable_padding = true

[logging]
level = "info"
```

## Building with Features

```bash
# Default (TLS, SOCKS5, HTTP proxy)
cargo build --release

# All features including DNS tunneling
cargo build --release --all-features

# Minimal binary size
cargo build --profile release-small
```

## Documentation

- [Protocol Specification](docs/PROTOCOL_SPEC.md) - Wire protocol details
- [Deployment Guide](docs/DEPLOYMENT.md) - Production setup, security hardening

## Architecture

```
┌─────────────────────────────────────────┐
│         Application Layer               │
│      (SOCKS5 / HTTP Proxy)              │
├─────────────────────────────────────────┤
│         Multiplexing Layer              │
│    (Streams, Flow Control)              │
├─────────────────────────────────────────┤
│          Tunnel Layer                   │
│   (Noise Protocol, Encryption)          │
├─────────────────────────────────────────┤
│        Obfuscation Layer                │
│  (TLS Mimicry, Padding, Timing)         │
├─────────────────────────────────────────┤
│         Transport Layer                 │
│     (TCP, TLS, DNS Tunnel)              │
└─────────────────────────────────────────┘
```

## Security

- **Noise Protocol IK** - Forward secrecy, mutual authentication
- **ChaCha20-Poly1305** - Fast, constant-time AEAD
- **TLS 1.3** - Modern encryption with browser fingerprints
- **No logging** - Privacy by design

## Testing

```bash
# Run all tests
cargo test

# Run with all features
cargo test --all-features
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
