# Phantom Tunnel

An encrypted, multiplexed TCP/UDP tunnel with a local SOCKS5 / HTTP proxy, built in Rust.

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## Features

- **Encryption and mutual authentication** with the Noise Protocol (IK pattern,
  X25519 + ChaCha20-Poly1305). The server only accepts allow-listed client keys.
- **Stream multiplexing** over one connection, with per-stream credit-based flow
  control (one slow connection does not stall the others)
- **SOCKS5 (including UDP ASSOCIATE) and HTTP CONNECT** proxies on the client
- **Automatic reconnect** and keepalive on the client, with **backup servers**
  tried in order when the primary is down, unreachable or refuses the client
- **Connect links** (`phantom://...`): set up a client from one pasted line
- **Server hardening**: fail-closed allow-list, no logging of visited sites,
  private/LAN destinations refused, handshake timeout
- **Camouflage (optional)**: carry the tunnel inside a real TLS + WebSocket
  session behind a reverse proxy, so it looks like ordinary HTTPS to your
  domain — see [docs/CAMOUFLAGE.md](docs/CAMOUFLAGE.md)

### Encrypted by default; camouflaged on request

In the **default** (`plain`) transport the tunnel is **encrypted, not
disguised**: length-prefixed Noise ciphertext over plain TCP. An observer
cannot read it, but a modern censor can recognise high-entropy traffic as "not
ordinary HTTPS" and block it.

For hostile networks, the **`wss` transport** carries the whole tunnel inside a
real TLS + WebSocket session. Pointed at a reverse proxy (e.g. Caddy) on a real
HTTPS domain, the connection *is* HTTPS to that domain with a real certificate,
and an active probe of the domain gets the real website. This is the
WebTunnel/Trojan model and it reuses audited TLS rather than imitating it.
See **[docs/CAMOUFLAGE.md](docs/CAMOUFLAGE.md)** for the threat model, the
design, the Caddy config, and the honest limits (TLS client fingerprint and
traffic analysis are *not* fully solved).

### Protocol versions and compatibility

The client and server negotiate a protocol version during the Noise handshake.
Flow control and UDP require **both** ends to be v2 (this build). A v2 build still
interoperates with an older v1 build (TCP CONNECT only, no flow control), so you
can upgrade the server and clients independently.

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
```

### Easy Setup (Recommended)

Run the interactive setup script - it guides you through everything:

```bash
./setup.sh
```

The script will:
1. Ask if you're setting up a **server** or **client**
2. Guide you through all configuration options
3. Generate keypairs automatically
4. Create the config file for you

### Manual Setup

<details>
<summary>Click to expand manual setup instructions</summary>

#### Server Setup

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

#### Client Setup

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

</details>

### Connect Links (easiest way to add a client)

On the server, the admin makes a link:

```bash
# One-step: the link carries a key issued for this device (treat it like a password)
phantom-server -c /etc/phantom_tunnel/config.toml link \
    --address vpn.example.com --label "alice-laptop" --new-client-key
```

This prints the link on stdout and, on stderr, the line to add to
`allowed_clients` (then restart the server). On the device:

```bash
phantom-client -c config.toml --import -     # paste the link, press Enter
phantom-client -c config.toml
```

`--import -` reads the link from standard input so a link containing a key
does not end up in your shell history. Without `--new-client-key` the link holds
no secret: importing it generates a key on the device and prints the public key
to send to the admin. Re-importing an updated link needs `--force`; it keeps the
device's key and local proxy ports and saves the old file as `config.toml.bak`.
`phantom-client -c config.toml --share-link` prints a key-less link for the
servers in an existing config.

Link format:

```text
phantom://SERVER_KEY@host:port?backup=[KEY@]host:port&key=CLIENT_KEY#label
```

Keys are base64url (43 characters). `backup` may repeat; `key` and `#label`
are optional.

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

# Optional: servers to try, in order, if `server` fails. A bare "host:port"
# uses server_public_key (the same server at another address, e.g. its IP in
# case DNS is blocked); a different box needs its own key.
backup_servers = [
    "203.0.113.10:443",
    { address = "backup.example.net:443", public_key = "BACKUP_SERVER_PUBLIC_KEY" },
]

[logging]
level = "info"
```

The client stays on whichever server last worked. When it fails (cannot
connect within 10 s, no handshake reply within 10 s, or the server closes the
connection right after the handshake because the client key is not allowed) the
client moves straight to the next server in the list, and only backs off once
every server has failed in a row. Restarting the client starts again from
`server`.

## Building

```bash
cargo build --release              # target/release/phantom-server, phantom-client
cargo build --profile release-small  # smaller binaries
```

Cross-compiling the Windows client from Linux:

```bash
rustup target add x86_64-pc-windows-gnu   # plus the MinGW-w64 gcc package
cargo build --release --bin phantom-client --target x86_64-pc-windows-gnu
```

## Documentation

- [Protocol Specification](docs/PROTOCOL_SPEC.md) - Wire protocol details
- [Deployment Guide](docs/DEPLOYMENT.md) - Production setup, security hardening

## Architecture

```
 app ── SOCKS5 / HTTP CONNECT ──┐                         ┌── destination
                                │                         │
                        phantom-client ══ TCP ══ phantom-server
                                │                         │
     streams + UDP associations, flow control (tunnel::Frame, StreamFlow)
                Noise IK transport encryption (crypto)
                 u16 length-prefixed ciphertext over TCP
```

| Code | Contents |
|---|---|
| `src/bin/client.rs` | Client: local proxies, tunnel event loop, reconnect |
| `src/bin/server.rs` | Server: handshake, allow-list, destination relay, UDP relay |
| `src/crypto/` | Noise IK handshake and transport, X25519 key types |
| `src/tunnel/` | Frame format, flow control, UDP address header |
| `src/config/` | TOML configuration |

## Security

- **Noise Protocol IK** — forward secrecy and mutual authentication
- **ChaCha20-Poly1305** — authenticated encryption of every frame
- **Fail-closed allow-list** — an empty `allowed_clients` admits nobody
- **No destination logging** — visited sites are logged only at `trace` level
- **Not audited** — the cryptography and protocol have not had an independent review

## Testing

```bash
cargo test                                  # unit, integration and end-to-end tests
cargo clippy --all-targets -- -D warnings   # lints (kept clean)
cargo bench --bench tunnel_bench            # frame / Noise / data-path benchmarks

# End-to-end throughput through the real binaries (prints MB/s):
cargo test --release --test e2e_proxy -- --ignored --nocapture throughput
```

The end-to-end tests in `tests/e2e_proxy.rs` start the real `phantom-server`
and `phantom-client` binaries and drive SOCKS5, HTTP CONNECT and UDP traffic
through them.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
