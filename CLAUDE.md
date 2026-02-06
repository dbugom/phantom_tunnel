# Phantom Tunnel - Project Context for Claude

This file preserves project context for future Claude sessions.

## Project Summary

**Phantom Tunnel** is a secure, censorship-resistant tunneling protocol implemented in Rust. It was designed for use in highly censored environments where privacy is critical.

## What Was Built

### Core Components (All Complete)

1. **Crypto Module** (`src/crypto/`)
   - `aead.rs` - ChaCha20-Poly1305 encryption
   - `kdf.rs` - HKDF-SHA256 key derivation
   - `keys.rs` - X25519 key management (KeyPair, PublicKey, PrivateKey)
   - `handshake.rs` - Noise Protocol IK pattern handshake

2. **Transport Layer** (`src/transport/`)
   - `tcp.rs` - Raw TCP transport
   - `tls.rs` - TLS 1.3 with browser fingerprint mimicry
   - `dns.rs` - DNS tunneling for heavily censored networks
   - `connection.rs` - Connection manager

3. **Tunnel Layer** (`src/tunnel/`)
   - `frame.rs` - Frame encoding/decoding (7 frame types)
   - `stream.rs` - Stream state management with flow control
   - `multiplexer.rs` - YAMUX-style stream multiplexing

4. **Proxy Layer** (`src/proxy/`)
   - `socks5.rs` - SOCKS5 proxy (RFC 1928)
   - `http.rs` - HTTP CONNECT proxy

5. **Obfuscation Layer** (`src/obfuscation/`)
   - `fingerprint.rs` - TLS fingerprint mimicry (Chrome, Firefox, Safari, Edge, iOS, Android)
   - `padding.rs` - Traffic padding strategies
   - `timing.rs` - Timing jitter and dummy packets

6. **Binaries** (`src/bin/`)
   - `server.rs` - Full server with keypair generation, Noise handshake, client auth, multiplexing
   - `client.rs` - Full client with local SOCKS5/HTTP proxy, reconnection logic

### Documentation (All Complete)

- `docs/PROTOCOL_SPEC.md` - Complete wire protocol specification
- `docs/DEPLOYMENT.md` - Server/client deployment guide
- `examples/server.config.toml` - Server configuration example
- `examples/client.config.toml` - Client configuration example
- `TODO.md` - Project progress tracker (in parent directory)

### Tests (54 Total - All Passing)

- Unit tests in each module (43 tests)
- Integration tests in `tests/integration_test.rs` (11 tests)

## Key Technical Decisions

1. **Noise Protocol IK** - Client knows server's public key ahead of time, prevents active probing
2. **snow crate** - Best Rust implementation of Noise Protocol
3. **rustls** - Pure Rust TLS, no OpenSSL (auditable, no backdoor risk)
4. **ring** - Audited crypto primitives, constant-time operations
5. **ChaCha20-Poly1305** - Fast AEAD, safe on all platforms
6. **TLS fingerprint mimicry** - Traffic looks like real browser connections
7. **DNS tunneling** - Fallback when TLS is blocked

## Project Structure

```
phantom_tunnel/
├── Cargo.toml
├── CLAUDE.md              # This file
├── src/
│   ├── lib.rs             # Library exports, VERSION constant
│   ├── bin/
│   │   ├── server.rs      # ~350 lines
│   │   └── client.rs      # ~600 lines
│   ├── config/mod.rs      # Config structs, TOML parsing
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── aead.rs
│   │   ├── kdf.rs
│   │   ├── keys.rs
│   │   └── handshake.rs
│   ├── transport/
│   │   ├── mod.rs         # Transport trait
│   │   ├── tcp.rs
│   │   ├── tls.rs
│   │   ├── dns.rs
│   │   └── connection.rs
│   ├── tunnel/
│   │   ├── mod.rs
│   │   ├── frame.rs
│   │   ├── stream.rs
│   │   └── multiplexer.rs
│   ├── proxy/
│   │   ├── mod.rs
│   │   ├── socks5.rs
│   │   └── http.rs
│   └── obfuscation/
│       ├── mod.rs
│       ├── fingerprint.rs
│       ├── padding.rs
│       └── timing.rs
├── docs/
│   ├── PROTOCOL_SPEC.md
│   └── DEPLOYMENT.md
├── tests/
│   └── integration_test.rs
└── examples/
    ├── server.config.toml
    └── client.config.toml
```

## Build & Test Commands

```bash
cd /home/kitchen/claude_code/protocol/phantom_tunnel

# Build
~/.cargo/bin/cargo build --release

# Build with all features (including DNS tunneling)
~/.cargo/bin/cargo build --release --all-features

# Run tests
~/.cargo/bin/cargo test --all-features

# Generate keypair
~/.cargo/bin/cargo run --bin phantom-server -- --generate-key

# Run server
~/.cargo/bin/cargo run --bin phantom-server -- -c examples/server.config.toml

# Run client
~/.cargo/bin/cargo run --bin phantom-client -- -c examples/client.config.toml
```

## Current Status

**PROJECT COMPLETE** - All 13 tasks finished:

1. Wire protocol specification
2. Crypto module
3. Transport layer
4. TLS fingerprint mimicry
5. Tunnel layer
6. SOCKS5 proxy
7. HTTP CONNECT proxy
8. Server binary
9. Client binary
10. DNS tunneling transport
11. Traffic padding/timing obfuscation
12. Integration tests
13. Deployment documentation

## Potential Future Enhancements

If the user wants to continue development:

1. **QUIC transport** - Add quinn-based QUIC transport (feature flag exists but not implemented)
2. **UDP ASSOCIATE** - SOCKS5 UDP relay support
3. **WebSocket transport** - For environments that only allow HTTP
4. **Plugin system** - Pluggable obfuscation strategies
5. **GUI client** - Desktop application with system tray
6. **Mobile clients** - iOS/Android apps
7. **Performance benchmarks** - Criterion benchmarks (scaffolded in Cargo.toml)
8. **Decoy website serving** - Server can serve static content to non-tunnel requests

## Known Issues / Warnings

- Some unused imports generate warnings (cosmetic, doesn't affect functionality)

## Recent Fixes (Latest Session - Feb 2026)

### Critical Fix: Tunnel Data Routing

The SOCKS5 and HTTP proxies were making **direct connections** to destinations instead of routing through the encrypted tunnel. This has been fixed:

1. **Client Architecture Refactored** (`src/bin/client.rs`):
   - Created `TunnelHandle` with channel-based communication to tunnel task
   - Proxy handlers now send `TunnelCommand::OpenStream` to open multiplexed streams
   - Data is sent via `TunnelCommand::SendData` through the encrypted tunnel
   - Bidirectional relay between local TCP connections and tunnel streams

2. **Server Architecture Refactored** (`src/bin/server.rs`):
   - Added `StreamToTunnel` enum for stream tasks to send data back
   - Server now spawns `handle_stream` tasks that connect to actual destinations
   - Bidirectional relay between tunnel streams and target connections

3. **Multiplexer Enhancement** (`src/tunnel/multiplexer.rs`):
   - `StreamHandle` now includes `destination` field
   - Added `destination()` method to get stream destination
   - `parse_destination` now supports both SOCKS5 binary format AND plain string format

### Previous Fixes

1. **Server/Client keypair loading** - Both now properly load keypairs from config
2. **Auto-generation on first run** - If no keys in config, generates and saves them
3. **Public key storage** - Both server and client configs now store public_key alongside private_key

## Data Flow (How Traffic Routes Through Tunnel)

```
Browser → SOCKS5 Proxy → Client Tunnel Task → [Encrypted] → Server → Destination
                ↓                    ↓                           ↓
         Parse SOCKS5         Encrypt Frame              Connect & Relay
         Open Stream          Send over TCP              Forward Data
```

1. Browser connects to local SOCKS5 proxy (127.0.0.1:1080)
2. Client parses destination, sends `TunnelCommand::OpenStream`
3. Tunnel task creates multiplexed stream, sends `STREAM_OPEN` frame (encrypted)
4. Server receives frame, spawns task to connect to actual destination
5. Data flows bidirectionally: Browser ↔ Client ↔ Server ↔ Destination

## Related Files

- `/home/kitchen/claude_code/protocol/PROTOCOL_RESEARCH.md` - Initial research document
- `/home/kitchen/claude_code/protocol/TODO.md` - Overall project progress tracker

## Last Updated

2024 - All tasks complete, 54 tests passing
