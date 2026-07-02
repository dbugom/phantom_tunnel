# Phantom Tunnel - Claude Code Context

## Project Goal
Bypass a WatchGuard firewall on the local network by tunneling all traffic through an encrypted, TLS-wrapped connection that looks like normal HTTPS to DPI inspection. The tunnel runs a local SOCKS5/HTTP proxy on the client, multiplexes connections through a Noise Protocol (IK pattern) encrypted channel wrapped in TLS to a remote server, which relays to the actual destinations.

## Project Overview
Secure, censorship-resistant tunnel using Noise Protocol (IK pattern) encryption with stream multiplexing and flow control. Client runs local SOCKS5/HTTP proxy, multiplexes connections through encrypted tunnel to server.

## Protocol Stack
```
TCP → TLS 1.3 (Chrome JA4 fingerprint) → HTTP/2 CONNECT → Noise IK (AES-256-GCM) → Multiplexed Frames
```

## Deployment (WORKING as of Feb 2026)
- **Server**: VPS at `46.225.106.10`, domain `phantom.yfy.ae`, Let's Encrypt TLS certs
- **Client (macOS)**: Connects to `46.225.106.10:443` with `tls_sni = "phantom.yfy.ae"`
- **Client (MikroTik RB5009)**: ARM64 container on RouterOS, connects to `46.225.106.10:443`
- **Stack**: `TCP → TLS (Chrome JA4 fingerprint) → HTTP/2 CONNECT → Noise IK → Multiplexed Frames`

### Key deployment notes
- Client `server` field uses IP directly (`46.225.106.10:443`) because WatchGuard DNS at `10.99.99.254` doesn't resolve through macOS system resolver (nslookup works but ping/nc/apps don't)
- `tls_sni` uses the domain (`phantom.yfy.ae`) — this goes in the TLS ClientHello for DPI camouflage
- Server TLS certs at `/etc/letsencrypt/live/phantom.yfy.ae/` (expires May 9 2026, renew with certbot)

## Build & Test
```bash
export PATH="$HOME/.cargo/bin:$PATH"   # Needed on dev machine (Kali)
cargo test --all-features              # Run all tests (unit + integration)
cargo build --release                  # Release build
cargo check                            # Quick compilation check
RUST_LOG=debug cargo run --bin phantom-client  # Run with debug logging
```

## Architecture
- `src/bin/client.rs` — Client binary: SOCKS5/HTTP proxy → tunnel → server
- `src/bin/server.rs` — Server binary: accepts clients, relays to destinations
- `src/tunnel/mod.rs` — Tunnel constants, BdpEstimator for dynamic flow control
- `src/tunnel/frame.rs` — Frame encoding/decoding (6-byte header + payload)
- `src/tunnel/multiplexer.rs` — Stream multiplexer with flow control
- `src/tunnel/stream.rs` — Individual stream state (windows, buffers, lifecycle)
- `src/crypto/` — Noise handshake, AEAD encryption, key derivation
- `src/crypto/session_cache.rs` — Session resumption tokens for 0-RTT reconnection
- `src/obfuscation/` — Timing, padding, TLS fingerprinting
- `src/transport/` — TCP, TLS, DNS, QUIC transport layers
- `src/transport/h2_camouflage.rs` — HTTP/2 CONNECT camouflage layer (DPI evasion)
- `src/transport/probe_resistance.rs` — Active probing resistance (decoy website fallback)
- `src/transport/quic.rs` — Optional QUIC transport (feature-gated)
- `src/transport/tcp_tuning.rs` — BBR congestion control + TCP buffer tuning
- `src/proxy/` — SOCKS5 and HTTP proxy implementations
- `deploy/Caddyfile` — Production Caddy reverse proxy config for active probing resistance

## Config Options
### Client (`ClientConfig`)
- `server` — Server address (IP:port)
- `tls_sni` — TLS SNI for DPI camouflage (enables TLS wrapping)
- `h2_camouflage` — Enable HTTP/2 CONNECT camouflage (default: true)
- `cipher` — Noise cipher: `"AES-256-GCM"` (default, hardware-accelerated) or `"ChaChaPoly"` (fast on ARM without AES-NI)

### Server (`ServerConfig`)
- `tls_cert` / `tls_key` — TLS certificate/key paths (enables TLS)
- `h2_camouflage` — Enable HTTP/2 CONNECT acceptance (default: true)
- `decoy_backend` — Decoy website URL for failed auth (e.g., `"127.0.0.1:8080"`)

## Key Patterns
- **Generic transport I/O**: `perform_handshake_split()` and `send_frame_write_buffered()` are generic over `AsyncRead + Unpin` / `AsyncWrite + Unpin`, allowing them to work with raw TCP, TLS, or H2 camouflage streams
- **HTTP/2 CONNECT camouflage**: After TLS, tunnel data flows as HTTP/2 DATA frames inside a CONNECT request — looks like a browser proxy session to DPI
- **Channel-based H2 adapters**: `ChannelReader`/`ChannelWriter` bridge h2 crate's stream API to AsyncRead/AsyncWrite traits via mpsc channels
- **TLS wrapping (optional)**: Client wraps TCP in TLS when `tls_sni` is configured; server accepts TLS when `tls_cert`/`tls_key` are configured. Both fall back to raw TCP when unconfigured
- **Split I/O**: Streams split via `into_split()` (TCP) or `tokio::io::split()` (TLS) for concurrent read/write
- **Reader task**: Dedicated spawned task reads frames, sends via mpsc channel to main select! loop
- **Drain-before-close**: Streams enter "draining" state before removal (STREAM_DRAIN_TIMEOUT)
- **Reusable encrypt buffer**: `encrypt_buf` allocated once, reused for all frame encryptions
- **Frame wire format**: 2-byte BE length prefix + encrypted payload (coalesced into single write)
- **Flow control**: Per-stream send/recv windows with BDP-aware auto-tuning, window updates at 50% consumption threshold
- **BBR congestion control**: Per-socket BBR via `setsockopt(TCP_CONGESTION)` for resilience under packet loss
- **Session resumption**: HKDF-derived tokens from handshake hash, 120s TTL, one-time use for replay resistance
- **Active probing resistance**: Failed auth proxied to decoy website via bidirectional copy

## Performance Tuning Constants
- `DEFAULT_WINDOW_SIZE` = 4MB — Per-stream flow control window
- `MAX_WINDOW_SIZE` = 16MB — BDP auto-tune ceiling
- `INITIAL_WINDOW_SIZE` = 1MB — Starting window for BDP auto-tuning
- `RELAY_BUFFER_SIZE` = 128KB — Relay read buffer size
- `TLS_BUFWRITER_CAPACITY` = 64KB — TLS write coalescing buffer
- `KEEPALIVE_INTERVAL` = 20s — Application-level Ping/Pong interval
- `MAX_MISSED_PONGS` = 2 — Missed pongs before declaring tunnel dead

## Feature Flags
- `tls` — TLS transport (enabled by default)
- `h2-camouflage` — HTTP/2 CONNECT camouflage layer (`dep:h2`, `dep:http`)
- `quic` — Optional QUIC transport via quinn (`dep:quinn`)
- `dns-tunnel` — DNS tunneling fallback transport

## MikroTik Container (WORKING as of Feb 2026)
Phantom client runs as a container on MikroTik RouterOS 7.4+ devices (RB5009 tested, ARM64).

### Container files
- `Dockerfile.mikrotik` — Multi-stage build: cross-compile with musl.cc, produce `scratch` image (~5-7MB)
- `mikrotik/entrypoint.sh` — Generates config.toml from env vars or uses bind-mounted config
- `mikrotik/build.sh` — Docker buildx wrapper, outputs `.tar` per architecture

### Building
```bash
sudo ./mikrotik/build.sh arm64          # Build ARM64 image (RB5009)
sudo docker save phantom-client:arm64 -o mikrotik/output/phantom-client-arm64.tar
```

## Known Issues / Gotchas
- CLAUDE.md is in .gitignore (not tracked in repo)
- Default log level is already "info" (set via CLI --log-level arg, override with RUST_LOG env)
- Timing obfuscation (obfuscation/timing.rs) adds per-packet delays when enabled — can severely impact throughput
- Stream IDs: odd = client-initiated, even = server-initiated
- Pre-existing compiler warnings (unused imports, dead code) — not from our changes
- WatchGuard DNS (10.99.99.254) resolves domains via nslookup but NOT through macOS system resolver — always use IP in client `server` field
- BDP estimator infrastructure is implemented but not yet wired into the main select! loops (requires integration in client.rs/server.rs relay logic)
- Session resumption cache is implemented but the resume/full-handshake protocol exchange is not yet wired into the client/server handshake flow

## Git Branching
- `main` — stable
- `fix/zombie-stream-bandwidth-waste` — production branch (all core fixes + TLS)
- `feature/v2-stealth-performance` — v2 stealth & performance overhaul (phases 1-11)
- `fix/client-relay-task-leak` — client relay task leak fix for MikroTik OOM
- `feature/mikrotik-container` — MikroTik container support (ARM64/ARMv7/AMD64)
- `perf/*` — performance improvements
- `fix/*` — bug fixes
- `feature/*` — new features

## GitHub
- Repo: https://github.com/dbugom/phantom_tunnel
- Push requires PAT (HTTPS) — SSH key not configured on GitHub
