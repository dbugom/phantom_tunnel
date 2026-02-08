# Phantom Tunnel - Claude Code Context

## Project Overview
Secure, censorship-resistant tunnel using Noise Protocol (IK pattern) encryption with stream multiplexing and flow control. Client runs local SOCKS5/HTTP proxy, multiplexes connections through encrypted tunnel to server.

## Build & Test
```bash
cargo test --all-features          # Run all tests (unit + integration)
cargo build --release              # Release build
cargo check                        # Quick compilation check
RUST_LOG=debug cargo run --bin phantom-client  # Run with debug logging
```

## Architecture
- `src/bin/client.rs` — Client binary: SOCKS5/HTTP proxy → tunnel → server
- `src/bin/server.rs` — Server binary: accepts clients, relays to destinations
- `src/tunnel/mod.rs` — Tunnel constants (DEFAULT_WINDOW_SIZE, MAX_STREAMS)
- `src/tunnel/frame.rs` — Frame encoding/decoding (6-byte header + payload)
- `src/tunnel/multiplexer.rs` — Stream multiplexer with flow control
- `src/tunnel/stream.rs` — Individual stream state (windows, buffers, lifecycle)
- `src/crypto/` — Noise handshake, AEAD encryption, key derivation
- `src/obfuscation/` — Timing, padding, TLS fingerprinting
- `src/transport/` — TCP, TLS, DNS transport layers
- `src/proxy/` — SOCKS5 and HTTP proxy implementations

## Key Patterns
- **Generic transport I/O**: `perform_handshake_split()` and `send_frame_write_buffered()` are generic over `AsyncRead + Unpin` / `AsyncWrite + Unpin`, allowing them to work with both raw TCP and TLS-wrapped streams
- **TLS wrapping (optional)**: Client wraps TCP in TLS when `tls_sni` is configured; server accepts TLS when `tls_cert`/`tls_key` are configured. Both fall back to raw TCP when unconfigured (backward compat)
- **Split I/O**: Streams split via `into_split()` (TCP) or `tokio::io::split()` (TLS) for concurrent read/write
- **Reader task**: Dedicated spawned task reads frames, sends via mpsc channel to main select! loop
- **Drain-before-close**: Streams enter "draining" state before removal (STREAM_DRAIN_TIMEOUT)
- **Reusable encrypt buffer**: `encrypt_buf` allocated once, reused for all frame encryptions
- **Frame wire format**: 2-byte BE length prefix + encrypted payload (coalesced into single write)
- **Flow control**: Per-stream send/recv windows, window updates sent when recv_window < threshold

## TLS Wrapping (feature/tls-wrapping branch)
Wraps the entire tunnel in a real TLS layer so traffic looks like normal HTTPS to DPI firewalls.
- **Stack**: `TCP → TLS → Noise Protocol → Multiplexed Frames`
- **Client**: When `tls_sni` is set in config, builds a `rustls::ClientConfig` with browser fingerprint mimicry and connects via `TlsConnector`
- **Server**: When `tls_cert` + `tls_key` are set in config, loads PEM cert/key via `rustls-pemfile`, builds `rustls::ServerConfig`, accepts via `TlsAcceptor`
- **Backward compat**: Both sides fall back to raw TCP when TLS config is absent
- **Cert setup**: Use Let's Encrypt (`certbot certonly --standalone -d your.domain`) for valid certs

## Performance Fixes Applied (perf/throughput-optimizations branch)
1. **TCP_NODELAY** on all TCP connections (client tunnel, server tunnel, server→destination)
2. **Coalesced frame writes**: Length prefix + ciphertext sent as single write_all() call
3. **Window size 256KB → 4MB**: DEFAULT_WINDOW_SIZE increased for high-RTT throughput
4. **recv_buffer memory leak fixed**: multiplexer.handle_data() no longer clones data into never-read buffer; tracks recv_window directly
5. **Relay buffers 32KB → 64KB**: Larger read buffers for SOCKS5/HTTP relay and server destination relay
6. **Fixed missing draining_since field** on client ActiveStream struct

## Known Issues / Gotchas
- CLAUDE.md is in .gitignore (not tracked in repo)
- Default log level is already "info" (set via CLI --log-level arg, override with RUST_LOG env)
- Timing obfuscation (obfuscation/timing.rs) adds per-packet delays when enabled — can severely impact throughput
- Client's reconnection loop breaks after first failure (TODO: proper channel recreation)
- Stream IDs: odd = client-initiated, even = server-initiated
- Pre-existing compiler warnings (unused imports, dead code) — not from our changes

## Git Branching
- `main` — stable
- `perf/*` — performance improvements
- `fix/*` — bug fixes
- `feature/*` — new features
- `docs/*` — documentation updates
