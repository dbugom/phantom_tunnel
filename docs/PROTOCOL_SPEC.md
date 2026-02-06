# Phantom Tunnel Protocol Specification

**Version:** 1.0.0-draft
**Date:** February 2026
**Status:** Draft

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Goals](#2-design-goals)
3. [Protocol Layers](#3-protocol-layers)
4. [Transport Layer](#4-transport-layer)
5. [Handshake Protocol](#5-handshake-protocol)
6. [Frame Format](#6-frame-format)
7. [Stream Multiplexing](#7-stream-multiplexing)
8. [Flow Control](#8-flow-control)
9. [Padding and Traffic Shaping](#9-padding-and-traffic-shaping)
10. [Error Handling](#10-error-handling)
11. [Security Considerations](#11-security-considerations)
12. [Wire Format Summary](#12-wire-format-summary)

---

## 1. Overview

Phantom Tunnel is a secure, censorship-resistant tunneling protocol designed for:

- Encrypted communication in hostile network environments
- Traffic obfuscation to evade deep packet inspection (DPI)
- Resistance to active probing attacks
- Low overhead multiplexed connections

The protocol operates over TLS 1.3 with browser fingerprint mimicry, using the Noise Protocol Framework for authenticated key exchange.

---

## 2. Design Goals

### 2.1 Security Goals

| Goal | Implementation |
|------|----------------|
| Confidentiality | ChaCha20-Poly1305 AEAD encryption |
| Integrity | Poly1305 MAC on all frames |
| Authentication | Noise IK pattern (mutual auth) |
| Forward Secrecy | Ephemeral X25519 keys per session |
| Replay Protection | Nonce-based, monotonic counters |

### 2.2 Anti-Censorship Goals

| Goal | Implementation |
|------|----------------|
| DPI Evasion | TLS 1.3 with browser fingerprint mimicry |
| Active Probe Resistance | Server requires client to know server's public key |
| Traffic Analysis Resistance | Padding, timing jitter, dummy packets |
| Protocol Fingerprint | Indistinguishable from HTTPS traffic |

### 2.3 Performance Goals

| Goal | Target |
|------|--------|
| Handshake Latency | 1-RTT (after TLS) |
| Header Overhead | 7 bytes per frame |
| Max Concurrent Streams | 1024 per connection |
| Max Frame Size | 65535 bytes |

---

## 3. Protocol Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Data                          │
│              (SOCKS5, HTTP CONNECT, Raw TCP/UDP)            │
├─────────────────────────────────────────────────────────────┤
│                    Stream Layer                              │
│         (Multiplexing, Flow Control, Stream Management)      │
├─────────────────────────────────────────────────────────────┤
│                    Frame Layer                               │
│              (Framing, Padding, Encryption)                  │
├─────────────────────────────────────────────────────────────┤
│                    Noise Transport                           │
│         (ChaCha20-Poly1305, Authenticated Encryption)        │
├─────────────────────────────────────────────────────────────┤
│                    Handshake Layer                           │
│              (Noise IK, Key Exchange, Auth)                  │
├─────────────────────────────────────────────────────────────┤
│                    Obfuscation Layer                         │
│         (TLS 1.3, Browser Fingerprint, SNI Camouflage)       │
├─────────────────────────────────────────────────────────────┤
│                    Transport Layer                           │
│                      (TCP / QUIC)                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Transport Layer

### 4.1 Primary Transport: TLS 1.3 over TCP

The primary transport wraps all Phantom Tunnel traffic in TLS 1.3:

```
Client                                           Server
   │                                                │
   │──────────── TCP SYN ──────────────────────────>│
   │<─────────── TCP SYN-ACK ──────────────────────│
   │──────────── TCP ACK ──────────────────────────>│
   │                                                │
   │══════════ TLS 1.3 Handshake ══════════════════│
   │──────────── ClientHello (mimicked) ──────────>│
   │<─────────── ServerHello + Finished ──────────│
   │──────────── Finished ────────────────────────>│
   │                                                │
   │══════════ Phantom Handshake (in TLS) ═════════│
   │──────────── Noise IK Message 1 ──────────────>│
   │<─────────── Noise IK Message 2 ──────────────│
   │                                                │
   │══════════ Encrypted Tunnel Traffic ═══════════│
```

### 4.2 TLS Fingerprint Requirements

The TLS ClientHello MUST mimic a real browser:

**Chrome Profile (Default):**
```
Cipher Suites (in order):
  - TLS_AES_128_GCM_SHA256 (0x1301)
  - TLS_AES_256_GCM_SHA384 (0x1302)
  - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
  - ... (see implementation for full list)

Extensions (randomized order):
  - server_name (SNI)
  - supported_versions
  - key_share
  - supported_groups
  - signature_algorithms
  - application_layer_protocol_negotiation
  - ... (see implementation for full list)

Supported Groups:
  - x25519 (0x001d)
  - secp256r1 (0x0017)
  - secp384r1 (0x0018)
```

### 4.3 SNI Selection

The SNI SHOULD be set to a legitimate, high-traffic website:
- Same or similar hosting infrastructure as the server
- Not blocked in the target region
- Examples: `www.microsoft.com`, `www.apple.com`, `cloudflare.com`

### 4.4 Fallback Transports

When TLS is blocked or detected:

1. **QUIC (HTTP/3)** - Disguised as legitimate QUIC traffic
2. **DNS Tunneling** - Encodes data in DNS queries (low bandwidth fallback)
3. **WebSocket** - Over HTTPS, appears as web application traffic

---

## 5. Handshake Protocol

### 5.1 Noise Protocol Pattern: IK

The handshake uses Noise_IK_25519_ChaChaPoly_SHA256:

```
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

**Pattern Explanation:**
- `<- s`: Client knows server's static public key (pre-shared)
- `-> e, es, s, ss`: Client sends ephemeral key, performs DH operations
- `<- e, ee, se`: Server responds, completes key exchange

### 5.2 Why IK Pattern?

| Property | Benefit |
|----------|---------|
| Client knows server key | Server can reject unknown clients (anti-probing) |
| Mutual authentication | Both parties verified |
| Forward secrecy | Ephemeral keys protect past sessions |
| 1-RTT | Minimal latency after TLS |

### 5.3 Handshake Message Format

**Message 1 (Client → Server):**
```
+----------------+----------------+----------------+
|  Ephemeral Key (32 bytes)                        |
+----------------+----------------+----------------+
|  Encrypted Static Key + Tag (48 bytes)           |
+----------------+----------------+----------------+
|  Encrypted Payload + Tag (variable)              |
+----------------+----------------+----------------+
```

**Message 2 (Server → Client):**
```
+----------------+----------------+----------------+
|  Ephemeral Key (32 bytes)                        |
+----------------+----------------+----------------+
|  Encrypted Payload + Tag (variable)              |
+----------------+----------------+----------------+
```

### 5.4 Handshake Payload

The handshake payload contains protocol negotiation:

```
+--------+--------+--------+--------+
|  Version (1B)   |  Flags (1B)     |
+--------+--------+--------+--------+
|  Timestamp (8 bytes)              |
+--------+--------+--------+--------+
|  Random (16 bytes)                |
+--------+--------+--------+--------+
```

**Version:** Protocol version (currently 0x01)

**Flags:**
```
Bit 0: Padding enabled
Bit 1: Compression enabled (reserved)
Bit 2-7: Reserved
```

### 5.5 Active Probe Resistance

The server MUST NOT reveal protocol identity to probes:

1. **Unknown Client**: If client's static key is not in allowed list:
   - Complete TLS handshake normally
   - Serve decoy website content (if configured)
   - OR close connection after timeout

2. **Invalid Handshake**: If Noise handshake fails:
   - Do NOT send error messages
   - Serve decoy content or close silently

3. **Replay Detection**: Reject replayed handshake messages

---

## 6. Frame Format

After handshake completion, all data is sent in encrypted frames.

### 6.1 Plaintext Frame Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |                Stream ID                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Payload Length         |  Padding Len  |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                                                               |
+                           Payload                             +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Padding                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Fields:**

| Field | Size | Description |
|-------|------|-------------|
| Type | 1 byte | Frame type (see 6.2) |
| Stream ID | 3 bytes | Stream identifier (big-endian) |
| Payload Length | 2 bytes | Payload size in bytes (big-endian) |
| Padding Length | 1 byte | Padding size in bytes |
| Payload | variable | Frame payload |
| Padding | variable | Random padding bytes |

**Total Header Size:** 7 bytes

### 6.2 Frame Types

| Type | Value | Description |
|------|-------|-------------|
| DATA | 0x00 | Stream data |
| STREAM_OPEN | 0x01 | Open new stream |
| STREAM_CLOSE | 0x02 | Close stream |
| WINDOW_UPDATE | 0x03 | Flow control update |
| PING | 0x04 | Keepalive request |
| PONG | 0x05 | Keepalive response |
| GOAWAY | 0x06 | Connection shutdown |
| PADDING | 0x07 | Padding only (no data) |

### 6.3 Wire Format (Encrypted)

Frames are encrypted with ChaCha20-Poly1305 before transmission:

```
+----------------+----------------+----------------+
|  Length Prefix (2 bytes, encrypted)             |
+----------------+----------------+----------------+
|  Encrypted Frame + Auth Tag (16 bytes)          |
+----------------+----------------+----------------+
```

The length prefix is encrypted separately to prevent length-based fingerprinting.

### 6.4 Frame Type Details

#### DATA (0x00)
```
Payload: Raw application data
Stream ID: Target stream
```

#### STREAM_OPEN (0x01)
```
Payload Format:
+--------+--------+--------+--------+
|  Address Type   |  Address Data   |
+--------+--------+--------+--------+
|  Port (2 bytes) |                 |
+-----------------+-----------------+

Address Types:
  0x01 = IPv4 (4 bytes)
  0x03 = Domain (1 byte length + domain)
  0x04 = IPv6 (16 bytes)
```

#### STREAM_CLOSE (0x02)
```
Payload: Empty or error code (optional)
```

#### WINDOW_UPDATE (0x03)
```
Payload: Window increment (4 bytes, big-endian)
```

#### PING (0x04) / PONG (0x05)
```
Payload: 8 bytes opaque data (echoed in PONG)
```

#### GOAWAY (0x06)
```
Payload:
+--------+--------+--------+--------+
|  Last Stream ID (4 bytes)         |
+--------+--------+--------+--------+
|  Error Code (4 bytes)             |
+--------+--------+--------+--------+
```

---

## 7. Stream Multiplexing

### 7.1 Stream Identifiers

- Stream IDs are 24-bit unsigned integers (0 to 16,777,215)
- Stream ID 0 is reserved for connection-level frames
- Client-initiated streams use odd IDs (1, 3, 5, ...)
- Server-initiated streams use even IDs (2, 4, 6, ...)

### 7.2 Stream Lifecycle

```
     STREAM_OPEN
          │
          ▼
    ┌─────────┐
    │  OPEN   │◄────────────────┐
    └────┬────┘                 │
         │                      │
    DATA │                      │ DATA
         │                      │
         ▼                      │
    ┌─────────┐            ┌────┴────┐
    │HALF_CLOSED│          │HALF_CLOSED│
    │  (local)  │          │ (remote) │
    └────┬────┘            └────┬────┘
         │                      │
         │    STREAM_CLOSE      │
         └──────────┬───────────┘
                    ▼
              ┌─────────┐
              │ CLOSED  │
              └─────────┘
```

### 7.3 Stream Limits

| Parameter | Default | Description |
|-----------|---------|-------------|
| MAX_CONCURRENT_STREAMS | 1024 | Max open streams per connection |
| MAX_STREAM_ID | 16777215 | Maximum stream ID value |
| STREAM_IDLE_TIMEOUT | 300s | Close idle streams after |

---

## 8. Flow Control

### 8.1 Window-Based Flow Control

Each stream has independent send and receive windows:

| Parameter | Default | Description |
|-----------|---------|-------------|
| INITIAL_WINDOW_SIZE | 262144 (256 KB) | Initial flow control window |
| MAX_WINDOW_SIZE | 16777215 (16 MB) | Maximum window size |

### 8.2 Window Update Rules

1. Receiver sends WINDOW_UPDATE when window falls below 50%
2. Sender MUST NOT send data exceeding available window
3. Window updates are per-stream

### 8.3 Connection-Level Flow Control

Stream ID 0 WINDOW_UPDATE frames control the entire connection.

---

## 9. Padding and Traffic Shaping

### 9.1 Padding Strategies

| Strategy | Description |
|----------|-------------|
| NONE | No padding |
| BLOCK | Pad to fixed block size (e.g., 64 bytes) |
| RANDOM | Random padding 0-255 bytes |
| POWER_OF_TWO | Pad to next power of 2 |

### 9.2 Padding Rules

1. Padding bytes MUST be cryptographically random
2. Maximum padding per frame: 255 bytes
3. Minimum frame size (after padding): 64 bytes (configurable)

### 9.3 Dummy Traffic

To defeat traffic analysis:

1. Send PADDING frames during idle periods
2. Randomize inter-packet timing (jitter)
3. Maintain minimum traffic rate when idle

### 9.4 Timing Obfuscation

| Parameter | Default | Description |
|-----------|---------|-------------|
| MIN_PACKET_INTERVAL | 1ms | Minimum time between packets |
| MAX_JITTER | 50ms | Maximum random delay |
| IDLE_PADDING_INTERVAL | 5s | Send dummy packet if idle |

---

## 10. Error Handling

### 10.1 Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x00 | NO_ERROR | Graceful shutdown |
| 0x01 | PROTOCOL_ERROR | Protocol violation |
| 0x02 | INTERNAL_ERROR | Implementation error |
| 0x03 | FLOW_CONTROL_ERROR | Flow control violation |
| 0x04 | STREAM_CLOSED | Operation on closed stream |
| 0x05 | FRAME_SIZE_ERROR | Invalid frame size |
| 0x06 | REFUSED_STREAM | Stream refused |
| 0x07 | CANCEL | Stream cancelled |
| 0x08 | CONNECT_ERROR | Connection to target failed |
| 0x09 | ENHANCE_YOUR_CALM | Rate limiting |

### 10.2 Error Handling Behavior

**Connection Errors:**
- Send GOAWAY with error code
- Close connection after timeout

**Stream Errors:**
- Send STREAM_CLOSE with error code
- Do NOT affect other streams

---

## 11. Security Considerations

### 11.1 Key Management

| Requirement | Implementation |
|-------------|----------------|
| Key Generation | Use CSPRNG (ring::rand) |
| Key Storage | Encrypted at rest, zeroize on drop |
| Key Rotation | Rekey after 2^32 messages or 24 hours |

### 11.2 Replay Protection

1. Track received nonces per session
2. Reject duplicate nonces
3. Handshake includes timestamp (±5 minute window)

### 11.3 Denial of Service

| Attack | Mitigation |
|--------|------------|
| Connection flood | Rate limiting, proof-of-work (optional) |
| Stream flood | MAX_CONCURRENT_STREAMS limit |
| Memory exhaustion | Bounded buffers, window limits |

### 11.4 Side Channels

| Channel | Mitigation |
|---------|------------|
| Timing | Constant-time crypto (ring), padding |
| Traffic analysis | Padding, dummy traffic, jitter |
| Length | Encrypted length prefix, block padding |

---

## 12. Wire Format Summary

### 12.1 Complete Connection Example

```
┌─────────────────────────────────────────────────────────────┐
│                        TCP + TLS 1.3                         │
├─────────────────────────────────────────────────────────────┤
│  [TLS Record]                                                │
│    [Noise IK Message 1: 80+ bytes]                          │
├─────────────────────────────────────────────────────────────┤
│  [TLS Record]                                                │
│    [Noise IK Message 2: 48+ bytes]                          │
├─────────────────────────────────────────────────────────────┤
│  [TLS Record]                                                │
│    [Encrypted Length: 2 bytes]                              │
│    [Encrypted Frame + Tag: N + 16 bytes]                    │
│      - Type: STREAM_OPEN (0x01)                             │
│      - Stream ID: 1                                          │
│      - Payload: example.com:443                              │
├─────────────────────────────────────────────────────────────┤
│  [TLS Record]                                                │
│    [Encrypted Length: 2 bytes]                              │
│    [Encrypted Frame + Tag: N + 16 bytes]                    │
│      - Type: DATA (0x00)                                     │
│      - Stream ID: 1                                          │
│      - Payload: HTTP request...                              │
└─────────────────────────────────────────────────────────────┘
```

### 12.2 Byte-Level Frame Example

**Plaintext STREAM_OPEN Frame:**
```
Offset  Bytes           Description
------  -----           -----------
0       01              Type: STREAM_OPEN
1-3     00 00 01        Stream ID: 1
4-5     00 10           Payload Length: 16
6       08              Padding Length: 8
7       03              Address Type: Domain
8       0B              Domain Length: 11
9-19    example.com     Domain
20-21   01 BB           Port: 443
22-29   [random]        Padding (8 bytes)
```

**After Encryption:**
```
Offset  Bytes           Description
------  -----           -----------
0-1     [encrypted]     Length prefix (30)
2-47    [encrypted]     Frame (30) + Tag (16)
```

---

## Appendix A: Constants

```rust
// Protocol
pub const PROTOCOL_VERSION: u8 = 0x01;
pub const MAGIC: [u8; 4] = [0x50, 0x48, 0x54, 0x4E]; // "PHTN"

// Limits
pub const MAX_FRAME_SIZE: usize = 65535;
pub const MAX_STREAMS: u32 = 1024;
pub const MAX_WINDOW_SIZE: u32 = 16777215;
pub const DEFAULT_WINDOW_SIZE: u32 = 262144;

// Timeouts (seconds)
pub const HANDSHAKE_TIMEOUT: u64 = 30;
pub const IDLE_TIMEOUT: u64 = 300;
pub const KEEPALIVE_INTERVAL: u64 = 30;

// Crypto
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
```

---

## Appendix B: Test Vectors

### B.1 Frame Encoding

**Input:**
```
Type: DATA (0x00)
Stream ID: 42 (0x00002A)
Payload: "Hello"
Padding: 3 bytes
```

**Output (plaintext):**
```
00 00 00 2A 00 05 03 48 65 6C 6C 6F [3 random bytes]
```

### B.2 Noise Handshake

See `tests/crypto_vectors.rs` for complete test vectors.

---

*End of Specification*
