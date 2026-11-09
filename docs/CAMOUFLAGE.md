# Camouflage: making the tunnel look like ordinary HTTPS

> **Status (2026-11).** Implemented and tested: a pluggable outer transport
> that carries the tunnel inside a WebSocket, optionally over TLS
> (`src/transport.rs`). Pointed at a reverse proxy on a real HTTPS domain, the
> connection *is* HTTPS to that domain. The Noise encryption, authentication,
> flow control and UDP all run unchanged inside it.

This document explains the threat, why the obvious approaches fail, the design
that was chosen and why, how to deploy it, and — importantly — what it still
does **not** hide.

---

## 1. The adversary

A capable censor (the Great Firewall of China is the best-studied; Iran and
several Gulf DPI stacks are similar) has three tools:

1. **Passive classification.** It inspects every connection and decides, in
   real time, whether it looks like an allowed protocol. Since November 2021
   the GFW runs a classifier aimed specifically at *fully encrypted* traffic —
   traffic that is random-looking from the first byte, with no plaintext
   structure. That is exactly what a raw Noise/Shadowsocks/obfs stream looks
   like. ([Wu et al., USENIX Security 2023](https://www.usenix.org/system/files/usenixsecurity23-wu-mingshi.pdf))

2. **Active probing.** It connects to your server itself (or replays a
   handshake it saw) to see whether the server behaves like a proxy. A server
   that answers a probe differently from a normal web server is a proxy.

3. **Traffic analysis.** Even when it cannot read or probe a flow, it can look
   at packet sizes, directions and timing, and at who you are talking to and
   for how long.

Plain Phantom Tunnel (the `plain` transport) loses on #1 and #2 immediately: it
is high-entropy bytes over TCP on a non-standard port, and an active probe gets
a distinctive Noise handshake attempt and close.

---

## 2. Why the obvious fixes don't work

### "Look like nothing" (randomise everything, obfs4-style)

Make the stream look like uniform random bytes and refuse to answer probes
without a shared secret. obfs4 does this well against probing (Elligator-encoded
keys, per-bridge secret). **But the GFW's 2023 classifier is built to catch
precisely this category.** Its exemption rules (a connection is let through if
*any* rule matches the first data packet) include, approximately:

- **Popcount.** Average set-bits-per-byte of the first packet. Exempt if it is
  **≤ 3.4 or ≥ 4.6**. Encrypted/random data sits near 4.0 — right in the
  blocked band.
- **Printable ASCII.** Exempt if the first 6 bytes are printable, or if > 50%
  of bytes are printable, or if there is a run of > 20 printable bytes.
- **Known protocol.** Exempt if it matches TLS, HTTP, etc.

The paper's own suggested countermeasure is to *shape the first packet's
popcount* out of the band (insert ones/zeroes) or prepend an allowed-protocol
header — i.e. stop looking random. And a follow-up
([Xue et al., USENIX Security 2024](https://ensa.fi/papers/sec24-xue.pdf))
shows that **random padding and multiplexing alone do not reliably hide an
obfuscated proxy from a passive classifier.** So "look like nothing" is now a
losing position against a top-tier censor.

### "Imitate HTTPS" (mimicry: REALITY, ShadowTLS)

Pretend to be a TLS handshake to a popular site. This is strong in practice and
widely used, but it is an *imitation*, and imitations have tells. The
[Aparecium](https://github.com/ban6cat6/aparecium) proof-of-concept detects
REALITY and ShadowTLS v3 by their mishandling of TLS 1.3 post-handshake
messages (e.g. `NewSessionTicket`) and small length differences in
`ServerFinished`. The mimicry arms race is real and ongoing. In Rust the
problem is worse: **rustls deliberately will not emit a byte-exact browser
ClientHello** ([rustls#1932](https://github.com/rustls/rustls/issues/1932)), so
we could not win a JA3/JA4 fingerprint fight even if we tried.

---

## 3. The design: *be* HTTPS, don't imitate it

The robust move is not to imitate HTTPS but to run the tunnel **inside a real
TLS session to a real domain, terminated by a real web server that also serves a
real website.** This is the model used by Tor's
[WebTunnel](https://community.torproject.org/relay/setup/webtunnel/) (itself
based on HTTPT) and by Trojan: there is nothing to fingerprint because it is not
an imitation.

Phantom Tunnel already has the one thing this needs: the server box runs **Caddy
on :443 with real Let's Encrypt certificates and real sites.** So:

```
          TLS 1.3 to vpn.example.com:443, real cert, SNI = vpn.example.com
 client ───────────────────────────────────────────────►  Caddy
   │  (WebSocket upgrade on a secret path, e.g. /relay)       │
   │                                                          ├── /relay/*  → phantom-server (ws, localhost)
   │        Noise IK + flow control + UDP, unchanged,         │
   │        inside the WebSocket, inside the TLS              └── everything else → the real website
```

To the censor this is: genuine TLS 1.3 to a real domain, a valid public
certificate, and a WebSocket on one path — indistinguishable from any web app
that uses WebSockets. An **active probe** of the domain (or any other path) gets
the **real website**, because Caddy serves it. There is no separate proxy port
and no custom handshake to catch.

Why this is the right choice *for this project* specifically:

- It reuses **audited** components (rustls, Caddy, Let's Encrypt). We invent no
  crypto and imitate no handshake, so there is no Aparecium-style tell.
- It defeats the passive classifier: the outer bytes are real TLS (printable
  record headers, a real SNI), which the GFW rules exempt.
- It defeats active probing: the decoy is a genuine website, not a guess.
- The tunnel's own security is untouched — Noise IK still gives mutual
  authentication and forward secrecy *inside* the TLS.

---

## 4. How it works in the code

A pluggable outer transport sits under the Noise handshake (`src/transport.rs`).
The tunnel protocol is a byte stream; the transport decides what that byte
stream looks like on the wire. Three modes:

| Mode | Client `type` | Server `transport` | Wire appearance |
|------|---------------|--------------------|-----------------|
| Plain (default) | `plain` | `plain` | raw length-prefixed Noise over TCP |
| WebSocket | `ws` | `ws` | a WebSocket (no TLS; for a local terminator) |
| WebSocket/TLS | `wss` | `ws` (behind Caddy) | **real HTTPS + WebSocket to your domain** |

In `wss` mode the client does a real TLS 1.3 handshake (rustls, ring backend,
Mozilla roots, ALPN `http/1.1`) and a WebSocket upgrade; the server speaks plain
`ws` because **Caddy terminates the TLS**. The Noise stream rides inside the
WebSocket as binary frames, byte-for-byte unchanged.

---

## 5. Deploying it

### 5.1 Server

Run a second `phantom-server` (or point the existing one) at a localhost port in
`ws` mode, so only Caddy can reach it:

```toml
# /etc/phantom_tunnel/config-ws.toml
[server]
listen = "127.0.0.1:9444"      # localhost only; Caddy reaches it
transport = "ws"               # accept WebSocket; Caddy does the TLS
private_key = "…"              # the SAME key as your existing server, or a new one
public_key  = "…"
allowed_clients = [ "…" ]
max_connections = 100
allow_private_destinations = false

[logging]
level = "info"
format = "json"
```

Running it alongside the existing plain `:8444` server lets you migrate clients
gradually (the backup-server failover added earlier makes this painless).

### 5.2 Caddy

Add one route to the site that serves your domain. Pick an unobvious path. Put
the tunnel route **before** the website's catch-all so it matches first:

```caddyfile
vpn.example.com {
    # The tunnel: one secret path, upgraded to a WebSocket and proxied to
    # phantom-server. handle_path strips the prefix; the Connection: Upgrade
    # matcher means only WebSocket requests to this path are proxied.
    @relay {
        path /relay /relay/*
        header Connection *Upgrade*
        header Upgrade websocket
    }
    handle @relay {
        reverse_proxy 127.0.0.1:9444
    }

    # Everything else: the real website. An active probe lands here.
    handle {
        root * /var/www/your-real-site
        file_server
        # …or reverse_proxy to your existing web app.
    }
}
```

`reverse_proxy` passes WebSocket upgrades through with no extra configuration.
**Do not** disturb the existing `:443`/`:80`, LiveKit, webapp, postgres or redis
blocks — add only this one site (or this one route to an existing site).

### 5.3 Client

Either hand the user a connect link that already carries the camouflage —

```bash
phantom-server -c /etc/phantom_tunnel/config-ws.toml link \
    --address vpn.example.com:443 \
    --transport wss --ws-path /relay --sni vpn.example.com \
    --label alice --new-client-key
# → phantom://KEY@vpn.example.com:443?key=…&t=wss&path=%2Frelay&sni=vpn.example.com#alice
```

— and they `phantom-client -c config.toml --import -`, or they write it by hand:

```toml
[client]
server = "vpn.example.com:443"
server_public_key = "…"
private_key = "…"

[client.transport]
type = "wss"
path = "/relay"
sni  = "vpn.example.com"     # defaults to the host of `server`; set it if dialing by IP
# host = "vpn.example.com"   # HTTP Host header; defaults to sni
# insecure = false           # NEVER true against a real server
```

---

## 6. What this still does **not** hide (read this)

Camouflage is not invisibility. Be honest with yourself and your users:

- **TLS client fingerprint (JA3/JA4).** rustls does not produce a byte-exact
  browser ClientHello, so a censor that fingerprints TLS clients could notice
  that a "browser" domain is being reached by a non-browser TLS stack. Lots of
  legitimate non-browser HTTPS exists (apps, curl, Electron), so this is a
  *weak* signal, not a smoking gun — but it is real. The strongest fix is to run
  the client's TLS through a browser-grade stack (a uTLS/BoringSSL equivalent);
  that is **future work**, not done here.
- **Traffic analysis.** A long, high-volume, bidirectional flow does not look
  like casual browsing of a small website, regardless of the TLS wrapper
  (Xue et al.). Padding and timing jitter help only partially. If your threat
  model includes volume/timing correlation, no single-hop tunnel solves it —
  that is what Tor's multi-hop design is for.
- **The decoy must be real.** The anti-probing property only holds if the
  domain actually serves a plausible site on the other paths. A bare domain that
  returns 404 everywhere except `/relay` is itself a tell. Co-host a real site.
- **The `plain` and `ws` (no TLS) modes are not camouflage.** `plain` is
  high-entropy and will be flagged by the GFW classifier; plain `ws` is an
  unencrypted WebSocket. Only `wss` behind a real domain is the camouflage.
- **Not audited.** This code and design have not had an independent security
  review.

If you need a guarantee against a nation-state censor, prefer a mature, audited,
widely-used system (Tor + WebTunnel/obfs4/Snowflake). This design deliberately
mirrors WebTunnel so that the operational posture is the same.

---

## 7. References

- Wu et al., *How the Great Firewall of China Detects and Blocks Fully Encrypted
  Traffic*, USENIX Security 2023 —
  <https://www.usenix.org/system/files/usenixsecurity23-wu-mingshi.pdf>
- Xue et al., *Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS
  Handshakes*, USENIX Security 2024 — <https://ensa.fi/papers/sec24-xue.pdf>
- Tor WebTunnel — <https://community.torproject.org/relay/setup/webtunnel/>
- obfs4 / *Obfuscated Key Exchange* — <https://eprint.iacr.org/2024/1086.pdf>
- Aparecium (detecting REALITY / ShadowTLS) —
  <https://github.com/ban6cat6/aparecium>
- rustls on ClientHello fingerprinting —
  <https://github.com/rustls/rustls/issues/1932>
