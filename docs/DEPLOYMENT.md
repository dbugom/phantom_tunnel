# Phantom Tunnel Deployment Guide

This guide covers deploying Phantom Tunnel for secure, censorship-resistant communication.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building from Source](#building-from-source)
3. [Server Setup](#server-setup)
4. [Client Setup](#client-setup)
5. [Configuration Reference](#configuration-reference)
6. [Security Hardening](#security-hardening)
7. [Troubleshooting](#troubleshooting)
8. [Performance Tuning](#performance-tuning)

## Prerequisites

### Server Requirements
- Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+) or other Unix-like OS
- 512MB+ RAM
- Open ports: 443 (TLS) or custom port
- Domain name (recommended for TLS SNI)
- TLS certificate (Let's Encrypt recommended)

### Client Requirements
- Linux, macOS, or Windows
- 256MB+ RAM
- Network access to server

## Building from Source

### Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Clone and Build
```bash
git clone https://github.com/yourusername/phantom_tunnel.git
cd phantom_tunnel

# Build with default features (TLS, SOCKS5, HTTP proxy)
cargo build --release

# Build with all features
cargo build --release --all-features

# Build minimal (smaller binary)
cargo build --profile release-small
```

### Binary Locations
After building:
- Server: `target/release/phantom-server`
- Client: `target/release/phantom-client`

## Server Setup

### 1. Generate Keypair

```bash
./phantom-server --generate-key
```

Output:
```
╔══════════════════════════════════════════════════════════════╗
║              Phantom Tunnel Keypair Generated                ║
╠══════════════════════════════════════════════════════════════╣
║ PUBLIC KEY (share with clients):                             ║
║ ABC123xyz...                                                 ║
╠══════════════════════════════════════════════════════════════╣
║ PRIVATE KEY (keep secret, add to server config):             ║
║ XYZ789abc...                                                 ║
╚══════════════════════════════════════════════════════════════╝
```

**Important:** Save both keys. The public key is shared with clients.

### 2. Create Configuration

Create `/etc/phantom_tunnel/config.toml`:

```toml
[server]
listen = "0.0.0.0:443"
private_key = "YOUR_PRIVATE_KEY_HERE"
allowed_clients = [
    "CLIENT_PUBLIC_KEY_1",
    "CLIENT_PUBLIC_KEY_2"
]
max_connections = 1000

# Optional: TLS configuration
tls_cert = "/etc/phantom_tunnel/cert.pem"
tls_key = "/etc/phantom_tunnel/key.pem"

# Optional: Decoy website for censorship resistance
decoy_site = "/var/www/decoy"

[logging]
level = "info"
format = "json"
file = "/var/log/phantom_tunnel/server.log"
```

### 3. Set Up TLS Certificate

Using Let's Encrypt (recommended):
```bash
apt install certbot
certbot certonly --standalone -d your-domain.com

# Copy certificates
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /etc/phantom_tunnel/cert.pem
cp /etc/letsencrypt/live/your-domain.com/privkey.pem /etc/phantom_tunnel/key.pem
chmod 600 /etc/phantom_tunnel/*.pem
```

### 4. Create Systemd Service

Create `/etc/systemd/system/phantom-tunnel.service`:

```ini
[Unit]
Description=Phantom Tunnel Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=phantom
Group=phantom
ExecStart=/usr/local/bin/phantom-server -c /etc/phantom_tunnel/config.toml
Restart=always
RestartSec=5
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/phantom_tunnel

[Install]
WantedBy=multi-user.target
```

### 5. Start Server

```bash
# Create user
useradd -r -s /bin/false phantom

# Install binary
cp target/release/phantom-server /usr/local/bin/
chmod +x /usr/local/bin/phantom-server

# Create directories
mkdir -p /etc/phantom_tunnel /var/log/phantom_tunnel
chown phantom:phantom /var/log/phantom_tunnel

# Enable and start
systemctl daemon-reload
systemctl enable phantom-tunnel
systemctl start phantom-tunnel

# Check status
systemctl status phantom-tunnel
journalctl -u phantom-tunnel -f
```

## Client Setup

### 1. Generate Client Keypair

```bash
./phantom-client --generate-key
```

Share the **public key** with the server administrator to add to `allowed_clients`.

### 2. Create Configuration

Create `~/.config/phantom_tunnel/config.toml`:

```toml
[client]
server = "your-server.com:443"
server_public_key = "SERVER_PUBLIC_KEY_HERE"
private_key = "YOUR_CLIENT_PRIVATE_KEY"

# Local proxy addresses
socks5_listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"

# TLS settings for censorship resistance
tls_sni = "cdn.cloudflare.com"  # Camouflage SNI
tls_profile = "chrome"           # Browser fingerprint to mimic

# Traffic obfuscation
enable_padding = true

[logging]
level = "info"
format = "pretty"
```

### 3. Start Client

```bash
# Direct execution
./phantom-client -c ~/.config/phantom_tunnel/config.toml

# Or with verbose logging
./phantom-client -c config.toml -v debug
```

### 4. Configure Applications

**Firefox:**
1. Settings → Network Settings
2. Manual proxy configuration
3. SOCKS Host: 127.0.0.1, Port: 1080
4. Select "SOCKS v5"
5. Check "Proxy DNS when using SOCKS v5"

**curl:**
```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com

# Or HTTP proxy
curl -x http://127.0.0.1:8080 https://example.com
```

**System-wide (Linux):**
```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
export ALL_PROXY=socks5://127.0.0.1:1080
```

## Configuration Reference

### Server Options

| Option | Description | Default |
|--------|-------------|---------|
| `listen` | Address to listen on | `0.0.0.0:443` |
| `private_key` | Server's private key (base64) | Required |
| `allowed_clients` | List of allowed client public keys | `[]` |
| `tls_cert` | Path to TLS certificate | None |
| `tls_key` | Path to TLS private key | None |
| `decoy_site` | Path to decoy website content | None |
| `max_connections` | Maximum concurrent connections | `1000` |

### Client Options

| Option | Description | Default |
|--------|-------------|---------|
| `server` | Server address (host:port) | Required |
| `server_public_key` | Server's public key (base64) | Required |
| `private_key` | Client's private key (base64) | Required |
| `socks5_listen` | Local SOCKS5 proxy address | `127.0.0.1:1080` |
| `http_listen` | Local HTTP proxy address | `127.0.0.1:8080` |
| `tls_sni` | SNI to use for TLS handshake | Server hostname |
| `tls_profile` | Browser fingerprint profile | `chrome` |
| `enable_padding` | Enable traffic padding | `true` |

### TLS Profiles

Available TLS fingerprint profiles:
- `chrome` - Chrome 120+ fingerprint
- `firefox` - Firefox 120+ fingerprint
- `safari` - Safari 17+ fingerprint
- `edge` - Edge 120+ fingerprint
- `ios_safari` - iOS Safari fingerprint
- `android_chrome` - Android Chrome fingerprint
- `random` - Random selection at startup

## Security Hardening

### Server Security

1. **Firewall Configuration**
```bash
# Allow only necessary ports
ufw default deny incoming
ufw allow 22/tcp  # SSH
ufw allow 443/tcp # Phantom Tunnel
ufw enable
```

2. **Fail2ban for Rate Limiting**
Create `/etc/fail2ban/jail.d/phantom-tunnel.conf`:
```ini
[phantom-tunnel]
enabled = true
port = 443
filter = phantom-tunnel
logpath = /var/log/phantom_tunnel/server.log
maxretry = 5
bantime = 3600
```

3. **Restrict Client Access**
Only add trusted client public keys to `allowed_clients`.

### Client Security

1. **DNS Leak Prevention**
   - Always use "Proxy DNS when using SOCKS v5" in browser
   - Configure system DNS to 127.0.0.1 when running local DNS proxy

2. **Kill Switch (Linux)**
```bash
# Block all traffic except tunnel
iptables -A OUTPUT -d YOUR_SERVER_IP -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -j DROP
```

### Key Management

- Generate unique keypairs for each client
- Rotate keys periodically (recommended: every 90 days)
- Store private keys securely (use encrypted storage)
- Never share private keys

## Troubleshooting

### Connection Issues

**"Connection refused"**
- Check server is running: `systemctl status phantom-tunnel`
- Verify port is open: `nc -zv server.com 443`
- Check firewall rules

**"Authentication failed"**
- Verify client public key is in server's `allowed_clients`
- Check key format (must be base64)
- Ensure using correct server public key

**"TLS handshake failed"**
- Verify TLS certificate is valid
- Check certificate chain is complete
- Try different `tls_sni` value

### Performance Issues

**Slow connection**
- Check server load: `htop`
- Monitor bandwidth: `iftop`
- Consider disabling padding if not in censored environment
- Check for network congestion

**High latency**
- Use server closer to your location
- Disable timing obfuscation in low-censorship environments
- Check for packet loss: `mtr server.com`

### Debugging

Enable debug logging:
```bash
# Server
phantom-server -c config.toml -v debug

# Client
phantom-client -c config.toml -v debug
```

Check logs:
```bash
# Server logs
journalctl -u phantom-tunnel -f
tail -f /var/log/phantom_tunnel/server.log

# Client logs (if configured)
tail -f ~/.local/share/phantom_tunnel/client.log
```

## Performance Tuning

### Server Optimization

1. **Increase file descriptors**
```bash
# /etc/security/limits.conf
phantom soft nofile 65535
phantom hard nofile 65535
```

2. **TCP optimization** (`/etc/sysctl.conf`):
```ini
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
```

3. **Increase max connections** in config:
```toml
[server]
max_connections = 10000
```

### Client Optimization

1. **Disable padding** if not needed:
```toml
[client]
enable_padding = false
```

2. **Use HTTP/2** for multiplexing when connecting to modern servers

3. **Connection pooling** is automatic - multiple streams share one tunnel

## DNS Tunneling (Advanced)

For extremely censored environments where TLS is blocked:

```toml
[client]
# Use DNS tunneling as fallback
transport = "dns"
dns_base_domain = "t.yourdomain.com"
dns_resolver = "8.8.8.8:53"
```

**Note:** DNS tunneling is much slower but extremely difficult to block.

## Support

- Issues: https://github.com/yourusername/phantom_tunnel/issues
- Documentation: https://github.com/yourusername/phantom_tunnel/wiki
