# Phantom Tunnel — Deployment Guide

## Table of Contents

1. [Server Deployment](#server-deployment)
   - [One-Liner (Automated)](#one-liner-automated)
   - [Manual Step-by-Step](#manual-step-by-step)
2. [Client Setup](#client-setup)
3. [File Locations](#file-locations)
4. [Service Management](#service-management)
5. [Debugging & Logs](#debugging--logs)
6. [Updating](#updating)
7. [Testing](#testing)

---

## Server Deployment

### Prerequisites

- Fresh Ubuntu/Debian VPS (tested on Ubuntu 22.04/24.04)
- Domain pointing to the server IP (A record in DNS)
- Port 80 open (for certbot) and port 443 open (for the tunnel)
- Root access

### One-Liner (Automated)

This single command handles everything: dependencies, Rust, TLS cert, build, config, kernel tuning, and systemd service.

```bash
# Clone and run setup
git clone https://github.com/dbugom/phantom_tunnel.git /opt/phantom_tunnel
cd /opt/phantom_tunnel
git checkout release/stable-v2
sudo ./setup.sh server --domain phantom.yfy.ae --client-key "YOUR_CLIENT_PUBLIC_KEY"
```

Or with curl (no git clone needed):

```bash
curl -sSL https://raw.githubusercontent.com/dbugom/phantom_tunnel/release/stable-v2/setup.sh -o /tmp/setup.sh
sudo bash /tmp/setup.sh server --domain phantom.yfy.ae --client-key "YOUR_CLIENT_PUBLIC_KEY"
```

The script will print the **server public key** at the end — copy it for the client config.

#### Setup script options

| Flag | Description | Default |
|------|-------------|---------|
| `--domain <domain>` | Domain for TLS certificate | (prompted) |
| `--client-key <key>` | Client public key to authorize | (prompted) |
| `--listen <addr>` | Listen address | `0.0.0.0:443` |
| `--branch <branch>` | Git branch to build | `release/stable-v2` |
| `--install-dir <path>` | Where to clone the repo | `/opt/phantom_tunnel` |
| `--skip-deps` | Skip apt package installation | |
| `--skip-tls` | Skip certbot TLS certificate | |

### Manual Step-by-Step

#### 1. Install dependencies

```bash
apt update && apt install -y curl build-essential pkg-config libssl-dev git certbot
```

#### 2. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
```

#### 3. Get TLS certificate

Make sure the domain's A record points to this server, then:

```bash
certbot certonly --standalone -d phantom.yfy.ae --non-interactive --agree-tos --register-unsafely-without-email
```

Certificates are saved to `/etc/letsencrypt/live/phantom.yfy.ae/`.

#### 4. Clone and build

```bash
git clone https://github.com/dbugom/phantom_tunnel.git /opt/phantom_tunnel
cd /opt/phantom_tunnel
git checkout release/stable-v2
cargo build --release
```

Build output: `/opt/phantom_tunnel/target/release/phantom-server`

#### 5. Generate server keypair

```bash
./target/release/phantom-server --generate-key
```

This prints the **private key** and **public key**. Save both. The public key must be shared with clients.

#### 6. Create config file

```bash
mkdir -p /etc/phantom_tunnel
nano /etc/phantom_tunnel/config.toml
```

Paste the following (replace keys with your values):

```toml
[server]
listen = "0.0.0.0:443"

# Server keypair (from --generate-key output)
private_key = "YOUR_SERVER_PRIVATE_KEY"
public_key = "YOUR_SERVER_PUBLIC_KEY"

# Client public keys allowed to connect
allowed_clients = [
    "CLIENT_PUBLIC_KEY_1",
    # "CLIENT_PUBLIC_KEY_2",
]

max_connections = 1000

# TLS certificates
tls_cert = "/etc/letsencrypt/live/phantom.yfy.ae/fullchain.pem"
tls_key = "/etc/letsencrypt/live/phantom.yfy.ae/privkey.pem"

[logging]
level = "info"
format = "pretty"
```

#### 7. Apply kernel tuning (optional but recommended)

```bash
bash /opt/phantom_tunnel/scripts/server-sysctl.sh
```

Enables BBR congestion control and increases TCP buffer sizes for throughput.

#### 8. Create systemd service

```bash
cat > /etc/systemd/system/phantom-tunnel.service << 'EOF'
[Unit]
Description=Phantom Tunnel Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/phantom_tunnel/target/release/phantom-server -c /etc/phantom_tunnel/config.toml
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable phantom-tunnel
systemctl start phantom-tunnel
```

#### 9. Set up certificate auto-renewal

```bash
mkdir -p /etc/letsencrypt/renewal-hooks/post
cat > /etc/letsencrypt/renewal-hooks/post/phantom-tunnel.sh << 'EOF'
#!/bin/bash
systemctl restart phantom-tunnel
EOF
chmod +x /etc/letsencrypt/renewal-hooks/post/phantom-tunnel.sh
```

Certbot automatically renews certs and restarts the tunnel service.

---

## Client Setup

#### 1. Build the client (on your local machine)

```bash
git clone https://github.com/dbugom/phantom_tunnel.git
cd phantom_tunnel
git checkout release/stable-v2
cargo build --release
```

Or use the setup script:

```bash
./setup.sh client --server-ip 1.2.3.4 --server-key "SERVER_PUBLIC_KEY"
```

#### 2. Generate client keypair

```bash
./target/release/phantom-client --generate-key
```

Give the **client public key** to the server admin to add to `allowed_clients`.

#### 3. Create client config

```bash
nano client.toml
```

```toml
[client]
server = "SERVER_IP:443"
server_public_key = "SERVER_PUBLIC_KEY"
private_key = "YOUR_CLIENT_PRIVATE_KEY"
public_key = "YOUR_CLIENT_PUBLIC_KEY"

socks5_listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"

# TLS SNI — must match the domain on the server's TLS certificate
tls_sni = "phantom.yfy.ae"

# Browser fingerprint mimicry
tls_profile = "chrome"

enable_padding = true

[logging]
level = "info"
format = "pretty"
```

**Note:** Use the server IP directly (not domain) in the `server` field — avoids DNS resolution issues on some networks.

#### 4. Run the client

```bash
./target/release/phantom-client -c client.toml
```

#### 5. Configure applications

Set your browser or system proxy to:
- **SOCKS5:** `127.0.0.1:1080`
- **HTTP Proxy:** `127.0.0.1:8080`

---

## File Locations

### Server

| File | Path |
|------|------|
| Binary | `/opt/phantom_tunnel/target/release/phantom-server` |
| Config | `/etc/phantom_tunnel/config.toml` |
| Source code | `/opt/phantom_tunnel/` |
| Systemd service | `/etc/systemd/system/phantom-tunnel.service` |
| TLS certificate | `/etc/letsencrypt/live/phantom.yfy.ae/fullchain.pem` |
| TLS private key | `/etc/letsencrypt/live/phantom.yfy.ae/privkey.pem` |
| Cert renewal hook | `/etc/letsencrypt/renewal-hooks/post/phantom-tunnel.sh` |
| Kernel tuning | `/etc/sysctl.d/99-phantom-tunnel.conf` |

### Client

| File | Path |
|------|------|
| Binary | `./target/release/phantom-client` |
| Config | `./client.toml` (or wherever you place it) |

---

## Service Management

```bash
# Start the server
systemctl start phantom-tunnel

# Stop the server
systemctl stop phantom-tunnel

# Restart the server
systemctl restart phantom-tunnel

# Check if running
systemctl status phantom-tunnel

# Enable auto-start on boot
systemctl enable phantom-tunnel

# Disable auto-start on boot
systemctl disable phantom-tunnel
```

---

## Debugging & Logs

### View live logs

```bash
# Follow logs in real time
journalctl -u phantom-tunnel -f

# Last 50 lines
journalctl -u phantom-tunnel -n 50

# Logs since last boot
journalctl -u phantom-tunnel -b

# Logs from the last hour
journalctl -u phantom-tunnel --since "1 hour ago"
```

### Enable debug logging

Edit `/etc/phantom_tunnel/config.toml`:

```toml
[logging]
level = "debug"    # Options: trace, debug, info, warn, error
format = "pretty"
```

Then restart:

```bash
systemctl restart phantom-tunnel
```

For maximum verbosity (trace level), use `level = "trace"`. This logs every frame, every flow control update, and every stream event.

### One-time debug run (without systemd)

Stop the service and run manually:

```bash
systemctl stop phantom-tunnel

# Run with debug logging
RUST_LOG=debug /opt/phantom_tunnel/target/release/phantom-server -c /etc/phantom_tunnel/config.toml

# Or trace level
RUST_LOG=trace /opt/phantom_tunnel/target/release/phantom-server -c /etc/phantom_tunnel/config.toml
```

Press `Ctrl+C` to stop, then restart the service:

```bash
systemctl start phantom-tunnel
```

### Client-side debugging

```bash
# Debug logging
RUST_LOG=debug ./target/release/phantom-client -c client.toml

# Trace logging (very verbose)
RUST_LOG=trace ./target/release/phantom-client -c client.toml
```

### Test active probe resistance

From any machine, check that the server looks like a normal web server:

```bash
# Should return an nginx welcome page
curl -k https://phantom.yfy.ae/

# Should return 404
curl -k https://phantom.yfy.ae/nonexistent

# Should return 405
curl -k -X POST https://phantom.yfy.ae/

# Check server header
curl -kI https://phantom.yfy.ae/
# Should show: Server: nginx/1.24.0
```

### Test tunnel connectivity

```bash
# Test SOCKS5 proxy
curl --socks5 127.0.0.1:1080 https://ifconfig.me

# Test HTTP proxy
curl -x http://127.0.0.1:8080 https://ifconfig.me

# Speed test
curl --socks5 127.0.0.1:1080 -o /dev/null https://speed.cloudflare.com/__down?bytes=10000000
```

### Common issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `TLS handshake failed` | Wrong cert path or expired cert | Check `tls_cert`/`tls_key` paths, run `certbot renew` |
| `Client not in allowed list` | Client public key not in server config | Add client key to `allowed_clients` in server config |
| `Connection refused` | Server not running or wrong port | Check `systemctl status phantom-tunnel` and firewall rules |
| `Keepalive timeout` | Network issue or very heavy transfer | Check server logs, ensure both sides are on same version |
| `Decrypt failed` | Key mismatch or version mismatch | Verify `server_public_key` matches server's actual public key |

---

## Updating

To update the server to a new version:

```bash
# Stop the service
systemctl stop phantom-tunnel

# Pull latest code
cd /opt/phantom_tunnel
git fetch origin
git checkout release/stable-v2
git pull origin release/stable-v2

# Rebuild
source ~/.cargo/env
cargo build --release

# Start the service (config is preserved)
systemctl start phantom-tunnel

# Verify
systemctl status phantom-tunnel
journalctl -u phantom-tunnel -n 10
```

To switch branches:

```bash
systemctl stop phantom-tunnel
cd /opt/phantom_tunnel
git fetch origin
git checkout <branch-name>
git pull origin <branch-name>
cargo build --release
systemctl start phantom-tunnel
```

The config file at `/etc/phantom_tunnel/config.toml` is never overwritten by updates.
