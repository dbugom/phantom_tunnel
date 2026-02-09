# Phantom Tunnel - MikroTik Container Deployment

Run the Phantom Tunnel client as a container on MikroTik RouterOS, enabling the router to proxy LAN traffic through the encrypted tunnel.

## Prerequisites

- MikroTik RouterOS **7.4+** with the **container** package installed
- External storage (USB drive or SSD) — containers cannot run from internal flash
- Device architecture: ARM64, ARMv7, or AMD64 (see table below)
- Phantom Tunnel server already running and accessible

### Device Architecture Reference

| MikroTik Device | Architecture | Image File |
|---|---|---|
| RB5009, CCR2004, CCR2116 | ARM64 | `phantom-client-arm64.tar` |
| hAP ax², Audience, Chateau | ARM64 | `phantom-client-arm64.tar` |
| hAP ac³, RB4011 | ARMv7 | `phantom-client-armv7.tar` |
| hAP ac², RBcAPGi | ARMv7 | `phantom-client-armv7.tar` |
| CHR (Cloud Hosted Router) | AMD64 | `phantom-client-amd64.tar` |
| x86 RouterBOARD | AMD64 | `phantom-client-amd64.tar` |

## Building the Container Image

### Option 1: Build Locally

Requires Docker with BuildKit (Docker Desktop or `docker buildx`).

```bash
# Build for a specific architecture
./mikrotik/build.sh arm64

# Build for all architectures
./mikrotik/build.sh

# Output files are in mikrotik/output/
ls -lh mikrotik/output/*.tar
```

### Option 2: Download from GitHub Releases

Pre-built images are available from GitHub Actions artifacts on tagged releases.

## Generating Keys

Generate a client keypair before deployment:

```bash
# Using the phantom-client binary
cargo run --bin phantom-client -- --generate-keys

# Or use openssl to generate a 32-byte key
openssl rand -base64 32
```

Save the generated `private_key` and `public_key`. Add the client's `public_key` to the server's `allowed_clients` list.

## RouterOS Configuration

### Step 1: Enable Container Mode

```routeros
/system/device-mode/update container=yes
```

The router will reboot. Confirm with the mode button on the device if prompted.

### Step 2: Set Up Container Storage

```routeros
# Format and mount external storage if not already done
/disk/print

# Set the container tmpdir to external storage
/container/config/set tmpdir=usb1/containers
```

### Step 3: Create VETH Interface

```routeros
/interface/veth/add name=veth-phantom address=172.17.0.2/24 gateway=172.17.0.1
```

### Step 4: Create Bridge for Container

```routeros
/interface/bridge/add name=br-containers
/interface/bridge/port/add bridge=br-containers interface=veth-phantom
/ip/address/add address=172.17.0.1/24 interface=br-containers
```

### Step 5: Enable NAT for Container Traffic

```routeros
# Allow the container to reach the internet (to connect to your server)
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24
```

### Step 6: Configure Environment Variables

```routeros
/container/envs/add name=phantom_envs key=PHANTOM_SERVER value="YOUR_SERVER_IP:443"
/container/envs/add name=phantom_envs key=PHANTOM_SERVER_PUBKEY value="YOUR_SERVER_PUBLIC_KEY_BASE64"
/container/envs/add name=phantom_envs key=PHANTOM_PRIVATE_KEY value="YOUR_CLIENT_PRIVATE_KEY_BASE64"
/container/envs/add name=phantom_envs key=PHANTOM_PUBLIC_KEY value="YOUR_CLIENT_PUBLIC_KEY_BASE64"

# Optional: TLS SNI for DPI camouflage (recommended)
/container/envs/add name=phantom_envs key=PHANTOM_TLS_SNI value="your.domain.com"
```

### Step 7: Upload and Add Container

Upload the `.tar` file to the router's external storage via WinBox, FTP, or SCP:

```bash
scp mikrotik/output/phantom-client-arm64.tar admin@192.168.88.1:/usb1/
```

Add the container in RouterOS:

```routeros
/container/add file=usb1/phantom-client-arm64.tar \
    interface=veth-phantom \
    envlist=phantom_envs \
    hostname=phantom \
    start-on-boot=yes
```

### Step 8: Start the Container

```routeros
# Wait for the container status to show "stopped" (image extraction complete)
/container/print

# Start the container
/container/start 0
```

Verify it's running:

```routeros
/container/print
# Status should show "running"

# View container logs
/container/shell 0
```

## Routing Traffic Through the Tunnel

### Option A: Manual Proxy Configuration

Configure devices on the LAN to use the router as a SOCKS5 or HTTP proxy:

- **SOCKS5 Proxy**: `172.17.0.2:1080`
- **HTTP Proxy**: `172.17.0.2:8080`

### Option B: RouterOS Web Proxy Upstream

Route RouterOS's built-in web proxy through the tunnel:

```routeros
/ip/proxy/set enabled=yes port=8888 parent-proxy=172.17.0.2 parent-proxy-port=8080
```

Then configure LAN devices to use `192.168.88.1:8888` as their HTTP proxy.

### Option C: Transparent Proxy with Policy Routing

For advanced setups, use firewall mangle rules and routing marks to redirect traffic:

```routeros
# Mark connections from specific LAN devices
/ip/firewall/mangle/add chain=prerouting src-address=192.168.88.0/24 \
    dst-port=80,443 protocol=tcp action=mark-routing new-routing-mark=via-phantom

# Route marked traffic to the container
/ip/route/add dst-address=0.0.0.0/0 gateway=172.17.0.2 routing-mark=via-phantom
```

Note: Transparent proxy requires additional SOCKS5 redirection (e.g., `redsocks` or similar) — Option A or B is simpler.

## Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `PHANTOM_SERVER` | Yes | — | Server address (`host:port`) |
| `PHANTOM_SERVER_PUBKEY` | Yes | — | Server public key (base64) |
| `PHANTOM_PRIVATE_KEY` | Yes | — | Client private key (base64) |
| `PHANTOM_PUBLIC_KEY` | Yes | — | Client public key (base64) |
| `PHANTOM_SOCKS5_LISTEN` | No | `0.0.0.0:1080` | SOCKS5 proxy listen address |
| `PHANTOM_HTTP_LISTEN` | No | `0.0.0.0:8080` | HTTP proxy listen address |
| `PHANTOM_TLS_SNI` | No | — | TLS SNI for DPI camouflage |
| `PHANTOM_TLS_PROFILE` | No | `chrome` | TLS fingerprint (`chrome`, `firefox`, `safari`, `random`) |
| `PHANTOM_ENABLE_PADDING` | No | `true` | Enable traffic padding |
| `PHANTOM_LOG_LEVEL` | No | `info` | Log level (`trace`, `debug`, `info`, `warn`, `error`) |

## Alternative: Bind-Mounted Config File

Instead of environment variables, you can bind-mount a `config.toml` file:

```routeros
/container/mounts/add name=phantom-config src=usb1/phantom dst=/config

/container/add file=usb1/phantom-client-arm64.tar \
    interface=veth-phantom \
    mounts=phantom-config \
    hostname=phantom \
    start-on-boot=yes
```

Create `/usb1/phantom/config.toml` on the router:

```toml
[client]
server = "YOUR_SERVER_IP:443"
server_public_key = "YOUR_SERVER_PUBLIC_KEY_BASE64"
private_key = "YOUR_CLIENT_PRIVATE_KEY_BASE64"
public_key = "YOUR_CLIENT_PUBLIC_KEY_BASE64"
socks5_listen = "0.0.0.0:1080"
http_listen = "0.0.0.0:8080"
tls_sni = "your.domain.com"
tls_profile = "chrome"
enable_padding = true

[logging]
level = "info"
format = "compact"
```

## Troubleshooting

### Container Won't Start

- Check container status: `/container/print detail`
- Ensure external storage is mounted: `/disk/print`
- Verify the `.tar` file matches your device architecture
- Check available disk space: `/disk/print`

### Cannot Connect to Server

- Verify NAT masquerade rule is active: `/ip/firewall/nat/print`
- Test connectivity from the container: `/container/shell 0` then check if DNS resolves
- Check if the server IP is reachable from the router: `/tool/ping YOUR_SERVER_IP`
- If using TLS SNI, ensure the domain resolves to the server IP

### Proxy Not Accessible from LAN

- Verify the VETH address (`172.17.0.2`) is correct: `/interface/veth/print`
- Check bridge configuration: `/interface/bridge/port/print`
- Ensure no firewall rules block traffic to `172.17.0.2:1080` or `172.17.0.2:8080`
- Test from the router itself: `/tool/fetch url=http://172.17.0.2:8080 mode=http`

### High Memory Usage

- MikroTik devices with < 256MB RAM may struggle — monitor with `/system/resource/print`
- Consider disabling padding (`PHANTOM_ENABLE_PADDING=false`) to reduce overhead
- Use `info` log level (default) — `debug` and `trace` consume memory

### Updating the Container

```routeros
/container/stop 0
/container/remove 0
# Upload new .tar file
/container/add file=usb1/phantom-client-arm64.tar \
    interface=veth-phantom \
    envlist=phantom_envs \
    hostname=phantom \
    start-on-boot=yes
/container/start 0
```
