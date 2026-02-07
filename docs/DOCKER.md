# Docker Deployment Guide

This guide explains how to run Phantom Tunnel using Docker containers.

## Quick Start

### Build Images

```bash
# Build server image
docker build --target server -t phantom-tunnel:server .

# Build client image
docker build --target client -t phantom-tunnel:client .

# Or use Alpine for smaller images (~15MB)
docker build -f Dockerfile.alpine --target server -t phantom-tunnel:server-alpine .
docker build -f Dockerfile.alpine --target client -t phantom-tunnel:client-alpine .
```

### Run Server

```bash
# Generate keypair first (one-time)
docker run --rm phantom-tunnel:server --generate-key

# Create server.toml with your keys, then run:
docker run -d \
  --name phantom-server \
  -p 443:443 \
  -v $(pwd)/server.toml:/app/config.toml:ro \
  phantom-tunnel:server
```

### Run Client

```bash
# Create client.toml with server's public key, then run:
docker run -d \
  --name phantom-client \
  -p 1080:1080 \
  -p 8080:8080 \
  -v $(pwd)/client.toml:/app/config.toml:ro \
  phantom-tunnel:client
```

## Using Docker Compose

### Server Deployment

1. Create `server.toml`:
```toml
[server]
listen = "0.0.0.0:443"
private_key = "YOUR_PRIVATE_KEY"
public_key = "YOUR_PUBLIC_KEY"
allowed_clients = ["CLIENT_PUBLIC_KEY"]
max_connections = 1000

[logging]
level = "info"
```

2. Start server:
```bash
docker compose up -d server
```

### Client Deployment

1. Create `client.toml`:
```toml
[client]
server = "YOUR_SERVER_IP:443"
server_public_key = "SERVER_PUBLIC_KEY"
private_key = "YOUR_CLIENT_PRIVATE_KEY"
public_key = "YOUR_CLIENT_PUBLIC_KEY"
socks5_listen = "0.0.0.0:1080"
http_listen = "0.0.0.0:8080"
enable_padding = true

[logging]
level = "info"
```

2. Start client:
```bash
docker compose up -d client
```

## Configuration

### Environment Variables

- `RUST_LOG` - Log level (trace, debug, info, warn, error)

### Volume Mounts

| Path | Description |
|------|-------------|
| `/app/config.toml` | Configuration file (required) |
| `/var/log/phantom_tunnel` | Server logs (optional) |

### Ports

| Port | Service |
|------|---------|
| 443 | Server tunnel endpoint |
| 1080 | Client SOCKS5 proxy |
| 8080 | Client HTTP proxy |

## Production Recommendations

### Security Hardening

```yaml
# docker-compose.yml additions
services:
  server:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

### Resource Limits

```yaml
services:
  server:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 128M
```

### Logging

```yaml
services:
  server:
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

## Troubleshooting

### Check Container Logs

```bash
docker logs phantom-server
docker logs phantom-client
```

### Interactive Shell

```bash
docker exec -it phantom-server /bin/sh
docker exec -it phantom-client /bin/sh
```

### Verify Connectivity

```bash
# From client container
docker exec phantom-client wget -qO- --proxy=off ifconfig.me

# Test SOCKS5 proxy
curl --socks5-hostname localhost:1080 https://ifconfig.me
```

### Common Issues

1. **Connection refused**: Check firewall rules and that server is listening on 0.0.0.0
2. **Handshake failed**: Verify public keys match between client and server configs
3. **Port already in use**: Stop conflicting services or change port mappings

## Image Sizes

| Image | Base | Size |
|-------|------|------|
| phantom-tunnel:server | Debian | ~80MB |
| phantom-tunnel:client | Debian | ~80MB |
| phantom-tunnel:server-alpine | Alpine | ~15MB |
| phantom-tunnel:client-alpine | Alpine | ~15MB |
