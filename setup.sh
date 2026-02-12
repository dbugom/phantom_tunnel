#!/bin/bash

# Phantom Tunnel — Automated Setup Script
# Handles full server deployment or client configuration on a fresh machine.
#
# Server: ./setup.sh server --domain phantom.yfy.ae
# Client: ./setup.sh client --server-ip 1.2.3.4 --server-key "base64key..."

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

step()  { echo -e "${GREEN}==>${NC} $1"; }
info()  { echo -e "${BLUE}   $1${NC}"; }
warn()  { echo -e "${YELLOW}Warning: $1${NC}"; }
error() { echo -e "${RED}Error: $1${NC}"; exit 1; }

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║              PHANTOM TUNNEL SETUP                        ║"
    echo "║         Secure, Censorship-Resistant Tunneling           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ============================================================
# SERVER SETUP
# ============================================================

setup_server() {
    local DOMAIN=""
    local LISTEN="0.0.0.0:443"
    local CLIENT_PUBKEY=""
    local CONFIG_PATH="/etc/phantom_tunnel/config.toml"
    local BRANCH="release/stable-v2"
    local INSTALL_DIR="/opt/phantom_tunnel"
    local SKIP_DEPS=false
    local SKIP_TLS=false

    # Parse args
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)       DOMAIN="$2"; shift 2 ;;
            --listen)       LISTEN="$2"; shift 2 ;;
            --client-key)   CLIENT_PUBKEY="$2"; shift 2 ;;
            --config)       CONFIG_PATH="$2"; shift 2 ;;
            --branch)       BRANCH="$2"; shift 2 ;;
            --install-dir)  INSTALL_DIR="$2"; shift 2 ;;
            --skip-deps)    SKIP_DEPS=true; shift ;;
            --skip-tls)     SKIP_TLS=true; shift ;;
            *) warn "Unknown option: $1"; shift ;;
        esac
    done

    print_banner
    echo "Mode: SERVER"
    echo ""

    # Check root
    if [ "$EUID" -ne 0 ]; then
        error "Server setup must be run as root (need port 443, certbot, systemd)"
    fi

    # ── 1. Install system dependencies ──
    if [ "$SKIP_DEPS" = false ]; then
        step "Installing system dependencies..."
        apt update -qq
        apt install -y -qq curl build-essential pkg-config libssl-dev git certbot > /dev/null 2>&1
        info "Dependencies installed"
    else
        step "Skipping dependency installation (--skip-deps)"
    fi

    # ── 2. Install Rust (if not present) ──
    if ! command -v cargo &> /dev/null; then
        step "Installing Rust toolchain..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1
        source "$HOME/.cargo/env"
        info "Rust installed"
    else
        step "Rust already installed ($(rustc --version))"
    fi

    # ── 3. TLS certificate ──
    if [ "$SKIP_TLS" = false ]; then
        if [ -z "$DOMAIN" ]; then
            echo ""
            read -p "Enter domain name (e.g., phantom.yfy.ae): " DOMAIN
            [ -z "$DOMAIN" ] && error "Domain is required for TLS certificate"
        fi

        if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
            step "TLS certificate already exists for $DOMAIN"
        else
            step "Obtaining TLS certificate for $DOMAIN..."
            info "Make sure DNS A record points to this server and port 80 is open"
            echo ""

            # Stop anything on port 80
            systemctl stop nginx 2>/dev/null || true
            systemctl stop apache2 2>/dev/null || true

            certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email
            info "Certificate obtained"
        fi
    else
        step "Skipping TLS setup (--skip-tls)"
    fi

    # ── 4. Clone/update repo and build ──
    if [ -d "$INSTALL_DIR/.git" ]; then
        step "Updating existing repo in $INSTALL_DIR..."
        cd "$INSTALL_DIR"
        git fetch origin
        git checkout "$BRANCH"
        git pull origin "$BRANCH"
    else
        step "Cloning phantom_tunnel to $INSTALL_DIR..."
        git clone https://github.com/dbugom/phantom_tunnel.git "$INSTALL_DIR"
        cd "$INSTALL_DIR"
        git checkout "$BRANCH"
    fi

    step "Building release binary (this may take a few minutes)..."
    source "$HOME/.cargo/env" 2>/dev/null || true
    cargo build --release 2>&1 | tail -1
    info "Build complete"

    # ── 5. Generate server keypair ──
    step "Generating server keypair..."
    KEYGEN_OUTPUT=$(./target/release/phantom-server --generate-key 2>&1)

    # Extract keys (format may vary — try multiple patterns)
    SERVER_PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | grep -i "private" | grep -oE '[A-Za-z0-9+/=]{32,}' | head -1)
    SERVER_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | grep -i "public" | grep -oE '[A-Za-z0-9+/=]{32,}' | head -1)

    if [ -z "$SERVER_PRIVATE_KEY" ] || [ -z "$SERVER_PUBLIC_KEY" ]; then
        # Fallback: try line-after-label extraction
        SERVER_PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | grep -A1 "PRIVATE" | tail -1 | tr -d ' ║│|')
        SERVER_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | grep -A1 "PUBLIC" | tail -1 | tr -d ' ║│|')
    fi

    [ -z "$SERVER_PRIVATE_KEY" ] && error "Failed to extract server private key from:\n$KEYGEN_OUTPUT"
    [ -z "$SERVER_PUBLIC_KEY" ] && error "Failed to extract server public key from:\n$KEYGEN_OUTPUT"

    echo ""
    echo -e "  ${YELLOW}Server Public Key: $SERVER_PUBLIC_KEY${NC}"
    echo -e "  ${BLUE}(Give this to clients)${NC}"
    echo ""

    # ── 6. Get client public key ──
    if [ -z "$CLIENT_PUBKEY" ]; then
        echo -e "${CYAN}Enter client public key(s) to authorize:${NC}"
        info "Press Enter on empty line when done"
        ALLOWED_CLIENTS_TOML=""
        while true; do
            read -p "  Client public key: " KEY
            [ -z "$KEY" ] && break
            ALLOWED_CLIENTS_TOML="${ALLOWED_CLIENTS_TOML}    \"$KEY\",
"
        done
    else
        ALLOWED_CLIENTS_TOML="    \"$CLIENT_PUBKEY\",
"
    fi

    # ── 7. Write server config ──
    step "Writing config to $CONFIG_PATH..."
    mkdir -p "$(dirname "$CONFIG_PATH")"

    TLS_CONFIG=""
    if [ "$SKIP_TLS" = false ] && [ -n "$DOMAIN" ]; then
        TLS_CONFIG="
# TLS certificates (Let's Encrypt)
tls_cert = \"/etc/letsencrypt/live/$DOMAIN/fullchain.pem\"
tls_key = \"/etc/letsencrypt/live/$DOMAIN/privkey.pem\""
    fi

    cat > "$CONFIG_PATH" << EOF
# Phantom Tunnel Server Configuration
# Generated by setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)

[server]
listen = "$LISTEN"

# Server keypair
private_key = "$SERVER_PRIVATE_KEY"
public_key = "$SERVER_PUBLIC_KEY"

# Authorized client public keys
allowed_clients = [
$ALLOWED_CLIENTS_TOML]

# Max concurrent connections
max_connections = 1000
$TLS_CONFIG
[logging]
level = "info"
format = "pretty"
EOF

    info "Config written"

    # ── 8. Kernel tuning ──
    step "Applying kernel tuning (BBR, buffers)..."
    if [ -f "$INSTALL_DIR/scripts/server-sysctl.sh" ]; then
        bash "$INSTALL_DIR/scripts/server-sysctl.sh"
    else
        warn "server-sysctl.sh not found, skipping kernel tuning"
    fi

    # ── 9. Create systemd service ──
    step "Creating systemd service..."
    cat > /etc/systemd/system/phantom-tunnel.service << EOF
[Unit]
Description=Phantom Tunnel Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/target/release/phantom-server -c $CONFIG_PATH
Restart=always
RestartSec=5
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=/var/log
ReadWritePaths=/etc/letsencrypt

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable phantom-tunnel
    info "Systemd service created and enabled"

    # ── 10. Certbot auto-renew hook ──
    if [ "$SKIP_TLS" = false ] && [ -n "$DOMAIN" ]; then
        step "Setting up certificate auto-renewal hook..."
        mkdir -p /etc/letsencrypt/renewal-hooks/post
        cat > /etc/letsencrypt/renewal-hooks/post/phantom-tunnel.sh << 'EOF'
#!/bin/bash
systemctl restart phantom-tunnel
EOF
        chmod +x /etc/letsencrypt/renewal-hooks/post/phantom-tunnel.sh
        info "Certbot will restart phantom-tunnel after cert renewal"
    fi

    # ── 11. Start the service ──
    step "Starting phantom-tunnel service..."
    systemctl start phantom-tunnel
    sleep 2

    if systemctl is-active --quiet phantom-tunnel; then
        echo ""
        echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  SERVER SETUP COMPLETE${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "  Status:      ${GREEN}RUNNING${NC}"
        echo -e "  Listening:   ${CYAN}$LISTEN${NC}"
        [ -n "$DOMAIN" ] && echo -e "  Domain:      ${CYAN}$DOMAIN${NC}"
        echo -e "  Config:      ${CYAN}$CONFIG_PATH${NC}"
        echo -e "  Service:     ${CYAN}phantom-tunnel.service${NC}"
        echo ""
        echo -e "  ${YELLOW}Server Public Key (give to clients):${NC}"
        echo -e "  ${YELLOW}$SERVER_PUBLIC_KEY${NC}"
        echo ""
        echo "  Useful commands:"
        echo -e "    ${CYAN}systemctl status phantom-tunnel${NC}    — check status"
        echo -e "    ${CYAN}journalctl -u phantom-tunnel -f${NC}   — view logs"
        echo -e "    ${CYAN}systemctl restart phantom-tunnel${NC}  — restart"
        echo ""
    else
        warn "Service failed to start. Check logs:"
        echo -e "  ${CYAN}journalctl -u phantom-tunnel -n 20${NC}"
    fi
}

# ============================================================
# CLIENT SETUP
# ============================================================

setup_client() {
    local SERVER_IP=""
    local SERVER_PUBKEY=""
    local DOMAIN="phantom.yfy.ae"
    local SOCKS5="127.0.0.1:1080"
    local HTTP="127.0.0.1:8080"
    local TLS_PROFILE="chrome"
    local CONFIG_PATH="client.toml"
    local BRANCH="release/stable-v2"
    local SKIP_BUILD=false

    # Parse args
    while [[ $# -gt 0 ]]; do
        case $1 in
            --server-ip)    SERVER_IP="$2"; shift 2 ;;
            --server-key)   SERVER_PUBKEY="$2"; shift 2 ;;
            --domain)       DOMAIN="$2"; shift 2 ;;
            --socks5)       SOCKS5="$2"; shift 2 ;;
            --http)         HTTP="$2"; shift 2 ;;
            --profile)      TLS_PROFILE="$2"; shift 2 ;;
            --config)       CONFIG_PATH="$2"; shift 2 ;;
            --branch)       BRANCH="$2"; shift 2 ;;
            --skip-build)   SKIP_BUILD=true; shift ;;
            *) warn "Unknown option: $1"; shift ;;
        esac
    done

    print_banner
    echo "Mode: CLIENT"
    echo ""

    # ── 1. Install Rust if needed ──
    if ! command -v cargo &> /dev/null; then
        step "Installing Rust toolchain..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1
        source "$HOME/.cargo/env"
        info "Rust installed"
    else
        step "Rust already installed ($(rustc --version))"
    fi

    # ── 2. Build if needed ──
    if [ "$SKIP_BUILD" = false ]; then
        if [ ! -f "./target/release/phantom-client" ]; then
            step "Building release binary..."
            source "$HOME/.cargo/env" 2>/dev/null || true
            cargo build --release 2>&1 | tail -1
            info "Build complete"
        else
            step "Binary already exists (./target/release/phantom-client)"
        fi
    fi

    # ── 3. Gather required info ──
    if [ -z "$SERVER_IP" ]; then
        read -p "Server IP address: " SERVER_IP
        [ -z "$SERVER_IP" ] && error "Server IP is required"
    fi

    if [ -z "$SERVER_PUBKEY" ]; then
        read -p "Server public key: " SERVER_PUBKEY
        [ -z "$SERVER_PUBKEY" ] && error "Server public key is required"
    fi

    # ── 4. Generate client keypair ──
    step "Generating client keypair..."
    source "$HOME/.cargo/env" 2>/dev/null || true
    KEYGEN_OUTPUT=$(./target/release/phantom-client --generate-key 2>&1)

    CLIENT_PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | grep -i "private" | grep -oE '[A-Za-z0-9+/=]{32,}' | head -1)
    CLIENT_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | grep -i "public" | grep -oE '[A-Za-z0-9+/=]{32,}' | head -1)

    if [ -z "$CLIENT_PRIVATE_KEY" ] || [ -z "$CLIENT_PUBLIC_KEY" ]; then
        CLIENT_PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | grep -A1 "PRIVATE" | tail -1 | tr -d ' ║│|')
        CLIENT_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | grep -A1 "PUBLIC" | tail -1 | tr -d ' ║│|')
    fi

    [ -z "$CLIENT_PRIVATE_KEY" ] && error "Failed to extract client private key"
    [ -z "$CLIENT_PUBLIC_KEY" ] && error "Failed to extract client public key"

    echo ""
    echo -e "  ${YELLOW}Client Public Key: $CLIENT_PUBLIC_KEY${NC}"
    echo -e "  ${BLUE}(Add this to server's allowed_clients)${NC}"
    echo ""

    # ── 5. Write client config ──
    step "Writing config to $CONFIG_PATH..."

    cat > "$CONFIG_PATH" << EOF
# Phantom Tunnel Client Configuration
# Generated by setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)

[client]
# Server to connect to (use IP directly to bypass DNS issues)
server = "$SERVER_IP:443"

# Server's public key
server_public_key = "$SERVER_PUBKEY"

# Client keypair
private_key = "$CLIENT_PRIVATE_KEY"
public_key = "$CLIENT_PUBLIC_KEY"

# Local proxy addresses
socks5_listen = "$SOCKS5"
http_listen = "$HTTP"

# TLS SNI (must match server's TLS certificate domain)
tls_sni = "$DOMAIN"

# TLS fingerprint profile (chrome, firefox, safari, random)
tls_profile = "$TLS_PROFILE"

# Traffic padding
enable_padding = true

[logging]
level = "info"
format = "pretty"
EOF

    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  CLIENT SETUP COMPLETE${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Server:      ${CYAN}$SERVER_IP:443${NC}"
    echo -e "  SNI:         ${CYAN}$DOMAIN${NC}"
    echo -e "  SOCKS5:      ${CYAN}$SOCKS5${NC}"
    echo -e "  HTTP Proxy:  ${CYAN}$HTTP${NC}"
    echo -e "  Config:      ${CYAN}$CONFIG_PATH${NC}"
    echo ""
    echo -e "  ${YELLOW}Client Public Key (add to server config):${NC}"
    echo -e "  ${YELLOW}$CLIENT_PUBLIC_KEY${NC}"
    echo ""
    echo "  To start:"
    echo -e "    ${CYAN}./target/release/phantom-client -c $CONFIG_PATH${NC}"
    echo ""
    echo "  To test:"
    echo -e "    ${CYAN}curl --socks5 $SOCKS5 https://ifconfig.me${NC}"
    echo ""
}

# ============================================================
# USAGE
# ============================================================

usage() {
    echo "Usage: $0 <server|client> [options]"
    echo ""
    echo "Server options:"
    echo "  --domain <domain>      Domain for TLS cert (e.g., phantom.yfy.ae)"
    echo "  --listen <addr>        Listen address (default: 0.0.0.0:443)"
    echo "  --client-key <key>     Client public key to authorize"
    echo "  --config <path>        Config file path (default: /etc/phantom_tunnel/config.toml)"
    echo "  --branch <branch>      Git branch (default: release/stable-v2)"
    echo "  --install-dir <path>   Install directory (default: /opt/phantom_tunnel)"
    echo "  --skip-deps            Skip apt dependency installation"
    echo "  --skip-tls             Skip TLS certificate setup"
    echo ""
    echo "Client options:"
    echo "  --server-ip <ip>       Server IP address"
    echo "  --server-key <key>     Server public key"
    echo "  --domain <domain>      TLS SNI domain (default: phantom.yfy.ae)"
    echo "  --socks5 <addr>        SOCKS5 listen address (default: 127.0.0.1:1080)"
    echo "  --http <addr>          HTTP proxy listen address (default: 127.0.0.1:8080)"
    echo "  --profile <name>       TLS profile: chrome, firefox, safari (default: chrome)"
    echo "  --config <path>        Config file path (default: client.toml)"
    echo "  --branch <branch>      Git branch (default: release/stable-v2)"
    echo "  --skip-build           Skip building the binary"
    echo ""
    echo "Examples:"
    echo "  # Full server setup on fresh VPS:"
    echo "  sudo ./setup.sh server --domain phantom.yfy.ae"
    echo ""
    echo "  # Server with pre-authorized client:"
    echo "  sudo ./setup.sh server --domain phantom.yfy.ae --client-key 'a0GPa0wjlmhTW/k/VMmxzkCZJBHku0LlZdGxdaEd3Gc='"
    echo ""
    echo "  # Client setup:"
    echo "  ./setup.sh client --server-ip 1.2.3.4 --server-key 'kqYJ1U196Lme...'"
    echo ""
}

# ============================================================
# MAIN
# ============================================================

case "${1:-}" in
    server) shift; setup_server "$@" ;;
    client) shift; setup_client "$@" ;;
    -h|--help|help) usage ;;
    *)
        # Interactive mode if no args
        print_banner
        echo "What would you like to set up?"
        echo ""
        echo "  1) Server — fresh VPS deployment"
        echo "  2) Client — connect to a server"
        echo "  3) Help"
        echo ""
        read -p "Select [1-3]: " CHOICE
        case $CHOICE in
            1) setup_server ;;
            2) setup_client ;;
            3) usage ;;
            *) error "Invalid option" ;;
        esac
        ;;
esac
