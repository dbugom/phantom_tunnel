#!/usr/bin/env bash
#
# Phantom Tunnel — Identity-preserving server RESTORE
# ---------------------------------------------------
# Rebuild a phantom-tunnel server on a FRESH Ubuntu box from a backup tarball
# produced by deploy/backup-server.sh, REUSING the original server keypair so
# every existing client (macOS, MikroTik, ...) keeps working with zero changes.
#
# vs `setup.sh server` (which generates a NEW keypair): this restores the exact
# private_key + allowed_clients AND rebuilds the exact deployed commit (from the
# git bundle in the backup, so it does not depend on GitHub or a mutable branch).
#
# Usage (run as root on the new server):
#   ./restore-server.sh --backup phantom-decommission-*.tar.gz --domain phantom.yfy.ae
#
# Options:
#   --backup <file>     Backup tarball from backup-server.sh (required)
#   --domain <fqdn>     TLS domain; DNS A record must already point here (required)
#   --cert reissue      Fresh Let's Encrypt cert via certbot (default)
#   --cert restore      Reuse the backup's cert (falls back to reissue if <30d left)
#   --ref <sha|branch>  Code version to build (default: the exact commit from the backup)
#   --install-dir <dir> Source/build dir (default: /opt/phantom_tunnel)
#   --skip-deps         Skip apt + rustup install (already provisioned)
#
# PREREQUISITE: point the domain's DNS A record at this server BEFORE running.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
step()  { echo -e "${GREEN}==>${NC} $1"; }
info()  { echo -e "${BLUE}   $1${NC}"; }
warn()  { echo -e "${YELLOW}Warning:${NC} $1"; }
error() { echo -e "${RED}Error:${NC} $1"; exit 1; }

BACKUP=""; DOMAIN=""; CERT_MODE="reissue"; REF_OVERRIDE=""
BRANCH="release/stable-v2"; INSTALL_DIR="/opt/phantom_tunnel"
CONFIG_PATH="/etc/phantom_tunnel/config.toml"; SKIP_DEPS=false
REPO_URL="https://github.com/dbugom/phantom_tunnel.git"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backup)      BACKUP="$2"; shift 2 ;;
    --domain)      DOMAIN="$2"; shift 2 ;;
    --cert)        CERT_MODE="$2"; shift 2 ;;
    --ref)         REF_OVERRIDE="$2"; shift 2 ;;
    --branch)      BRANCH="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --skip-deps)   SKIP_DEPS=true; shift ;;
    *) warn "unknown option: $1"; shift ;;
  esac
done

[ "$EUID" -eq 0 ] || error "must run as root (needs :443, certbot, systemd)"
[ -n "$BACKUP" ] && [ -f "$BACKUP" ] || error "--backup <tarball> is required and must exist"
[ -n "$DOMAIN" ] || error "--domain <fqdn> is required"

echo "=== Phantom Tunnel restore: domain=$DOMAIN cert=$CERT_MODE ==="

# ── 1. Unpack backup + locate pieces ──
step "Unpacking backup..."
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
tar -xzf "$BACKUP" -C "$WORK"
SRC="$(find "$WORK" -maxdepth 1 -type d -name 'phantom-decommission-*' 2>/dev/null | head -1 || true)"
[ -n "$SRC" ] || error "backup does not contain a phantom-decommission-* directory"
BK_CONFIG="$(find "$SRC/config" -name config.toml -path '*phantom_tunnel*' ! -path '*example*' 2>/dev/null | head -1 || true)"
[ -n "$BK_CONFIG" ] && [ -f "$BK_CONFIG" ] || error "server config.toml not found inside backup"
BUNDLE="$SRC/phantom_tunnel.gitbundle"

# Pin the code version: --ref, else the exact deployed SHA recorded in the backup, else branch.
PIN_REF="$REF_OVERRIDE"
[ -z "$PIN_REF" ] && PIN_REF="$(awk 'NR>=2 && $1 ~ /^[0-9a-f]{40}$/ {print $1; exit}' "$SRC/deployed-git-ref.txt" 2>/dev/null || true)"
[ -z "$PIN_REF" ] && PIN_REF="$BRANCH"
info "backup at $SRC ; building code ref: $PIN_REF"

# ── 2. System deps + Rust ──
if [ "$SKIP_DEPS" = false ]; then
  step "Installing dependencies..."
  apt-get update -qq
  apt-get install -y -qq curl build-essential pkg-config libssl-dev git certbot nginx openssl >/dev/null
fi
if ! command -v cargo >/dev/null 2>&1; then
  step "Installing Rust..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null 2>&1
fi
# shellcheck disable=SC1090,SC1091
source "$HOME/.cargo/env" 2>/dev/null || true

# ── 3. Get the source at the pinned commit (prefer the offline bundle) ──
if [ -d "$INSTALL_DIR/.git" ]; then
  step "Updating existing repo in $INSTALL_DIR to $PIN_REF..."
  git -C "$INSTALL_DIR" fetch --all --quiet || true
  [ -f "$BUNDLE" ] && git -C "$INSTALL_DIR" fetch "$BUNDLE" '*:*' --quiet 2>/dev/null || true
  git -C "$INSTALL_DIR" checkout --detach "$PIN_REF"
elif [ -f "$BUNDLE" ]; then
  step "Cloning from the backup's git bundle (GitHub-independent)..."
  git clone --no-checkout "$BUNDLE" "$INSTALL_DIR"
  git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL" 2>/dev/null || true
  git -C "$INSTALL_DIR" checkout --detach "$PIN_REF"
else
  step "Cloning from GitHub..."
  git clone "$REPO_URL" "$INSTALL_DIR"
  git -C "$INSTALL_DIR" checkout --detach "$PIN_REF"
fi
step "Building release binary (may take a few minutes)..."
( cd "$INSTALL_DIR" && cargo build --release 2>&1 | tail -1 )
[ -x "$INSTALL_DIR/target/release/phantom-server" ] || error "build did not produce phantom-server"

# ── 4. Restore server config (SAME keypair + allowed_clients) ──
step "Restoring server config (preserving keypair + authorized clients)..."
mkdir -p "$(dirname "$CONFIG_PATH")"
cp "$BK_CONFIG" "$CONFIG_PATH"
sed -i -E "s#(tls_cert[[:space:]]*=[[:space:]]*\").*(\")#\1/etc/letsencrypt/live/$DOMAIN/fullchain.pem\2#" "$CONFIG_PATH"
sed -i -E "s#(tls_key[[:space:]]*=[[:space:]]*\").*(\")#\1/etc/letsencrypt/live/$DOMAIN/privkey.pem\2#" "$CONFIG_PATH"
grep -qE '^[[:space:]]*tls_cert' "$CONFIG_PATH" \
  || error "restored config has no tls_cert — server would run WITHOUT TLS and every client would fail"
PUB="$(grep -E '^[[:space:]]*public_key' "$CONFIG_PATH" 2>/dev/null | head -1 | sed -E 's/.*"([^"]*)".*/\1/' || true)"
info "restored config → $CONFIG_PATH (server public key: ${PUB:-unknown})"

# ── 5. TLS certificate ──
LIVE_FC="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
issue_cert() {
  info "DNS A record for $DOMAIN must point here; freeing :80 for validation"
  systemctl stop nginx apache2 2>/dev/null || true
  certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email
}
if [ "$CERT_MODE" = "restore" ]; then
  step "Restoring Let's Encrypt certs from backup..."
  [ -d "$SRC/letsencrypt" ] || error "no letsencrypt/ in backup to restore"
  mkdir -p /etc/letsencrypt
  cp -a "$SRC/letsencrypt/." /etc/letsencrypt/
  if [ ! -e "$LIVE_FC" ] && [ -d "/etc/letsencrypt/archive/$DOMAIN" ]; then
    mkdir -p "/etc/letsencrypt/live/$DOMAIN"
    for f in cert chain fullchain privkey; do
      latest="$(ls -1v "/etc/letsencrypt/archive/$DOMAIN/${f}"*.pem 2>/dev/null | tail -1 || true)"
      [ -n "$latest" ] && ln -sf "$latest" "/etc/letsencrypt/live/$DOMAIN/${f}.pem"
    done
  fi
  # A restored cert may be near expiry; if <30d left (or missing/broken), reissue.
  if openssl x509 -in "$LIVE_FC" -noout -checkend $((30*86400)) >/dev/null 2>&1; then
    info "restored cert is valid for >30 days"
  else
    warn "restored cert missing or expiring within 30 days — reissuing fresh"
    issue_cert
  fi
else
  step "Obtaining fresh Let's Encrypt cert for $DOMAIN..."
  issue_cert
fi
[ -e "$LIVE_FC" ] || error "no cert at $LIVE_FC after cert step — aborting before starting a broken server"

# ── 6. Kernel tuning ──
step "Applying kernel tuning..."
if [ -f "$SRC/network/99-phantom-tunnel.conf" ]; then
  cp "$SRC/network/99-phantom-tunnel.conf" /etc/sysctl.d/99-phantom-tunnel.conf
  sysctl --system >/dev/null 2>&1 || true
elif [ -f "$INSTALL_DIR/scripts/server-sysctl.sh" ]; then
  bash "$INSTALL_DIR/scripts/server-sysctl.sh" || true
fi

# ── 7. systemd service (rewrite ExecStart to the ACTUAL install dir / config) ──
step "Installing systemd service..."
if [ -f "$SRC/systemd/phantom-tunnel.service" ]; then
  cp "$SRC/systemd/phantom-tunnel.service" /etc/systemd/system/phantom-tunnel.service
  sed -i "s#^ExecStart=.*#ExecStart=$INSTALL_DIR/target/release/phantom-server -c $CONFIG_PATH#" \
    /etc/systemd/system/phantom-tunnel.service
else
  cat > /etc/systemd/system/phantom-tunnel.service <<EOF
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
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=/var/log
ReadWritePaths=/etc/letsencrypt

[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload
systemctl enable phantom-tunnel >/dev/null 2>&1

# ── 8. Renewal hooks that COEXIST with nginx on :80 ──
# certbot for this domain is standalone (needs :80); nginx also holds :80. Free it
# during renewal, then bring nginx back and reload the tunnel's cert.
step "Installing renewal hooks (free :80 for standalone renewal)..."
mkdir -p /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post
printf '#!/bin/bash\nsystemctl stop nginx\n'                           > /etc/letsencrypt/renewal-hooks/pre/stop-nginx.sh
printf '#!/bin/bash\nsystemctl start nginx\nsystemctl restart phantom-tunnel\n' > /etc/letsencrypt/renewal-hooks/post/phantom-restart.sh
chmod +x /etc/letsencrypt/renewal-hooks/pre/stop-nginx.sh /etc/letsencrypt/renewal-hooks/post/phantom-restart.sh

# ── 9. Start decoy (:80) + tunnel (:443) ──
step "Starting services..."
systemctl enable --now nginx >/dev/null 2>&1 || warn "nginx not started (optional :80 decoy)"
systemctl restart phantom-tunnel
sleep 2

# ── 10. Verify it actually serves TLS (not a silent raw-TCP fallback) ──
if ! systemctl is-active --quiet phantom-tunnel; then
  error "phantom-tunnel failed to start — check: journalctl -u phantom-tunnel -n 40"
fi
if echo | openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" 2>/dev/null \
     | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
  TLS_OK="TLS handshake OK, cert valid"
else
  TLS_OK="WARNING: could not verify TLS on :443 — check journalctl and 'openssl s_client -connect $DOMAIN:443'"
fi

echo
echo -e "${GREEN}=== RESTORE COMPLETE — phantom-tunnel is RUNNING ===${NC}"
echo "  domain:            $DOMAIN"
echo "  code ref built:    $PIN_REF"
echo "  config:            $CONFIG_PATH"
echo "  server public key: ${PUB:-<see config>}"
echo "  $TLS_OK"
echo
echo "  Existing clients need NO changes — same server key. If the server IP"
echo "  changed, update ONLY each client's 'server = <newIP>:443' line."
echo "  Logs: journalctl -u phantom-tunnel -f"
