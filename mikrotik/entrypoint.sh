#!/bin/sh
set -e

CONFIG_PATH="/config/config.toml"

# If a bind-mounted config exists, use it directly
if [ -f "$CONFIG_PATH" ]; then
    echo "Using bind-mounted config at $CONFIG_PATH"
    exec /phantom-client --config "$CONFIG_PATH"
fi

# Otherwise, generate config from environment variables
echo "No config file found, generating from environment variables..."

# Validate required environment variables
missing=""
[ -z "$PHANTOM_SERVER" ] && missing="$missing PHANTOM_SERVER"
[ -z "$PHANTOM_SERVER_PUBKEY" ] && missing="$missing PHANTOM_SERVER_PUBKEY"
[ -z "$PHANTOM_PRIVATE_KEY" ] && missing="$missing PHANTOM_PRIVATE_KEY"
[ -z "$PHANTOM_PUBLIC_KEY" ] && missing="$missing PHANTOM_PUBLIC_KEY"

if [ -n "$missing" ]; then
    echo "ERROR: Missing required environment variables:$missing"
    echo ""
    echo "Required variables:"
    echo "  PHANTOM_SERVER         - Server address (e.g. 1.2.3.4:443)"
    echo "  PHANTOM_SERVER_PUBKEY  - Server public key (base64)"
    echo "  PHANTOM_PRIVATE_KEY    - Client private key (base64)"
    echo "  PHANTOM_PUBLIC_KEY     - Client public key (base64)"
    echo ""
    echo "Optional variables:"
    echo "  PHANTOM_SOCKS5_LISTEN  - SOCKS5 listen address (default: 0.0.0.0:1080)"
    echo "  PHANTOM_HTTP_LISTEN    - HTTP proxy listen address (default: 0.0.0.0:8080)"
    echo "  PHANTOM_TLS_SNI        - TLS SNI hostname for DPI camouflage"
    echo "  PHANTOM_TLS_PROFILE    - TLS fingerprint profile (default: chrome)"
    echo "  PHANTOM_ENABLE_PADDING - Enable traffic padding (default: true)"
    echo "  PHANTOM_LOG_LEVEL      - Log level: trace/debug/info/warn/error (default: info)"
    exit 1
fi

# Defaults
SOCKS5_LISTEN="${PHANTOM_SOCKS5_LISTEN:-0.0.0.0:1080}"
HTTP_LISTEN="${PHANTOM_HTTP_LISTEN:-0.0.0.0:8080}"
TLS_PROFILE="${PHANTOM_TLS_PROFILE:-chrome}"
ENABLE_PADDING="${PHANTOM_ENABLE_PADDING:-true}"
LOG_LEVEL="${PHANTOM_LOG_LEVEL:-info}"

# Create config directory if needed
mkdir -p /config

# Generate config.toml
cat > "$CONFIG_PATH" <<EOF
[client]
server = "${PHANTOM_SERVER}"
server_public_key = "${PHANTOM_SERVER_PUBKEY}"
private_key = "${PHANTOM_PRIVATE_KEY}"
public_key = "${PHANTOM_PUBLIC_KEY}"
socks5_listen = "${SOCKS5_LISTEN}"
http_listen = "${HTTP_LISTEN}"
tls_profile = "${TLS_PROFILE}"
enable_padding = ${ENABLE_PADDING}
EOF

# Add optional TLS SNI if set
if [ -n "$PHANTOM_TLS_SNI" ]; then
    echo "tls_sni = \"${PHANTOM_TLS_SNI}\"" >> "$CONFIG_PATH"
fi

# Add logging section
cat >> "$CONFIG_PATH" <<EOF

[logging]
level = "${LOG_LEVEL}"
format = "compact"
EOF

echo "Generated config at $CONFIG_PATH"
exec /phantom-client --config "$CONFIG_PATH"
