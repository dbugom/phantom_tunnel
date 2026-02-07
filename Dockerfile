# Phantom Tunnel - Multi-stage Docker Build
# Builds both server and client binaries in a minimal container

# ============================================
# Stage 1: Build environment
# ============================================
FROM rust:1.75-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src to cache dependencies
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/server.rs && \
    echo "fn main() {}" > src/bin/client.rs && \
    echo "pub const VERSION: &str = \"0.1.0\";" > src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src target/release/phantom-*

# Copy actual source code
COPY src ./src

# Build the actual binaries
RUN cargo build --release --bin phantom-server --bin phantom-client

# ============================================
# Stage 2: Server runtime
# ============================================
FROM debian:bookworm-slim AS server

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false phantom

WORKDIR /app

# Copy server binary
COPY --from=builder /build/target/release/phantom-server /app/

# Copy example config
COPY examples/server.config.toml /app/config.toml

# Create log directory
RUN mkdir -p /var/log/phantom_tunnel && \
    chown phantom:phantom /var/log/phantom_tunnel

# Set ownership
RUN chown -R phantom:phantom /app

USER phantom

# Default port
EXPOSE 443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD pgrep phantom-server || exit 1

ENTRYPOINT ["/app/phantom-server"]
CMD ["-c", "/app/config.toml"]

# ============================================
# Stage 3: Client runtime
# ============================================
FROM debian:bookworm-slim AS client

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false phantom

WORKDIR /app

# Copy client binary
COPY --from=builder /build/target/release/phantom-client /app/

# Copy example config
COPY examples/client.config.toml /app/config.toml

# Set ownership
RUN chown -R phantom:phantom /app

USER phantom

# SOCKS5 and HTTP proxy ports
EXPOSE 1080 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD pgrep phantom-client || exit 1

ENTRYPOINT ["/app/phantom-client"]
CMD ["-c", "/app/config.toml"]
