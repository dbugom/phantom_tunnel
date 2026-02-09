#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
BUILDER_NAME="phantom-mikrotik"
IMAGE_NAME="phantom-client"

mkdir -p "$OUTPUT_DIR"

# Map CLI argument to Docker platform string
arch_to_platform() {
    case "$1" in
        arm64)  echo "linux/arm64" ;;
        armv7)  echo "linux/arm/v7" ;;
        amd64)  echo "linux/amd64" ;;
        *)
            echo "Unknown architecture: $1"
            echo "Usage: $0 [arm64|armv7|amd64]"
            echo "  No arguments builds all three architectures"
            exit 1
            ;;
    esac
}

# Build a single architecture
build_arch() {
    local arch="$1"
    local platform
    platform=$(arch_to_platform "$arch")
    local output_file="$OUTPUT_DIR/$IMAGE_NAME-${arch}.tar"

    echo "========================================="
    echo "Building $IMAGE_NAME for $arch ($platform)"
    echo "========================================="

    docker buildx build \
        --builder "$BUILDER_NAME" \
        --file "$PROJECT_DIR/Dockerfile.mikrotik" \
        --platform "$platform" \
        --tag "$IMAGE_NAME:$arch" \
        --output "type=docker,dest=$output_file" \
        "$PROJECT_DIR"

    local size
    size=$(du -h "$output_file" | cut -f1)
    echo "Built: $output_file ($size)"
}

# Ensure buildx builder exists
ensure_builder() {
    if ! docker buildx inspect "$BUILDER_NAME" >/dev/null 2>&1; then
        echo "Creating buildx builder: $BUILDER_NAME"
        docker buildx create --name "$BUILDER_NAME" --driver docker-container --use
    else
        docker buildx use "$BUILDER_NAME"
    fi
}

ensure_builder

if [ $# -eq 0 ]; then
    # Build all architectures
    for arch in arm64 armv7 amd64; do
        build_arch "$arch"
    done
    echo ""
    echo "All builds complete. Output files:"
    ls -lh "$OUTPUT_DIR"/*.tar
else
    # Build specified architectures
    for arch in "$@"; do
        build_arch "$arch"
    done
fi
