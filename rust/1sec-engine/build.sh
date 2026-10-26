#!/usr/bin/env bash
# Build the 1SEC Rust engine.
# Usage:
#   ./build.sh              # Build with default features (includes pcap)
#   ./build.sh --no-pcap    # Build without pcap (no libpcap dependency)
#   ./build.sh --all        # Build with all active features (includes pcap)

set -euo pipefail

cd "$(dirname "$0")"

FEATURES="default"

for arg in "$@"; do
    case "$arg" in
        --no-pcap)
            FEATURES="--no-default-features"
            ;;
        --all)
            FEATURES="--all-features"
            ;;
        --help|-h)
            echo "Usage: $0 [--no-pcap|--all]"
            echo "  --no-pcap  Build without libpcap dependency"
            echo "  --all      Build with all active features (pcap)"
            exit 0
            ;;
    esac
done

echo "Building 1sec-engine..."

if [ "$FEATURES" = "default" ]; then
    cargo build --release
elif [ "$FEATURES" = "--all-features" ]; then
    cargo build --release --all-features
else
    cargo build --release $FEATURES
fi

BINARY="target/release/1sec-engine"
if [ -f "$BINARY" ]; then
    SIZE=$(du -h "$BINARY" | cut -f1)
    echo "✓ Built: $BINARY ($SIZE)"
    echo ""
    echo "To install system-wide:"
    echo "  sudo cp $BINARY /usr/local/bin/1sec-engine"
    echo ""
    echo "Or enable in 1SEC config:"
    echo "  rust_engine:"
    echo "    enabled: true"
    echo "    binary: \"$(realpath $BINARY)\""
fi
