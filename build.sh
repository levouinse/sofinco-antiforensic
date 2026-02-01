#!/bin/bash

# SOFINCO Anti-Forensic Toolkit - Build Script
# Author: sofinco
# Version: 2.0.0

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         SOFINCO ANTI-FORENSIC TOOLKIT v2.0.0             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "✗ Cargo not found. Please install Rust:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

echo "✓ Rust toolchain found"
echo ""

# Build main Rust tool
echo "Building main toolkit..."
cargo build --release

if [ $? -eq 0 ]; then
    echo "✓ Build successful!"
    echo ""
    echo "Binary location: target/release/sofinco-antiforensic"
    echo ""
    echo "To install system-wide:"
    echo "  sudo cp target/release/sofinco-antiforensic /usr/local/bin/"
    echo ""
    echo "To run:"
    echo "  ./target/release/sofinco-antiforensic --help"
else
    echo "✗ Build failed"
    exit 1
fi

# Optional: Build kernel module
if [ -d "silk-guardian" ]; then
    echo ""
    read -p "Build silk-guardian kernel module? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd silk-guardian
        make
        echo "✓ Kernel module built: silk-guardian/silk.ko"
        cd ..
    fi
fi

echo ""
echo "Build complete!"
