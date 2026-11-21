#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/bin"
OUT_BIN="$OUT_DIR/airlock-vz-helper"
CACHE_DIR="/tmp/airlock-swift-cache"

mkdir -p "$OUT_DIR" "$CACHE_DIR"

swiftc -O \
  -module-cache-path "$CACHE_DIR" \
  -framework Foundation \
  -framework Virtualization \
  "$SCRIPT_DIR/Sources/main.swift" \
  -o "$OUT_BIN"

codesign --force --sign - \
  --entitlements "$SCRIPT_DIR/entitlements.plist" \
  "$OUT_BIN"

echo "Built and signed: $OUT_BIN"
