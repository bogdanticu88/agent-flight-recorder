#!/usr/bin/env bash
# Cross-compile afr for every platform the fleet runs. Pure Go (no cgo), so
# one Linux box builds them all.
set -euo pipefail
cd "$(dirname "$0")"
VERSION=$(grep -oP 'const Version = "\K[^"]+' internal/core/event.go)
rm -rf dist && mkdir -p dist
for target in windows/amd64 windows/arm64 darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
  os=${target%/*}; arch=${target#*/}
  ext=""; [ "$os" = windows ] && ext=".exe"
  out="dist/afr-${VERSION}-${os}-${arch}${ext}"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "$out" .
  echo "built $out"
done
(cd dist && sha256sum afr-* > SHA256SUMS)
echo "checksums in dist/SHA256SUMS"
