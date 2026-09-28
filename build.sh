#!/usr/bin/env bash
# Build the cfprobe release binaries reproducibly (Go 1.26.1) into dist/ and print their sha256.
# -buildvcs=false matters: inside a git checkout Go would otherwise embed the commit, and the
# binaries would no longer match the published ones.
# 32-bit ARM is built for ARMv5 (runs on v6 and v7 too), MIPS with software floating point (most
# router SoCs, e.g. MT7621 and ath79, have no FPU).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
for target in linux/amd64 linux/arm64 linux/arm linux/mips linux/mipsle darwin/amd64 darwin/arm64 windows/amd64; do
  os=${target%/*}
  arch=${target#*/}
  out="dist/cfprobe-$os-$arch"
  [ "$os" = windows ] && out="$out.exe"
  (cd echprobe && GOOS=$os GOARCH=$arch GOARM=5 GOMIPS=softfloat CGO_ENABLED=0 \
    go build -buildvcs=false -trimpath -ldflags="-s -w" -o "../$out" .)
done
go version
sha256sum dist/cfprobe-*
