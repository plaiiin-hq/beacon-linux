#!/usr/bin/env bash
set -euo pipefail
# Usage: Scripts/build.sh [version]   →  dist/: static binaries for amd64 and arm64, .deb and .rpm, SHA256SUMS
#
# Reproducible: no cgo, -trimpath, -buildvcs=false (Go would otherwise stamp the git revision of whatever repository it
# runs in into the binary, so a build in a clone differs from one in the original), no build ID, the same Go version, so anyone rebuilding this commit with
# Go $(go env GOVERSION) gets the same bytes and can compare SHA256SUMS. nfpm (MIT) packages; it is a build
# tool only, nothing of it ends up in the binary.
cd "$(dirname "$0")/.."
VERSION="${1:-0.1.0}"
NFPM="github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.1"
rm -rf dist && mkdir -p dist
# With SIGNING_KEY (an armored private key file), the .rpm files are signed too; dnf checks that signature.
CONFIG=nfpm.yaml
if [[ -n "${SIGNING_KEY:-}" ]]; then
    CONFIG=dist/nfpm-signed.yaml
    { cat nfpm.yaml; printf 'rpm:\n  signature:\n    key_file: %s\n' "$SIGNING_KEY"; } > "$CONFIG"
    export NFPM_RPM_PASSPHRASE="${NFPM_RPM_PASSPHRASE:-}"
fi
go vet ./...
go test ./...
# Known vulnerabilities the code actually reaches; a finding stops the build.
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
for ARCH in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "dist/beacon-linux-$ARCH" .
    mkdir -p dist/staging && cp "dist/beacon-linux-$ARCH" dist/staging/beacon
    for FMT in deb rpm; do
        ARCH=$ARCH VERSION=$VERSION go run "$NFPM" package --config "$CONFIG" --packager "$FMT" --target dist/ >/dev/null
    done
done
rm -rf dist/staging dist/nfpm-signed.yaml
(cd dist && shasum -a 256 beacon-linux-* *.deb *.rpm > SHA256SUMS)
echo "built with $(go env GOVERSION):"; cat dist/SHA256SUMS
