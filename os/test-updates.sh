#!/bin/bash
# Makes signed test updates from a built system image, for VM testing:
#   <version>.next    the same image with hardyd/hardyd-priv/hardyctl rebuilt
#                     as a newer version (a normal update)
#   <version>.broken  the same, but hardyd exits at once (must roll back)
#
# Usage: os/test-updates.sh <rootfs.squashfs> <version> <signing key> <outdir>
# Needs root (unsquashfs keeps ownership), squashfs-tools and Go.
set -euo pipefail
SQ=$1 VERSION=$2 KEY=$3 OUT=$4
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT"
unsquashfs -q -d "$WORK/root" "$SQ"

build() {
  (cd "$ROOT/daemon" && CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/hardyos/hardyos/daemon/internal/version.Version=$1 -X github.com/hardyos/hardyos/daemon/internal/version.Commit=test" \
    -o "$WORK/bin/" ./cmd/hardyd ./cmd/hardyd-priv ./cmd/hardyctl)
}
bundle() {
  (cd "$ROOT/daemon" && go run ./cmd/hardyrelease bundle -key "$KEY" -version "$1" -rootfs "$2" \
    -out "$OUT/hardyos-$1-amd64.hupd" -notes "$3")
}

NEXT="$VERSION.next"
build "$NEXT"
cp "$WORK"/bin/* "$WORK/root/usr/bin/"
mksquashfs "$WORK/root" "$WORK/next.squashfs" -comp gzip -noappend -quiet
bundle "$NEXT" "$WORK/next.squashfs" "Test update: same system, newer version number."
rm -f "$WORK/next.squashfs"

BROKEN="$VERSION.broken"
printf '#!/bin/sh\necho "deliberately broken test build" >&2\nexit 1\n' > "$WORK/root/usr/bin/hardyd"
chmod 755 "$WORK/root/usr/bin/hardyd"
mksquashfs "$WORK/root" "$WORK/broken.squashfs" -comp gzip -noappend -quiet
bundle "$BROKEN" "$WORK/broken.squashfs" "Broken on purpose: hardyd won't start. The server must go back by itself."
ls -la "$OUT"
