#!/bin/bash
# Installs the restic HardyOS pins (os/live/config/hooks/normal/0160-restic.hook.chroot)
# for tests: CI and development machines. Usage: scripts/install-restic.sh [dest]
set -euo pipefail

RESTIC_VERSION=0.18.1
DEST=${1:-/usr/local/bin/restic}
case "$(uname -m)" in
  x86_64) arch=amd64 sum=680838f19d67151adba227e1570cdd8af12c19cf1735783ed1ba928bc41f363d ;;
  aarch64) arch=arm64 sum=87f53fddde38764095e9c058a3b31834052c37e5826d2acf34e18923c006bd45 ;;
  *) echo "no pinned restic for $(uname -m)" >&2; exit 1 ;;
esac
file="restic_${RESTIC_VERSION}_linux_${arch}.bz2"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/$file" "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/${file}"
echo "$sum  $tmp/$file" | sha256sum -c -
bunzip2 "$tmp/$file"
install -m 0755 "$tmp/restic_${RESTIC_VERSION}_linux_${arch}" "$DEST"
"$DEST" version
