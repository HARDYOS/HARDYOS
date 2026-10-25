#!/bin/bash
# Builds the HardyOS live/installer ISO in a privileged Debian 13 container.
# Works in WSL2 (with Docker Desktop or Docker Engine) and on any Linux host.
#
# Usage: os/build-iso.sh            (expects dist/hardyos-core_*.deb from `make deb`)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=${VERSION:-$("$ROOT/scripts/version.sh")}
IMAGE=${IMAGE:-debian:trixie}

if ! command -v docker >/dev/null; then
  echo "Docker is required. In WSL2, install Docker Desktop with WSL integration or Docker Engine." >&2
  exit 1
fi

mkdir -p "$ROOT/dist"
echo "Building HardyOS $VERSION ISO in $IMAGE (this takes 15-40 minutes)..."
docker run --rm --privileged \
  -e VERSION="$VERSION" \
  -v "$ROOT:/src" \
  -v hardyos-live-build:/build \
  "$IMAGE" bash /src/os/build-in-container.sh
