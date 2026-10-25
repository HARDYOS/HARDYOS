#!/bin/bash
# Runs inside a privileged debian:trixie container. Called by os/build-iso.sh.
set -euo pipefail

: "${VERSION:?VERSION must be set}"
SRC=/src
WORK=/build/live

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends live-build debootstrap ca-certificates \
  xorriso squashfs-tools mtools dosfstools grub-efi-amd64-bin grub-pc-bin syslinux syslinux-common isolinux \
  >/dev/null

rm -rf "$WORK"
mkdir -p "$WORK"
cp -a "$SRC/os/live/." "$WORK/"
chmod +x "$WORK"/auto/* "$WORK"/config/hooks/normal/*

mkdir -p "$WORK/config/packages.chroot"
shopt -s nullglob
debs=("$SRC"/dist/hardyos-core_"${VERSION}"_amd64.deb)
if [ ${#debs[@]} -eq 0 ]; then
  echo "No hardyos-core ${VERSION} .deb in dist/. Run 'make deb' first." >&2
  exit 1
fi
cp "${debs[@]}" "$WORK/config/packages.chroot/"

cd "$WORK"
lb clean
lb config
lb build

isos=("$WORK"/*.iso)
iso=${isos[0]:?no ISO produced}
out="$SRC/dist/hardyos-${VERSION}-amd64.iso"
mv "$iso" "$out"
sha256sum "$out" > "$out.sha256"
# The system image doubles as the payload of signed update files (make release).
cp "$WORK/binary/live/filesystem.squashfs" "$SRC/dist/hardyos-${VERSION}-amd64.squashfs"
echo "Built $out"
