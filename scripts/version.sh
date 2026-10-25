#!/bin/sh
# Prints a Debian-compatible version for the current checkout.
#   tagged v0.1.0          -> 0.1.0
#   3 commits after v0.1.0 -> 0.1.0+3.g1a2b3c4
#   no tags yet            -> 0.1.0~dev.20261024.g1a2b3c4
# A ".dirty" suffix marks uncommitted changes.
set -e

BASE=0.1.0
dirty=""
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  dirty=".dirty"
fi

if desc=$(git describe --tags --match 'v[0-9]*' 2>/dev/null); then
  # v0.1.0 or v0.1.0-3-g1a2b3c4
  echo "$desc" | sed -E 's/^v//; s/-([0-9]+)-(g[0-9a-f]+)$/+\1.\2/' | sed "s/\$/$dirty/"
else
  hash=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
  echo "${BASE}~dev.$(date -u +%Y%m%d).g${hash}${dirty}"
fi
