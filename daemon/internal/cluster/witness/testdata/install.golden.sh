#!/bin/sh
# HardyOS cluster witness installer (HardyOS 1.8.0).
#
# Run as root on the VPS (plain Ubuntu, already in the cluster's NetBird
# network):   sudo sh hardyos-witness.sh
# Remove it again (after Cluster > Witness > Remove on a member):
#             sudo sh hardyos-witness.sh --remove
#
# This file holds a one-time join code: it works once, for 30 minutes.
# Don't keep or share it.
set -eu

CLUSTER='abcdefghijklmnopqrstuvwxyz'
NODE='witness'
SHA256='0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f'
PORT='44500'
BIN=/usr/local/bin/hardyos-witness
ETC=/etc/hardyos-witness
UNIT=/etc/systemd/system/hardyos-witness.service
DROPIN=/etc/systemd/system/hardyos-witness.service.d
STATE=/var/lib/hardyos-witness

fail() { echo "hardyos-witness: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run this as root (sudo sh $0)"
command -v systemctl >/dev/null || fail "systemd is required"

if [ "${1:-}" = "--remove" ]; then
	systemctl disable --now hardyos-witness.service 2>/dev/null || true
	rm -rf "$UNIT" "$DROPIN" "$ETC" "$BIN"
	rm -rf /var/lib/private/hardyos-witness "$STATE"
	systemctl daemon-reload
	echo "The HardyOS witness is removed."
	exit 0
fi

command -v curl >/dev/null || fail "curl is required (apt install curl)"
command -v sha256sum >/dev/null || fail "sha256sum is required"

# The witness listens on this VPS's NetBird address only.
LISTEN=$(ip -4 -o addr show dev wt0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
[ -n "$LISTEN" ] || fail "this VPS isn't on NetBird (no wt0 address): join it to the cluster's NetBird network first"
# The NetBird network (wt0's prefix, host bits cleared): the only one the
# witness may talk to.
NBNET=$(ip -4 -o addr show dev wt0 2>/dev/null | awk '{split($4, a, "/"); split(a[1], o, "."); p = a[2] + 0;
	ip = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]; s = 2 ^ (32 - p); n = ip - (ip % s);
	printf "%d.%d.%d.%d/%d\n", int(n / 16777216) % 256, int(n / 65536) % 256, int(n / 256) % 256, n % 256, p; exit}')
[ -n "$NBNET" ] || fail "couldn't read the NetBird network of wt0"
# shellcheck disable=SC2018,SC2019 # ASCII on purpose
NAME=$(hostname -s | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-\n' '-' | cut -c1-32)
[ -n "$NAME" ] || NAME=witness

# Download the binary from a member over NetBird; curl checks the
# member's key, then the file's checksum is checked.
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
GOT=""
if [ -z "$GOT" ] && curl -fsS --max-time 120 -k --pinnedpubkey 'sha256//q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=' -o "$TMP" 'https://100.64.0.105:44500/cluster/v1/witness/binary'; then
	GOT='100.64.0.105:44500'
fi
if [ -z "$GOT" ] && curl -fsS --max-time 120 -k --pinnedpubkey 'sha256//zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0=' -o "$TMP" 'https://100.64.0.21:44500/cluster/v1/witness/binary'; then
	GOT='100.64.0.21:44500'
fi
[ -n "$GOT" ] || fail "couldn't download the witness from any member over NetBird"
echo "$SHA256  $TMP" | sha256sum -c --status - || fail "the downloaded witness doesn't match its checksum"
install -m 0755 -o root -g root "$TMP" "$BIN"

# Configuration (nothing secret) and the join code (root only, handed to
# the service as a credential until it has joined).
install -d -m 0755 "$ETC"
umask 077
cat > "$ETC/witness.json" <<EOF
{
  "cluster": "$CLUSTER",
  "node": "$NODE",
  "name": "$NAME",
  "listen": "$LISTEN",
  "members": [
    {"address": "100.64.0.105:44500", "pin": "abababababababababababababababababababababababababababababababab"},
    {"address": "100.64.0.21:44500", "pin": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}
  ]
}
EOF
chmod 0644 "$ETC/witness.json"
printf '%s\n' 'ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ' > "$ETC/join.code"
chmod 0600 "$ETC/join.code"
umask 022

cat > "$UNIT" <<EOF
[Unit]
Description=HardyOS cluster witness
Documentation=https://github.com/HARDYOS/HARDYOS
After=network-online.target netbird.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN run --config $ETC/witness.json
DynamicUser=yes
StateDirectory=hardyos-witness
StateDirectoryMode=0700
Restart=always
RestartSec=3s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=$NBNET
UMask=0077
ProtectProc=invisible
ProcSubset=pid
PrivateUsers=yes
PrivateIPC=yes
RemoveIPC=yes
MemoryMax=128M

[Install]
WantedBy=multi-user.target
EOF
install -d -m 0755 "$DROPIN"
cat > "$DROPIN/join.conf" <<EOF
[Service]
LoadCredential=join:$ETC/join.code
EOF
systemctl daemon-reload
systemctl enable hardyos-witness.service >/dev/null
systemctl restart hardyos-witness.service

# Wait for the join, then take the code away.
i=0
while [ $i -lt 90 ]; do
	if grep -q '"joined": true' "$STATE/status.json" 2>/dev/null; then
		rm -f "$DROPIN/join.conf" "$ETC/join.code"
		rmdir "$DROPIN" 2>/dev/null || true
		systemctl daemon-reload
		# Restarted without the credential: the code is gone from the
		# service too, not only from the disk.
		systemctl restart hardyos-witness.service
		echo "The HardyOS witness joined the cluster (through $GOT). It listens on $LISTEN:$PORT."
		exit 0
	fi
	if grep -q '"problem": "[^"]' "$STATE/status.json" 2>/dev/null; then
		sed -n 's/.*"problem": "\(.*\)".*/\1/p' "$STATE/status.json" >&2
	fi
	i=$((i + 1))
	sleep 2
done
rm -f "$DROPIN/join.conf" "$ETC/join.code"
systemctl daemon-reload
systemctl stop hardyos-witness.service
fail "the witness didn't join within 3 minutes: see journalctl -u hardyos-witness"

