#!/bin/sh
set -e

if ! getent group hardyd >/dev/null; then
  addgroup --system hardyd
fi
if ! getent passwd hardyd >/dev/null; then
  adduser --system --ingroup hardyd --home /var/lib/hardyos --no-create-home \
    --shell /usr/sbin/nologin --gecos "HardyOS control plane" hardyd
fi

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable hardyos-issue.service hardyd-priv.service hardyd.service >/dev/null
  systemctl restart hardyd-priv.service hardyd.service || true
  systemctl restart hardyos-issue.service || true
else
  # Inside an image build (no running systemd): just enable the units.
  systemctl enable hardyos-issue.service hardyd-priv.service hardyd.service >/dev/null 2>&1 || true
fi
