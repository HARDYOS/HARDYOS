#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
  systemctl stop hardyd.service hardyd-priv.service hardyos-issue.service >/dev/null 2>&1 || true
fi
systemctl disable hardyd.service hardyd-priv.service hardyos-issue.service >/dev/null 2>&1 || true
