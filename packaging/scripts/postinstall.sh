#!/bin/sh
set -e

if ! getent group hardyd >/dev/null; then
  addgroup --system hardyd
fi
if ! getent passwd hardyd >/dev/null; then
  adduser --system --ingroup hardyd --home /var/lib/hardyos --no-create-home \
    --shell /usr/sbin/nologin --gecos "HardyOS control plane" hardyd
fi

# HardyOS administrators read and write files in the File Manager as this
# user (never root); hardyd-priv gives it access to every shared folder.
if ! getent group hardyos-files >/dev/null; then
  addgroup --system --gid 29999 hardyos-files
fi
if ! getent passwd hardyos-files >/dev/null; then
  adduser --system --uid 29999 --ingroup hardyos-files --home /nonexistent --no-create-home \
    --shell /usr/sbin/nologin --gecos "HardyOS File Manager" hardyos-files
fi

# VM disk image imports run qemu-img and xz as this user, in a sandbox,
# never as root (decision 134).
if ! getent group hardyos-import >/dev/null; then
  addgroup --system hardyos-import
fi
if ! getent passwd hardyos-import >/dev/null; then
  adduser --system --ingroup hardyos-import --home /nonexistent --no-create-home \
    --shell /usr/sbin/nologin --gecos "HardyOS VM image imports" hardyos-import
fi

# Cloud backups run restic as this user, in a sandbox with only the
# capabilities each run needs, never as root (decision 236).
if ! getent group hardyos-restic >/dev/null; then
  addgroup --system hardyos-restic
fi
if ! getent passwd hardyos-restic >/dev/null; then
  adduser --system --ingroup hardyos-restic --home /nonexistent --no-create-home \
    --shell /usr/sbin/nologin --gecos "HardyOS cloud backups (restic)" hardyos-restic
fi

# Mailboxes on disk belong to this user; Dovecot's mail processes run as
# it (never root). Rspamd reads its Redis instance's socket.
if ! getent group hardyos-vmail >/dev/null; then
  addgroup --system hardyos-vmail
fi
if ! getent passwd hardyos-vmail >/dev/null; then
  adduser --system --ingroup hardyos-vmail --home /nonexistent --no-create-home \
    --shell /usr/sbin/nologin --gecos "HardyOS mailboxes" hardyos-vmail
fi
if getent passwd _rspamd >/dev/null && getent group redis >/dev/null; then
  adduser _rspamd redis >/dev/null 2>&1 || true
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
