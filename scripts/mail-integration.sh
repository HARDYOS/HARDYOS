#!/bin/bash
# Runs the mail server's integration test (daemon/internal/mail,
# build tag mailintegration) inside a Debian 13 container with the same
# packages the HardyOS image ships: real Postfix, Dovecot, Rspamd, Redis and
# Radicale, configured by hardyd-priv's mail code, with hardyd's mail
# sign-in in front of a fake password checker.
#
#   scripts/mail-integration.sh            # builds the test, needs Docker
#
# The container gets NET_ADMIN (the test puts the VPS's address on its own
# loopback) and nothing else from the host.
set -euo pipefail

cd "$(dirname "$0")/.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
(cd daemon && CGO_ENABLED=0 go test -c -tags mailintegration -o "$out/mail.test" ./internal/mail)

docker run --rm --cap-add NET_ADMIN -v "$out:/t:ro" debian:trixie bash -euo pipefail -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections
  apt-get install -y -qq postfix dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve \
    rspamd redis-server radicale nftables iproute2 procps openssl ca-certificates >/dev/null
  # What the image hook and hardyos-core'"'"'s postinst set up.
  adduser --system --group --no-create-home --home /nonexistent hardyos-vmail >/dev/null
  adduser _rspamd redis >/dev/null
  cd /tmp
  status=0
  /t/mail.test -test.v -test.timeout 10m || status=$?
  if [ $status -ne 0 ]; then
    echo "---- dovecot ----"; tail -80 /var/log/dovecot-it.log 2>/dev/null || true
    echo "---- rspamd ----"; tail -40 /var/log/rspamd/rspamd.log 2>/dev/null || true
    echo "---- queue ----"; postqueue -p 2>/dev/null || true
  fi
  exit $status
'
