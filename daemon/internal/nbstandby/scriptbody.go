package nbstandby

// scriptTemplate is the VPS script; @@HOSTNAME@@ (a checked host name),
// @@KEYLINE@@ (root's key with its restrictions) and @@RESTORE_CASE@@ (the
// restore entry names) are filled in by Script. Everything between the
// quoted heredoc markers is written out as is.
//
// Hand-back safety (decision 427): restore needs a one-shot arm made on the
// VPS by a person (arm-restore, expiring, at most 24 h), the generation id
// of a snapshot this VPS served in the last 30 days, a standby version not
// newer than the VPS's, SQLite checks run as nobody on copies (-safe,
// trusted_schema off) under the dedicated user hardyos-sqlcheck, the same
// NetBird accounts as the VPS has, and (unless the arm allows them) no new or
// changed owners, admins, access tokens or sign-in tables, compared row by
// row with every query's exit status checked and the tables it reads
// required; the checked copies are hash-verified as root before they go in
// place. After the swap it watches the server and rolls back to its own copy
// (as it was: stopped while fenced) on any failure.
//
// Fencing (decision 426) lasts two hours unless HardyOS renews it while it
// has taken over; a systemd timer on the VPS starts the server again once a
// fence expires.
const scriptTemplate = `#!/bin/bash
# HardyOS NetBird standby, VPS side, for @@HOSTNAME@@.
#
# Run once as root on the VPS (and again after HardyOS makes a new key):
#   bash hardyos-standby.sh                   # sync only (HardyOS reads)
#   bash hardyos-standby.sh --allow-handback  # also fence and hand-back
#   bash hardyos-standby.sh --uninstall
#
# It adds the user hardyos-standby whose only key may run only
# /usr/local/sbin/hardyos-netbird-standby (verbs: status, snapshot and, with
# --allow-handback, fence, unfence, restore). A hand-back must also be armed
# here, by you, each time:
#   hardyos-netbird-standby-root arm-restore 2h
# Nothing else about NetBird is changed.
set -euo pipefail
umask 077
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

ALLOW_HANDBACK=0
UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --allow-handback) ALLOW_HANDBACK=1 ;;
    --uninstall) UNINSTALL=1 ;;
    *) echo "usage: $0 [--allow-handback | --uninstall]" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "Run this as root." >&2; exit 1; }

if [ "$UNINSTALL" = 1 ]; then
  rm -f /etc/sudoers.d/hardyos-standby /usr/local/sbin/hardyos-netbird-standby /usr/local/sbin/hardyos-netbird-standby-root
  if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    systemctl disable --now hardyos-standby-fence.timer >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/hardyos-standby-fence.service /etc/systemd/system/hardyos-standby-fence.timer
  rm -f /etc/hardyos-standby/standby.conf /etc/hardyos-standby/restore-armed /etc/hardyos-standby/fenced /etc/hardyos-standby/allow-restore
  rmdir /etc/hardyos-standby 2>/dev/null || true
  if id hardyos-standby >/dev/null 2>&1; then userdel hardyos-standby || true; fi
  if id hardyos-sqlcheck >/dev/null 2>&1; then userdel hardyos-sqlcheck || true; fi
  echo "Removed. Backups made by hand-back stay in /var/lib/hardyos-standby/root."
  exit 0
fi

for c in docker sha256sum tar runuser; do
  command -v "$c" >/dev/null || { echo "$c is missing on this VPS." >&2; exit 1; }
done
if ! command -v sqlite3 >/dev/null || ! command -v sudo >/dev/null || ! command -v jq >/dev/null; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sqlite3 sudo jq
  else
    echo "Install sqlite3, sudo and jq first." >&2; exit 1
  fi
fi
# The hand-back checks need sqlite3's -safe mode (3.37 or newer).
sv=$(sqlite3 -version | cut -d' ' -f1)
if [ "$(printf '%s\n3.37.0\n' "$sv" | sort -V | head -1)" != 3.37.0 ]; then
  echo "sqlite3 $sv is too old: HardyOS needs 3.37 or newer (for -safe)." >&2; exit 1
fi

# NetBird's combined server (the current self-hosted layout).
SERVER=""
for n in $(docker ps -a --format '{{.Names}}'); do
  img=$(docker inspect -f '{{.Config.Image}}' "$n")
  case "$img" in
    *netbirdio/netbird-server*) SERVER="$n" ;;
    *netbirdio/management*) echo "This VPS runs NetBird's older split layout ($n). Move to the combined server first: https://docs.netbird.io/selfhosted/migration/combined-container" >&2; exit 1 ;;
  esac
done
[ -n "$SERVER" ] || { echo "No netbirdio/netbird-server container found." >&2; exit 1; }
# Traefik is found later by the NetBird compose project's label.
PROJECT=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$SERVER" | tr -cd 'A-Za-z0-9._-')
[ -n "$PROJECT" ] || { echo "$SERVER isn't part of a Docker Compose project." >&2; exit 1; }

if ! id hardyos-standby >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/hardyos-standby --shell /bin/sh hardyos-standby
fi
passwd -l hardyos-standby >/dev/null 2>&1 || true
# The hand-back's SQLite checks run as this user (no login, no home, owns
# nothing else): never nobody, whose processes other services share.
if ! id hardyos-sqlcheck >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin hardyos-sqlcheck
fi
passwd -l hardyos-sqlcheck >/dev/null 2>&1 || true
install -d -m 0700 -o hardyos-standby -g hardyos-standby /var/lib/hardyos-standby /var/lib/hardyos-standby/.ssh
install -d -m 0700 -o root -g root /var/lib/hardyos-standby/root
cat > /var/lib/hardyos-standby/.ssh/authorized_keys <<'KEY'
@@KEYLINE@@
KEY
chown hardyos-standby:hardyos-standby /var/lib/hardyos-standby/.ssh/authorized_keys
chmod 0600 /var/lib/hardyos-standby/.ssh/authorized_keys

install -d -m 0700 /etc/hardyos-standby
printf 'SERVER=%q\nPROJECT=%q\nHOSTNAME_NB=%q\nHANDBACK=%q\nCHECK_USER=hardyos-sqlcheck\n' "$SERVER" "$PROJECT" "@@HOSTNAME@@" "$ALLOW_HANDBACK" > /etc/hardyos-standby/standby.conf
chmod 0600 /etc/hardyos-standby/standby.conf
# The old always-on marker is gone: a hand-back is armed each time.
rm -f /etc/hardyos-standby/allow-restore /etc/hardyos-standby/restore-armed

# The forced command: the only thing HardyOS's key can run.
cat > /usr/local/sbin/hardyos-netbird-standby <<'FORCED'
#!/bin/sh
# HardyOS NetBird standby: the forced command of hardyos-standby's key.
case "${SSH_ORIGINAL_COMMAND:-}" in
  status|snapshot|restore|fence|unfence) exec sudo -n /usr/local/sbin/hardyos-netbird-standby-root "$SSH_ORIGINAL_COMMAND" ;;
  *) echo "hardyos-standby: refused" >&2; exit 2 ;;
esac
FORCED
chmod 0755 /usr/local/sbin/hardyos-netbird-standby

cat > /usr/local/sbin/hardyos-netbird-standby-root <<'ROOT'
#!/bin/bash
# HardyOS NetBird standby, root side.
#   status | snapshot | fence | unfence | restore   (HardyOS, through sudo)
#   arm-restore <30m|2h|...> [--allow-new-admins]    (you, on the VPS)
#   fence-expire                                     (the systemd timer)
set -euo pipefail
umask 077
# R is for HardyOS's own tests only (sudo's env_reset never passes it on).
R="${HARDYOS_STANDBY_TEST_ROOT:-}"
export LC_ALL=C PATH="${R:+$R/bin:}/usr/sbin:/usr/bin:/sbin:/bin"
. "$R/etc/hardyos-standby/standby.conf"
STATE=$R/var/lib/hardyos-standby/root
ARM=$R/etc/hardyos-standby/restore-armed
FENCED=$R/etc/hardyos-standby/fenced
FENCE_TTL=7200
MAX_UPLOAD=1073741824
CHECK_USER="${CHECK_USER:-hardyos-sqlcheck}"
fail() { echo "$*" >&2; exit 1; }
case "$CHECK_USER" in hardyos-sqlcheck|nobody) ;; *) fail "bad CHECK_USER in standby.conf" ;; esac
clean() { tr -cd 'A-Za-z0-9._:/@+-' | cut -c1-200; }
mount_of() { docker inspect -f "{{range .Mounts}}{{if eq .Destination \"$2\"}}{{.Source}}{{end}}{{end}}" "$1"; }
image_id() { docker inspect -f '{{.Image}}' "$SERVER"; }
version() {
  v=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$(image_id)" 2>/dev/null | clean || true)
  if [ -z "$v" ] || [ "$v" = "<no value>" ]; then
    v=$(docker inspect -f '{{.Config.Image}}' "$SERVER" | sed -n 's/.*:\([^:@/]*\)$/\1/p' | clean)
  fi
  echo "$v"
}
digest() { docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$(image_id)" 2>/dev/null | sed -n 's/.*@\(sha256:[0-9a-f]*\)$/\1/p' | head -1; }
config_file() {
  c=$(mount_of "$SERVER" /etc/netbird/config.yaml)
  [ -n "$c" ] && [ -f "$c" ] && { echo "$c"; return; }
  d=$(mount_of "$SERVER" /etc/netbird)
  [ -n "$d" ] && [ -f "$d/config.yaml" ] && { echo "$d/config.yaml"; return; }
  fail "can't find the NetBird server's config.yaml"
}
data_dir() {
  d=$(mount_of "$SERVER" /var/lib/netbird)
  [ -n "$d" ] && [ -d "$d" ] || fail "can't find the NetBird server's data folder"
  echo "$d"
}
# Traefik of the same compose project as the server, never another one.
traefik() {
  for n in $(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}'); do
    case "$(docker inspect -f '{{.Config.Image}}' "$n")" in *traefik*) echo "$n"; return ;; esac
  done
}
# The fence's expiry (seconds since 1970); fails when not fenced or expired.
fenced_until() {
  [ -e "$FENCED" ] || return 1
  exp=""
  read -r exp _ < "$FENCED" || true
  case "$exp" in ''|*[!0-9]*) exp=$(( $(stat -c %Y "$FENCED") + FENCE_TTL )) ;; esac
  [ "$exp" -gt "$(date +%s)" ] || return 1
  echo "$exp"
}
armed_until() {
  [ -f "$ARM" ] || return 1
  read -r exp _ < "$ARM" || return 1
  case "$exp" in ''|*[!0-9]*) return 1 ;; esac
  [ "$exp" -gt "$(date +%s)" ] || return 1
  echo "$exp"
}

verb="${1:-}"
case "$verb" in
status)
  running=$(docker inspect -f '{{.State.Running}}' "$SERVER" 2>/dev/null || echo false)
  allowed=false; until_s=""
  if [ "$HANDBACK" = 1 ] && exp=$(armed_until); then allowed=true; until_s=$(date -u -d "@$exp" +%Y-%m-%dT%H:%M:%SZ); fi
  installed=false; [ "$HANDBACK" = 1 ] && installed=true
  fenced=false; fu=""
  if fexp=$(fenced_until); then fenced=true; fu=$(date -u -d "@$fexp" +%Y-%m-%dT%H:%M:%SZ); fi
  printf '{"format":2,"running":%s,"version":"%s","digest":"%s","image":"%s","hostname":"%s","restoreAllowed":%s,"restoreArmedUntil":"%s","handbackInstalled":%s,"fenced":%s,"fencedUntil":"%s","time":"%s"}\n' \
    "$( [ "$running" = true ] && echo true || echo false)" "$(version)" "$(digest)" \
    "$(docker inspect -f '{{.Config.Image}}' "$SERVER" | clean)" "$(echo "$HOSTNAME_NB" | clean)" "$allowed" "$until_s" "$installed" "$fenced" "$fu" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ;;
snapshot)
  cfg=$(config_file); data=$(data_dir)
  if grep -Eq '^[[:space:]]*engine:[[:space:]]*"?postgres' "$cfg" || docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVER" | grep -q '^NETBIRD_STORE_ENGINE_POSTGRES_DSN='; then
    echo "the NetBird store is PostgreSQL: HardyOS's standby supports SQLite only" >&2; exit 3
  fi
  [ -f "$data/store.db" ] || fail "no store.db in $data"
  install -d -m 0700 "$STATE"
  tmp=$(mktemp -d "$STATE/snap.XXXXXX")
  trap 'rm -rf -- "$tmp"' EXIT
  mkdir "$tmp/config" "$tmp/data" "$tmp/tls"
  cp -- "$cfg" "$tmp/config/config.yaml"
  wd=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$SERVER" 2>/dev/null || true)
  if [ -n "$wd" ] && [ -f "$wd/dashboard.env" ]; then cp -- "$wd/dashboard.env" "$tmp/config/dashboard.env"; fi
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVER" \
    | grep -E '^(NB_STORE_ENCRYPTION_KEY|NB_AUTH_SECRET|NB_IDP_SESSION_COOKIE_ENCRYPTION_KEY)=.' > "$tmp/config/server.env" || true
  [ -s "$tmp/config/server.env" ] || rm -f "$tmp/config/server.env"
  for db in store idp events; do
    if [ -f "$data/$db.db" ]; then sqlite3 "$data/$db.db" ".backup '$tmp/data/$db.db'"; fi
  done
  peers=$(sqlite3 "$tmp/data/store.db" 'SELECT count(*) FROM peers;' 2>/dev/null | tr -cd 0-9 || true); peers=${peers:-0}
  keys=$(sqlite3 "$tmp/data/store.db" 'SELECT count(*) FROM setup_keys;' 2>/dev/null | tr -cd 0-9 || true); keys=${keys:-0}
  tr_name=$(traefik || true)
  if [ -n "$tr_name" ]; then
    le=$(mount_of "$tr_name" /letsencrypt 2>/dev/null || true)
    if [ -n "$le" ] && [ -s "$le/acme.json" ]; then
      # Only this name's certificate, never the ACME account's key; none
      # when Traefik's file is empty or unreadable.
      jq --arg h "$HOSTNAME_NB" 'with_entries(.value |= {Certificates: [ (.Certificates // [])[] | select(.domain.main == $h or (((.domain.sans // []) | index($h)) != null)) ]})' \
        "$le/acme.json" > "$tmp/tls/acme.json" 2>/dev/null || rm -f "$tmp/tls/acme.json"
      [ ! -e "$tmp/tls/acme.json" ] || [ -s "$tmp/tls/acme.json" ] || rm -f "$tmp/tls/acme.json"
    fi
  fi
  host=$(sed -n 's/^[[:space:]]*exposedAddress:[[:space:]]*"\{0,1\}https:\/\/\([A-Za-z0-9.-]*\).*/\1/p' "$tmp/config/config.yaml" | head -1 | clean)
  # A generation id for this snapshot: a hand-back must name one this VPS served.
  gen=$(od -An -N16 -tx1 /dev/urandom | tr -cd 0-9a-f)
  printf '%s %s\n' "$gen" "$(date +%s)" >> "$STATE/generations"
  tail -n 50 "$STATE/generations" > "$STATE/generations.new" && mv -f "$STATE/generations.new" "$STATE/generations"
  fenced=false; fenced_until >/dev/null && fenced=true
  files=""
  list=$(cd "$tmp" && find config data tls -type f | sort)
  for f in $list; do
    s=$(sha256sum "$tmp/$f" | cut -d' ' -f1)
    files="$files${files:+,}\"$f\":\"$s\""
  done
  printf '{"format":1,"created":"%s","hostname":"%s","image":"%s","digest":"%s","version":"%s","engine":"sqlite","peers":%s,"setupKeys":%s,"generation":"%s","fenced":%s,"files":{%s}}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$host" "$(docker inspect -f '{{.Config.Image}}' "$SERVER" | clean)" "$(digest)" "$(version)" \
    "$peers" "$keys" "$gen" "$fenced" "$files" > "$tmp/manifest.json"
  # shellcheck disable=SC2086
  tar -C "$tmp" --owner=0 --group=0 --numeric-owner -cf - manifest.json $list
  ;;
fence)
  [ "$HANDBACK" = 1 ] || fail "fencing isn't allowed on this VPS (run HardyOS's script with --allow-handback)"
  # Two hours, renewed by HardyOS while it has taken over; then the timer
  # starts the server again.
  exp=$(( $(date +%s) + FENCE_TTL ))
  printf '%s\n' "$exp" > "$FENCED.new" && mv -f "$FENCED.new" "$FENCED"
  docker stop -t 30 "$SERVER" >/dev/null
  logger -p daemon.warning -t hardyos-standby "FENCED: netbird-server stopped for HardyOS's take-over until $(date -u -d "@$exp" +%Y-%m-%dT%H:%M:%SZ) unless renewed" || true
  echo "fenced until $(date -u -d "@$exp" +%Y-%m-%dT%H:%M:%SZ)"
  ;;
fence-expire)
  [ "${SUDO_USER:-}" != hardyos-standby ] || fail "refused"
  if [ -e "$FENCED" ] && ! fenced_until >/dev/null; then
    rm -f "$FENCED"
    docker start "$SERVER" >/dev/null
    logger -p daemon.warning -t hardyos-standby "the fence expired (HardyOS didn't renew it): netbird-server started" || true
    echo "the fence expired: started"
  fi
  ;;
unfence)
  [ "$HANDBACK" = 1 ] || fail "fencing isn't allowed on this VPS"
  rm -f "$FENCED"
  docker start "$SERVER" >/dev/null
  logger -p daemon.warning -t hardyos-standby "unfenced: netbird-server started" || true
  echo "started"
  ;;
arm-restore)
  # A person on the VPS, never HardyOS's key.
  [ "${SUDO_USER:-}" != hardyos-standby ] || fail "refused"
  [ "$HANDBACK" = 1 ] || fail "hand-back isn't installed (run HardyOS's script with --allow-handback)"
  dur="${2:-}"; allow=0
  echo "$dur" | grep -Eq '^[0-9]{1,4}[mh]$' || fail "usage: $0 arm-restore <30m|2h> [--allow-new-admins]"
  [ "${3:-}" = "--allow-new-admins" ] && allow=1
  case "$dur" in
    [0-9]*m) secs=$(( ${dur%m} * 60 )) ;;
    [0-9]*h) secs=$(( ${dur%h} * 3600 )) ;;
    *) fail "usage: $0 arm-restore <30m|2h> [--allow-new-admins]" ;;
  esac
  [ "$secs" -ge 60 ] && [ "$secs" -le 86400 ] || fail "arm for 1 minute to 24 hours"
  exp=$(( $(date +%s) + secs ))
  printf '%s %s\n' "$exp" "$allow" > "$ARM"
  chmod 0600 "$ARM"
  echo "hand-back armed once until $(date -u -d "@$exp" +%Y-%m-%dT%H:%M:%SZ)"
  ;;
restore)
  [ "$HANDBACK" = 1 ] || fail "hand-back isn't installed on this VPS (run HardyOS's script with --allow-handback)"
  [ -f "$ARM" ] || fail "hand-back isn't armed: on the VPS run: hardyos-netbird-standby-root arm-restore 2h"
  read -r exp allow < "$ARM" || fail "the hand-back arm is damaged: arm it again"
  rm -f "$ARM" # one use, whatever happens next
  case "$exp" in ''|*[!0-9]*) fail "the hand-back arm is damaged: arm it again" ;; esac
  [ "$exp" -gt "$(date +%s)" ] || fail "the hand-back arm expired: arm it again"
  data=$(data_dir)
  install -d -m 0700 "$STATE"
  # Outside the root-only state folder, so nobody can reach its copies.
  in=$(mktemp -d /tmp/hardyos-restore.XXXXXX)
  chmod 0711 "$in"
  bk=""
  vd=""
  swapping=0
  was_running=false
  # Back as it was: the backup's databases only (one the upload added goes),
  # and the server stopped while fenced or if it was stopped before.
  rollback() {
    swapping=0
    docker stop -t 30 "$SERVER" >/dev/null 2>&1 || true
    for db in store idp events; do
      if [ -f "$bk/$db.db" ]; then
        install -m 0600 -o root -g root "$bk/$db.db" "$data/$db.db"
      else
        rm -f "$data/$db.db"
      fi
      rm -f "$data/$db.db-wal" "$data/$db.db-shm"
    done
    if [ -e "$FENCED" ]; then
      echo "the server stays stopped: the VPS is fenced (HardyOS's standby serves)" >&2
    elif [ "$was_running" = true ]; then
      docker start "$SERVER" >/dev/null 2>&1 || true
    fi
    echo "the VPS's previous databases were put back from $bk" >&2
  }
  # The checker's processes end before root reads what it touched.
  checker_stop() {
    [ "$CHECK_USER" != nobody ] || return 0
    command -v pkill >/dev/null || return 0
    for _ in 1 2 3 4 5; do
      pkill -KILL -u "$CHECK_USER" 2>/dev/null || return 0
      sleep 0.2
    done
    return 1
  }
  # Root takes the copies back and refuses anything but plain files.
  take_back() {
    checker_stop || fail "the SQLite checker's processes didn't stop"
    chown -R root:root "$in/x" "$in/cmp" 2>/dev/null || chown -R root:root "$in/x"
    chmod -R go-rwx "$in/x"
    [ -z "$(find "$in/x" ! -type f ! -type d)" ] || fail "the checked copies hold something other than files: refused"
  }
  cleanup() {
    set +e
    if [ "$swapping" = 1 ]; then rollback; fi
    checker_stop
    rm -rf -- "$in"
    [ -z "$vd" ] || rm -rf -- "$vd"
  }
  trap cleanup EXIT
  head -c $((MAX_UPLOAD + 1)) > "$in/upload.tar"
  [ "$(stat -c %s "$in/upload.tar")" -le "$MAX_UPLOAD" ] || fail "the upload is too large"
  tar -tvf "$in/upload.tar" | while read -r perms _; do
    case "$perms" in -*) ;; *) fail "the upload holds something other than files" ;; esac
  done
  for n in $(tar -tf "$in/upload.tar"); do
    case "$n" in @@RESTORE_CASE@@) ;; *) fail "unexpected entry in the upload: $n" ;; esac
  done
  mkdir "$in/x"
  tar -C "$in/x" --no-same-owner --no-same-permissions -xf "$in/upload.tar"
  rm -f "$in/upload.tar"
  [ -f "$in/x/SHA256SUMS" ] && [ -f "$in/x/data/store.db" ] && [ -f "$in/x/GENERATION" ] || fail "the upload has no store.db, checksums or generation"
  if grep -Evq '^[0-9a-f]{64}  data/(store|idp|events)\.db(-wal)?$' "$in/x/SHA256SUMS"; then fail "bad checksum list"; fi
  (cd "$in/x" && sha256sum --check --strict --quiet SHA256SUMS) || fail "the upload doesn't match its checksums"
  [ "$(cd "$in/x" && find data -type f | wc -l)" = "$(grep -c . "$in/x/SHA256SUMS")" ] || fail "the checksums don't list every file"
  # It must come from a snapshot this VPS served (in the last 30 days).
  gen=$(head -c 64 "$in/x/GENERATION" | tr -cd 0-9a-f)
  [ "${#gen}" = 32 ] || fail "the upload's generation id isn't valid"
  served=$(grep "^$gen " "$STATE/generations" 2>/dev/null | head -1 | cut -d' ' -f2 | tr -cd 0-9 || true)
  [ -n "$served" ] || fail "the upload doesn't come from a snapshot this VPS served"
  [ $(( $(date +%s) - served )) -le $(( 30 * 86400 )) ] || fail "the snapshot the standby started from is more than 30 days old"
  # The standby may have migrated the store: never onto an older server.
  want=$(head -c 40 "$in/x/VERSION" 2>/dev/null | tr -cd '0-9.' || true)
  have=$(version | tr -cd '0-9.')
  if [ -n "$want" ] && [ -n "$have" ] && [ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -1)" != "$want" ]; then
    fail "this VPS runs NetBird $have, older than the standby's $want: update netbird-server on the VPS first"
  fi
  # SQLite runs as hardyos-sqlcheck on copies, without trusting the schema;
  # root reads only its output (into a folder it can't write) and checks
  # every exit status.
  mkdir "$in/cmp"
  install -d -m 0700 "$in/q"
  sq() { runuser -u "$CHECK_USER" -- sqlite3 -safe -batch -noheader "$1" "PRAGMA trusted_schema=OFF; $2"; }
  chown -R "$CHECK_USER" "$in/x"
  for db in store idp events; do
    f="$in/x/data/$db.db"
    [ -f "$f" ] || continue
    sq "$f" 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null || fail "SQLite couldn't read $db.db from HardyOS: refused"
  done
  # What the checks read and what goes in place is the same: hashed here.
  take_back
  : > "$in/checked.sums"
  for db in store idp events; do
    f="$in/x/data/$db.db"
    rm -f "$f-wal" "$f-shm"
    [ -f "$f" ] || continue
    (cd "$in/x" && sha256sum "data/$db.db") >> "$in/checked.sums"
  done
  bk=$(mktemp -d "$STATE/before-handback-$(date -u +%Y%m%dT%H%M%SZ).XXXX")
  chmod 0700 "$bk"
  # Keep the newest five backups.
  for d in $(ls -1dt "$STATE"/before-handback-* 2>/dev/null | tail -n +6); do rm -rf -- "$d"; done
  for db in store idp events; do
    if [ -f "$data/$db.db" ]; then sqlite3 "$data/$db.db" ".backup '$bk/$db.db'"; fi
  done
  cp -- "$bk/store.db" "$in/cmp/old.db"
  [ ! -f "$bk/idp.db" ] || cp -- "$bk/idp.db" "$in/cmp/old-idp.db"
  chown -R "$CHECK_USER" "$in/x" "$in/cmp"
  for db in store idp events; do
    f="$in/x/data/$db.db"
    [ -f "$f" ] || continue
    sq "$f" 'PRAGMA integrity_check;' > "$in/q/ic" || fail "SQLite couldn't check $db.db from HardyOS: refused"
    [ "$(cat "$in/q/ic")" = ok ] || fail "$db.db from HardyOS failed SQLite's integrity check"
  done
  # Compare with what the VPS has, row by row (security review N3).
  old="$in/cmp/old.db"; new="$in/x/data/store.db"
  q() { sq "$1" "$2" > "$3" || fail "SQLite couldn't read $4: refused"; sort -o "$3" "$3"; }
  need() { # db what table columns...
    nd=$1; nw=$2; nt=$3; shift 3
    q "$nd" "SELECT type FROM sqlite_master WHERE name='$nt' COLLATE NOCASE;" "$in/q/t" "$nw ($nt)"
    [ "$(cat "$in/q/t")" = table ] || fail "$nw has no table $nt: refused"
    for nc in "$@"; do
      q "$nd" "SELECT count(*) FROM pragma_table_info('$nt') WHERE name='$nc' COLLATE NOCASE;" "$in/q/t" "$nw ($nt.$nc)"
      [ "$(cat "$in/q/t")" = 1 ] || fail "$nw's table $nt has no column $nc: refused"
    done
  }
  for side in old new; do
    sd=$old; sw="the VPS's store"
    if [ "$side" = new ]; then sd=$new; sw="the standby's store"; fi
    need "$sd" "$sw" accounts id
    need "$sd" "$sw" users id role blocked is_service_user
    need "$sd" "$sw" personal_access_tokens id user_id hashed_token
    need "$sd" "$sw" setup_keys id
    need "$sd" "$sw" policies id
    need "$sd" "$sw" routes id
  done
  for side in old new; do
    sd=$old; [ "$side" = new ] && sd=$new
    q "$sd" "SELECT hex(quote(id)) FROM accounts;" "$in/q/accounts.$side" "accounts"
    for t in users personal_access_tokens setup_keys policies routes; do
      q "$sd" "SELECT hex(quote(id)) FROM $t;" "$in/q/$t.$side" "$t"
    done
    # Users: id, role, blocked, service user, and whether the role is plain.
    q "$sd" "SELECT hex(quote(id))||' '||hex(quote(role))||' '||hex(quote(blocked))||' '||hex(quote(is_service_user))||' '||(role IS 'user') FROM users;" "$in/q/urows.$side" "users"
    q "$sd" "SELECT hex(quote(id))||' '||hex(quote(user_id))||' '||hex(quote(hashed_token)) FROM personal_access_tokens;" "$in/q/prows.$side" "personal_access_tokens"
  done
  cmp -s "$in/q/accounts.old" "$in/q/accounts.new" || fail "the standby's state is for other NetBird accounts than this VPS's: refused"
  summary=""
  for t in users personal_access_tokens setup_keys policies routes; do
    summary="$summary $t:+$(comm -13 "$in/q/$t.old" "$in/q/$t.new" | grep -c . || true)"
  done
  # Any user row that is new or changed, unless it's a new plain user.
  comm -13 "$in/q/urows.old" "$in/q/urows.new" > "$in/q/urows.changed"
  admins=$(awk 'NR==FNR { seen[$1] = 1; next } $5 != "1" || ($1 in seen)' "$in/q/users.old" "$in/q/urows.changed" | grep -c . || true)
  # Any token that is new, moved to another user or given another hash.
  pats=$(comm -13 "$in/q/prows.old" "$in/q/prows.new" | grep -c . || true)
  # The embedded IdP's sign-in tables, when the upload carries idp.db.
  idp=""
  if [ -f "$in/x/data/idp.db" ]; then
    for t in password keys connector client; do
      for side in old new; do
        f="$in/cmp/old-idp.db"; [ "$side" = new ] && f="$in/x/data/idp.db"
        : > "$in/q/idp-$t.$side"
        if [ -f "$f" ]; then
          runuser -u "$CHECK_USER" -- sqlite3 -safe -batch -noheader -cmd 'PRAGMA trusted_schema=OFF;' "$f" ".dump $t" > "$in/q/idp-$t.raw" \
            || fail "SQLite couldn't read idp.db ($t): refused"
          grep -vxF -e 'PRAGMA foreign_keys=OFF;' -e 'BEGIN TRANSACTION;' -e 'COMMIT;' "$in/q/idp-$t.raw" | sort > "$in/q/idp-$t.$side" || true
        fi
      done
      cmp -s "$in/q/idp-$t.old" "$in/q/idp-$t.new" || idp="$idp $t"
    done
  fi
  echo "changes from HardyOS's standby:$summary owners/admins changed:$admins tokens changed:$pats sign-in tables changed:${idp:- none}"
  logger -p daemon.warning -t hardyos-standby "restore:$summary owners/admins changed:$admins tokens changed:$pats sign-in tables changed:${idp:- none}" || true
  if { [ "$admins" != 0 ] || [ "$pats" != 0 ] || [ -n "$idp" ]; } && [ "$allow" != 1 ]; then
    fail "the standby added or changed $admins owner/admin users and $pats access tokens, and these sign-in tables:${idp:- none}: check them, then on the VPS run arm-restore 2h --allow-new-admins and hand back again"
  fi
  # Checked: take the copies back, copy them where only root can write and
  # check they are what was hashed before they go in place.
  take_back
  vd=$(mktemp -d "$STATE/verified.XXXXXX")
  mkdir "$vd/data"
  for db in store idp events; do
    [ ! -f "$in/x/data/$db.db" ] || cp -- "$in/x/data/$db.db" "$vd/data/$db.db"
  done
  (cd "$vd" && sha256sum --check --strict --quiet "$in/checked.sums") || fail "the checked copies changed: refused"
  [ "$(cd "$vd" && find data -type f | wc -l)" = "$(grep -c . "$in/checked.sums")" ] || fail "the checked copies changed: refused"
  was_running=$(docker inspect -f '{{.State.Running}}' "$SERVER" 2>/dev/null || echo false)
  swapping=1
  docker stop -t 30 "$SERVER" >/dev/null
  for db in store idp events; do
    f="$vd/data/$db.db"
    [ -f "$f" ] || continue
    install -m 0600 -o root -g root "$f" "$data/$db.db.hardyos-new"
    rm -f "$data/$db.db-wal" "$data/$db.db-shm"
    mv -f "$data/$db.db.hardyos-new" "$data/$db.db"
  done
  docker start "$SERVER" >/dev/null
  rc=$(docker inspect -f '{{.RestartCount}}' "$SERVER")
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 3
    [ "$(docker inspect -f '{{.State.Running}}' "$SERVER")" = true ] || fail "netbird-server didn't stay up with the handed-back state"
  done
  [ "$(docker inspect -f '{{.RestartCount}}' "$SERVER")" = "$rc" ] || fail "netbird-server restarted with the handed-back state"
  swapping=0
  rm -f "$FENCED"
  echo "restored; the VPS's previous databases are in $bk"
  ;;
*)
  echo "hardyos-standby: refused" >&2; exit 2 ;;
esac
ROOT
chmod 0700 /usr/local/sbin/hardyos-netbird-standby-root

rule="/usr/local/sbin/hardyos-netbird-standby-root status, /usr/local/sbin/hardyos-netbird-standby-root snapshot"
if [ "$ALLOW_HANDBACK" = 1 ]; then
  rule="$rule, /usr/local/sbin/hardyos-netbird-standby-root restore, /usr/local/sbin/hardyos-netbird-standby-root fence, /usr/local/sbin/hardyos-netbird-standby-root unfence"
fi
tmp_sudo=$(mktemp)
printf 'Defaults:hardyos-standby env_reset, !requiretty\nhardyos-standby ALL=(root) NOPASSWD: %s\n' "$rule" > "$tmp_sudo"
visudo -cf "$tmp_sudo" >/dev/null
install -m 0440 -o root -g root "$tmp_sudo" /etc/sudoers.d/hardyos-standby
rm -f "$tmp_sudo"

# A fence ends two hours after HardyOS last renewed it.
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  cat > /etc/systemd/system/hardyos-standby-fence.service <<'UNIT'
[Unit]
Description=HardyOS NetBird standby: start netbird-server when a fence expires

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hardyos-netbird-standby-root fence-expire
UNIT
  cat > /etc/systemd/system/hardyos-standby-fence.timer <<'UNIT'
[Unit]
Description=HardyOS NetBird standby: check the fence's expiry

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now hardyos-standby-fence.timer >/dev/null
else
  echo "Note: no systemd here: run 'hardyos-netbird-standby-root fence-expire' from cron every few minutes."
fi

if grep -Eiq '^[[:space:]]*(AllowUsers|AllowGroups)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
  echo "Note: sshd has AllowUsers/AllowGroups; add hardyos-standby there, or HardyOS can't connect."
fi
echo
echo "HardyOS's key installed. Compare its fingerprint with the one HardyOS shows"
echo "(Control Panel > NetBird Standby, or 'sudo hardyctl netbird-standby fingerprint' on its console):"
ssh-keygen -lf /var/lib/hardyos-standby/.ssh/authorized_keys || true
echo
echo "Paste this host key into Control Panel > NetBird Standby on HardyOS:"
cat /etc/ssh/ssh_host_ed25519_key.pub
`
