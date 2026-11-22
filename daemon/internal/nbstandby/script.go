package nbstandby

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The VPS side (decision 421). HardyOS never runs a command of its choosing
// on the VPS: its one key is installed with `restrict` and a forced command
// that accepts exactly the verbs below (anything else, including what the
// client asks for, is refused), runs as the unprivileged user
// hardyos-standby, and reaches root only through sudo for exactly
// "<root script> <verb>". restore (hand-back) is in sudoers, and accepted by
// the root script, only when the script was installed with
// --allow-handback.
const (
	VerbStatus   = "status"
	VerbSnapshot = "snapshot"
	VerbRestore  = "restore"
)

// VPSUser is the account HardyOS's key may log in as.
const VPSUser = "hardyos-standby"

// Restore uploads carry these entries (the standby's databases with their
// write-ahead logs, and their checksums): nothing else is accepted.
var restoreEntries = []string{"SHA256SUMS", "data/store.db", "data/idp.db", "data/events.db",
	"data/store.db-wal", "data/idp.db-wal", "data/events.db-wal"}

// ScriptSetup is what the VPS script is made from.
type ScriptSetup struct {
	Hostname  string // the NetBird server's name (vpn.example.net)
	PublicKey string // root's public key, authorized_keys format
	// From are the addresses (or prefixes) HardyOS connects from; empty
	// means no from= restriction (the key alone).
	From []string
}

// Validate checks the inputs before they go into a script.
func (s ScriptSetup) Validate() error {
	if !ValidHostname(s.Hostname) {
		return errors.New("set the NetBird server's name first")
	}
	pk, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(s.PublicKey))
	if err != nil || len(strings.TrimSpace(string(rest))) > 0 || pk.Type() != ssh.KeyAlgoED25519 {
		return errors.New("HardyOS hasn't made its SSH key yet")
	}
	return s.validateFrom()
}

func (s ScriptSetup) keyLine() string {
	pk, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(s.PublicKey))
	opts := `restrict,command="/usr/local/sbin/hardyos-netbird-standby"`
	if len(s.From) > 0 {
		opts += `,from="` + strings.Join(s.From, ",") + `"`
	}
	return opts + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " hardyos-standby@" + s.Hostname
}

// Script is the shell script to run once on the VPS as root (again after a
// new key). It installs the user, its one key, the forced command, the root
// script and its sudo rule; it changes nothing about NetBird itself.
func Script(s ScriptSetup) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	restoreCase := strings.Join(restoreEntries, "|")
	return fmt.Sprintf(`#!/bin/bash
# HardyOS NetBird standby, VPS side, for %[1]s.
#
# Run once as root on the VPS (and again after HardyOS makes a new key):
#   bash hardyos-standby.sh                   # sync only (HardyOS reads)
#   bash hardyos-standby.sh --allow-handback  # also allow Hand back
#   bash hardyos-standby.sh --uninstall
#
# It adds the user hardyos-standby whose only key may run only
# /usr/local/sbin/hardyos-netbird-standby (verbs: status, snapshot and, with
# --allow-handback, restore). Nothing else about NetBird is changed.
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
  rm -rf /etc/hardyos-standby
  if id hardyos-standby >/dev/null 2>&1; then userdel hardyos-standby || true; fi
  echo "Removed. Backups made by hand-back stay in /var/lib/hardyos-standby."
  exit 0
fi

for c in docker sha256sum tar; do
  command -v "$c" >/dev/null || { echo "$c is missing on this VPS." >&2; exit 1; }
done
if ! command -v sqlite3 >/dev/null || ! command -v sudo >/dev/null; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sqlite3 sudo
  else
    echo "Install sqlite3 and sudo first." >&2; exit 1
  fi
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
TRAEFIK=""
for n in $(docker ps -a --format '{{.Names}}'); do
  img=$(docker inspect -f '{{.Config.Image}}' "$n")
  case "$img" in *traefik*) TRAEFIK="$n" ;; esac
done

if ! id hardyos-standby >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/hardyos-standby --shell /bin/sh hardyos-standby
fi
passwd -l hardyos-standby >/dev/null 2>&1 || true
install -d -m 0700 -o hardyos-standby -g hardyos-standby /var/lib/hardyos-standby /var/lib/hardyos-standby/.ssh
install -d -m 0700 -o root -g root /var/lib/hardyos-standby/root
cat > /var/lib/hardyos-standby/.ssh/authorized_keys <<'KEY'
%[2]s
KEY
chown hardyos-standby:hardyos-standby /var/lib/hardyos-standby/.ssh/authorized_keys
chmod 0600 /var/lib/hardyos-standby/.ssh/authorized_keys

install -d -m 0700 /etc/hardyos-standby
printf 'SERVER=%%q\nTRAEFIK=%%q\nHOSTNAME_NB=%%q\n' "$SERVER" "$TRAEFIK" %[1]q > /etc/hardyos-standby/standby.conf
chmod 0600 /etc/hardyos-standby/standby.conf
if [ "$ALLOW_HANDBACK" = 1 ]; then touch /etc/hardyos-standby/allow-restore; else rm -f /etc/hardyos-standby/allow-restore; fi

# The forced command: the only thing HardyOS's key can run.
cat > /usr/local/sbin/hardyos-netbird-standby <<'FORCED'
#!/bin/sh
# HardyOS NetBird standby: the forced command of hardyos-standby's key.
case "${SSH_ORIGINAL_COMMAND:-}" in
  status|snapshot|restore) exec sudo -n /usr/local/sbin/hardyos-netbird-standby-root "$SSH_ORIGINAL_COMMAND" ;;
  *) echo "hardyos-standby: refused" >&2; exit 2 ;;
esac
FORCED
chmod 0755 /usr/local/sbin/hardyos-netbird-standby

cat > /usr/local/sbin/hardyos-netbird-standby-root <<'ROOT'
#!/bin/bash
# HardyOS NetBird standby, root side: status | snapshot | restore.
set -euo pipefail
umask 077
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
. /etc/hardyos-standby/standby.conf
STATE=/var/lib/hardyos-standby/root
fail() { echo "$*" >&2; exit 1; }
clean() { tr -cd 'A-Za-z0-9._:/@+-' | cut -c1-200; }
mount_of() { docker inspect -f "{{range .Mounts}}{{if eq .Destination \"$2\"}}{{.Source}}{{end}}{{end}}" "$1"; }
image_id() { docker inspect -f '{{.Image}}' "$SERVER"; }
version() {
  v=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$(image_id)" 2>/dev/null | clean)
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

verb="${1:-}"
case "$verb" in
status)
  running=$(docker inspect -f '{{.State.Running}}' "$SERVER" 2>/dev/null || echo false)
  allowed=false; [ -e /etc/hardyos-standby/allow-restore ] && allowed=true
  printf '{"format":1,"running":%%s,"version":"%%s","digest":"%%s","image":"%%s","hostname":"%%s","restoreAllowed":%%s,"time":"%%s"}\n' \
    "$( [ "$running" = true ] && echo true || echo false)" "$(version)" "$(digest)" \
    "$(docker inspect -f '{{.Config.Image}}' "$SERVER" | clean)" "$(echo "$HOSTNAME_NB" | clean)" "$allowed" "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"
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
  peers=$(sqlite3 "$tmp/data/store.db" 'SELECT count(*) FROM peers;' 2>/dev/null | tr -cd 0-9); peers=${peers:-0}
  keys=$(sqlite3 "$tmp/data/store.db" 'SELECT count(*) FROM setup_keys;' 2>/dev/null | tr -cd 0-9); keys=${keys:-0}
  if [ -n "$TRAEFIK" ]; then
    le=$(mount_of "$TRAEFIK" /letsencrypt 2>/dev/null || true)
    if [ -n "$le" ] && [ -f "$le/acme.json" ]; then cp -- "$le/acme.json" "$tmp/tls/acme.json"; fi
  fi
  host=$(sed -n 's/^[[:space:]]*exposedAddress:[[:space:]]*"\{0,1\}https:\/\/\([A-Za-z0-9.-]*\).*/\1/p' "$tmp/config/config.yaml" | head -1 | clean)
  files=""
  list=$(cd "$tmp" && find config data tls -type f | sort)
  for f in $list; do
    s=$(sha256sum "$tmp/$f" | cut -d' ' -f1)
    files="$files${files:+,}\"$f\":\"$s\""
  done
  printf '{"format":1,"created":"%%s","hostname":"%%s","image":"%%s","digest":"%%s","version":"%%s","engine":"sqlite","peers":%%s,"setupKeys":%%s,"files":{%%s}}\n' \
    "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" "$host" "$(docker inspect -f '{{.Config.Image}}' "$SERVER" | clean)" "$(digest)" "$(version)" \
    "$peers" "$keys" "$files" > "$tmp/manifest.json"
  # shellcheck disable=SC2086
  tar -C "$tmp" --owner=0 --group=0 --numeric-owner -cf - manifest.json $list
  ;;
restore)
  [ -e /etc/hardyos-standby/allow-restore ] || fail "hand-back isn't allowed on this VPS (run the HardyOS script with --allow-handback)"
  data=$(data_dir)
  install -d -m 0700 "$STATE"
  in=$(mktemp -d "$STATE/restore.XXXXXX")
  trap 'rm -rf -- "$in"' EXIT
  head -c 2147483649 > "$in/upload.tar"
  [ "$(stat -c %%s "$in/upload.tar")" -le 2147483648 ] || fail "the upload is too large"
  tar -tvf "$in/upload.tar" | while read -r perms _; do
    case "$perms" in -*) ;; *) fail "the upload holds something other than files" ;; esac
  done
  for n in $(tar -tf "$in/upload.tar"); do
    case "$n" in %[3]s) ;; *) fail "unexpected entry in the upload: $n" ;; esac
  done
  mkdir "$in/x"
  tar -C "$in/x" --no-same-owner --no-same-permissions -xf "$in/upload.tar"
  [ -f "$in/x/SHA256SUMS" ] && [ -f "$in/x/data/store.db" ] || fail "the upload has no store.db or checksums"
  if grep -Evq '^[0-9a-f]{64}  data/(store|idp|events)\.db(-wal)?$' "$in/x/SHA256SUMS"; then fail "bad checksum list"; fi
  (cd "$in/x" && sha256sum --check --strict --quiet SHA256SUMS) || fail "the upload doesn't match its checksums"
  [ "$(cd "$in/x" && find data -type f | wc -l)" = "$(grep -c . "$in/x/SHA256SUMS")" ] || fail "the checksums don't list every file"
  for db in store idp events; do
    f="$in/x/data/$db.db"
    [ -f "$f" ] || continue
    sqlite3 "$f" 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null
    [ "$(sqlite3 "$f" 'PRAGMA integrity_check;')" = ok ] || fail "$db.db from HardyOS failed SQLite's integrity check"
    rm -f "$f-wal" "$f-shm"
  done
  bk="$STATE/before-handback-$(date -u +%%Y%%m%%dT%%H%%M%%SZ)"
  install -d -m 0700 "$bk"
  for db in store idp events; do
    if [ -f "$data/$db.db" ]; then sqlite3 "$data/$db.db" ".backup '$bk/$db.db'"; fi
  done
  docker stop -t 30 "$SERVER" >/dev/null
  for db in store idp events; do
    f="$in/x/data/$db.db"
    [ -f "$f" ] || continue
    install -m 0600 -o root -g root "$f" "$data/$db.db.hardyos-new"
    rm -f "$data/$db.db-wal" "$data/$db.db-shm"
    mv -f "$data/$db.db.hardyos-new" "$data/$db.db"
  done
  docker start "$SERVER" >/dev/null
  echo "restored; the VPS's previous databases are in $bk"
  ;;
*)
  echo "hardyos-standby: refused" >&2; exit 2 ;;
esac
ROOT
chmod 0700 /usr/local/sbin/hardyos-netbird-standby-root

rule="/usr/local/sbin/hardyos-netbird-standby-root status, /usr/local/sbin/hardyos-netbird-standby-root snapshot"
if [ "$ALLOW_HANDBACK" = 1 ]; then rule="$rule, /usr/local/sbin/hardyos-netbird-standby-root restore"; fi
tmp_sudo=$(mktemp)
printf 'Defaults:hardyos-standby env_reset, !requiretty\nhardyos-standby ALL=(root) NOPASSWD: %%s\n' "$rule" > "$tmp_sudo"
visudo -cf "$tmp_sudo" >/dev/null
install -m 0440 -o root -g root "$tmp_sudo" /etc/sudoers.d/hardyos-standby
rm -f "$tmp_sudo"

if grep -Eiq '^[[:space:]]*(AllowUsers|AllowGroups)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
  echo "Note: sshd has AllowUsers/AllowGroups; add hardyos-standby there, or HardyOS can't connect."
fi
echo
echo "Done. Paste this host key into Control Panel > NetBird Standby on HardyOS:"
cat /etc/ssh/ssh_host_ed25519_key.pub
`, s.Hostname, s.keyLine(), restoreCase), nil
}
