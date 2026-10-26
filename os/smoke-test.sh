#!/bin/bash
# shellcheck disable=SC2054 # commas are part of QEMU's options
# End-to-end smoke test of a HardyOS ISO in QEMU (UEFI, two NVMe boot disks,
# three data disks), driven only through the web API:
#
#   1. boot the installer and read the install code from the serial console
#   2. install onto both NVMe disks (mirror) and restart from them
#   3. sign in as the administrator chosen in the installer
#   4. create a storage pool from the recommendation
#   5. back up the settings onto the pool
#   6. create a domain, a domain user and a group; the DC must answer
#   7. with an update file: install it, restart, check it's confirmed and
#      that the domain carried over
#
# Usage: os/smoke-test.sh <hardyos.iso> [update.hupd]
# Needs qemu-system-x86_64, OVMF, bsdtar, curl and jq; KVM makes it fast.
set -euo pipefail

ISO=$(realpath "$1")
UPDATE=${2:+$(realpath "$2")}
WORK=${SMOKE_WORK:-$(mktemp -d)}
PORT=${SMOKE_PORT:-18443}
API="https://127.0.0.1:$PORT/api/v1"
ADMIN_USER=smoke
ADMIN_PASS=smoke-test-password-1
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
QEMU_PID=

log() { printf '\n=== %s\n' "$*"; }
fail() {
  printf '\nFAILED: %s\n' "$*" >&2
  echo "--- last serial output:" >&2
  tail -n 60 "$WORK"/serial-*.log 2>/dev/null | tr -d '\r' | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' >&2 || true
  exit 1
}
cleanup() { stop_vm; }
trap cleanup EXIT

# --- the VM -------------------------------------------------------------------

accel=(-machine q35)
if [ -w /dev/kvm ]; then accel=(-machine q35,accel=kvm -cpu host); else echo "no KVM: this will be slow"; accel+=(-cpu max); fi

cp "$OVMF_VARS" "$WORK/vars.fd"
for d in boot1 boot2; do qemu-img create -q -f qcow2 "$WORK/$d.qcow2" 20G; done
for d in data1 data2 data3; do qemu-img create -q -f qcow2 "$WORK/$d.qcow2" 8G; done

start_vm() { # start_vm <name> [installer]
  local name=$1
  local args=(
    "${accel[@]}" -smp 4 -m 4096 -display none -no-reboot
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
    -drive if=pflash,format=raw,file="$WORK/vars.fd"
    -drive file="$WORK/boot1.qcow2",if=none,id=b1 -device nvme,drive=b1,serial=HARDYBOOT1
    -drive file="$WORK/boot2.qcow2",if=none,id=b2 -device nvme,drive=b2,serial=HARDYBOOT2
    -drive file="$WORK/data1.qcow2",if=none,id=d1 -device virtio-blk-pci,drive=d1,serial=DATA1
    -drive file="$WORK/data2.qcow2",if=none,id=d2 -device virtio-blk-pci,drive=d2,serial=DATA2
    -drive file="$WORK/data3.qcow2",if=none,id=d3 -device virtio-blk-pci,drive=d3,serial=DATA3
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:443" -device virtio-net-pci,netdev=n0
    -serial "file:$WORK/serial-$name.log"
  )
  if [ "${2:-}" = installer ]; then
    # Boot the ISO's own kernel with the serial console added, so the login
    # screen (and the install code on it) also shows up in the serial log.
    bsdtar -xf "$ISO" -C "$WORK" live/vmlinuz live/initrd.img
    args+=(-kernel "$WORK/live/vmlinuz" -initrd "$WORK/live/initrd.img"
      -append "boot=live components hostname=hardyos live-config.noautologin console=tty0 console=ttyS0,115200"
      -drive file="$ISO",media=cdrom,if=none,id=cd -device ide-cd,drive=cd)
  fi
  qemu-system-x86_64 "${args[@]}" > "$WORK/qemu-$name.log" 2>&1 &
  QEMU_PID=$!
}

stop_vm() {
  if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  QEMU_PID=
}

# wait_vm_exit waits for a restart (QEMU exits instead, because of -no-reboot).
wait_vm_exit() {
  local deadline=$((SECONDS + ${1:-300}))
  while kill -0 "$QEMU_PID" 2>/dev/null; do
    [ $SECONDS -lt $deadline ] || fail "the VM didn't restart"
    sleep 2
  done
  QEMU_PID=
}

# --- the API ------------------------------------------------------------------

JAR="$WORK/cookies"
api() { # api METHOD PATH [JSON]  -> body on stdout; fails on HTTP errors
  local method=$1 path=$2 body=${3:-}
  local out status
  out=$(curl -sk -m 120 -w '\n%{http_code}' -b "$JAR" -c "$JAR" -X "$method" \
    -H 'X-HardyOS-Request: 1' -H 'Content-Type: application/json' ${body:+--data "$body"} "$API$path") || return 1
  status=${out##*$'\n'}
  out=${out%$'\n'*}
  if [ "$status" -ge 400 ]; then
    echo "$method $path -> $status: $out" >&2
    return 1
  fi
  printf '%s' "$out"
}

wait_api() { # wait_api PATH SECONDS
  local deadline=$((SECONDS + $2))
  until curl -skf -m 10 "$API$1" >/dev/null 2>&1; do
    [ $SECONDS -lt $deadline ] || fail "$API$1 didn't answer in $2 s"
    kill -0 "$QEMU_PID" 2>/dev/null || fail "the VM stopped"
    sleep 3
  done
}

wait_job() { # wait_job ID [SECONDS] -> the job JSON
  local id=$1 deadline=$((SECONDS + ${2:-1200})) j state
  while :; do
    j=$(api GET "/jobs/$id") || fail "reading job $id"
    state=$(jq -r .state <<<"$j")
    case $state in
      succeeded) printf '%s' "$j"; return 0 ;;
      failed | cancelled) fail "job $(jq -r .title <<<"$j") $state: $(jq -r .error <<<"$j")" ;;
    esac
    [ $SECONDS -lt $deadline ] || fail "job $id still $state"
    sleep 5
  done
}

# --- 1. installer ---------------------------------------------------------------

log "Booting the installer"
start_vm installer installer
deadline=$((SECONDS + 600))
code=
until [ -n "$code" ]; do
  code=$(tr -d '\r' < "$WORK/serial-installer.log" | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' |
    grep -oE 'enter this code:[[:space:]]+[A-Z0-9]{4}-[A-Z0-9]{4}' | tail -n1 | grep -oE '[A-Z0-9]{4}-[A-Z0-9]{4}' || true)
  [ $SECONDS -lt $deadline ] || fail "no install code on the serial console"
  kill -0 "$QEMU_PID" 2>/dev/null || fail "the installer VM stopped"
  [ -n "$code" ] || sleep 3
done
echo "install code: $code"
wait_api /installer 300

api POST /installer/unlock "$(jq -nc --arg c "$code" '{code:$c}')" > /dev/null || fail "unlock"
hw=$(api GET /installer/hardware) || fail "hardware"
mapfile -t boot < <(jq -r '.disks[] | select(.transport=="nvme") | .byId' <<<"$hw" | sort)
[ "${#boot[@]}" -eq 2 ] || fail "expected two NVMe disks, found: ${boot[*]}"
echo "boot disks: ${boot[*]}"
plan=$(jq -nc --arg a "${boot[0]}" --arg b "${boot[1]}" '{disks:[$a,$b], hostname:"smoke", timezone:"Etc/UTC", network:{mode:"dhcp"}}')
api POST /installer/check "$(jq -nc --argjson p "$plan" '{plan:$p}')" > /dev/null || fail "install check"

log "Installing"
api POST /installer/install "$(jq -nc --argjson p "$plan" --arg u "$ADMIN_USER" --arg pw "$ADMIN_PASS" \
  '{plan:$p, admin:{username:$u, displayName:"Smoke Test", password:$pw}, confirmWipe:true}')" > /dev/null || fail "start install"
deadline=$((SECONDS + 1800))
while :; do
  st=$(api GET /installer) || fail "installer status"
  state=$(jq -r '.job.state // "none"' <<<"$st")
  case $state in
    succeeded) break ;;
    failed | cancelled) fail "install $state: $(jq -r .job.error <<<"$st")" ;;
  esac
  [ $SECONDS -lt $deadline ] || fail "install still $state"
  echo "  $(jq -r '"\(.job.progress // 0 | floor)% \(.job.message // "")"' <<<"$st")"
  sleep 10
done
api POST /installer/reboot > /dev/null || true
wait_vm_exit 300

# --- 2. first boot from the disks -------------------------------------------------

log "Starting from the boot disks"
rm -f "$JAR"
start_vm disk
wait_api /health 600
setup=$(curl -skf "$API/setup") || fail "setup status"
[ "$(jq -r .needsAdmin <<<"$setup")" = false ] || fail "the installer's administrator wasn't created: $setup"

log "Signing in"
api POST /auth/login "$(jq -nc --arg u "$ADMIN_USER" --arg p "$ADMIN_PASS" '{username:$u, password:$p}')" > /dev/null || fail "sign-in"
me=$(api GET /auth/me) || fail "who am I"
[ "$(jq -r .role <<<"$me")" = admin ] || fail "signed in, but not as an administrator: $me"
bootpool=$(api GET /storage/boot) || fail "boot disks"
[ "$(jq -r '.disks | length' <<<"$bootpool")" = 2 ] || fail "boot mirror: $bootpool"
[ "$(jq -r .status.state <<<"$bootpool")" = ONLINE ] || fail "boot pool not ONLINE: $(jq -r .status.state <<<"$bootpool")"
api GET /network > /dev/null || fail "network settings"

# --- 3. storage and backups ---------------------------------------------------------

log "Creating a storage pool"
rec=$(api GET "/storage/recommendation?name=tank") || fail "pool recommendation"
job=$(api POST /storage/pools "$(jq -c '{spec:.spec, confirmWipe:true}' <<<"$rec")") || fail "create pool"
wait_job "$(jq -r .job.id <<<"$job")" 600 > /dev/null
api GET /storage/pools | jq -e 'map(select(.name=="tank" and .health=="ONLINE")) | length == 1' > /dev/null || fail "pool tank isn't ONLINE"

log "Backing up settings onto the pool"
job=$(api POST /system/backups/run '{}') || fail "start backup"
wait_job "$(jq -r .job.id <<<"$job")" 300 > /dev/null
api GET /system/backups | jq -e '.backups | length == 1' > /dev/null || fail "no backup on the pool"

# --- 4. the domain controller ------------------------------------------------------

wait_domain() { # wait_domain SECONDS: until the DC answers from the NAS
  local deadline=$((SECONDS + $1)) st
  until st=$(api GET /domain) && jq -e '.running and .responding' > /dev/null <<<"$st"; do
    [ $SECONDS -lt $deadline ] || fail "the domain controller isn't answering: $st"
    sleep 5
  done
}

log "Creating a domain"
sug=$(api GET /domain/suggest) || fail "domain suggestion"
addr=$(jq -r .address <<<"$sug")
[ -n "$addr" ] || fail "no free address for the domain controller: $sug"
job=$(api POST /domain "$(jq -nc --arg a "$addr" '{domain:"home.hardyos-smoke.net", adminPassword:"Smoke-Adm1n-Pass", address:$a}')") || fail "create the domain"
wait_job "$(jq -r .job.id <<<"$job")" 600 > /dev/null
wait_domain 120
api POST /domain/users '{"username":"alice","givenName":"Alice","surname":"Hardy","password":"Al1ce-Passw0rd!"}' > /dev/null || fail "create a domain user"
api POST /domain/groups '{"name":"Family","members":["alice"]}' > /dev/null || fail "create a domain group"
api GET /domain/users | jq -e '.users | map(select(.username=="alice" and (.groups | index("Family")))) | length == 1' > /dev/null || fail "alice isn't in Family"

# --- 5. an update ------------------------------------------------------------------

if [ -n "$UPDATE" ]; then
  log "Installing $(basename "$UPDATE")"
  out=$(curl -sk -m 1800 -b "$JAR" -X POST -H 'X-HardyOS-Request: 1' -H 'Content-Type: application/octet-stream' \
    --data-binary "@$UPDATE" "$API/system/updates/upload") || fail "upload update"
  wait_job "$(jq -r .job.id <<<"$out")" 1800 > /dev/null
  want=$(api GET /system/updates | jq -r .pending.version) || fail "update status"
  if [ -z "$want" ] || [ "$want" = null ]; then fail "the update isn't waiting for a restart"; fi
  api POST /system/reboot > /dev/null || fail "restart"
  wait_vm_exit 300
  start_vm updated
  wait_api /health 600
  api POST /auth/login "$(jq -nc --arg u "$ADMIN_USER" --arg p "$ADMIN_PASS" '{username:$u, password:$p}')" > /dev/null || fail "sign-in after update"
  # hardyd confirms the new version after a minute of running well.
  deadline=$((SECONDS + 300))
  until api GET /system/updates | jq -e '.pending == null and .last.ok == true' > /dev/null; do
    [ $SECONDS -lt $deadline ] || fail "the update wasn't confirmed: $(api GET /system/updates)"
    sleep 10
  done
  running=$(api GET /system/updates | jq -r '.versions[] | select(.running) | .version')
  [ "$running" = "$want" ] || fail "running $running, expected $want"
  api GET /storage/pools | jq -e 'map(select(.name=="tank")) | length == 1' > /dev/null || fail "pool tank missing after the update"
  # The domain lives outside the boot environment, so it carries over.
  wait_domain 180
  api GET /domain/users | jq -e '.users | map(select(.username=="alice")) | length == 1' > /dev/null || fail "alice is missing after the update"
fi

log "All smoke tests passed"
