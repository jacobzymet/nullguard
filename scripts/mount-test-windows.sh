#!/usr/bin/env bash
# End-to-end WinFsp test (Windows, Git Bash): create a vault, mount it on a
# drive letter, use it like a normal drive, check that only this user can
# access it, unmount, verify integrity, remount read-only.
# Needs WinFsp installed. Usage: scripts/mount-test-windows.sh path/to/nullguard.exe [DRIVE]
set -euo pipefail

NG=$(realpath "${1:?usage: $0 path/to/nullguard.exe [drive letter]}")
HERE=$(cd "$(dirname "$0")" && pwd -W)
D="${2:-N}:"
WORK=$(mktemp -d)
PW="correct horse battery staple"
cd "$WORK"
cleanup() { "$NG" unmount "$D" >/dev/null 2>&1 || true; cd /; rm -rf "$WORK"; }
trap cleanup EXIT

is_mounted() { [ -d "$D/" ]; }

mount_vault() {
  printf '%s\n' "$PW" | "$NG" mount v.ngv "$D" --password-stdin "$@" 2> mount.log &
  MOUNT_PID=$!
  for _ in $(seq 150); do is_mounted && return 0; sleep 0.2; done
  cat mount.log; echo "mount did not appear"; exit 1
}

unmount_vault() {
  "$NG" unmount "$D"
  wait "$MOUNT_PID"
  ! is_mounted
  grep -q "unmounted and locked" mount.log
}

echo "== create"
printf '%s\n' "$PW" | "$NG" create v.ngv --size 64M --low-memory --password-stdin

echo "== mount and use"
mount_vault
echo "hello vault" > "$D/hello.txt"
mkdir -p "$D/a/b/c"
head -c 20000000 /dev/urandom > big.bin
cp big.bin "$D/a/b/c/big.bin"
cmp big.bin "$D/a/b/c/big.bin"
mv "$D/hello.txt" "$D/a/greeting.txt"
[ "$(cat "$D/a/greeting.txt")" = "hello vault" ]
echo "more" >> "$D/a/greeting.txt"
[ "$(wc -l < "$D/a/greeting.txt")" = 2 ]
truncate -s 5 "$D/a/greeting.txt"
[ "$(cat "$D/a/greeting.txt")" = "hello" ]
echo "temp" > "$D/tmp.txt" && rm "$D/tmp.txt"
[ ! -e "$D/tmp.txt" ]
mkdir "$D/empty" && rmdir "$D/empty"
[ ! -e "$D/empty" ]
ls "$D/a" | grep -q greeting.txt

echo "== security: only this user has access"
powershell -NoProfile -Command "
  \$acl = Get-Acl '$D\\a\\greeting.txt'
  \$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  if (\$acl.Access.Count -ne 1) { throw \"expected one access rule, got \$(\$acl.Access.Count)\" }
  \$who = \$acl.Access[0].IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
  if (\$who -ne \$me) { throw \"access rule is for \$who, not \$me\" }
  if (\$acl.GetOwner([System.Security.Principal.SecurityIdentifier]) -ne \$me) { throw 'wrong owner' }
"

echo "== isolation: other local users can't open anything or probe names"
if net session >/dev/null 2>&1; then
  powershell -NoProfile -ExecutionPolicy Bypass -File "$HERE/winfsp-other-user.ps1" -Drive "$D"
else
  echo "(skipped: needs an administrator to create a second user)"
fi

echo "== refuses a drive letter that is in use"
if printf '%s\n' "$PW" | "$NG" mount v.ngv "$D" --password-stdin 2> err.log; then echo "mounted twice"; exit 1; fi
grep -q "in use" err.log

echo "== unmount"
unmount_vault
if grep -a -q "hello vault" v.ngv; then echo "PLAINTEXT LEAKED"; exit 1; fi
if grep -a -q "greeting" v.ngv; then echo "FILE NAME LEAKED"; exit 1; fi

echo "== verify"
printf '%s\n' "$PW" | "$NG" verify v.ngv --password-stdin

echo "== remount read-only, check persistence"
mount_vault --read-only
cmp big.bin "$D/a/b/c/big.bin"
[ "$(cat "$D/a/greeting.txt")" = "hello" ]
if echo nope > "$D/nope.txt" 2>/dev/null; then echo "read-only mount accepted a write"; exit 1; fi
unmount_vault

echo "== tampering is detected"
python - <<'PY'
import os
size = os.path.getsize("v.ngv")
with open("v.ngv", "r+b") as f:
    for off in range(8192 + 2 * (16 * 1024 + 40), size, 4096):
        f.seek(off); b = f.read(1); f.seek(off); f.write(bytes([b[0] ^ 1]))
PY
if printf '%s\n' "$PW" | "$NG" verify v.ngv --password-stdin; then echo "TAMPERING NOT DETECTED"; exit 1; fi

echo "ALL WINDOWS MOUNT TESTS PASSED"
