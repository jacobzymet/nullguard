#!/usr/bin/env bash
# End-to-end FUSE test: create a vault, mount it, use it like a normal
# filesystem, unmount, verify integrity, remount and check persistence.
# Usage: scripts/mount-test.sh path/to/nullguard
set -euo pipefail

NG=$(realpath "${1:?usage: $0 path/to/nullguard}")
WORK=$(mktemp -d)
PW="correct horse battery staple"
KDF=(--kdf-memory 64 --kdf-iterations 2 --kdf-parallelism 1)
cd "$WORK"
cleanup() { fusermount3 -u "$WORK/mnt" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

is_mounted() { grep -q " $WORK/mnt " /proc/mounts; }

mount_vault() {
  printf '%s\n' "$PW" | "$NG" mount v.ngv mnt --password-stdin "$@" 2> mount.log &
  MOUNT_PID=$!
  for _ in $(seq 100); do is_mounted && return 0; sleep 0.1; done
  cat mount.log; echo "mount did not appear"; exit 1
}

unmount_vault() {
  "$NG" unmount mnt
  wait "$MOUNT_PID"
  ! is_mounted
}

echo "== create"
printf '%s\n' "$PW" | "$NG" create v.ngv --size 64M --password-stdin "${KDF[@]}"
mkdir mnt

echo "== mount and use"
mount_vault
echo "hello vault" > mnt/hello.txt
mkdir -p mnt/a/b/c
head -c 20000000 /dev/urandom > big.bin
cp big.bin mnt/a/b/c/big.bin
cmp big.bin mnt/a/b/c/big.bin
mv mnt/hello.txt mnt/a/greeting.txt
ln -s a/greeting.txt mnt/link
[ "$(cat mnt/link)" = "hello vault" ]
dd if=/dev/zero of=mnt/sparse bs=1 count=1 seek=10000000 status=none
[ "$(stat -c %s mnt/sparse)" = 10000001 ]
truncate -s 5 mnt/a/greeting.txt
[ "$(cat mnt/a/greeting.txt)" = "hello" ]
echo "temp" > mnt/tmp && rm mnt/tmp
[ ! -e mnt/tmp ]
chmod 600 mnt/a/greeting.txt
[ "$(stat -c %a mnt/a/greeting.txt)" = 600 ]
python3 - <<'PY' 2>/dev/null || true
import os
# Open-then-unlink: data stays readable through the open handle.
p = "mnt/unlinked"
with open(p, "w+") as f:
    f.write("still here"); f.flush()
    os.unlink(p); f.seek(0)
    assert f.read() == "still here"
PY
sync
df -h mnt | tail -1

echo "== security: mount options"
grep " $WORK/mnt " /proc/mounts
grep " $WORK/mnt " /proc/mounts | grep -q nosuid
grep " $WORK/mnt " /proc/mounts | grep -q nodev

echo "== unmount"
unmount_vault
grep -q "unmounted and locked" mount.log
if strings v.ngv | grep -q "hello vault"; then echo "PLAINTEXT LEAKED"; exit 1; fi
if strings v.ngv | grep -q "greeting"; then echo "FILE NAME LEAKED"; exit 1; fi

echo "== verify"
printf '%s\n' "$PW" | "$NG" verify v.ngv --password-stdin

echo "== remount read-only, check persistence"
mount_vault --read-only
cmp big.bin mnt/a/b/c/big.bin
[ "$(cat mnt/a/greeting.txt)" = "hello" ]
if touch mnt/nope 2>/dev/null; then echo "read-only mount accepted a write"; exit 1; fi
unmount_vault

echo "== Ctrl-C locks the vault"
mount_vault
echo "after ctrl-c" > mnt/sigint.txt
kill -INT "$MOUNT_PID"
wait "$MOUNT_PID" || true
! is_mounted
printf '%s\n' "$PW" | "$NG" ls v.ngv / --password-stdin | grep -q sigint.txt

echo "== SIGTERM locks the vault"
mount_vault
echo "after sigterm" > mnt/sigterm.txt
kill -TERM "$MOUNT_PID"
wait "$MOUNT_PID" || true
! is_mounted
printf '%s\n' "$PW" | "$NG" ls v.ngv / --password-stdin | grep -q sigterm.txt

echo "== refuses a non-empty mount point"
mkdir full && touch full/existing
if printf '%s\n' "$PW" | "$NG" mount v.ngv full --password-stdin 2>err.log; then echo "mounted over files"; exit 1; fi
grep -q "not empty" err.log

if [ "$(id -u)" = 0 ] && command -v useradd >/dev/null && command -v su >/dev/null; then
  echo "== ownership: a vault written by another uid mounts for the current user"
  useradd -m ngtester 2>/dev/null || true
  chmod 755 "$WORK"
  # The test user may not be able to reach the build directory (e.g. under
  # /home/runner on CI), so give it its own copy of the binary.
  cp "$NG" "$WORK/ng" && chmod 755 "$WORK/ng"
  UNG="$WORK/ng"
  printf '%s\n' "$PW" | "$NG" create other.ngv --size 16M --quick --password-stdin "${KDF[@]}"
  echo "written by root" > rootfile.txt
  printf '%s\n' "$PW" | "$NG" put other.ngv rootfile.txt / --password-stdin
  [ "$(stat -c %a other.ngv)" = 600 ]   # vault files are private
  chown ngtester other.ngv
  M=/home/ngtester/m
  su ngtester -c "mkdir -p $M"
  su ngtester -c "printf '%s\n' '$PW' | $UNG mount $WORK/other.ngv $M --password-stdin" 2> other.log &
  for _ in $(seq 100); do grep -q " $M " /proc/mounts && break; sleep 0.1; done
  grep -q " $M " /proc/mounts || { cat other.log; echo "user mount failed"; exit 1; }
  [ "$(su ngtester -c "cat $M/rootfile.txt")" = "written by root" ]
  [ "$(su ngtester -c "stat -c %U $M/rootfile.txt")" = ngtester ]
  su ngtester -c "echo mine > $M/new.txt"
  echo "== isolation: not even root can read another user's mounted vault"
  if cat "$M/rootfile.txt" 2>/dev/null; then echo "root could read the mount"; exit 1; fi
  su ngtester -c "$UNG unmount $M"
  for _ in $(seq 50); do grep -q " $M " /proc/mounts || break; sleep 0.1; done
  ! grep -q " $M " /proc/mounts
fi

echo "== tampering is detected"
python3 - <<'PY' || perl -e 'open F,"+<","v.ngv"; for($o=128*1024+2*(16424);$o<-s "v.ngv";$o+=4096){seek F,$o,0;read F,$b,1;seek F,$o,0;print F chr(ord($b)^1)}'
import os
size = os.path.getsize("v.ngv")
with open("v.ngv", "r+b") as f:
    for off in range(128 * 1024 + 2 * (16 * 1024 + 40), size, 4096):
        f.seek(off); b = f.read(1); f.seek(off); f.write(bytes([b[0] ^ 1]))
PY
if printf '%s\n' "$PW" | "$NG" verify v.ngv --password-stdin; then echo "TAMPERING NOT DETECTED"; exit 1; fi

echo "ALL MOUNT TESTS PASSED"
