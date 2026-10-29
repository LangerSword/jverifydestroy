#!/usr/bin/env bash
# Spike H6: on an ext4 image, does delete-only leave file contents? Does block overwrite remove them?
set -u
cd "$(dirname "$0")"
IMG=ext4-probe.img
CAN=canary.bin
head -c 8192 /dev/urandom > "$CAN"
PAT=$(python3 -c "import sys;d=open('$CAN','rb').read();print(d[:32].hex())")

scan() { python3 - "$1" "$PAT" <<'PY'
import sys
img,pat=sys.argv[1],bytes.fromhex(sys.argv[2])
d=open(img,'rb').read()
i=d.find(pat)
print("FOUND" if i>=0 else "NOT_FOUND", ("at "+hex(i)) if i>=0 else "")
PY
}

mkimg() { rm -f "$IMG"; truncate -s 32M "$IMG"; mkfs.ext4 -q -F "$IMG"; }

blocks() { debugfs -R "stat /secret" "$IMG" 2>/dev/null | sed -n 's/^(0):\([0-9]*\)-\([0-9]*\).*/\1 \2/p' | head -1; }

echo "== delete only =="
mkimg
debugfs -w -R "write $CAN /secret" "$IMG" >/dev/null 2>&1
echo -n "before delete: "; scan "$IMG"
debugfs -w -R "rm /secret" "$IMG" >/dev/null 2>&1
echo -n "after delete : "; scan "$IMG"

echo "== one-pass zero overwrite then delete =="
mkimg
debugfs -w -R "write $CAN /secret" "$IMG" >/dev/null 2>&1
read -r B E <<<"$(blocks)"
echo "blocks: $B-$E"
dd if=/dev/zero of="$IMG" bs=4096 seek="$B" count=$((E-B+1)) conv=notrunc status=none
debugfs -w -R "rm /secret" "$IMG" >/dev/null 2>&1
echo -n "after overwrite+delete: "; scan "$IMG"

echo "== three-pass overwrite then delete =="
mkimg
debugfs -w -R "write $CAN /secret" "$IMG" >/dev/null 2>&1
read -r B E <<<"$(blocks)"
dd if=/dev/zero of="$IMG" bs=4096 seek="$B" count=$((E-B+1)) conv=notrunc status=none
tr '\0' '\377' < /dev/zero | dd of="$IMG" bs=4096 seek="$B" count=$((E-B+1)) conv=notrunc status=none 2>/dev/null
dd if=/dev/urandom of="$IMG" bs=4096 seek="$B" count=$((E-B+1)) conv=notrunc status=none
debugfs -w -R "rm /secret" "$IMG" >/dev/null 2>&1
echo -n "after 3-pass+delete: "; scan "$IMG"

rm -f "$IMG" "$CAN"
