#!/bin/bash
# Flash a full 16 MiB SPI image into the BIOS region of a Supermicro X9DRG-QF
# (C602, AMI Aptio IV). Adapted for this repo: paths are derived from the
# script's own location, structure checks call verify_image.py, and the flash
# region layout is generated from the live registers if you have no layout file.
#
# Region facts on this board (measured, from flashrom reading the live
# descriptor; the layout file baked into the image is unusable — see AGENTS.md §6):
#
#   FREG0  descriptor  0x000000 .. 0x00FFFF   read-only    never touched
#   FREG1  BIOS        0x400000 .. 0xFFFFFF   read-write   the only region written
#   FREG2  ME          0x020000 .. 0x3FFFFF   locked       never touched
#
# Chip marking N25Q128A -> flashrom definition "N25Q128..3E".
#
# With a layout, flashrom indexes the image at chip offsets and requires a
# full-chip-size image (16,777,216 bytes). Region slices are rejected.
#
# Usage:
#   ./flash.sh <image> check     validate structure only (no root needed)
#   sudo ./flash.sh <image> backup    read the BIOS region twice, keep a backup
#   sudo ./flash.sh <image> flash     check + backup + write + read-back verify
#   ./flash.sh <image> verify    validate the newest read-back
#
# Gates enforced by 'flash':
#   1. the image is exactly 16,777,216 bytes
#   2. every FFS header and FFS file-data checksum in the image closes
#      (the FV header checksum field is stale on stock and is informational only)
#   3. a backup exists, and two consecutive reads of the chip are identical
#   4. after the write, the chip read-back equals the image byte-for-byte across
#      the whole BIOS region, and the read-back passes structure validation
#
# Override any of: BINDIR WORK LAY CHIP STOCK BIOS_OFF BIOS_LEN CHIP_SIZE LPC
set -uo pipefail

SCRIPT=$(readlink -f "$0")
BINDIR=${BINDIR:-$(dirname "$SCRIPT")}
WORK=${WORK:-$BINDIR/bios-backups}
CHIP=${CHIP:-N25Q128..3E}
LAY=${LAY:-$BINDIR/bios.layout}
STOCK=${STOCK:-$BINDIR/X9DRGQF8.921}
LPC=${LPC:-00:1f.0}
BIOS_OFF=${BIOS_OFF:-0x400000}
BIOS_LEN=${BIOS_LEN:-0xC00000}
CHIP_SIZE=${CHIP_SIZE:-16777216}
FR="flashrom -p internal -c $CHIP -l $LAY -i bios"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

IMG=${1:-}
CMD=${2:-check}
[ -n "$IMG" ] || { echo "usage: $0 <image> <check|backup|flash|verify>   (backup/flash need root)"; exit 1; }
[ -e "$IMG" ] || { echo "image not found: $IMG"; exit 1; }
PY=${PY:-$(command -v python3 || command -v python)}
[ -n "$PY" ] || { echo "no python interpreter found (need python3)"; exit 1; }
VER="$BINDIR/verify_image.py"
[ -e "$VER" ] || { echo "verifier not found: $VER"; exit 1; }
mkdir -p "$WORK" 2>/dev/null || true

# flashrom, root and a layout file are needed only by the modes that touch the
# chip. 'check' and 'verify' validate a file, so they must run on any machine and
# ask for none of the three.
case "$CMD" in
	backup|flash)
		command -v flashrom >/dev/null || { echo "flashrom not installed"; exit 1; }
		[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0 $IMG $CMD"; exit 1; }
		# Generate the layout from the measured region table if none is present.
		# Never derive it from the image file: that descriptor has FRBA = 0, so
		# every region decodes to base 0xfff000 / limit 0xffffff.
		if [ ! -e "$LAY" ]; then
			echo "  generating $LAY from the measured region table"
			printf '0x%08x:0x%08x bios\n' "$BIOS_OFF" "$((BIOS_OFF + BIOS_LEN - 1))" >"$LAY"
		fi
		;;
esac

hdr() {
	echo "== target =="
	echo "  image    $IMG"
	echo "  size     $(stat -c %s "$IMG") bytes"
	echo "  sha256   $(sha256sum "$IMG" | cut -d' ' -f1)"
	echo "  chip     $CHIP"
	echo "  region   bios = $(printf '0x%08x..0x%08x' "$BIOS_OFF" "$((BIOS_OFF + BIOS_LEN - 1))")" \
		"(12 MiB); descriptor and ME untouched"
	echo
}

check_structure() {	# $1 = file ; returns 1 on any invalid checksum
	local out
	out=$($PY "$VER" --structure-only "$1" 2>&1)
	echo "$out" | grep -E "FV headers|FFS headers|FFS file data" | sed 's/^/  /'
	if echo "$out" | grep -q INVALID; then
		echo "  [!] INVALID CHECKSUMS in $1"
		echo "$out" | grep INVALID | sed 's/^/      /' | head -6
		return 1
	fi
	return 0
}

show_delta() {	# what the image changes vs the stock image, if one is present
	[ -e "$STOCK" ] || { echo "  (no stock image at $STOCK, no delta shown;" \
		"set STOCK=/path/to/X9DRGQF8.921 to see one)"; return; }
	$PY - "$IMG" "$STOCK" "$BIOS_OFF" "$BIOS_LEN" <<'PY'
import sys
a = open(sys.argv[1], 'rb').read()
s = open(sys.argv[2], 'rb').read()
off, ln = int(sys.argv[3], 0), int(sys.argv[4], 0)
A, B = a[off:off + ln], s[off:off + ln]
print('== what this image changes vs stock (BIOS region) ==')
# the measured layout of this image: AGENTS.md §3
for lo, hi, name in [(0x400000, 0x41FFFF, 'FV00'),
                     (0x420000, 0x45FFFF, 'NCB1'),
                     (0x460000, 0xDCFFFF, 'FV01 (DXE)'),
                     (0xDD0000, 0xDFFFFF, 'NCB2'),
                     (0xE00000, 0xFFFFFF, 'FV02 (PEI + boot block)')]:
    n = hi - lo + 1
    runs, i = [], lo - off
    while i < lo - off + n:
        if A[i] != B[i]:
            j = i
            while j < lo - off + n and A[j] != B[j]:
                j += 1
            runs.append((off + i, j - i)); i = j
        else:
            i += 1
    d = sum(l for _, l in runs)
    print(f'  {name:24s} {d:9d} B in {len(runs)} run(s)')
    if 0 < len(runs) <= 8:
        for st, l in runs:
            print(f'      {st:#x} len {l}  stock {B[st-off:st-off+l].hex()}'
                  f'  image {A[st-off:st-off+l].hex()}')
print()
PY
}

live_regions() {
	flashrom -p internal -c "$CHIP" --wp-status 2>&1 | grep -E "^FREG[0-9]+:" | sed 's/^/  /'
}

do_backup() {
	$FR -r "$WORK/d1.bin" >/dev/null 2>&1 && $FR -r "$WORK/d2.bin" >/dev/null 2>&1 || {
		echo "  [!] read failed"; return 1; }
	if cmp -s "$WORK/d1.bin" "$WORK/d2.bin"; then
		cp -a "$WORK/d1.bin" "$WORK/BACKUP-$STAMP.bin"
		chmod 444 "$WORK/BACKUP-$STAMP.bin"
		echo "  backup ok: $WORK/BACKUP-$STAMP.bin"
		sha256sum "$WORK/BACKUP-$STAMP.bin" | sed 's/^/  /'
		return 0
	fi
	echo "  [!] two reads differ - read path unstable, do not flash"; return 1
}

case "$CMD" in
check)
	hdr
	echo "== structure validation =="
	check_structure "$IMG" && echo "  all checksums valid"
	echo
	show_delta
	;;
backup)
	hdr
	echo "== backup =="
	do_backup
	;;
flash)
	hdr
	echo "== gate 1: image size =="
	SZ=$(stat -c %s "$IMG")
	[ "$SZ" = "$CHIP_SIZE" ] || { echo "  [!] $SZ bytes, need $CHIP_SIZE"; exit 1; }
	echo "  ok"
	echo
	echo "== gate 2: structure validation =="
	check_structure "$IMG" || { echo "  [!] refusing to flash an image with invalid checksums"; exit 1; }
	echo "  ok"
	echo
	show_delta
	echo "== gate 3: live regions and backup =="
	live_regions
	echo "  BIOS eSPI/LPC base register ($LPC +0xF0) = $(setpci -s $LPC 0xF0.l 2>/dev/null)"
	if [ -z "$(ls -1t "$WORK"/BACKUP-*.bin 2>/dev/null | head -1)" ]; then
		echo "  no backup yet, reading the chip now"
		do_backup || exit 1
	else
		echo "  backup present: $(ls -1t "$WORK"/BACKUP-*.bin | head -1)"
	fi
	echo
	echo "== write =="
	$FR -w "$IMG" --noverify-all || { echo "  [!] flashrom failed - chip may be partial, do not power off"; exit 1; }
	echo
	echo "== gate 4: read-back compare =="
	$FR -r "$WORK/after-$STAMP.bin" >/dev/null 2>&1 || { echo "  [!] read-back failed"; exit 1; }
	$PY - "$IMG" "$WORK/after-$STAMP.bin" "$BIOS_OFF" "$BIOS_LEN" <<'PY'
import sys
img = open(sys.argv[1], 'rb').read()
af = open(sys.argv[2], 'rb').read()
off, ln = int(sys.argv[3], 0), int(sys.argv[4], 0)
img, af = img[off:off + ln], af[off:off + ln]
print(f'  compared {len(img)} bytes at chip {off:#x}..{off + ln - 1:#x}')
print('  READ-BACK == IMAGE BIOS REGION: PASS' if af == img
      else '  [!] READ-BACK != IMAGE: FAIL')
sys.exit(0 if af == img else 1)
PY
	[ $? -eq 0 ] || exit 1
	check_structure "$WORK/after-$STAMP.bin"
	echo
	echo "  Done. Power-cycle now: the new code has not run yet."
	echo "  The BIOS region write covers the UEFI variable store: boot entries reset."
	echo "  Keep the USB boot stick plugged in. Check: sudo efibootmgr -v"
	;;
verify)
	AFTER=$(ls -1t "$WORK"/after-*.bin 2>/dev/null | head -1)
	[ -n "$AFTER" ] || { echo "  no read-back found in $WORK"; exit 1; }
	echo "== newest read-back: $AFTER =="
	sha256sum "$AFTER" | sed 's/^/  /'
	check_structure "$AFTER"
	;;
*)
	echo "usage: $0 <image> <check|backup|flash|verify>   (backup/flash need root)"; exit 1
	;;
esac
