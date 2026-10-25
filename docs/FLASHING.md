# Flashing a patched X9DRG-QF image

Board: Supermicro X9DRG-QF, 128-Mbit (16 MiB) SPI flash, AMI Aptio IV.

**Read this whole file before writing anything.** Then read §5.

---

## 1. Risk, honestly

**Low risk:** patch 1 (`patch_mmioh.py`) changes 8 bytes in 16 MiB — 7 code bytes
plus one FFS checksum byte. File sizes identical, no section resize, no volume
repack, patch pattern unique across the whole image.

**Real risk:** the patched module is **`IvtQpiandMrcInit`** — Intel **MRC (Memory
Reference Code) + QPI init**. If it is rejected or misbehaves, **memory training
fails and the board will not POST**. This is not a "settings didn't take"
situation. The board has **no dual-BIOS**.

**Unproven on hardware:** patch 2 baked into flash. The firmware's own
allocation path already computes the same numbers and the patch only changes
what is written into the ACPI table, so risk is low — but it is not a table
override. If you want zero untested flash: ship patch 1 in flash and patch 2 as
an initrd ACPI table override.

**Therefore: establish a recovery path (§5) before you start. Do not skip it.**

---

## 2. Method A — flashrom (recommended)

BIOS-region only. Leaves the flash descriptor, ME firmware and GbE MAC alone.

```bash
sudo apt install flashrom            # Debian/Ubuntu; dnf/pacman equivalent

# 1. Identify the chip. Expect a Winbond W25Q128-class 128-Mbit part.
sudo flashrom -p internal

# 2. Write protection. If "write protect is enabled": in BIOS setup disable
#    "BIOS Lock" / "BIOS Interface Locking" (Advanced -> Chipset Configuration),
#    then:
sudo flashrom -p internal --wp-status
sudo flashrom -p internal --wp-disable

# 3. Dump TWICE and compare. This is not optional.
sudo flashrom -p internal -r dump1.bin
sudo flashrom -p internal -r dump2.bin
md5sum dump1.bin dump2.bin           # MUST be identical
cp dump1.bin bios_stock_BACKUP.bin && chmod 444 bios_stock_BACKUP.bin

# 4. Read the LIVE region registers (C600 LPC/eSPI host bridge 00:1f.0,
#    FREG0-3 at 0x50/54/58/5C; base = [31:12] x 4KiB, limit = [11:0] x 4KiB + 0xFFF)
sudo setpci -s 00:1f.0 0x50.l 0x54.l 0x58.l 0x5c.l
#    FREG1 expected: 0x00400FFF  ->  BIOS region 0x00400000 .. 0x00FFFFFF

# 5. Write BIOS region only, from the full 16 MiB image
echo '0x00400000:0x00ffffff bios' > bios.layout
sudo flashrom -p internal -l bios.layout -w patched.bin
```

### Why the explicit layout file and not `--ifd <image>`

`flashrom --ifd <file>` derives the region table from the descriptor **inside
that file**. This image's descriptor has **`FRBA = 0`** (FLMAP1), so the region
table is read from offset `0x000`, where every byte is `0xFF` — every region
decodes to base `0xfff000`, limit `0xffffff`. A tool that trusts the file's
descriptor computes a garbage BIOS region and writes to the wrong offset.

The real region table is at `0x40`; the BIOS entry (`0x44` = `0x0fff0400`)
decodes to `0x400000 .. 0xFFFFFF`, 12 MiB.

Use the **live** FREG numbers in an explicit layout file, as above.
`flashrom -p internal --ifd -i bios` with **no** filename after `--ifd` is also
safe — flashrom then reads the descriptor from the chip. Only `--ifd <file>` is
broken here.

Layout offsets are absolute chip offsets, and the input image is indexed at the
same offsets — so the input must be the full 16 MiB image. It is.

### Verify against the live chip, not the image file

```bash
sudo flashrom -p internal -r after.bin
cmp -l <(dd if=patched.bin bs=65536 skip=64 count=192 status=none) \
       <(dd if=after.bin bs=65536 skip=64 count=192 status=none)
#   192 x 64 KiB = 12 MiB = the BIOS region. Expect no output (identical).
```

If flashrom refuses with a descriptor/permissions error, use Method B. Do **not**
force it with `-i bios` plus `--force` on a hunch.

---

## 3. Method B — FreeDOS USB + AFUDOSU

Copy to the stick (FAT32, 8.3 filenames are safest): the AFUDOSU binary from
your firmware package, and `patched.bin` renamed to `PATCH.BIN`. BIOS setup:
enable CSM, set the stick as a LEGACY/USB-HDD boot entry.

```
AFUDOSU.EXE PATCH.BIN /P /R /X
```

| flag | does |
|---|---|
| `/P` | Program main BIOS image — **the only write you want** |
| `/R` | Preserve ALL SMBIOS structures (serial, MAC) |
| `/X` | Don't check ROM ID — needed because the file is not byte-identical to stock |

Drop from Supermicro's stock `ami.bat`
(`AFUDOSU.EXE %1 /P /B /N /K /R /FDT /MER /OPR`):

| flag | why not |
|---|---|
| `/B` | Program Boot Block. Descriptor-locked: AFU reports success while the write cannot complete, leaving a partially written block. That block holds the reset vector **and** the `Ctrl+Home` recovery agent. |
| `/FDT` `/MER` `/OPR` `/me` | ME firmware regions. Also descriptor-locked. A partial ME write = the ME never boots, the CPU's power-up handshake never completes → hang at reset, no POST. |
| `/K` | All non-critical blocks and ROM holes — widens the write set for no benefit. |
| `/SANTA` | Skips AFU's ROM validation. Removes the last safety net. |

`/N` (NVRAM) is optional; leave it off to keep your current setup variables.

AFUDOSU is a 16-bit DOS executable — it needs a real DOS environment, not a
shell prompt.

### After programming

Power off → **unplug AC** → clear CMOS (JBT1 pads, short with a metal object
~5 s) → wait 10 s → AC back → power on. First boot after MRC changes is long:
memory re-training can take a couple of minutes and the board may reset itself
once or twice. That is normal.

---

## 4. Method C — BMC / IPMI firmware update

The X9DRG-QF BMC (AST2400/2500) can flash the host BIOS over IPMI
(`ipmitool mc flash ...`) or the web UI. Same content rules apply: BIOS region
only, never the descriptor or ME. Check your BMC firmware supports the
bare-image path before relying on it; on some X9 BMC builds it expects the
vendor's `.rom` wrapper.

---

## 5. Recovery — establish this BEFORE flashing

* **A CH341A-class SPI programmer and a 16 MiB SOIC-8 test clip.** This is the
  **only** recovery path on a board that will not POST. Clip to the flash
  (25Q128 / W25Q128 class), `flashrom -p ch341a -r recover.bin`, verify the dump
  is sane (non-FF, contains `_FVH`), and keep it somewhere safe.
* **The stock image.** Keep the untouched file you downloaded, forever.
* **Your first dump** (`bios_stock_BACKUP.bin`). It holds your board's
  MAC/serial/UUID data, which the stock image does **not**.
* **Jumpers:** `JWP1` (flash write-protect) and `JPME2` (ME recovery). Check
  `JWP1` before flashing; know where `JPME2` is before you need it.
* **Serial console / BMC SOL** open in a second terminal during the flash — you
  get the flash progress and the POST output.

### Symptom table

| symptom | likely cause |
|---|---|
| fans spin, BMC alive, no POST, no video, `Ctrl+Home` does nothing | boot block damaged → programmer |
| fans spin, no POST, hangs very early, ME-related | partial ME write → `JPME2` ME recovery, then programmer |
| POST beeps, memory training fails | MRC module rejected → programmer (this is the patch-1 risk) |
| boots, GPU BAR unassigned | patch not applied / not flashed → verify the image |
| boots, `amdgpu` hangs in `xgpu_ai_mailbox_trans_msg`, `MCBP is enabled` | a BAR aliases ECAM → patch 2 not in effect |

---

## 6. What must never change

* SPI flash descriptor (offsets `0x000000`–`0x000FFF`, and the Access Control
  fields).
* ME firmware region (`0x020000`–`0x3FFFFF`).
* GbE / MAC region.
* The boot block.

Every build in this repo is checked so those regions are byte-identical to
stock. `verify_image.py` asserts it.
