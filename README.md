# sandy-bridge-ep-rebar

Enable **ReBAR (Resizable BAR / large 64-bit MMIO)** on Intel **Sandy Bridge-EP /
Ivy Bridge-EP** (Xeon E5-2600 v1/v2) server platforms — and fix the 32-bit
aperture collision that stops the big BAR from being *used*.

Reference board: **Supermicro X9DRG-QF** (C602 "Patsburg", AMI Aptio IV), BIOS
3.3 (`X9DRGQF8.921`), Xeon **E5-2690 v2**, AMD Instinct **MI210** (64 GiB BAR0).
Both patches are **flashed and running on that board**.

Pure Python, no proprietary tool in the build path.

## Quick start

```bash
pip install -r requirements.txt
python patch_bios.py X9DRGQF8.921
```

That applies both patches, installs the repo's POST logo, writes
`X9DRGQF8.921.rebar.bin`, and then verifies the result against the stock image
from its own bytes — refusing to call it good if anything fails. The input image
is opened read-only and never modified.

```
input   X9DRGQF8.921  (16777216 bytes)
output  X9DRGQF8.921.rebar.bin
logo    logo.dat
...
ALL CHECKS PASSED

==================================================================
  X9DRGQF8.921.rebar.bin   ready to flash (main BIOS region only)
==================================================================
  patches: MMIOH 1 TiB -> 8 TiB, published aperture ECAM-excluded
  logo   : replaced
```

No arguments are needed; the defaults are the shapes proven on the reference
board. Options:

```bash
python patch_bios.py X9DRGQF8.921 --nologo             # patches only
python patch_bios.py X9DRGQF8.921 --logo mine.bmp      # your 640x480 8-bit BMP
python patch_bios.py X9DRGQF8.921 --logo-uncompressed   # logo shape the reference board runs
python patch_bios.py X9DRGQF8.921 --recompress          # patch 2 recompressed: 16 B of volume moved, not ~45 KB
python patch_bios.py X9DRGQF8.921 --size 0x1000         # MMIOH size in GiB (power of two)
```

Needs **Python 3.10+** (the `uefi-firmware` wheels carrying the EDK2 Tiano codec
require it). `patch_mmioh.py` alone runs on 3.8+ with no third-party packages.

## The two defects

They are independent; a card can be blocked by one, the other, or both.

| | defect | patch | shape |
|---|---|---|---|
| **1** | the 64-bit MMIO aperture (MMIOH) is hard-coded to **1 TiB**, and its size variable is wired to no setup question — so a 64 GiB BAR lands one aperture-width past the end of the window | 7 code bytes in the PEIM `IvtQpiandMrcInit` (FV02), **1 TiB → 8 TiB** | size-preserving, no volume repack; 8 bytes change in total (7 code + 1 FFS checksum) |
| **2** | the root-bridge **32-bit** aperture published in the DSDT *contains ECAM*, so Linux hands out BARs that alias PCI config space | 14 code bytes in the DXE driver `PciRootBridge` (FV01): subtract ECAM from the published window | module expanded, patched, repacked in place |

**Patch 1 is the ReBAR enabler** — on its own it is enough for a GPU whose BAR
fits in the 32-bit window plus the 8 TiB 64-bit window. **Patch 2** is needed when
the card is SR-IOV / large enough that Linux reallocates the bridge window and
lands it on ECAM — exactly the MI210 case.

`0x2000` GiB = 8 TiB is the **maximum legal value** on this platform: base
`0x3800` × 4 GiB = 56 TiB, and base + size must not exceed the CPU's 46-bit
physical address space. The script refuses anything larger. Patch 1 prints what
it programmed:

```
MMIOH base         0x380000000000  (56 TiB)   [default 0x3800 x 4 GiB]
MMIOH size         0x080000000000  (8 TiB)   [0x2000 GiB]
MMIOH mask         0x07ffffffffff   (= size-1, base/mask decoder)
MMIOH window       0x380000000000 .. 0x3fffffffffff
top of 46-bit space  0x3fffffffffff   -> window ends EXACTLY at 2^46
```

## Patch 2, step by step

`PciRootBridge` is stored **Tiano/LZH-compressed** inside FV01, so patching it
means decompressing, editing, re-compressing and repacking the volume.
`patch_aperture.py` does all of that itself on the raw image:

* locates the FFS file by GUID, splits `hdr + DEPEx + COMPRESSION`, and Tiano-
  decompresses the section — whose payload is itself a section stream
  (`PE32 + USER_INTERFACE`), not a bare PE32 image;
* replaces the two 7-byte loads of the MMIO32 base/length struct fields with
  `mov r9d, imm32` + `nop`, asserting each pattern occurs exactly once;
* rebuilds the module **uncompressed** by default — exactly the shape MMTool's
  `/r` writes (`0xB29B → 0x16168`, FV01 shifts 44,744 bytes, FV01 free space
  falls from 7,520,336 to 7,475,592 bytes) — and closes both live FFS checksums;
* repacks FV01 in place: every following FFS file moves by the 8-aligned delta,
  the volume's trailing `0xFF` free space gives up exactly that many bytes, the
  image stays exactly 16 MiB, and everything outside FV01 is byte-identical;
* re-reads what it wrote and re-verifies all of it from the bytes.

It refuses — non-zero exit, no output file — if the module is missing, a pattern
is not unique, the volume's block map is not a power-of-two layout, the free
space is insufficient, the decode does not reproduce the module, or a checksum
does not close.

```bash
python patch_aperture.py X9DRGQF8.921 -o patched.bin
```

`--recompress` re-compresses with Tiano instead: the EDK2 stream is 22 bytes
larger than AMI's, so the module grows 19 bytes and FV01 shifts 16 instead of
~45 KB. Smaller, but the board then decompresses a stream from EDK2's encoder
rather than the one that built the ROM — so it is the opt-in, not the default.

`--reference-extract FILE` asserts that the pure-Python rebuild of the
*unpatched* module is byte-for-byte identical to an MMTool `/e` extract: the gate
that proves the (de)compression and framing are exact.

### MMTool fallback (optional, not used by the build)

If you prefer AMI's own tool to do the repack, this route needs no Python
packages:

```bash
MMTOOL_4.50.0.23.exe X9DRGQF8.921 /e 80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910 PciRootBridge.bin
python patch_aperture.py X9DRGQF8.921 --from-extract PciRootBridge.bin \
       --store-uncompressed --no-write --module-out PciRootBridge.patched.bin
MMTOOL_4.50.0.23.exe X9DRGQF8.921 /r 80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910 PciRootBridge.patched.bin
python patch_mmioh.py X9DRGQF8.921 -o patched.bin
```

The module written by `--module-out` is byte-identical to the one the pure-Python
`--store-uncompressed` path produces.

MMTool is a GUI-subsystem binary with a text UI, so it looks like it hangs.
`tools/mmtool_run.py` drives it through a real console and always cleans up:

```bash
python tools/mmtool_run.py X9DRGQF8.921 /e 80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910 PciRootBridge.bin --pty
```

Under Git-Bash/MSYS you **must** set `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`,
or MSYS rewrites `/e` into `E:/` and MMTool drops into its interactive menu.

## Verify

```bash
python verify_image.py X9DRGQF8.921 patched.bin
```

It trusts nothing, including the patchers: it re-walks all three firmware
volumes, re-decompresses the patched module out of the image, re-disassembles the
patch sites it finds (detecting which of the two patches an image carries and
checking the rest of the image is untouched), recomputes the aperture arithmetic
from the emitted immediates, and asserts every FFS checksum closes — **171 files,
171/171 header and 171/171 file-data** in stock and in every built image.
**All checks must PASS.**

## POST logo

```bash
python patch_logo.py X9DRGQF8.921                    # install logo/logo.dat
python patch_logo.py X9DRGQF8.921 mine.bmp -o out.bin
python patch_logo.py X9DRGQF8.921 --extract now.bmp   # dump the current one
```

640×480, 8-bit indexed, BI_RGB, bottom-up — AMI's logo plane. The payload is
`3A B4 04 19` + BMP + 2 pad bytes inside a Tiano-compressed FFS file;
`patch_logo.py` rebuilds the section, recomputes the FFS checksums and repacks
FV01. `--store-uncompressed` writes the shape the reference board runs.

Round-trip fidelity, measured with the stock logo: decompress, re-compress,
re-decompress → **byte-identical, 3,720 → 3,721 bytes**. The codec and framing are
exact; a round-trip costs one byte.

## Flashing

Read [`docs/FLASHING.md`](docs/FLASHING.md) fully before writing anything.

### `flash.sh` — the gated flasher (Linux, flashrom)

`flash.sh` wraps flashrom with the gates this board needs. It is the recommended
path on Linux.

```bash
./flash.sh X9DRGQF8.921.rebar.bin check              # structure only, no root
sudo ./flash.sh X9DRGQF8.921.rebar.bin backup        # read the region twice, keep a backup
sudo ./flash.sh X9DRGQF8.921.rebar.bin flash         # check + backup + write + read-back verify
./flash.sh X9DRGQF8.921.rebar.bin verify             # re-validate the newest read-back
```

`flash` runs four gates and stops at the first failure:

1. the image is exactly 16,777,216 bytes (a full chip image — with a layout file
   flashrom indexes it at chip offsets and rejects region slices);
2. every FFS header and FFS file-data checksum in the image closes — checked by
   `verify_image.py --structure-only`, the same code that audits the built image;
3. a backup exists and **two consecutive reads of the chip are identical** — if
   they differ the read path is unstable and flashing is refused;
4. after the write, the chip read-back must equal the image byte-for-byte across
   the whole BIOS region, and that read-back must itself pass structure
   validation.

It writes **only** the BIOS region: `0x400000..0xFFFFFF`. The flash descriptor
(`0x000000..0x00FFFF`) and the ME (`0x020000..0x3FFFFF`) are never in scope. The
layout file is generated from that measured region table if you don't supply one.

Paths are derived from the script's own location; nothing is hard-coded. Backups
land in `bios-backups/` (git-ignored) and are `chmod 444`. `check` and `verify`
need neither root nor flashrom, so you can audit an image on any machine. `STOCK`
points at a stock image to get a per-region byte delta in the output:

```
  FV01 (DXE)                 2276349 B in 9017 run(s)
  FV02 (PEI + boot block)          8 B in 2 run(s)
      0xe26011 len 1  stock a6  image f4
      0xe3019e len 7  stock 0fb796c0020000  image ba002000006690
```

### The manual path

* **flashrom**: use an explicit layout file. Do **not** use `--ifd <image>` —
  this image's descriptor has a zeroed `FRBA`, so a tool that derives the layout
  from the *file's* descriptor computes a garbage BIOS region.
  ```bash
  echo '0x00400000:0x00ffffff bios' > bios.layout
  sudo flashrom -p internal -l bios.layout -w patched.bin
  ```
* **AFUDOSU**: `AFUDOSU.EXE PATCH.BIN /P /R /X`. Avoid `/B` (boot block),
  `/FDT /MER /OPR /me` (ME regions) and `/SANTA` (skips ROM validation) — those
  regions are write-protected by the flash descriptor, so AFU can report success
  on a write that did not complete.
* Dump the chip twice and diff the dumps **before** writing. That dump is your
  only recovery on a board that will not POST.

## Results

Before, on Ubuntu with an MI210:

```
pci 0000:04:00.0: bridge window [mem size 0x2000400000 64bit pref]: can't assign
```

After both patches:

```
pci_bus 0000:00: root bus resource [mem 0x380000000000-0x3fffffffffff window]
pci_bus 0000:00: root bus resource [mem 0x90000000-0xfbffffff window]
amdgpu: VRAM: 65520M      /dev/kfd present      rocminfo OK      P2P DMA registered
```

## Files

| file | what |
|---|---|
| **`patch_bios.py`** | **the one command** — applies both patches, then verifies |
| `patch_mmioh.py` | patch 1 — 64-bit MMIOH aperture (raw image → raw image) |
| `patch_aperture.py` | patch 2 — published 32-bit root-bridge aperture (Tiano de/compression in-process) |
| `patch_logo.py` | replace the POST logo |
| `logo/logo.dat` | the compressed logo payload injected into the logo FFS file |
| `verify_image.py` | independent verifier for the finished image; `--structure-only <image>` audits one image with no baseline |
| `flash.sh` | gated Linux flasher: size → checksums → double-read backup → write → read-back compare |
| `tools/mmtool_run.py` | ConPTY driver for MMTool 4.50's CLI (optional fallback route only) |
| `requirements.txt` | `uefi-firmware` (EDK2 codecs) and `capstone` (disassembly in the verifier) |
| `docs/FLASHING.md` | flashrom / AFUDOSU procedures, recovery |
| `AGENTS.md` | the full technical reference: measured layouts, disassembly, checksum rules, post-mortem, dead ends |

## Risk

This writes firmware. The module patch 1 edits is **MRC (memory reference code) +
QPI init** — the memory-training PEIM. If it is rejected the board will not POST.
Have a SPI programmer (CH341A) and a known-good dump ready before you start. This
hardware has no dual-BIOS.
