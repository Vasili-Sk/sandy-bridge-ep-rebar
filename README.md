# sandy-bridge-ep-rebar

Enable **ReBAR (Resizable BAR / large 64-bit MMIO)** on Intel **Sandy Bridge-EP /
Ivy Bridge-EP** (Xeon E5-2600 v1/v2) server platforms — and fix the 32-bit
aperture collision that stops the big BAR from being *used*.

Reference board: **Supermicro X9DRG-QF** (C602 "Patsburg", AMI Aptio IV), BIOS
3.3 (`X9DRGQF8.921`), Xeon **E5-2690 v2**, AMD Instinct **MI210** (64 GiB BAR0).
**Verified on hardware.**

Two independent defects block a large BAR. Both are patched here.

| | defect | patch | needs MMTool? |
|---|---|---|---|
| **1** | 64-bit MMIO aperture (MMIOH) hard-coded to **1 TiB**; the size variable is unwired to any setup question | `patch_mmioh.py` — raise it to **8 TiB** | no |
| **2** | the root-bridge **32-bit** aperture published in the DSDT *contains ECAM*, so Linux hands out BARs that alias PCI config space | `patch_aperture.py` — subtract ECAM | yes |

**Patch 1 is the ReBAR enabler.** On its own it is enough for a GPU whose BAR
fits in the 32-bit window plus the 8 TiB 64-bit window. Patch 2 is needed when
the card is SR-IOV / large enough that Linux reallocates the bridge window and
lands it on ECAM.

## Quick start

Requires Python 3.8+. No third-party packages.

```bash
# unpack the .zip Supermicro gives you; use the raw SPI image inside
python patch_mmioh.py X9DRGQF8.921 -o patched.bin
```

That is the whole of patch 1: 7 code bytes + 1 checksum byte, size-preserving,
no volume repack. It prints the aperture it just programmed:

```
MMIOH base         0x380000000000  (56 TB)
MMIOH size         0x080000000000  (8 TB)   [0x2000 GiB]
MMIOH window       0x380000000000 .. 0x3fffffffffff
top of 46-bit space0x3fffffffffff   -> window ends EXACTLY at 2^46
bytes changed      8
```

`--size` takes any power of two up to `0xFFFF` GiB; the script refuses anything
whose window would end above the CPU's physical address limit.

## Patch 2 (needs MMTool 4.50, from your firmware package)

Module 009 is stored **compressed** and AMI's compressor is proprietary — no
open encoder reproduces it, so MMTool has to expand it first.

```bash
MMTOOL_4.50.0.23.exe X9DRGQF8.921 /e 80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910 PciRootBridge.bin
python patch_aperture.py PciRootBridge.bin -o PciRootBridge.patched.bin
MMTOOL_4.50.0.23.exe X9DRGQF8.921 /r 80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910 PciRootBridge.patched.bin
python patch_mmioh.py X9DRGQF8.921 -o patched.bin
```

MMTool is a GUI-subsystem binary with a text UI, so it looks like it hangs.
`tools/mmtool_run.py` drives it through a real console and always cleans up:

```bash
python tools/mmtool_run.py X9DRGQF8.921 /e 80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910 PciRootBridge.bin --pty
```

Under Git-Bash/MSYS you **must** set `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`,
or MSYS rewrites `/e` into `E:/` and MMTool drops into its interactive menu.

## Verify before you flash

```bash
python verify_image.py X9DRGQF8.921 patched.bin
```

It trusts nothing: it re-walks all three firmware volumes, re-disassembles both
patch sites, recomputes the aperture arithmetic from the emitted immediates, and
asserts every FFS checksum closes. **All checks must PASS.**

## Flashing

Read [`docs/FLASHING.md`](docs/FLASHING.md) fully before writing anything. The
short version:

* **flashrom**: use an explicit layout file. Do **not** use `--ifd <image>` —
  this image's descriptor has a zeroed `FRBA`, so a tool that derives the layout
  from the *file's* descriptor computes a garbage BIOS region.
  ```bash
  echo '0x00400000:0x00ffffff bios' > bios.layout
  sudo flashrom -p internal -l bios.layout -w patched.bin
  ```
* **AFUDOSU**: `AFUDOSU.EXE PATCH.BIN /P /R /X`. Never `/B` (boot block), never
  `/FDT /MER /OPR /me` (ME regions), never `/SANTA` (skips ROM validation).
  Supermicro's own `ami.bat` passes all of them.
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
| `patch_mmioh.py` | patch 1 — 64-bit MMIOH aperture (pure Python, raw image → raw image) |
| `patch_aperture.py` | patch 2 — published 32-bit root-bridge aperture (MMTool module extract) |
| `verify_image.py` | independent verifier for the finished image |
| `tools/mmtool_run.py` | ConPTY driver for MMTool 4.50's GUI-subsystem CLI |
| `docs/FLASHING.md` | flashrom / AFUDOSU procedures, recovery |
| `AGENTS.md` | the full technical reference: measured layouts, disassembly, checksum rules, dead ends |

## Risk

This writes firmware. The patched module in patch 1 is **MRC (memory reference
code) + QPI init** — if it is rejected, memory training fails and the board will
not POST. Have a SPI programmer (CH341A) and a known-good dump ready before you
start. You are modifying firmware on hardware that has no dual-BIOS.

MIT licensed. Not affiliated with Supermicro, AMI, AMD or Intel.
