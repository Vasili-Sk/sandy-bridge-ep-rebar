# AGENTS.md — ReBAR on Sandy Bridge-EP / Ivy Bridge-EP

Self-contained technical reference. Every number in this file was **measured**
from the image, the disassembly, or the running machine — not inferred. Where a
claim is a hypothesis it says so.

Repo files referenced: `patch_mmioh.py`, `patch_aperture.py`, `verify_image.py`,
`tools/mmtool_run.py`, `docs/FLASHING.md`. Nothing outside this repo is needed.

---

## 1. Platform

| | |
|---|---|
| Board | Supermicro **X9DRG-QF** (image name `X9DRGQF8`) |
| Chipset | Intel C602 (Patsburg) + C602J, AMI **Aptio IV** |
| CPU | Xeon **E5-2690 v2** — Ivy Bridge-EP, **46-bit** physical address space (64 TiB) |
| Sockets | 2 × LGA2011, QPI |
| BIOS | **3.3**, file `X9DRGQF8.921`, 16 MiB raw SPI |
| GPU | AMD Instinct **MI210** — gfx90a/CDNA2, 64 GB HBM2e, **BAR0 = 2^36 = 64 GiB**, SR-IOV, headless |

### ReBAR headroom on X9 — do not copy consumer numbers

The MMIOH aperture is programmed as **base + power-of-two mask** in the C600
uncore. Base is in units of **4 GiB**, size in units of **1 GiB**, both 16-bit
fields.

* Base default shipped by Supermicro = `0x3800` × 4 GiB = **56 TiB**.
* Size field is 16 bits → max `0xFFFF` GiB, but the real ceiling is the CPU's
  physical address space: **base + size ≤ 2^46 = 64 TiB**.
* ⇒ max legal size at base `0x3800` is **`0x2000` GiB = 8 TiB**, window
  `0x380000000000 … 0x3FFFFFFFFFFF`, ending flush with 2^46.
* This platform routes **terabytes** of 64-bit MMIO. A 64 GiB MI210 BAR0 is
  1/128 of the window; four MI210s fit with room to spare.
* **Consumer platforms (Intel 100→700 series, AMD AM4/AM5) are the ones capped at
  64 GiB.** Their MMIOH tables stop there, which is why ReBarUEFI's "MMIOH Size"
  table tops out at 64 GiB and why 64 GB cards fail on them. That ceiling does
  not exist on X9. Do not port a consumer 64 GiB limit into this image, and do
  not port this image's 8 TiB value to a consumer board.
* Do **not** raise the size past `0x2000` here: the decoder mask becomes
  `size-1`, and a window ending above 2^46 decodes addresses the CPU cannot drive.

---

## 2. The two problems (independent)

### Problem A — MMIOH aperture (primary; this is what blocked 64 GB ReBAR)

The firmware reads the MMIOH size from a setup variable that is **not wired to
any setup question** on X9: the entire `Advanced → PCIe/PCI/PnP Configuration`
page in the X9DRG-QF manual (ch. 4) has `Above 4G Decoding`, `PCI ROM Priority`,
`VGA Priority`, payload/ASPM and per-slot OPROM — and **no** `MMIOH Base` /
`MMIO High Granularity Size`. Supermicro's GPU FAQ that lists those two options
applies to **X10/X11**, not X9.

Unwired ⇒ the size is never raised above the hard-coded default of **1 TiB**
(`0x400` GiB, written unconditionally at `0x0E26972`; a second path writes
`0x20` = 32 GiB at `0x0E2DF98`). Aperture =
`0x380000000000 .. 0x380FFFFFFFFFFF`. Linux placed the MI210's 64 GB BAR at
**`0x381000000000` = base + exactly 1 TiB** — the first address *outside* the
aperture. That is the whole failure, to the byte.

Disassembly of `IvtQpiandMrcInit` (capstone):

```
0e30173  movzx eax, word ptr [esi+0x2cf]    ; MMIOH BASE variable
0e30189  mov  dword [ebp-0x28], 0x3800      ; default base = 0x3800 x 4 GiB = 56 TiB
0e30190  test ax,ax / je 0xe3019e
0e30198  shl  eax,6                         ; base = var x 64 x 4 GiB = var x 256 GiB
0e3019e  movzx edx, word ptr [esi+0x2c0]    ; MMIOH SIZE, GiB, 16-bit  <== PATCH SITE
0e301a5  test dx,dx
0e301a8  jne  0xe301d7                      ; non-zero -> use it
0e301b5  mov  dword [ebp+8], 2             ; zero     -> 2 GiB fallback
0e301d7  movzx edx,dx
0e301da  push edx
0e301dd  mov  eax,0x40000000
0e301e4  call 0xe6dc16                      ; Mul64x32 -> size_bytes  (unit = GiB)
0e301ed  call 0xe6dd06                      ; Sub64    -> size_bytes-1 (decoder MASK)
```

The `size == 0` fallback (and the `call 0xe2f1b3` behind it) is **dead code on a
normal boot** — `[esi+0x2c0]` is always non-zero by the time it is tested.

Patch (10 bytes → 10 bytes, size-preserving, unique in 16 MiB):

```
@0x0e3019e  0f b7 96 c0 02 00 00 66 85 d2   movzx edx,[esi+0x2c0] ; test dx,dx
          → ba 00 20 00 00 66 90 66 85 d2   mov edx,0x2000 ; nop  ; test dx,dx
```

### Problem B — ECAM (MMCFG) is inside the published 32-bit MMIO aperture

```
MCFG / ECAM base          0x80000000, 256 MiB  -> 0x80000000-0x8FFFFFFF
Host bridge _CRS aperture 0x80000000-0xFBFFFFFF   <-- CONTAINS ECAM
```

`Device (VTDR)` (`PNP0C02`) reserves **only** the VT-d register block. ECAM is
reserved nowhere. PCI Firmware Spec r3.3 §4.1.2 requires the ECAM range to appear
under a `PNP0C02` `_CRS`. This firmware does not do that.

Consequence — exactly the case Bjorn Helgaas described in *"x86/pci: Work around
lack of ECAM space reservation"* (`Cc: stable # v6.2+`): the kernel allocates PCI
BARs **bottom-up** out of the advertised aperture, so the first BARs land on
`0x80000000` = PCI config space. A BAR pointing at config space makes
`RCC_CONFIG_MEMSIZE` read garbage and `amdgpu` hangs in
`xgpu_ai_mailbox_trans_msg()` with `MCBP is enabled`.

The trigger is present: MI210 is SR-IOV and firmware leaves the VF BARs
unallocated (`VF BAR 0 [mem 0x00000000-0x00003fff 64bit pref]`), so Linux
reallocates the bridge window and drops it on the ECAM range.

**Proven live**: `MBB 0x80000000 → 0x90000000`, `MBL 0x7C000000 → 0x6C000000`
(end stays `0xFBFFFFFF`). Root bus window became
`[mem 0x90000000-0xfbffffff window]`, ECAM no longer handed out, `amdgpu`
probes, `VRAM: 65520M`, `/dev/kfd` present, `rocminfo` works.

---

## 3. Image layout (measured)

```
NCB 0  0x000000-0x3FFFFF   (flash descriptor / ME / legacy)
FV 00  0x400000            1 FFS
FV 01  0x460000  len 0x970000               140 FFS   (DXE)
FV 02  0xE00000  len 0x200000                26 FFS   (PEI + boot block)
NCB 1  0x420000  len 0x040000
NCB 2  0xDD0000  len 0x030000
```

All three FV headers: `_FVH`, `HeaderLength = 0x48`, FFS files start at `fv + 0x48`.
No nested FV.

| # | Name | GUID | Location | Compressed | Uncompressed |
|---|---|---|---|---|---|
| 008 | PciBus | `3C1DE39F-D207-408A-AACC-731CFB7F1DD7` | `0x49D410` | `0x8360` | |
| **009** | **PciRootBridge** | **`80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910`** | `0x4A5770` | `0xB29B` | 90,472 |
| 010 | AmiBoardInfo | `9F3A0016-AE55-4288-829D-D22FD344C347` | `0x4B0A10` | `0x3E74` | 54,260 |
| **044** | ACPI (driver) | `16D0A23E-C09C-407D-A14A-AD058FDD0CA1` | `0x563448` | `0x4CBC` | 39,972 |
| **010/PEI** | **IvtQpiandMrcInit** (FV 02) | **`5C08C7C8-24C2-4400-9627-CF2869421E06`** | `0xE26000` | — | 457,920 |

`IvtQpiandMrcInit` is stored **uncompressed** in FV02, so patch 1 is a raw-image
byte patch. `PciRootBridge` is stored **compressed** in FV01, so patch 2 needs
MMTool.

### Firmware-side facts proven by disassembly (`IvtQpiandMrcInit`, imagebase `0xffe26058`)

```
0xffe76986  ECAM base is READ FROM HARDWARE: PCIEXBAR = bus0 dev31 fn0 reg 0x84
0xffe2df6e  MRC defaults:
              [esi+0x2b0] = MMCFG base  (from PCIEXBAR)
              [esi+0x2b4] = MMCFG size  = 0x10000000 (256 MiB)
              [esi+0x2c0] = MMIOH size  (16-bit, GiB)
0xffe302a7  MMIOH base  = MMCFG base + MMCFG size = 0x90000000
            MMIOH limit = clamped to <= 0xFBFFFFFF
0xffe300ca  validator: ecx = (0xFC000000 - MMCFGsize - MMCFGbase) >> 26 ; cmp ecx,4 ; jb ->
              "Invalid MMCFG Base Supplied. Insufficient MMIOL space."
0xffe2d84e  guard: if MRC's MMCFG base != PCIEXBAR -> force COLD RESET, print
              "PCIEXBASE ADDRESS IS CHANGED.SYSTEM WILL DO A RESET !!!!"
```

The firmware's *internal* allocation is already correct
(`MMIOH base = MMCFG base + MMCFG size = 0x90000000`,
`len = 0xFC000000 − that = 0x6C000000`). The defect is purely that the **ACPI
table published to the OS is 256 MiB wider than it should be**. Patch 2 makes the
publishing layer use the correct pair.

### Where the DSDT lives, and who writes the aperture constants

The DSDT is in module 010 `AmiBoardInfo` (DSDT header at module offset `0xA94`,
length `0xBC34` = 48,180 — the exact table the live OS reports). Its
`MBB_`/`MBL_` constants are **placeholders** shipped as `0x00010000`; runtime
code overwrites them. **Editing the DSDT template is a no-op.**

The writer is **`PciRootBridge`** (module 009), in a loop at RVA
`0x18000225c..0x18000248b` walking the AMI resource-name table in `.rdata` at
RVA `0x13284`. Each iteration:

```
  0x18000235d   mov  r9,  qword ptr [rdi + 0x168]   ; the VALUE
  0x180002364   mov  rdx, qword ptr [rdi + 0x100]   ; ACPI device path
  0x18000236b   lea  r8,  [rip + 0x10f46]           ; -> 'MBB'
  0x180002372   mov  rcx, rbx                       ; the DSDT table
  0x180002375   call 0x180010ba4                    ; the DSDT writer
```

The two struct fields, proven at `0x18001251b..0x180012545`:

```
  [rbp + 0x168] = MMIO32 base                       ; MBB = 0x80000000
  [rbp + 0x170] = MMIO32 limit - base + 1            ; MBL = 0x7C000000
```

Exhaustive check: `.text` of module 009 references the `MBB` string exactly once
and `MBL` exactly once, and those are the only reads of `+0x168`/`+0x170` that
reach the writer.

Patch (module-file offsets in the `/e` extract; `41 B9 id=1 imm32` = `mov r9d,
imm32`, zero-extended into `r9`, plus a `90` nop to keep the length):

```
  0x23c5  4c 8b 8f 68 01 00 00  ->  41 b9 00 00 00 90 90   mov r9d, 0x90000000 ; nop
  0x23e2  4c 8b 8f 70 01 00 00  ->  41 b9 00 00 00 6c 90   mov r9d, 0x6C000000 ; nop
```

Encoding trap: `41 B8 …` is `mov r8d`, **`41 B9 …`** is `mov r9d`.
The struct is untouched — only the numbers written into the table the OS reads.

---

## 4. FFS checksums — the real rules

### Layout

Firmware Volume header at `fv`:

```
0x00 16 ZeroVector      0x10 16 FileSystemGuid   0x20  8 FvLength
0x28  4 '_FVH'          0x2C  4 Attributes
0x30  2 HeaderLength    0x32  2 Checksum
0x34  2 ExtHeaderOffset 0x36  1 Reserved   0x37  1 Revision
```

`HeaderLength` (0x48 here) is the offset of the **first FFS file's GUID**, not of
its ZeroVector.

FFS file — `g` = offset of its Name (GUID), which is exactly what MMTool's `/v`
reports as `Location`:

```
g+0x00 16  Name (GUID)
g+0x10  1  IntegrityCheck.Header   <-- header checksum
g+0x11  1  IntegrityCheck.File     <-- file-data checksum
g+0x12  1  Type
g+0x13  1  Attributes              <-- bit 0x40 = FFS_ATTRIB_CHECKSUM
g+0x14  3  Size (LE, measured FROM the GUID)
g+0x17  1  State
g+0x18 --  file data (sections)
```

Next file's GUID = `align8(g + Size)`. An MMTool `/e` extract **is the file
starting at the GUID**, so inside an extract the fields are at
`0x10/0x11/0x12/0x13/0x14/0x17`, data at `0x18`, and the extract's length equals
its own `Size` field.

### The two rules (PI Vol. 3, FFS_FILE_HEADER)

```
header:  sum(GUID..State) with Header, File and State zeroed, + Header  == 0 (mod 256)
file  :  if Attributes & 0x40 (FFS_ATTRIB_CHECKSUM):
             sum(data[g+0x18 .. g+Size]) + File  == 0 (mod 256)
         else:
             File == 0xAA
```

### Measured on stock X9DRGQF8.921

| Field | Result |
|---|---|
| FFS header checksum | **closes on 167 / 167** — live |
| FFS file-data checksum | **closes on 161 / 167**; the other 6 have `FFS_ATTRIB_CHECKSUM` clear and carry `0xAA` — live |
| FV header `Checksum` (`fv+0x32`) | closes on **0 / 3** — stale residue Supermicro ships; the board boots with it broken. Informational only. |
| ACPI table `Checksum` (offset 52, whole-table 8-bit sum `== 0`) | must be recomputed for any table handed to the OS |
| SPI flash descriptor / ME region | **never touch** |

⇒ The FFS checksums are **live fields**.

### The repair (what `patch_aperture.py` does)

MMTool writes a **closing** pair of checksums into every `/e` extract and
**validates the file-data checksum when you `/r` a module back in**. So any
hand-edited module is rejected:

```
MMTOOL rom /r <GUID> patched.bin   ->   "Invalid FFS File",  exit 127
```

It rejects a **one-byte** change anywhere in the file, including a pure NOP-out.
Nothing is written to the ROM. Repair:

```python
d = bytearray(open('module.bin','rb').read())   # an /e extract: GUID at offset 0
assert d[0x13] & 0x40                          # FFS_ATTRIB_CHECKSUM
size = int.from_bytes(d[0x14:0x17], 'little')
assert size == len(d)
d[0x11] = (-sum(d[0x18:size])) & 0xFF          # file-data checksum
h = bytearray(d[:0x18]); h[0x10] = h[0x11] = h[0x17] = 0
d[0x10] = (-sum(h)) & 0xFF                     # header checksum (unchanged if size is)
```

Do **not** clear `Attributes & 0x40` to silence the error: that switches the rule
to `File == 0xAA` and desynchronises the module from how the volume was built.
Do not compute a payload checksum when the attribute is clear — the rule there is
the literal `0xAA`.

### The tripwire

MMTool's FFS walk of a volume **stops at the first file whose checksum fails**, so
a stale checksum shows up as a *shrinking file count*, not an error. Stock:
FV00 = 1, FV01 = 140, FV02 = **26**. A patch that edits code bytes and leaves the
checksum untouched makes MMTool report **FV02 = 4**. Recompute the checksum and it
is 26 again.

**Any build whose MMTool file counts differ from stock's is not finished.**

---

## 5. MMTool 4.50 CLI

It is a GUI-subsystem PE with a text-mode UI: given valid args it AllocConsoles,
prints, then blocks in `ReadConsoleInputA`. From a pipe it has no console, so it
dies with `0xC000013A`. `tools/mmtool_run.py` drives it through a real ConPTY
console and always tears down the console/window.

**`module id` is the module's GUID, not the `044` index.**

```
MMTOOL <ROM> /s                                   summary report
MMTOOL <ROM> /v                                   verbose module list
MMTOOL <ROM> /e  <GUID> <file>                    extract module AND UNCOMPRESS it
MMTOOL <ROM> /ec <GUID> <file>                    extract in COMPRESSED form
MMTOOL <ROM> /r  <GUID> <file>                    replace with UNCOMPRESSED module file
MMTOOL <ROM> /rc <GUID> <file>                    replace with ALREADY-COMPRESSED module file
MMTOOL <ROM> /i  <GUID> <file> <VolIndex>         insert new module
MMTOOL <ROM> /d  <GUID>                           delete module
```

Measured behaviour:

* **`/ec` + `/rc` round-trip is byte-exact: 0 bytes changed in 16 MiB.** The
  lossless path; use it to prove the tool is not corrupting anything.
* **`/r` does NOT recompress.** Module 009 grows `0xB29B` → `0x16168` and MMTool
  **repacks the whole FV01: ~2.1 MB moved.** It succeeds and FV01 has the space,
  but the blast radius is the entire DXE volume.
* **`/y` (compress on insert) is accepted only with `/i`.** There is **no**
  "replace and recompress" mode.
* MMTool fixes FFS/FV bookkeeping on `/r`/`/rc`/`/i`/`/d`, but **does not
  recompute the checksum of the file you handed it** — it validates it and refuses
  the file if it does not close.

### Git-Bash / MSYS

MSYS path conversion rewrites a bare `/r` into `R:/` and `/e` into `E:/`, so
MMTool sees a bogus argument and drops into its interactive menu (then times out).
Always:

```bash
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
```

Exit codes: MMTool exits 0 on success; on its own error path it exits
`3221225786` (`STATUS_CONTROL_C_EXIT`) with the message in `<rom-basename>.mmtool.log`.

Consequences:

1. Any DSDT/module edit forces a full FV repack. Do the MMTool step **first**,
   then apply byte patches **by pattern, never by hard-coded offset** — offsets
   move.
2. There is no way to keep a module compressed *and* patch its contents with
   MMTool alone, and no open encoder reproduces AMI's compressor (measured:
   `TianoCompress` 3,821 B, `EfiCompress` 3,769 B, `LzmaCompress` 2,732 B vs the
   ROM's 3,687 B stream; brute-force LZMA1/LZMA_ALONE decode at every offset and
   every property byte finds no valid stream). So a compressed module must be
   stored uncompressed after editing.

---

## 6. Flashing — the flags, and the descriptor trap

### AFUDOSU's real option table (extracted from the binary)

| flag | meaning |
|---|---|
| `/P` | **Program main BIOS image** ← the only write you want |
| `/B` | Program Boot Block |
| `/N` | Program NVRAM |
| `/K` | Program all non-critical blocks and ROM Holes |
| `/R` | Preserve ALL SMBIOS structures |
| `/X` | Don't check ROM ID |
| `/FDT`, `/MER`, `/OPR`, `/me` | ME firmware FDT / ME / OPR / entire regions |
| `/SANTA` | Update BIOS **without validating** the inserted ROM |

Raw proof from `AFUDOSU.smc`: `Program main BIOS image\x00P\x00Program Boot
Block\x00Pb` and, in the second table, `Program main BIOS image\x00p\x00Program
Boot Block\x00b`.

**Safe shape: `AFUDOSU.EXE PATCH.BIN /P /R /X`.**

Never `/B` — the boot block is write-protected by the flash descriptor's Access
Control; AFU reports success while the write cannot complete, leaving a partially
written block. That block holds the reset vector **and** the `Ctrl+Home`
recovery agent. Never `/FDT /MER /OPR /me` — the ME regions are also locked; a
partial ME write means the ME never boots and the CPU's power-up handshake never
completes → hang at reset, no POST. Never `/SANTA` — it removes AFU's last
refusal.

Supermicro's stock `ami.bat` runs
`AFUDOSU.EXE %1 /P /B /N /K /R /FDT /MER /OPR`, i.e. it puts the boot block and
three ME regions in scope. That is correct for a full stock image from the
vendor; it is the shape that bricked a board here.

### flashrom: do not derive the layout from the image file

The image's own descriptor has **`FRBA = 0`** (FLMAP1), so the Flash Region Table
is read from offset `0x000`, where the bytes are all `0xFF`. Every region then
decodes to base `0xfff000`, limit `0xffffff`. The real table is at `0x40`:

```
0x40  0x000f0000 -> descriptor  0x000000 .. 0x00FFFF
0x44  0x0fff0400 -> BIOS        0x400000 .. 0xFFFFFF   (12 MiB)
0x48  0x03ff0020 -> ME          0x020000 .. 0x3FFFFF
0x4c  0x00000fff -> GbE         degenerate
```

So `flashrom --ifd <image>` computes a garbage BIOS region from the file. Use the
**live** registers in an explicit layout file instead. C600 LPC/eSPI host bridge
`00:1f.0`, FREG0–3 at config offsets `0x50/54/58/5C`, base = `[31:12]`×4 KiB,
limit = `[11:0]`×4 KiB + `0xFFF`:

```bash
sudo setpci -s 00:1f.0 0x54.l          # expect 0x00400FFF  -> 0x00400000..0x00FFFFFF
echo '0x00400000:0x00ffffff bios' > bios.layout
sudo flashrom -p internal -l bios.layout -w patched.bin
```

`flashrom -p internal --ifd -i bios` with **no** `--ifd` filename is also fine —
flashrom then reads the descriptor from the live chip. Only `--ifd <file>` is
broken here. Full procedure, including the double-dump rule, in
[`docs/FLASHING.md`](docs/FLASHING.md).

---

## 7. Dead ends — do not re-litigate

* **Editing `MBB_`/`MBL_` in the DSDT template** (module 010, module offsets
  `0x2216`/`0x2220`, socket-2 copy `0x6BE8`/`0x6BF2`). They ship as
  `Name(MBB_, 0x00010000)` and the live table reads `0x80000000`. Runtime
  overwrites them. No-op.
* **Adding a `PNP0C02` device reserving `0x80000000-0x8FFFFFFF`.** It cannot work.
  `allocate_resource()` on the root-bus window only avoids conflicts with
  children *of that window*; a PNP0C02 reservation is inserted as a *sibling* of
  the window in `iomem_resource`, so the PCI allocator's first-fit never sees it.
  This is precisely why the upstream kernel workaround keys off the **e820 map**,
  not off `PNP0C02`.
* **Moving MMCFG base.** The published aperture always starts at the ECAM base, so
  the collision moves with it. `0xE0000000` is additionally rejected by MRC's own
  validator (`Insufficient MMIOL space`), and any change trips the guard at
  `0xffe2d84e` → forced cold-reset loop. **Never flash a build that moves MMCFG
  base.**
* **"The patch deleted the `call 0xe2f1b3` on the size==0 auto path."** Refuted:
  `[esi+0x2c0]` is set to `0x400` unconditionally at `0x0E26972`, so stock already
  takes the `jne` branch and never executes that call. Deleting a call that never
  ran cannot be the delta.
* **"The 8 TiB aperture value was illegal."** `0x2000` GiB at base `0x3800`×4 GiB
  closes the window flush with `0x3FFFFFFFFFFF` = 2⁴⁶−1. Legal.
* **Recompiling the DSDT with `iasl`.** Fails: the resource templates ship with
  `Min=Max=0, Length=0xFDFC0000` and are filled at runtime, which modern iasl
  rejects (`Error 6049`, then *Maximum error count (200) exceeded*). Binary-patch
  the AML only.
* **`pci=nocrs`** on the kernel command line. It strips `_CRS` windows for every
  root bus, including the 4-deep Matrox G200eR2 chain behind `00:1c.7`. No
  framebuffer.
* **Flashing the MI210 VBIOS.** `MCBP is enabled` / `trn=2` were artifacts of
  reading config space through an ECAM alias, not evidence of MxGPU firmware.
* **Clover.** It patches tables, not chipset init.
* **Hunting for a setup variable to flip.** There is none. The variable exists in
  the MRC structure (`[esi+0x2c0]`, GiB, 16-bit) and is unwired.

Other rules:

* A PCI TLP must pass **every** bridge on the path. Moving a BAR means all three
  bridges in the chain (`00:03.0`, `03:00.0`, `04:00.0`) must cover the new
  range; to remove a stale window you remove the **whole subtree at the root
  port**, not just the endpoint.
* AML name segments are **4 chars**: the names are `MBB_`/`MBL_`, iasl *prints*
  them as `MBB`/`MBL`. The real bytes are `08 4D 42 42 5F 0C <dword>` and the
  dword is at `i+5`, not `i+4` (a `0x0C` DWordPrefix sits between).
* The string `MBB_` occurs **0 times** in the raw 16 MiB image — it only exists
  compressed. Any scan of the raw ROM for AML names is guaranteed to fail.

---

## 8. Rules for the next agent

1. **Never edit the stock image in place.** Copy → patch → diff → verify. Keep an
   untouched copy of the original BIOS forever.
2. Patch **by unique byte pattern**, assert the pattern occurs exactly once in
   16 MiB.
3. After every patch run `verify_image.py` and diff against stock, expecting only
   the intended runs.
4. Preserve an untouched copy of the original. Preserve FFS `Attributes` unless
   there is a verified reason to change them.
5. Rebuilding must preserve valid file sizes, firmware-volume boundaries and
   8-byte file alignment.
6. Do not assume MMTool recomputes the file-data checksum. It does not — it
   validates it.
7. Do not assume every UEFI section has its own checksum. Only the FFS file
   header carries the two checksums described in §4.
8. Do not patch the full BIOS image until the exact cause has been identified.
9. Do not treat the DSDT/ACPI checksum, the PE/COFF checksum, the FFS checksum and
   the firmware-volume checksum as interchangeable. They are four different
   fields with four different rules.
10. **Verify before you flash, and believe the verifier only if it re-derives.**
    `verify_image.py` re-walks the volumes, re-disassembles both patch sites and
    recomputes the aperture arithmetic from the emitted immediates. It does not
    read the patchers' output.
11. Never flash without a recovery path: a CH341A-class programmer and a
    known-good dump. A board that will not POST has no other escape.

---

## 9. Status

**Proven on hardware (this board, this image):**

* Patch 1 (MMIOH → 8 TiB) flashed, boots, works. Root bus window is
  `[mem 0x380000000000-0x3fffffffffff window]` — exactly the 8 TiB requested.
* Patch 2 (aperture `0x90000000`/`0x6C000000`) proven as an **initrd ACPI table
  override**: `ACPI: Table Upgrade: override [DSDT-SUPERM-SMCI--MB]`, root bus
  resource `[mem 0x90000000-0xfbffffff window]`, ECAM no longer handed out,
  `amdgpu` probes, `VRAM: 65520M`, `/dev/kfd` present, `rocminfo` works.
* MMTool CLI cracked; lossless `/ec`+`/rc` round-trip verified byte-exact;
  `/r` round-trip of an unmodified `/e` extract is byte-exact too.

**Not proven on hardware:**

* Patch 2 **baked into flash**. The firmware's own allocation path already
  computes the same numbers, and the patch changes only the values written into
  the table the OS reads, so the risk is low — but a flash is not a table
  override. If you want zero untested flash, ship patch 1 in flash and patch 2 as
  the initrd override.
