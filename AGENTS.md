# AGENTS.md — ReBAR on Sandy Bridge-EP / Ivy Bridge-EP

Technical reference for patching this firmware. Every number here was measured
from the image, the disassembly, or the running machine. Hypotheses say so.

Repo files: `patch_bios.py`, `patch_mmioh.py`, `patch_aperture.py`,
`patch_logo.py`, `verify_image.py`, `flash.sh`, `tools/mmtool_run.py`,
`docs/FLASHING.md`.

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

### Headroom — do not copy consumer numbers

The MMIOH aperture is programmed as **base + power-of-two mask** in the C600
uncore. Base is in units of **4 GiB**, size in units of **1 GiB**, both 16-bit
fields.

* Base default shipped by Supermicro = `0x3800` × 4 GiB = **56 TiB**.
* Size is 16 bits → max `0xFFFF` GiB, but the real ceiling is the CPU's physical
  address space: **base + size ≤ 2^46 = 64 TiB**.
* ⇒ max legal size at base `0x3800` is **`0x2000` GiB = 8 TiB**, window
  `0x380000000000 … 0x3FFFFFFFFFFF`, flush with 2^46.
* A 64 GiB MI210 BAR0 is 1/128 of that window; four MI210s fit with room to
  spare.
* **Consumer platforms (Intel 100→700 series, AMD AM4/AM5) are the ones capped at
  64 GiB** — their MMIOH tables stop there, which is why ReBarUEFI's "MMIOH Size"
  table tops out at 64 GiB and why 64 GB cards fail on them. That ceiling does not
  exist on X9. Do not port a consumer 64 GiB limit into this image, and do not
  port this image's 8 TiB value to a consumer board.
* Do **not** raise the size past `0x2000` here: the decoder mask becomes
  `size-1`, and a window ending above 2^46 decodes addresses the CPU cannot drive.

---

## 2. The two problems (independent)

### Problem A — MMIOH aperture too small (this is what blocked 64 GB ReBAR)

The firmware reads the MMIOH size from a setup variable that is **not wired to any
setup question** on X9: the whole `Advanced → PCIe/PCI/PnP Configuration` page in
the X9DRG-QF manual (ch. 4) has `Above 4G Decoding`, `PCI ROM Priority`, `VGA
Priority`, payload/ASPM and per-slot OPROM — and **no** `MMIOH Base` / `MMIO High
Granularity Size`. Supermicro's GPU FAQ listing those two options applies to
**X10/X11**, not X9.

Unwired ⇒ the size is never raised above the hard-coded default of **1 TiB**
(`0x400` GiB, written unconditionally at `0x0E26972`; a second path writes
`0x20` = 32 GiB at `0x0E2DF98`). Aperture = `0x380000000000 .. 0x380FFFFFFFFFFF`.
Linux placed the MI210's 64 GB BAR at **`0x381000000000` = base + exactly 1 TiB** —
the first address *outside* the aperture. That is the whole failure, to the byte.

`IvtQpiandMrcInit`, disassembled:

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
0e301dd  mov  eax,0x40000000
0e301e4  call 0xe6dc16                      ; Mul64x32 -> size_bytes  (unit = GiB)
0e301ed  call 0xe6dd06                      ; Sub64    -> size_bytes-1 (decoder MASK)
```

The `size == 0` fallback (and the `call 0xe2f1b3` behind it) is **dead code on a
normal boot** — `[esi+0x2c0]` is always non-zero by the time it is tested.

**Patch 1** — 10 bytes → 10 bytes, size-preserving, unique in 16 MiB:

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
under a `PNP0C02` `_CRS`; this firmware does not do that.

Consequence — exactly the case Bjorn Helgaas described in *"x86/pci: Work around
lack of ECAM space reservation"* (`Cc: stable # v6.2+`): the kernel allocates PCI
BARs **bottom-up** out of the advertised aperture, so the first BARs land on
`0x80000000` = PCI config space. A BAR pointing at config space makes
`RCC_CONFIG_MEMSIZE` read garbage and `amdgpu` hangs in
`xgpu_ai_mailbox_trans_msg()` with `MCBP is enabled`.

The trigger is present: MI210 is SR-IOV and firmware leaves the VF BARs
unallocated (`VF BAR 0 [mem 0x00000000-0x00003fff 64bit pref]`), so Linux
reallocates the bridge window and drops it on the ECAM range.

The firmware's *internal* allocation is already correct — see §3.2. The defect is
purely that the ACPI table published to the OS is 256 MiB wider than it should be.

**Patch 2** makes the publishing layer emit `MBB 0x90000000` / `MBL 0x6C000000`
(end stays `0xFBFFFFFF`). Result on the live board: root bus window
`[mem 0x90000000-0xfbffffff window]`, ECAM no longer handed out, `amdgpu` probes,
`VRAM: 65520M`, `/dev/kfd` present, `rocminfo` works.

---

## 3. Image layout (measured)

```
NCB 0  0x000000-0x3FFFFF   (flash descriptor / ME / legacy)
FV 00  0x400000  len 0x0200000   1 FFS
FV 01  0x460000  len 0x970000  140 FFS   (DXE)
FV 02  0xE00000  len 0x200000   26 FFS   (PEI + boot block)
NCB 1  0x420000  len 0x040000
NCB 2  0xDD0000  len 0x030000
```

All three FV headers: `_FVH`, `HeaderLength = 0x48`, FFS files start at
`fv + 0x48`. No nested FV.

The counts above are MMTool's summary. A raw FFS walk finds **1 / 142 / 28 = 171**
files, because it also yields entries MMTool's summary omits. 171 is the number
`verify_image.py` checks, and every one of them closes both FFS checksums — in
stock and in every built image.

| # | Name | GUID | Location | Compressed | Uncompressed |
|---|---|---|---|---|---|
| 008 | PciBus | `3C1DE39F-D207-408A-AACC-731CFB7F1DD7` | `0x49D410` | `0x8360` | |
| **009** | **PciRootBridge** | **`80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910`** | `0x4A5770` | `0xB29B` | 90,472 |
| 010 | AmiBoardInfo | `9F3A0016-AE55-4288-829D-D22FD344C347` | `0x4B0A10` | `0x3E74` | 54,260 |
| 044 | ACPI (driver) | `16D0A23E-C09C-407D-A14A-AD058FDD0CA1` | `0x563448` | `0x4CBC` | 39,972 |
| PEI | **IvtQpiandMrcInit** (FV 02) | `5C08C7C8-24C2-4400-9627-CF2869421E06` | `0xE26000` | — | 457,920 |

`IvtQpiandMrcInit` is stored **uncompressed** in FV02, so patch 1 is a raw-image
byte patch. `PciRootBridge` is stored **compressed** in FV01, so patch 2 needs the
decode → patch → repack path in §3.1.

### 3.1 The AMI/EDK2 COMPRESSION section, and the codec

Module 009 is `hdr(24) + DEPEx(76) + COMPRESSION`, 8-byte aligned in FV01. The
compression section body is

```
+0   u24 size + u8 type (0x01 = EFI_SECTION_COMPRESSION)
+4   u32 DestinationSize
+8   u8  CompressionType (0x01 = Tiano/LZH on this image, NOT EFI/LZMA)
+9   u32 CompressedSize
+13  u32 DestinationSize (repeated)
+17  bitstream              (13 + CompressedSize == section body length)
```

The buffer handed to the decoder starts at **+9**: `[CompressedSize]
[DestinationSize][bitstream]`. `TianoCompress()` from the `uefi-firmware` package
returns exactly that framing, so a re-compressed stream drops into the section
with no reshaping.

The payload is **the remaining sections of the file**, not a bare PE32 image
(standard `EFI_COMPRESSION2` semantics):

```
PE32(0x160E4, body 0x160E0 = 90,336 B, starts "MZ") + USER_INTERFACE(0x20) = 90,372 B
```

so `hdr + DEPEx + <those two sections>` = 90,472 B = exactly what MMTool's `/e`
extract of the same module contains, byte for byte. `patch_aperture.py
--reference-extract <extract>` asserts that identity.

Measured round-trips on stock, EDK2 codec only:

| module | stock stream | `TianoCompress` | delta | re-decompress |
|---|---|---|---|---|
| PciRootBridge (009) | 45,606 | 45,628 | **+22** | byte-identical |
| AmiBoardInfo (010) | 15,939 | 15,951 | **+12** | byte-identical |
| POST logo | 3,679 | 3,696 | **+17** | byte-identical |

AMI's encoder is not byte-reproducible, but it is within ~22 bytes. So
re-compression is viable: it moves FV01 by **16 bytes** (module 009:
`0xB29B → 0xB2AE`), against the **44,744** bytes that storing the module
uncompressed costs (`0xB29B → 0x16168`, MMTool's `/r` shape).

FV01 free space, measured by MMTool: stock **7,344 KB**; after patch 2
recompressed **7,344 KB**; after patch 2 stored uncompressed **7,300 KB**.

The default stores the module **uncompressed** — the larger of the two options. It
is byte-for-byte what MMTool's `/r` writes, it is the shape this board is known to
boot from, and FV01 already ships an uncompressed module (022 `BdsS3Logo`), so the
platform demonstrably stores modules that way. `--recompress` takes the 16-byte
option: a freshly EDK2-encoded stream decodes correctly through the EDK2
`TianoDecompress` the firmware uses, but has not been flashed and POSTed.

**Logo control test** — stock art out and back in, so the picture is not a
variable:

| | logo module | payload | pixels / palette | payload bytes differing |
|---|---|---|---|---|
| stock | 3,720 | 308,284 | — | — |
| re-embedded, Tiano | 3,721 | 308,284 | identical | **2** |
| re-embedded, raw (`--store-uncompressed`) | 308,306 | 308,282 | identical | **2** |

The 2 bytes are `biSizeImage` (BMP `+0x23/+0x24`), zeroed deliberately: the field
is ignored for uncompressed BI_RGB. Everything else in the payload is
byte-for-byte what Supermicro shipped. `biClrUsed` is treated the same way —
the stock template carries `0xB0000000` there, so the palette is sized from
`bfOffBits` and the field normalised to 0 on write.

### 3.2 Who computes the aperture, and who writes it to the DSDT

Firmware-side facts, `IvtQpiandMrcInit` (imagebase `0xffe26058`):

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

MRC already computes `base = 0x90000000`, `len = 0xFC000000 − base = 0x6C000000` —
byte-for-byte the `MBB`/`MBL` the fix needs. The ACPI layer publishes
`MMCFG base` / `0xFC000000 − MMCFG base` = `0x80000000` / `0x7C000000` instead:
256 MiB too wide at the bottom.

The DSDT is in module 010 `AmiBoardInfo` (DSDT header at module offset `0xA94`,
length `0xBC34` = 48,180 — the exact table the live OS reports). Its `MBB_`/`MBL_`
constants are **placeholders** shipped as `0x00010000`; runtime code overwrites
them. **Editing the DSDT template is a no-op.**

The writer is **`PciRootBridge`** (module 009), in a loop at RVA
`0x18000225c..0x18000248b` walking the AMI resource-name table in `.rdata` at RVA
`0x13284`. Each iteration:

```
  0x18000235d   mov  r9,  qword ptr [rdi + 0x168]   ; the VALUE
  0x180002364   mov  rdx, qword ptr [rdi + 0x100]   ; ACPI device path
  0x18000236b   lea  r8,  [rip + 0x10f46]           ; -> 'MBB'
  0x180002372   mov  rcx, rbx                       ; the DSDT table
  0x180002375   call 0x180010ba4                    ; the DSDT writer
```

The two struct fields, proven at `0x18001251b..0x180012545`:

```
  [rbp + 0x168] = MMIO32 base                  ; MBB = 0x80000000
  [rbp + 0x170] = MMIO32 limit - base + 1      ; MBL = 0x7C000000
```

Exhaustive check: `.text` of module 009 references the `MBB` string exactly once
and `MBL` exactly once, and those are the only reads of `+0x168`/`+0x170` that
reach the writer.

**Patch 2** (module-file offsets; `41 B9 imm32` = `mov r9d, imm32`, zero-extended
into `r9`, plus a `90` nop to keep the length):

```
  0x23c5  4c 8b 8f 68 01 00 00  ->  41 b9 00 00 00 90 90   mov r9d, 0x90000000 ; nop
  0x23e2  4c 8b 8f 70 01 00 00  ->  41 b9 00 00 00 6c 90   mov r9d, 0x6C000000 ; nop
```

Encoding trap: `41 B8 …` is `mov r8d`, **`41 B9 …`** is `mov r9d`. The struct is
untouched — only the numbers written into the table the OS reads.

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

FFS file — `g` = offset of its Name (GUID), exactly what MMTool's `/v` reports as
`Location`:

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

The **header checksum covers only the 24-byte header** — code and data bytes do
not affect it. Patching content changes the *file-data* checksum and must leave
the *header* checksum alone.

### Measured on stock X9DRGQF8.921

| Field | Result |
|---|---|
| FFS header checksum | **closes on 171 / 171** — live |
| FFS file-data checksum | **closes on 171 / 171**: 161 by sum, 10 with `FFS_ATTRIB_CHECKSUM` clear carrying `0xAA` — live |
| FV header `Checksum` (`fv+0x32`) | closes on **0 / 3** — stale residue Supermicro ships; the board boots with it broken. Informational only. |
| ACPI table `Checksum` (offset 52, whole-table 8-bit sum `== 0`) | must be recomputed for any table handed to the OS |
| SPI flash descriptor / ME region | **never touch** |

### Enforcement — which one the firmware actually checks

| field | enforced by firmware? | evidence |
|---|---|---|
| FFS **header** checksum | **Yes** | §7: the rev-1 image broke it in the MRC PEIM and the board did not POST |
| FFS **file-data** checksum | **No** | rev-2 boots with it stale (§7) |
| MMTool, on `/r` import | **Yes** (file-data) | rejects a one-byte change anywhere in the module |

So a content patch *must* keep the header checksum closing, and *should*
recompute the file-data checksum: the firmware tolerates the latter being stale,
MMTool does not, and a stale one silently truncates MMTool's volume walk (the
tripwire below). Rev 1 is what happens when you fix the wrong one.

### The repair (what the patchers do)

MMTool writes a **closing** pair of checksums into every `/e` extract and
**validates the file-data checksum when you `/r` a module back in**. Any
hand-edited module is therefore rejected — a **one-byte** change anywhere,
including a pure NOP-out — and nothing is written to the ROM:

```
MMTOOL rom /r <GUID> patched.bin   ->   "Invalid FFS File",  exit 127
```

Repair:

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
FV00 = 1, FV01 = 140, FV02 = **26**. A patch that edits code bytes in an FV02
module and leaves the checksum untouched makes MMTool report **FV02 = 4**.
Recompute it and 26 comes back.

**Any build whose MMTool file counts differ from stock's is not finished.**

---

## 5. MMTool 4.50 CLI

A GUI-subsystem PE with a text-mode UI: given valid args it AllocConsoles, prints,
then blocks in `ReadConsoleInputA`. From a pipe it has no console, so it dies with
`0xC000013A`. `tools/mmtool_run.py` drives it through a real ConPTY console and
always tears the console/window down.

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

Measured:

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
* MMTool's `/r` repack is not surgical: against a stock baseline the MMTool-built
  image differs from stock in **two** FV01 modules' contents (module 009 plus
  `EFD652CC-0E99-40F0-96C0-E08C089070FC`), while the pure-Python repack differs in
  exactly one. Prefer the pure-Python path when you want a minimal, explainable
  diff.

### Git-Bash / MSYS

MSYS path conversion rewrites a bare `/r` into `R:/`, `/s` into `S:/` and `/e`
into `E:/`, so MMTool sees a bogus argument and drops into its interactive menu
(then times out). Always:

```bash
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
```

Exit codes: MMTool exits 0 on success; on its own error path it exits
`3221225786` (`STATUS_CONTROL_C_EXIT`) with the message in `<rom-basename>.mmtool.log`.

### Repacking by hand

Any module edit that changes a module's size forces an FV repack. Do the repacking
step **first**, then apply byte patches **by pattern, never by hard-coded
offset** — offsets move.

`patch_aperture.py` repacks FV01 itself: it shifts every following FFS file by the
8-aligned size delta (so all files stay 8-byte aligned) and shrinks the volume's
trailing `0xFF` free space by exactly the same amount, keeping the image exactly
16 MiB. A shift that is not a multiple of 8 corrupts the volume: measure the delta
between the *aligned* footprints, and drop the freed bytes from the **end** of the
volume, not from the front of the file stream.

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

Raw proof, from the strings in `AFUDOSU.smc` (the 16-bit DOS flasher shipped in
Supermicro's BIOS download package): `Program main BIOS image\x00P\x00Program
Boot Block\x00Pb` and, in a second table, `Program main BIOS image\x00p\x00Program
Boot Block\x00b`.

**Safe shape: `AFUDOSU.EXE PATCH.BIN /P /R /X`.**

Avoid `/B` — the boot block is write-protected by the flash descriptor's Access
Control, so AFU can report success while the write cannot complete. Avoid
`/FDT /MER /OPR /me` for the same reason on the ME regions. Avoid `/SANTA` — it
removes AFU's last refusal.

Supermicro's own flash script (`ami.bat`, shipped in the same package) runs
`AFUDOSU.EXE %1 /P /B /N /K /R /FDT /MER /OPR`, putting the boot block and three ME
regions in scope. That is the vendor's shape for a full stock image, and it has
flashed a patched image on this board without harm — so it is not the reason the
rev-1 build died (§7). Prefer the narrow form anyway: fewer regions in scope means
fewer ways to half-write a locked one.

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

### `flash.sh` — the gated flasher

`flash.sh` wraps flashrom and enforces the gates that matter on this board. It
writes only `FREG1` (BIOS, `0x400000..0xFFFFFF`); the descriptor and ME are never
in scope. It generates the layout file from that measured region table when none
is supplied — it never derives one from the image, for the `FRBA = 0` reason
above. Its gates, in order, each a hard stop:

1. image is exactly 16,777,216 bytes;
2. every FFS header and FFS file-data checksum closes, via
   `verify_image.py --structure-only` (the FV header checksum field is stale on
   stock and is reported as information, not a failure);
3. a backup exists and **two consecutive chip reads are identical**;
4. the post-write read-back equals the image byte-for-byte across the BIOS
   region and passes structure validation itself.

Gate 3 is the one that catches an unstable read path before it costs you a chip.
Gate 2 is the one that would have stopped rev 1 (§7): a broken FFS header
checksum in the MRC PEIM is a refusal, not a brick. `check` and `verify` need
neither root nor flashrom, so an image can be audited on any machine.

---

## 7. Post-mortem: the rev-1 brick

A rev-1 build of the MMIOH patch bricked a board. The cause is a checksum field,
not a flash flag — and the distinction is the whole lesson.

Rev 1 changed **8 bytes** vs stock: 7 code bytes at `0x0E3019E` (identical to every
later revision) **plus** `0x00E26010`, which is `IntegrityCheck.Header` of
`IvtQpiandMrcInit` — the MRC/QPI-init PEIM. Boot block, flash descriptor, ME, GBE
and NVRAM: 0 bytes differ from stock.

| build | `0x00E26010` header | header checksum | file checksum | outcome |
|---|---|---|---|---|
| stock | `0x5a` | closes | closes | boots |
| **rev 1** | `0xa8` | **BROKEN** | stale | **board dead** |
| rev 2 | `0x5a` | **closes** | stale | **boots, flashed** |
| rev 3+ | `0x5a` | closes | closes | current builds |

Rev 1 and rev 2 differ in **one byte**, and rev 2 boots. So the byte is the
discriminator — and the flags are not: both images were flashed from a FreeDOS
USB stick with the same AFUDOSU command line,
`AFUDOSU.EXE PATCH.BIN /P /B /N /K /R /FDT /MER /OPR /SANTA`, byte for byte.

The mechanism is legible. The 7 code bytes change the file-data sum by **+0x4e
(78)**. The rev-1 patch computed that delta correctly and applied it to the
**header** checksum at `+0x10` instead of the **file-data** checksum at `+0x11`.
Net effect: the field that needed no change got broken, and the field that needed
changing stayed stale.

`IvtQpiandMrcInit` is the memory-training PEIM. Break its FFS **header** checksum,
the volume walk rejects the file, memory training never runs: fans spin, BMC
heartbeat alive, host never fetches the reset vector. It also explains why
`Ctrl+Home` recovery produced no video and no second beep — the recovery agent is
found by walking the same FFS.

**Rule: the FFS header checksum is load-bearing. The file-data checksum is not
enforced by the firmware, only by MMTool. Never "fix" a header checksum to
compensate for a content change — the content change never affects it.**

Caveat: this is a single A/B pair, and the rev-1 flash could in principle have
been interrupted. There is no evidence that it was, and the byte difference
explains the symptom exactly.

---

## 8. Dead ends — do not re-litigate

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
* **"The `/P` + `/K` flash flags killed rev 1."** Refuted in §7 — the same command
  flashed the image that boots.
* **Recompiling the DSDT with `iasl`.** Fails: the resource templates ship with
  `Min=Max=0, Length=0xFDFC0000` and are filled at runtime, which modern iasl
  rejects (`Error 6049`, then *Maximum error count (200) exceeded*). Binary-patch
  the AML only.
* **`pci=nocrs`** on the kernel command line. It strips `_CRS` windows for every
  root bus, including the 4-deep Matrox G200eR2 chain behind `00:1c.7`. No
  framebuffer.
* **Flashing the MI210 VBIOS.** `MCBP is enabled` / `trn=2` were artifacts of
  reading config space through an ECAM alias, not evidence of MxGPU firmware.
* **A bootloader (Clover, GRUB, an initrd table override) to fix the aperture.**
  A bootloader can rewrite ACPI tables; it cannot program chipset registers, and
  the aperture is set by MRC long before any bootloader runs. So boot-time table
  patches can fix Problem B — that is exactly how it was first proven, and the
  override route is still the zero-risk way to test it — but no boot-time trick
  can fix Problem A. That one has to be in flash.
* **Hunting for a setup variable to flip.** There is none. The variable exists in
  the MRC structure (`[esi+0x2c0]`, GiB, 16-bit) and is unwired.

Geometry rules that are easy to get wrong:

* A PCI TLP must pass **every** bridge on the path. Moving a BAR means all three
  bridges in the chain (`00:03.0`, `03:00.0`, `04:00.0`) must cover the new range;
  to remove a stale window you remove the **whole subtree at the root port**, not
  just the endpoint.
* AML name segments are **4 chars**: the names are `MBB_`/`MBL_`, iasl *prints*
  them as `MBB`/`MBL`. The real bytes are `08 4D 42 42 5F 0C <dword>` and the
  dword is at `i+5`, not `i+4` (a `0x0C` DWordPrefix sits between).
* The string `MBB_` occurs **0 times** in the raw 16 MiB image — it only exists
  compressed. Any scan of the raw ROM for AML names is guaranteed to fail.

---

## 9. Rules

1. **Never edit the stock image in place.** Copy → patch → diff → verify. Keep an
   untouched copy of the original forever.
2. Patch **by unique byte pattern**, and assert the pattern occurs exactly once in
   16 MiB.
3. After every patch run `verify_image.py` and diff against stock, expecting only
   the intended runs.
4. Preserve FFS `Attributes` unless there is a verified reason to change them.
   Preserve valid file sizes, firmware-volume boundaries and 8-byte file
   alignment.
5. Do not assume MMTool recomputes the file-data checksum. It does not — it
   validates it.
6. Do not assume every UEFI section has its own checksum. Only the FFS file header
   carries the two checksums described in §4.
7. Do not treat the DSDT/ACPI checksum, the PE/COFF checksum, the FFS checksums and
   the firmware-volume checksum as interchangeable. They are separate fields with
   separate rules.
8. Do not patch the full BIOS image until the exact cause of what you are fixing
   has been identified.
9. **Believe the verifier only if it re-derives.** `verify_image.py` re-walks the
   volumes, detects which patches an image carries, re-decompresses the patched
   module out of the image, re-disassembles the sites it finds and recomputes the
   aperture arithmetic from the emitted immediates. It does not read the patchers'
   output.
10. Never flash without a recovery path: a CH341A-class programmer and a
    known-good dump. A board that will not POST has no other escape.

---

## 10. Status

**Proven on hardware** (the reference board, flashed to the main BIOS region;
the image running on it is stock + patch 1 + patch 2 + a replaced POST logo,
sha256 `01ea1341…`). Read back out of the flashed chip:

```
0x0e3019e  ba 00 20 00 00 66 90 66 85 d2     patch 1: mov edx,0x2000 ; nop  (8 TiB)
module 009 @0x4a5770  size 0x16168           patch 2 applied, stored UNCOMPRESSED
  +0x23c5  41 b9 00 00 00 90 90              MBB = mov r9d, 0x90000000 ; nop
  +0x23e2  41 b9 00 00 00 6c 90              MBL = mov r9d, 0x6C000000 ; nop
```

| | |
|---|---|
| Patch 1, MMIOH → 8 TiB | flashed; root bus window `[mem 0x380000000000-0x3fffffffffff window]` — exactly the 8 TiB requested |
| Patch 2, aperture excludes ECAM | flashed and baked into flash; also proven standalone as an initrd ACPI table override (`ACPI: Table Upgrade`, root bus `[mem 0x90000000-0xfbffffff window]`, ECAM not handed out, `amdgpu` probes, `VRAM: 65520M`, `/dev/kfd`, `rocminfo` OK) |
| Pure-Python FV01 repack, module stored uncompressed | flashed. Byte-identical to MMTool's `/r` output at both patch sites |
| Logo replacement, pure Python | flashed; MMTool's volume walk of that image reports 1 / 140 / 26, identical to stock |
| MMTool CLI | `/ec`+`/rc` round-trip byte-exact; `/r` of an unmodified `/e` extract byte-exact |

**Not proven on hardware:** a **re-compressed** module booting on the board. The
re-compressed stream is produced and consumed by the EDK2 Tiano codec and
round-trips byte-identical, and the volume passes every structural check, but that
image has not been flashed and POSTed. The uncompressed shape — the default — has.
