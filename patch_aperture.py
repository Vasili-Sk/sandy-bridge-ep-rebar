#!/usr/bin/env python3
"""X9DRG-QF root-bridge aperture patch (the ECAM half of the fix).

PROBLEM
-------
MCFG/ECAM = 0x80000000..0x8FFFFFFF (256 MiB, PCIEXBAR, bus0 dev31 fn0 reg 0x84).
The DSDT publishes the root bridge 32-bit MMIO aperture as
    MBB = 0x80000000  (= MMCFG base)
    MBL = 0x7C000000  (= 0xFC000000 - MMCFG base)
so the aperture handed to the OS *contains* ECAM.  Nothing reserves ECAM
(`Device (VTDR)`/PNP0C02 covers only the VT-d block), so Linux's first-fit
allocator hands BARs out of that range and the first ones land on config space.
That is the `amdgpu` / `xgpu_ai_mailbox_trans_msg()` hang: a BAR aliasing ECAM
makes RCC_CONFIG_MEMSIZE read garbage.

MRC's *internal* numbers are already correct (IvtQpiandMrcInit):
    [esi+0x2b8] = MMCFG base + MMCFG size = 0x90000000
    [esi+0x2bc] = 0xFC000000 - that      = 0x6C000000
The ACPI publishing layer publishes the MMCFG base itself instead.  The defect is
purely that the table shown to the OS is 256 MiB too wide at the bottom.

PATCH SITE (measured, Ghidra 12.1.4 decompilation + capstone)
------------------------------------------------------------
The values are written into the DSDT by **PciRootBridge** (module 009,
80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910), in the loop at RVA 0x18000225c..0x18000248b
that walks the AMI resource-name table in .rdata at RVA 0x13284:

    MALH MALL MAMH MAML MABH MABL MBL MBB IOL IOB BRL BRB STAV LVGA CPRB

Each iteration calls the DynamicPciBase service (vftn +0x18, RVA 0x180010ba4)
which locates `Name(<name>, DWord)` in the DSDT and overwrites its operand.
The two relevant instructions (module-file offsets in the MMTool `/e` extract):

    0x23c5  4c 8b 8f 68 01 00 00   mov r9, [rdi+0x168]   ; -> "MBB"
    0x23e2  4c 8b 8f 70 01 00 00   mov r9, [rdi+0x170]   ; -> "MBL"

Both are 7 bytes.  Both are replaced by 7 bytes:

    41 b8 <imm32> 90               mov r9d, imm32 ; nop

A 32-bit `mov r9d, imm32` zero-extends, so r9 == the intended 64-bit value and
the callee writes 4 bytes into the DWord operand, exactly as before.
No length change, no new section, no code cave, no relocation, no checksum field
other than what MMTool recomputes on module replace.

RESULT
------
    MBB 0x80000000 -> 0x90000000   (MMCFG base + MMCFG size)
    MBL 0x7C000000 -> 0x6C000000   (0xFC000000 - 0x90000000)
    published aperture 0x90000000..0xFBFFFFFF  -- ECAM excluded.

These are byte-for-byte the values proven live via the initrd ACPI table
override: `root bus resource [mem 0x90000000-0xfbffffff window]`, ECAM no longer
handed out, amdgpu probes, VRAM 65520M, /dev/kfd present.

WHY NOT THE OTHER CANDIDATE SITES
---------------------------------
* The DSDT template's `Name(MBB_, 0x00010000)` (module 010 AmiBoardInfo, offsets
  0x2216 / 0x6BE8): overwritten at runtime by the loop above.  Editing it is a
  no-op -- that is why the template ships 0x10000 and the live table reads
  0x80000000.
* Adding a PNP0C02 reservation for 0x80000000-0x8FFFFFFF: cannot work.  It is
  inserted as a sibling of the root-bus window in iomem_resource, and
  allocate_resource() on the window only avoids children of the window.  This is
  exactly why the upstream kernel workaround keys off the e820 map, not PNP0C02.
* Moving MMCFG base: the published aperture always starts at the ECAM base, so
  the collision moves with it.  0xE0000000 is additionally rejected by MRC's own
  validator, and any change trips the guard at 0xffe2d84e
  ("PCIEXBASE ADDRESS IS CHANGED. SYSTEM WILL DO A RESET !!!!") -> cold-reset loop.

FFS CHECKSUMS -- why MMTool says "Invalid FFS File"
-----------------------------------------------
An MMTool `/e` extract is the FFS file starting at its Name (GUID), i.e. the
EFI_FFS_FILE_HEADER with the 16-byte ZeroVector stripped:

    0x00 16  Name (GUID)
    0x10  1  IntegrityCheck.Header   (header checksum)
    0x11  1  IntegrityCheck.File     (file-data checksum)
    0x12  1  Type
    0x13  1  Attributes
    0x14  3  Size (LE, whole file incl. this header)
    0x17  1  State
    0x18 --  file data (sections)

Module 009 has **Attributes = 0x40 = FFS_ATTRIB_CHECKSUM**, so per PI
V3.11.3.1 the File checksum is live and must satisfy

    (sum(file[0x18:size]) + FileChk) & 0xff == 0

Verified on the stock extract: stored 0x78, computed 0x78.  Header checksum
stored 0x3a, computed 0x3a (sum over the 24-byte header with 0x10/0x11/0x17
zeroed).  Both valid on stock; the header checksum is unaffected by a same-size
code patch, the file-data checksum is NOT.  That is exactly why `/r` accepted the
unmodified extract byte-for-byte and rejected every 1-byte-modified variant with
"Invalid FFS File": MMTool validates the imported module's file-data checksum.
So this script recomputes it.  Attributes are preserved, never cleared.

Usage:
    python patch_aperture.py <PciRootBridge module extract> -o <patched module>

The input is an MMTool `/e` extract of module 009, not the whole ROM: the module
is stored compressed and AMI's compressor is proprietary, so it has to be
expanded by MMTool first. `patch_aperture.py` recognises a full 16 MiB image on
the command line and prints the exact extract command to run. See AGENTS.md
"Building patch 2" for the three-command sequence.
"""
import argparse, os, re, sys, uuid

GUID = "80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910"          # PciRootBridge, FV01
SITE = [
    # (pattern, replacement, name, new value)
    # 41 B9 /id=1 imm32 == mov r9d, imm32 (zero-extends into r9); 90 == nop
    (bytes.fromhex("4c8b8f68010000"), bytes.fromhex("41b900000090" + "90"),
     "MBB", 0x90000000),
    (bytes.fromhex("4c8b8f70010000"), bytes.fromhex("41b90000006c" + "90"),
     "MBL", 0x6C000000),
]
MMCFG_BASE, MMCFG_SIZE, TOM = 0x80000000, 0x10000000, 0xFC000000


def ffs_fix_checksums(d, expect_attrs=0x40):
    """Recompute the FFS file-data checksum of a ZeroVector-stripped FFS file."""
    assert len(d) >= 0x18, "shorter than an FFS header"
    attrs = d[0x13]
    assert attrs & 0x01 == 0, "FFS_ATTRIB_LARGE_FILE: extended header unsupported"
    size = int.from_bytes(d[0x14:0x17], "little")
    assert size == len(d), f"FFS size {size:#x} != file length {len(d):#x}"
    assert attrs & expect_attrs, f"FFS_ATTRIB_CHECKSUM not set (attrs {attrs:#04x})"

    hdr = bytearray(d[:0x18])
    hdr[0x10] = hdr[0x11] = hdr[0x17] = 0
    hdr_chk = (-sum(hdr)) & 0xFF
    data_sum = sum(d[0x18:size])
    file_chk = (-data_sum) & 0xFF

    print(f"\nFFS header: type {d[0x12]:#04x} attrs {attrs:#04x} "
          f"state {d[0x17]:#04x} size {size:#x}")
    print(f"  header chksum  stored {d[0x10]:#04x}  required {hdr_chk:#04x}"
          f"  {'unchanged' if d[0x10] == hdr_chk else 'UPDATED'}")
    print(f"  file   chksum  stored {d[0x11]:#04x}  required {file_chk:#04x}"
          f"  {'unchanged' if d[0x11] == file_chk else 'UPDATED'}")
    d[0x10] = hdr_chk
    d[0x11] = file_chk

    # independent re-validation of what we just wrote
    hdr = bytearray(d[:0x18])
    hdr[0x10] = hdr[0x11] = hdr[0x17] = 0
    assert (sum(hdr) + d[0x10]) & 0xFF == 0, "header checksum does not close"
    assert (sum(d[0x18:size]) + d[0x11]) & 0xFF == 0, "file checksum does not close"
    print("  both checksums re-validated: sum == 0 mod 256")


def main():
    ap = argparse.ArgumentParser(
        description="Shrink the published root-bridge 32-bit MMIO aperture so it no "
                    "longer contains ECAM. Input = MMTool /e extract of PciRootBridge.",
        epilog="example:  python patch_aperture.py PciRootBridge.bin -o PciRootBridge.patched.bin")
    ap.add_argument("module", help="MMTool /e extract of module 009 PciRootBridge "
                                   "(GUID 80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910)")
    ap.add_argument("-o", "--out", default=None)
    a = ap.parse_args()
    a.inp = a.module

    if os.path.getsize(a.inp) >= 8 << 20:
        sys.exit(
            f"ABORT: {a.inp} is {os.path.getsize(a.inp)} bytes - that is a whole ROM image.\n"
            f"Module 009 is stored compressed and AMI's compressor is proprietary, so it\n"
            f"must be expanded by MMTool (Aptio IV module tool, from your firmware package)\n"
            f"before it can be patched:\n"
            f"\n"
            f"  MMTOOL <rom> /e {GUID} PciRootBridge.bin\n"
            f"  python patch_aperture.py PciRootBridge.bin -o PciRootBridge.patched.bin\n"
            f"  MMTOOL <rom> /r {GUID} PciRootBridge.patched.bin\n")

    d = bytearray(open(a.inp, "rb").read())
    if uuid.UUID(bytes_le=bytes(d[:16])) != uuid.UUID(GUID):
        sys.exit(f"ABORT: {os.path.basename(a.inp)} is module "
                 f"{uuid.UUID(bytes_le=d[:16])}, expected {GUID} (PciRootBridge)")

    # sanity: the constants we are deriving from must be the ones this board uses
    assert MMCFG_BASE + MMCFG_SIZE == 0x90000000
    assert TOM - (MMCFG_BASE + MMCFG_SIZE) == 0x6C000000

    for pat, rep, nm, val in SITE:
        assert len(pat) == len(rep) == 7, "patch must be size-preserving"
        n = d.count(pat)
        if n != 1:
            sys.exit(f"ABORT: '{nm}' pattern {pat.hex()} occurs {n}x in "
                     f"{os.path.basename(a.inp)}, expected exactly 1")
        o = d.find(pat)
        print(f"{nm}: @{o:#07x}  {d[o:o+7].hex()} -> {rep.hex()}"
              f"   mov r9,[rdi+{int.from_bytes(pat[3:7],'little'):#x}]"
              f"  ==>  mov r9d,{val:#x} ; nop")
        d[o:o + 7] = rep

    ffs_fix_checksums(d)

    dst = a.out or re.sub(r"\.bin$", "", os.path.basename(a.inp)) + ".aperture.bin"
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    open(dst, "wb").write(bytes(d))
    print(f"\nmodule length unchanged: {len(d):#x}")
    print(f"published aperture: {MMCFG_BASE + MMCFG_SIZE:#010x} .. {TOM - 1:#010x}"
          f"   (ECAM {MMCFG_BASE:#010x}-{MMCFG_BASE + MMCFG_SIZE - 1:#010x} excluded)")
    print(f"wrote {dst}")


if __name__ == "__main__":
    main()
