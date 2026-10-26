#!/usr/bin/env python3
"""Independent structural + semantic verification of a patched flash image.

    python verify_image.py <stock.921> <patched.bin>

Nothing here trusts the patchers: every claim is re-derived from the bytes.

WHAT THE IMAGES ARE
-------------------
stock = Supermicro X9DRGQF8.921 (3.3), 16 MiB raw SPI.
final = stock + any subset of the two patches:
      + MMIOH aperture 1 TiB -> 8 TiB: 7 code bytes in the PEIM
        IvtQpiandMrcInit (FV02) + its FFS file-data checksum byte.
      + published root-bridge 32-bit MMIO aperture 0x80000000/0x7C000000 ->
        0x90000000/0x6C000000: 14 code bytes in the DXE driver PciRootBridge
        (FV01) + its FFS file-data checksum byte.  That module lives inside
        FV01 and may be stored compressed (Tiano) or uncompressed, and the
        volume may have been repacked around it (files shifted), so FV01 is
        verified structurally -- geometry, file count, every file's checksums,
        and the module's code re-decompressed from the image -- rather than as
        a byte run.  Which patches are present is detected from the bytes and
        the corresponding region checks are applied.

MEASURED LAYOUT FACTS THIS VERIFIER RELIES ON
--------------------------------------------
Firmware Volume header (at `fv`):
    0x00 16 ZeroVector   0x10 16 FileSystemGuid   0x20  8 FvLength
    0x28  4 Signature '_FVH'                      0x2C  4 Attributes
    0x30  2 HeaderLength (0x48 here)              0x32  2 Checksum
    0x34  2 ExtHeaderOffset  0x36 1 Reserved  0x37 1 Revision
HeaderLength is the offset of the FIRST FFS file's Name (GUID), not of its
ZeroVector: FV01 HeaderLength 0x48 -> first GUID at 0x460048, and MMTool's
listing reports exactly that.

FFS file (GUID at `g`, i.e. g = fv+HeaderLength for the first file):
    0x00 16 Name (GUID)          0x10  1 IntegrityCheck.Header
    0x11  1 IntegrityCheck.File  0x12  1 Type
    0x13  1 Attributes           0x14  3 Size (LE, measured FROM the GUID)
    0x17  1 State                0x18 -- file data (sections)
Next file's GUID = align8(g + Size).  Checked against MMTool's own listing:
FV01 file0 0x460048+0x5028 = 0x465070 = file1's GUID; FV02 file0
0xE00048+0x1D828 = 0xE1D870 = CRBPEI's GUID.  Exact, both.

Checksum conventions (PI Vol.3 FFS_FILE_HEADER):
    header: sum(GUID..State) with Header, File and State zeroed, + Header == 0
    file  : if Attributes & FFS_ATTRIB_CHECKSUM (0x40):
                sum(data) + File == 0
            else File == 0xAA
Measured on stock: header closes 167/167, file closes 161/167, the other 6
carry 0xAA with the attribute clear.  So both fields are LIVE on this image.
The FV header Checksum does NOT close on any of the 3 volumes in stock
(residue Supermicro ships); it is reported, not asserted.
"""
import hashlib
import re
import struct
import sys
import uuid
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

# The DXE module this verifier checks is stored Tiano-compressed in FV01, so
# re-deriving its code bytes needs the same compiled EDK2 codecs the patcher
# uses (`pip install uefi-firmware>=1.16`).  Without it the module-level checks
# are reported as skipped; everything structural still runs.
try:
    from uefi_firmware import efi_compressor as ec
except ImportError:
    ec = None

PHYS = 46
FV01 = (0x460000, 0xDD0000)
ok = True
def chk(c, m):
    global ok
    print(f"  [{'PASS' if c else 'FAIL'}] {m}")
    ok = ok and bool(c)
def info(m):
    print(f"  [info] {m}")

def volumes(d):
    res, o = [], 0
    while True:
        i = d.find(b"_FVH", o)
        if i < 0:
            break
        h = i - 0x28
        ln = struct.unpack_from("<Q", d, h + 0x20)[0]
        hl = struct.unpack_from("<H", d, h + 0x30)[0]
        if not (0x1000 <= ln <= len(d) and h + ln <= len(d) and 0x20 <= hl <= 0x1000):
            o = i + 4
            continue
        hc = struct.unpack_from("<H", d, h + 0x32)[0]
        hh = bytearray(d[h:h + hl])
        hh[0x32] = hh[0x33] = 0
        p, files = h + hl, []
        while p + 0x18 <= h + ln:
            if d[p] == 0xFF:
                break
            attrs = d[p + 0x13]
            size = int.from_bytes(d[p + 0x14:p + 0x17], "little")
            if not 0x18 <= size <= h + ln - p:
                break
            files.append((p, size, attrs))
            p = (p + size + 7) & ~7
        res.append((h, ln, hc, (sum(hh) + hc) & 0xFFFF == 0, files))
        o = h + ln
    return res

def closes(d, g, size, attrs):
    h = bytearray(d[g:g + 0x18])
    h[0x10] = h[0x11] = h[0x17] = 0
    hdr = (sum(h) + d[g + 0x10]) & 0xFF == 0
    fil = ((sum(d[g + 0x18:g + size]) + d[g + 0x11]) & 0xFF == 0) if attrs & 0x40 \
        else d[g + 0x11] == 0xAA
    return hdr, fil

def runs(idxs):
    out, i = [], 0
    while i < len(idxs):
        j = i
        while j + 1 < len(idxs) and idxs[j + 1] == idxs[j] + 1:
            j += 1
        out.append((idxs[i], j - i + 1))
        i = j + 1
    return out


def sections(blob):
    """Yield (type, body) for every section in an FFS file body / payload."""
    p = 0
    while p + 4 <= len(blob):
        size = int.from_bytes(blob[p:p + 3], "little")
        stype = blob[p + 3]
        if not 4 <= size <= len(blob) - p:
            return
        yield stype, blob[p + 4:p + size]
        p = (p + size + 3) & ~3


def pe32_of(d, g):
    """The PE32 image body of the FFS file whose GUID is at g, decompressed.

    Handles both shapes a module can have here: PE32 section at the top level
    (MMTool's /r shape, no compression section) and PE32 inside an
    AMI/EDK2 COMPRESSION section (type 0x01, CompressionType 0x01 = Tiano).
    """
    size = int.from_bytes(d[g + 0x14:g + 0x17], "little")
    for stype, body in sections(d[g + 0x18:g + size]):
        if stype == 0x10:
            return body
        if stype == 0x01 and ec is not None:
            dest, ctype = struct.unpack_from("<I", body, 0)[0], body[4]
            if ctype != 0x01:
                continue
            buf = body[5:]                       # CompressedSize, DestinationSize, bitstream
            out = ec.TianoDecompress(buf, dest + (1 << 20))
            if len(out) != dest:
                continue
            for t2, b2 in sections(out):
                if t2 == 0x10:
                    return b2
    return None

stock_f, final_f = sys.argv[1], sys.argv[2]
a, b = open(stock_f, "rb").read(), open(final_f, "rb").read()
print(f"stock {stock_f}\n      {len(a):,} B  sha256 {hashlib.sha256(a).hexdigest()}")
print(f"final {final_f}\n      {len(b):,} B  sha256 {hashlib.sha256(b).hexdigest()}\n")

print("=== image shape ===")
chk(len(b) == 16 * 1024 * 1024, f"16 MiB ({len(b):,} B)")
chk(len(a) == len(b), "same length as stock (no resize)")
chk(struct.unpack_from("<I", b, 0x10)[0] == 0x0FF0A55A, "flash descriptor signature at 0x10 intact")

print("\n=== regions that must be byte-identical to stock ===")
for lo, hi, nm in [(0x000000, 0x400000, "flash descriptor / ME / NCB0"),
                   (0x420000, 0x460000, "NCB1"),
                   (0xDD0000, 0xE00000, "NCB2")]:
    chk(a[lo:hi] == b[lo:hi], f"{nm} {lo:#x}..{hi:#x}")

S = 0x0E3019E                     # MMIOH size site, IvtQpiandMrcInit (FV02)
MMIOH_ORIG = bytes.fromhex("0fb796c00200006685d2")
mmioh = b[S:S + 10] != MMIOH_ORIG         # is patch 1 present in this image?
chk(a[S:S + 10] == MMIOH_ORIG, "stock bytes at the MMIOH site are the original "
                               "movzx/test pair")
if mmioh:
    chk(a[0xE00000:0xE26011] == b[0xE00000:0xE26011], "FV02 up to the checksum byte")
    chk(a[0xE26012:0xE3019E] == b[0xE26012:0xE3019E], "FV02 between the two sites")
    chk(a[0xE301A5:0x1000000] == b[0xE301A5:0x1000000], "FV02 from the site to end of image")
else:
    chk(a[0xE00000:] == b[0xE00000:], "FV02 (PEI + boot block) byte-identical to stock: "
                                     "the MMIOH patch is not in this image")
outside = [i for i in range(len(a)) if a[i] != b[i]
           if not (FV01[0] <= i < FV01[1])]
info(f"outside FV01: {len(outside)} bytes in {len(runs(outside))} run(s) -> "
     + (", ".join(f"{s:#x}+{n}" for s, n in runs(outside)) or "none"))
if mmioh:
    chk(len(runs(outside)) == 2 and runs(outside)[0] == (0xE26011, 1)
        and runs(outside)[1] == (0xE3019E, 7),
        "outside FV01 exactly 2 runs: 1 checksum byte + 7 code bytes")
else:
    chk(not outside, "outside FV01: nothing at all (aperture-only patch, "
                     "MMIOH untouched)")

print("\n=== firmware volumes ===")
va, vb = volumes(a), volumes(b)
chk(len(va) == len(vb) == 3, f"3 firmware volumes ({len(vb)})")
for (h, ln, hc, hok, fa), (h2, ln2, hc2, hok2, fb) in zip(va, vb):
    t = f"FV @ {h:#x} len {ln:#x}"
    chk((h, ln) == (h2, ln2), f"{t}: offset/length unchanged")
    chk(hc == hc2, f"{t}: FV header checksum field unchanged ({hc:#06x})")
    info(f"{t}: FV header checksum closes = {hok} (stock; Supermicro ships it stale)")
    chk(len(fa) == len(fb), f"{t}: FFS file count {len(fa)} -> {len(fb)}")
    chk([(s, at) for _, s, at in fa] == [(s, at) for _, s, at in fb]
        if h != FV01[0] else True,
        f"{t}: per-file size/attribute sequence unchanged" if h != FV01[0]
        else f"{t}: (FV01 is the volume the aperture patch repacks; per-file "
             f"sizes are expected to shift there)")

print("\n=== FFS integrity: every file in every volume, final image ===")
for (h, ln, _, _, fa), (h2, ln2, _, _, fb) in zip(va, vb):
    sa = [closes(a, g, s, at) for g, s, at in fa]
    sb = [closes(b, g, s, at) for g, s, at in fb]
    print(f"  FV @ {h:#x}: stock hdr {sum(x for x,_ in sa)}/{len(sa)} "
          f"file {sum(y for _,y in sa)}/{len(sa)}   |   final hdr "
          f"{sum(x for x,_ in sb)}/{len(sb)} file {sum(y for _,y in sb)}/{len(sb)}")
    chk(sum(x for x, _ in sb) == len(sb), f"FV @ {h:#x}: all FFS header checksums close")
    chk(sum(y for _, y in sb) == len(sb), f"FV @ {h:#x}: all FFS file-data checksums close")

print("\n=== patch site 1: MMIOH size (PEIM IvtQpiandMrcInit, FV02) ===")
g4 = b.find(uuid.UUID("5C08C7C8-24C2-4400-9627-CF2869421E06").bytes_le)
chk(g4 == 0xE26000, f"IvtQpiandMrcInit GUID at {g4:#x}")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
ins = {i.address: (i.mnemonic, i.op_str) for i in md32.disasm(b[S - 0x15:S + 0x14], S - 0x15)}
for ad in sorted(ins):
    mark = "  <== patched" if S <= ad <= S + 5 else ""
    print(f"    {ad:#09x}  {ins[ad][0]:8s} {ins[ad][1]}{mark}")
chk(a[S:S + 10] == MMIOH_ORIG,
    "stock bytes here are movzx edx,[esi+0x2c0] ; test dx,dx")
if not mmioh:
    info("MMIOH patch not present in this image (aperture-only build); "
         "site 1 checks skipped, FV02 verified byte-identical above")
if mmioh:
    chk(ins[S] == ("mov", "edx, 0x2000"), f"{S:#x} now decodes as mov edx, 0x2000")
    chk(ins[S + 5][0] in ("nop", "xchg"), "padding decodes as a real nop")
    chk(ins[S + 7] == ("test", "dx, dx"), "original test dx,dx preserved")
    chk(ins[S + 0xA][0] == "jne", "original jne preserved (non-zero -> size used)")
size_gib = struct.unpack_from("<I", b, S + 1)[0]
base_u4g = struct.unpack_from("<I", b, 0x0E3018C)[0]
mult = struct.unpack_from("<I", b, 0x0E301DE)[0]
chk(mult == 0x40000000, f"callee multiplier {mult:#x} = 1 GiB -> field unit is GiB")
chk(base_u4g == 0x3800, f"base {base_u4g:#x} x 4 GiB = {base_u4g << 32 >> 40} TiB")
if mmioh:
    chk(size_gib & (size_gib - 1) == 0 and size_gib <= 0xFFFF,
        f"size {size_gib:#x} GiB is a power of two and fits the 16-bit field")
    base_addr, top = base_u4g << 32, (base_u4g << 32) + (size_gib << 30)
    chk(top == 1 << PHYS, f"window {base_addr:#x}..{top-1:#x} ends exactly at 2^{PHYS}")
    chk(size_gib << 30 >= 64 << 30, f"{size_gib<<30>>30} GiB covers a 64 GiB MI210 BAR0")
    chk((sum(b[g4+0x18:g4+int.from_bytes(b[g4+0x14:g4+0x17],'little')]) + b[g4+0x11]) & 0xFF == 0,
        f"IvtQpiandMrcInit file-data checksum recomputed ({b[g4+0x11]:#04x})")
else:
    chk((sum(b[g4+0x18:g4+int.from_bytes(b[g4+0x14:g4+0x17],'little')]) + b[g4+0x11]) & 0xFF == 0,
        f"IvtQpiandMrcInit file-data checksum still closes ({b[g4+0x11]:#04x}, untouched)")

print("\n=== patch site 2: published root-bridge aperture (DXE PciRootBridge, FV01) ===")
G9 = uuid.UUID("80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910").bytes_le
g9, g9a = b.find(G9), a.find(G9)
chk(g9 >= 0 and g9a >= 0, f"PciRootBridge GUID: stock {g9a:#x} -> final {g9:#x}")
for tag, d, g in (("stock", a, g9a), ("final", b, g9)):
    sz = int.from_bytes(d[g + 0x14:g + 0x17], "little")
    hdr, fil = closes(d, g, sz, d[g + 0x13])
    print(f"    {tag:5s}: GUID@{g:#x} size {sz:#x} attrs {d[g+0x13]:#04x} "
          f"state {d[g+0x17]:#04x}  hdr {'OK' if hdr else 'BAD'} file {'OK' if fil else 'BAD'}")
    chk(hdr and fil, f"{tag}: PciRootBridge FFS checksums close")
chk(b[g9 + 0x13] == a[g9a + 0x13], f"FFS Attributes preserved ({b[g9+0x13]:#04x})")
pe_a, pe_b = pe32_of(a, g9a), pe32_of(b, g9)
aperture = False
if pe_a is None or pe_b is None:
    chk(False, "PE32 image recovered from both PciRootBridge modules "
               f"(stock {'ok' if pe_a else 'FAILED'}, final {'ok' if pe_b else 'FAILED'}; "
               f"codec {'loaded' if ec else 'NOT installed - pip install uefi-firmware>=1.16'})")
else:
    info(f"PE32 image recovered from both modules: stock {len(pe_a):,} B, "
         f"final {len(pe_b):,} B"
         + (" (Tiano-decompressed)" if ec else " (stored uncompressed)"))
    md64 = Cs(CS_ARCH_X86, CS_MODE_64)
    SITES = ((bytes.fromhex("41b90000009090"), 0x90000000, "MBB",
              bytes.fromhex("4c8b8f68010000")),
             (bytes.fromhex("41b90000006c90"),
              0x6C000000, "MBL", bytes.fromhex("4c8b8f70010000")))
    # Like patch 1, patch 2 is detected from the bytes: an image may carry either,
    # both, or neither, and the verifier must say which rather than cry wolf.
    aperture = all(pat in pe_b for pat, _w, _n, _o in SITES)
    if not aperture:
        info("patch 2 (published aperture) is NOT present in this image: the two stock "
             "loads are intact, so its code checks are skipped")
        for _p, _w, nm, orig in SITES:
            chk(len(re.findall(re.escape(orig), pe_b)) == 1,
                f"{nm}: the unpatched module still has its stock load")
        chk(pe_a == pe_b,
            "the PciRootBridge PE32 image is byte-identical to stock (patch 2 not applied)")
    else:
        sites = []
        for pat, want, nm, orig in SITES:
            h = [m.start() for m in re.finditer(re.escape(pat), pe_b)]
            chk(len(h) == 1, f"{nm}: 'mov r9d,{want:#x}; nop' occurs exactly once in the "
                              f"final module's PE32 image")
            chk(len([m for m in re.finditer(re.escape(orig), pe_a)]) == 1,
                f"{nm}: the stock module has exactly one mov r9,[rdi+{int.from_bytes(orig[3:7], 'little'):#x}] "
                f"at PE32 offset {pe_a.find(orig):#x}")
            chk(len([m for m in re.finditer(re.escape(orig), pe_b)]) == 0,
                f"{nm}: the original load is gone from the final module")
            o = h[0]
            sites.append((o, nm))
            seq = list(md64.disasm(pe_b[o:o + 0x38], 0))
            chk(seq[0].mnemonic == "mov" and seq[0].op_str == f"r9d, {want:#x}",
                f"{nm}: decodes as mov r9d, {want:#x}")
            chk(seq[1].mnemonic in ("nop", "xchg"), f"{nm}: padding is a real nop")
            chk(any(i.mnemonic == "call" for i in seq), f"{nm}: followed by the DSDT writer call")
            chk(any(i.mnemonic == "lea" and "rip" in i.op_str for i in seq),
                f"{nm}: the AMI resource-name string is loaded for the same call")
        chk(len(pe_a) == len(pe_b), "module code length unchanged by the patch")
        n = sum(1 for x, y in zip(pe_a, pe_b) if x != y)
        chk(n == 14, f"exactly {n} bytes differ between the stock and final PE32 images "
                     f"(2 x 7 code bytes)")
        dr = runs([i for i in range(len(pe_a)) if pe_a[i] != pe_b[i]])
        chk(dr == sorted((o, 7) for o, _n in sites),
            "the only bytes that differ in the whole 90 KB PE32 image are the two "
            "7-byte sites: " + ", ".join(f"{o:#x}+7 ({nm})" for o, nm in sites))

print("\n=== the aperture the OS will be told about"
      + (" ===" if aperture else " (the values patch 2 would publish) ==="))
MBB, MBL, MMCFG_BASE, MMCFG_SIZE, TOM = 0x90000000, 0x6C000000, 0x80000000, 0x10000000, 0xFC000000
chk(MBB == MMCFG_BASE + MMCFG_SIZE, f"MBB {MBB:#x} == MMCFG base + MMCFG size")
chk(MBL == TOM - MBB, f"MBL {MBL:#x} == {TOM:#x} - MBB")
chk(MBB + MBL == TOM, f"aperture {MBB:#x}..{MBB+MBL-1:#x} ends at TOM")
chk(not (MBB <= MMCFG_BASE <= MBB + MBL - 1), "ECAM base is NOT inside the published aperture")
chk(not (MBB <= MMCFG_BASE + MMCFG_SIZE - 1 <= MBB + MBL - 1), "ECAM end is NOT inside it")
chk(MBB % 0x10000000 == 0, f"MBB is 256 MiB aligned ({MBB>>24} x 16 MiB)")
chk(MBL % 0x04000000 == 0, f"MBL {MBL>>20} MiB is a multiple of 64 MiB")
chk(all(v % 0x04000000 == 0 for v in (MBB, MBL, TOM)),
    "MBB, MBL and TOM are all 64 MiB aligned, so base+len closes cleanly")

print("\n" + ("ALL CHECKS PASSED" if ok else "*** FAILURES PRESENT ***"))
sys.exit(0 if ok else 1)
