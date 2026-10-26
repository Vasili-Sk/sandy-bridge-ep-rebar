#!/usr/bin/env python3
"""X9DRG-QF root-bridge aperture patch (the ECAM half of the fix).

Runs directly on the raw 16 MiB SPI image. No MMTool, no proprietary tool:
the module is located by GUID, Tiano-decompressed in pure Python (a thin
wrapper over the compiled EDK2 codecs shipped by the `uefi-firmware` pip
package), patched, rebuilt, checksummed and repacked into its volume.

    pip install -r requirements.txt        # uefi-firmware>=1.16
    python patch_aperture.py X9DRGQF8.921 -o patched.bin

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
    MMIOH base = MMCFG base + MMCFG size = 0x90000000
    MMIOH len  = 0xFC000000 - that      = 0x6C000000
The ACPI publishing layer publishes the MMCFG base itself instead.  The defect is
purely that the table shown to the OS is 256 MiB too wide at the bottom.

PATCH SITES (measured, Ghidra decompilation + capstone)
------------------------------------------------------
The values are written into the DSDT by **PciRootBridge** (module 009,
80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910, FV01), in the loop at RVA
0x18000225c..0x18000248b that walks the AMI resource-name table in .rdata:

    MALH MALL MAMH MAML MABH MABL MBL MBB IOL IOB BRL BRB STAV LVGA CPRB

Each iteration calls the DynamicPciBase service (RVA 0x180010ba4), which locates
`Name(<name>, DWord)` in the DSDT and overwrites its operand.  The two relevant
instructions, in the PE32 image body of the module:

    4c 8b 8f 68 01 00 00   mov r9, [rdi+0x168]   ; -> "MBB"
    4c 8b 8f 70 01 00 00   mov r9, [rdi+0x170]   ; -> "MBL"

Both are 7 bytes, both are replaced by 7 bytes:

    41 b9 <imm32> 90       mov r9d, imm32 ; nop

`mov r9d, imm32` zero-extends, so r9 == the intended 64-bit value and the callee
writes 4 bytes into the DWord operand, exactly as before.  No length change, no
code cave, no relocation.  Encoding trap: `41 B8` is `mov r8d`, `41 B9` is
`mov r9d`.  The struct itself is untouched -- only the numbers written into the
table the OS reads.

RESULT
------
    MBB 0x80000000 -> 0x90000000   (MMCFG base + MMCFG size)
    MBL 0x7C000000 -> 0x6C000000   (0xFC000000 - 0x90000000)
    published aperture 0x90000000..0xFBFFFFFF  -- ECAM excluded.

These are byte-for-byte the values proven live via the initrd ACPI table
override: `root bus resource [mem 0x90000000-0xfbffffff window]`, ECAM no longer
handed out, amdgpu probes, VRAM 65520M, /dev/kfd present.

HOW THE MODULE IS STORED (measured on X9DRGQF8.921)
--------------------------------------------------
FV01 = 0x460000 + 0x970000, 151 x 64 KiB blocks, HeaderLength 0x48 (the offset of
the first FFS file's Name).  Module 009 is at 0x4A5770, FFS Size 0xB29B:

    hdr(24)  DEPEx(0x4C)  COMPRESSION(0xB237)

The AMI/EDK2 COMPRESSION section (type 0x01) is

    +0   u24 size + u8 type (0x01)
    +4   u32 DestinationSize
    +8   u8  CompressionType (0x01 = Tiano/LZH here)
    +9   u32 CompressedSize
    +13  u32 DestinationSize (repeated)
    +17  bitstream

and the buffer the Tiano decoder consumes starts at +9, i.e. it is
[CompressedSize][DestinationSize][bitstream].  `TianoCompress()` from
`uefi-firmware` returns exactly that same 8-byte-prefixed framing, so a
re-compressed stream drops into the section with no reshaping.

The compressed payload is *the remaining sections of the file* (standard
EFI_COMPRESSION2 semantics), not a bare PE32 image:

    PE32(0x160E4, body 90,336 B, starts "MZ") + USER_INTERFACE(0x20)  = 90,372 B

so the file is hdr + DEPEx + COMPRESSION(PE32 + UI), and
hdr + DEPEx + <those two sections uncompressed> is byte-for-byte what MMTool's
`/e` extract of the same module contains (90,472 B).  `--reference-extract`
checks that identity and aborts if it does not hold.

REBUILD
-------
default (uncompressed): hdr + DEPEx + PE32 + UI, no compression section
                       -> module grows to 90,472 B (0x16168); FV01 shifts by
                          44,744 B (FV01 keeps 803,128 B free afterwards).
                       This is byte-for-byte the shape MMTool's `/r` produces and
                       stock already ships an uncompressed module in FV01, so it is
                       the shape to flash.  With --from-extract it needs no codec.
--recompress:          hdr + DEPEx + COMPRESSION(TianoCompress(payload))
                       -> the stream grows 45,606 -> 45,628 B, the module
                          0xB29B -> 0xB2AE (+19), FV01 shifts by 16 B. Smaller,
                       but the board decompresses an EDK2-encoded stream.

Both forms keep Attributes (0x40 = FFS_ATTRIB_CHECKSUM) and State, rewrite the
24-bit Size, and recompute the two live FFS checksums (AGENTS.md "FFS
checksums"):

    header: sum(GUID..State) with Header, File and State zeroed, + Header == 0
    file  : sum(data[0x18:Size]) + File == 0     (attribute 0x40 is set)

Then the volume is repacked in place: every following FFS file moves by the
8-aligned size delta (so all files stay 8-byte aligned), FV01's trailing 0xFF
free space shrinks by the same amount, and the image stays exactly 16 MiB.  The
FV header is untouched -- Supermicro ships its `Checksum` field stale on all
three volumes and the board boots with it broken, so it is informational only.

WHY NOT THE OTHER CANDIDATE SITES
---------------------------------
* The DSDT template's `Name(MBB_, 0x00010000)` (module 010 AmiBoardInfo):
  overwritten at runtime by the loop above.  Editing it is a no-op -- that is why
  the template ships 0x10000 and the live table reads 0x80000000.
* Adding a PNP0C02 reservation for 0x80000000-0x8FFFFFFF: cannot work.  It is
  inserted as a sibling of the root-bus window in iomem_resource, and
  allocate_resource() on the window only avoids children of the window.  This is
  exactly why the upstream kernel workaround keys off the e820 map, not PNP0C02.
* Moving MMCFG base: the published aperture always starts at the ECAM base, so
  the collision moves with it.  0xE0000000 is additionally rejected by MRC's own
  validator, and any change trips the guard at 0xffe2d84e
  ("PCIEXBASE ADDRESS IS CHANGED. SYSTEM WILL DO A RESET !!!!") -> cold-reset loop.

MMTOOL FALLBACK (documented, not required)
-----------------------------------------
If you would rather let AMI's own tool do the repack:

    MMTOOL <rom> /e  80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910 prb.bin
    python patch_aperture.py <rom> --from-extract prb.bin --store-uncompressed \
                             --no-write --module-out prb.patched.bin
    MMTOOL <rom> /r  80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910 prb.patched.bin

`tools/mmtool_run.py` drives MMTool 4.50's console UI; export
`MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'` in Git-Bash or `/e` and `/r` get
rewritten into Windows paths.  MMTool *validates* the file-data checksum of a
module you hand it and refuses a one-byte-modified file ("Invalid FFS File");
this script closes both checksums, so its output is accepted by `/r`.
"""
import argparse
import os
import re
import struct
import sys
import uuid

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

GUID = "80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910"          # PciRootBridge, FV01
SITE = [
    # (pattern, replacement, name, new value)
    # 41 B9 /id=1 imm32 == mov r9d, imm32 (zero-extends into r9); 90 == nop
    (bytes.fromhex("4c8b8f68010000"), bytes.fromhex("41b90000009090"), "MBB", 0x90000000),
    (bytes.fromhex("4c8b8f70010000"), bytes.fromhex("41b90000006c90"), "MBL", 0x6C000000),
]
MMCFG_BASE, MMCFG_SIZE, TOM = 0x80000000, 0x10000000, 0xFC000000

FFS_HEADER_SIZE = 0x18
FFS_ATTRIB_CHECKSUM = 0x40
FFS_ATTRIB_LARGE_FILE = 0x01
SECTION_ALL = 0x01          # EFI_SECTION_COMPRESSION / all-in-one (AMI uses 0x01)
SECTION_PE32 = 0x10
SECTION_USER_INTERFACE = 0x15
SECTION_DEPEX = 0x13
TIANO = 0x01
ALIGN = 8


def die(msg):
    sys.exit("ABORT: " + msg)


# ------------------------------------------------------------------ codec
def load_codec():
    """The compiled EDK2 codecs from the `uefi-firmware` pip package."""
    try:
        from uefi_firmware import efi_compressor as ec
    except ImportError:
        die("no Tiano/LZH codec available.\n"
            "       pip install 'uefi-firmware>=1.16'   (provides efi_compressor)\n"
            "       No codec is needed for the MMTool route: pass\n"
            "       --from-extract <MMTool /e extract> --store-uncompressed.")
    for fn in ("TianoCompress", "TianoDecompress"):
        if not hasattr(ec, fn):
            die("uefi-firmware codec lacks %s" % fn)
    return ec


def tiano_decompress(ec, buf):
    return ec.TianoDecompress(buf, len(buf) + (1 << 22))


def tiano_compress(ec, payload):
    return ec.TianoCompress(payload, len(payload))


# ------------------------------------------------------------- FFS walking
def find_fvs(d):
    """(base, length, header_len) for every FFS volume in the image."""
    ffs2 = uuid.UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3").bytes_le  # EFI_FIRMWARE_FILE_SYSTEM2
    for i in range(0, len(d) - 0x48, 0x10):
        if d[i + 0x10:i + 0x20] == ffs2 and d[i + 0x28:i + 0x2c] == b"_FVH":
            ln = struct.unpack_from("<Q", d, i + 0x20)[0]
            hl = struct.unpack_from("<H", d, i + 0x30)[0]
            if 0x1000 <= ln <= len(d) - i and 0x20 <= hl <= 0x1000:
                yield i, ln, hl


def walk_fv(d, base, ln, hl):
    """Yield (guid_offset, guid, size) for every FFS file in a volume."""
    p = base + hl
    while p + FFS_HEADER_SIZE <= base + ln:
        if d[p] == 0xFF:
            return
        size = int.from_bytes(d[p + 0x14:p + 0x17], "little")
        if not 0x18 <= size <= base + ln - p:
            return
        yield p, uuid.UUID(bytes_le=bytes(d[p:p + 16])), size
        p = (p + size + (ALIGN - 1)) & ~(ALIGN - 1)


def fv_blocks(d, base, ln, hl):
    """[(NumberOfBlocks, BlockSize)] from the volume's block map.

    The map is the last 16 bytes of the 0x48-byte header (2 descriptors,
    zero-terminated).  Returns [] if it does not describe the volume exactly
    with power-of-two blocks -- the caller refuses that layout.
    """
    out, p = [], base + hl - 0x10
    while p + 8 <= base + hl:
        nb, bs = struct.unpack_from("<II", d, p)
        if nb == 0 and bs == 0:
            break
        if bs == 0 or bs & (bs - 1):
            return []
        out.append((nb, bs))
        p += 8
    if not out or sum(nb * bs for nb, bs in out) != ln:
        return []
    return out


def ffs_checksums(d, g, size):
    """(header_ok, file_ok) for the FFS file whose Name (GUID) is at `g`."""
    h = bytearray(d[g:g + 0x18])
    h[0x10] = h[0x11] = h[0x17] = 0
    hdr = (sum(h) + d[g + 0x10]) & 0xFF == 0
    if d[g + 0x13] & FFS_ATTRIB_CHECKSUM:
        fil = (sum(d[g + 0x18:g + size]) + d[g + 0x11]) & 0xFF == 0
    else:
        fil = d[g + 0x11] == 0xAA
    return hdr, fil


def scan_image(d):
    """Per-volume: (base, ln, blocks_ok, files, header_ok, file_ok)."""
    out = []
    for base, ln, hl in find_fvs(d):
        files = list(walk_fv(d, base, ln, hl))
        res = [ffs_checksums(d, g, s) for g, _, s in files]
        out.append((base, ln, bool(fv_blocks(d, base, ln, hl)), files,
                    sum(x for x, _ in res), sum(y for _, y in res)))
    return out


# --------------------------------------------------------- module structure
def sec_pack(stype, body):
    """A section: u24 size (incl. this 4-byte header) + u8 type + body."""
    total = len(body) + 4
    if total > 0xFFFFFF:
        die("section too big: %d" % total)
    return total.to_bytes(3, "little") + bytes([stype]) + body


def sec_parse(blob, what):
    """Split a section stream into whole sections (headers included)."""
    out, p = [], 0
    while p < len(blob):
        size = int.from_bytes(blob[p:p + 3], "little")
        stype = blob[p + 3]
        if size < 4 or p + size > len(blob):
            die("%s: bad section at +%#x (size %#x, stream %#x)" % (what, p, size, len(blob)))
        out.append((stype, blob[p:p + size]))
        p = (p + size + 3) & ~3
    return out


def comp_unpack(sec):
    """COMPRESSION section -> (ctype, dest_size, decoder_buffer)."""
    body = sec[4:]
    dest = struct.unpack_from("<I", body, 0)[0]
    ctype = body[4]
    buf = body[5:]
    if ctype != TIANO:
        die("compression type %#02x unsupported (only 0x01 Tiano/LZH)" % ctype)
    csize = struct.unpack_from("<I", buf, 0)[0]
    if len(buf) != csize + 8:
        die("COMPRESSION section framing: %d bytes after the header, "
            "CompressedSize says %d + 8" % (len(buf), csize))
    return ctype, dest, buf


def comp_pack(ctype, dest_size, buf):
    """COMPRESSION section around `buf`, the decoder buffer (CompressedSize,
    DestinationSize and bitstream as the Tiano decoder expects them)."""
    body = struct.pack("<IB", dest_size, ctype) + buf
    return sec_pack(SECTION_ALL, body)


class Module(object):
    """An FFS module split into the parts this patcher needs.

    head     the leading sections kept verbatim (DEPEx)
    pe32     the PE32 section body (the image the CPU executes)
    tail     the sections that follow the PE32 image (USER_INTERFACE)
    ctype    not None when the module carries a COMPRESSION section; the PE32
             and tail sections then live *inside* that section and only appear
             after decode().
    """

    def __init__(self, raw, what="module"):
        self.raw = bytes(raw)
        hdr, body = self.raw[:FFS_HEADER_SIZE], self.raw[FFS_HEADER_SIZE:]
        self.guid = uuid.UUID(bytes_le=bytes(hdr[0:16]))
        self.state = hdr[0x17]
        self.ftype, self.attr = hdr[0x12], hdr[0x13]
        if self.attr & FFS_ATTRIB_LARGE_FILE:
            die("FFS_ATTRIB_LARGE_FILE: extended FFS header unsupported")
        self.head, self.tail, self.pe32 = [], [], None
        self.ctype, self.dest, self.comp_buf = None, None, None
        for stype, sec in sec_parse(body, "%s %s" % (what, self.guid)):
            if stype == SECTION_ALL:
                self.ctype, self.dest, self.comp_buf = comp_unpack(sec)
            elif stype == SECTION_PE32:
                self.pe32 = sec[4:]
            elif stype == SECTION_DEPEX:
                self.head.append(sec)
            else:
                self.tail.append(sec)
        if not self.head:
            die("module %s has no DEPEx section" % self.guid)

    def decode(self, ec):
        """Expand the COMPRESSION section into pe32 + tail sections."""
        if self.pe32 is not None:
            return
        if self.ctype is None:
            die("module %s has no PE32 section and nothing compressed" % self.guid)
        if ec is None:
            die("module %s is compressed and no codec is loaded" % self.guid)
        payload = tiano_decompress(ec, self.comp_buf)
        if len(payload) != self.dest:
            die("COMPRESSION section declares DestinationSize %d, decodes to %d"
                % (self.dest, len(payload)))
        for stype, sec in sec_parse(payload, "compressed payload of %s" % self.guid):
            if stype == SECTION_PE32:
                if self.pe32 is not None:
                    die("more than one PE32 section in %s" % self.guid)
                self.pe32 = sec[4:]
            elif stype == SECTION_DEPEX:
                self.head.append(sec)
            else:
                self.tail.append(sec)
        if self.pe32 is None:
            die("module %s has no PE32 section, compressed or otherwise" % self.guid)
        if self.pe32[:2] != b"MZ":
            die("PE32 section body does not start with 'MZ'")

    def describe(self):
        s = "hdr(24) + " + " + ".join("%s(0x%x)" % (_sec_name(x[3]), len(x))
                                      for x in self.head)
        if self.ctype is not None:
            s += " + COMPRESSION(0x%x)" % (len(self.comp_buf) + 9)
        if self.pe32 is not None:
            s += " -> PE32(0x%x, body 0x%x)" % (len(self.pe32) + 4, len(self.pe32))
        s += "".join(" + %s(0x%x)" % (_sec_name(x[3]), len(x)) for x in self.tail)
        return s

    # -- payload = the sections that live inside the compression section ---
    @property
    def payload(self):
        """The byte stream the COMPRESSION section wraps: PE32 + trailing sections."""
        return sec_pack(SECTION_PE32, self.pe32) + b"".join(self.tail)

    def build(self, recompress=True, ec=None):
        """Rebuild the module file (header included), checksums closed."""
        secs = list(self.head)
        if recompress:
            if ec is None:
                die("recompression needs the codec")
            buf = tiano_compress(ec, self.payload)
            if tiano_decompress(ec, buf) != self.payload:
                die("codec round-trip failed: the rebuilt stream does not "
                    "decompress to the payload it was made from")
            secs.append(comp_pack(TIANO, len(self.payload), buf))
        else:
            secs.append(sec_pack(SECTION_PE32, self.pe32))
            secs.extend(self.tail)
        body = b"".join(secs)
        size = FFS_HEADER_SIZE + len(body)
        if size > 0xFFFFFF:
            die("rebuilt module is %d bytes, does not fit a 24-bit FFS Size" % size)
        hdr = (self.guid.bytes_le + bytes([0, 0, self.ftype, self.attr])
               + size.to_bytes(3, "little") + bytes([self.state]))
        return fix_checksums(bytearray(hdr + body))


_SECTION_NAMES = {SECTION_ALL: "COMPRESSION", SECTION_PE32: "PE32",
                  SECTION_USER_INTERFACE: "USER_INTERFACE",
                  SECTION_DEPEX: "DEPEx"}


def _sec_name(t):
    return _SECTION_NAMES.get(t, "SECTION_%02x" % t)


def fix_checksums(m):
    """Close both live FFS checksums of a ZeroVector-stripped FFS file."""
    size = int.from_bytes(m[0x14:0x17], "little")
    if size != len(m):
        die("rebuilt module Size field (%d) != length (%d)" % (size, len(m)))
    if m[0x13] & FFS_ATTRIB_CHECKSUM:
        m[0x11] = (-sum(m[0x18:size])) & 0xFF
    else:
        m[0x11] = 0xAA
    h = bytearray(m[:0x18])
    h[0x10] = h[0x11] = h[0x17] = 0
    m[0x10] = (-sum(h)) & 0xFF
    h = bytearray(m[:0x18])
    h[0x10] = h[0x11] = h[0x17] = 0
    if (sum(h) + m[0x10]) & 0xFF:
        die("header checksum does not close")
    if (sum(m[0x18:size]) + m[0x11]) & 0xFF:
        die("file-data checksum does not close")
    return bytes(m)


# -------------------------------------------------------------- the patch
def apply_sites(mod):
    """Patch the PE32 body in place; return [(name, off, pat, rep, val)]."""
    done = []
    for pat, rep, nm, val in SITE:
        if len(pat) != len(rep):
            die("patch %s is not size-preserving" % nm)
        n = mod.pe32.count(pat)
        if n != 1:
            die("'%s' pattern %s occurs %d time(s) in the PE32 body of module "
                "%s, expected exactly 1" % (nm, pat.hex(), n, mod.guid))
        o = mod.pe32.find(pat)
        mod.pe32 = mod.pe32[:o] + rep + mod.pe32[o + len(rep):]
        done.append((nm, o, pat, rep, val))
    return done


# ------------------------------------------------------------- repacking
def repack(d, fv, off, old_size, built):
    """Put `built` where the module was; shift the rest of its volume.

    Files are 8-byte aligned, so only a delta that is a multiple of 8 keeps the
    volume legal: the shift is measured between the *aligned* footprints, and
    the volume's trailing 0xFF free space gives up exactly that many bytes.
    """
    base, ln, hl = fv
    old_aligned = (old_size + (ALIGN - 1)) & ~(ALIGN - 1)
    new_aligned = (len(built) + (ALIGN - 1)) & ~(ALIGN - 1)
    delta = new_aligned - old_aligned
    fv_end = base + ln
    rest = d[off + old_aligned:fv_end]          # the following files
    free = d[off + old_size:off + old_aligned]   # its own trailing pad
    if delta > 0 and len(rest) < delta:
        die("volume %s has no room: %d bytes after this file, need %d"
            % (hex(base), len(rest), delta))
    if delta > 0 and set(rest[len(rest) - delta:]) != {0xFF}:
        die("the %d bytes the volume would give up are not 0xFF free space" % delta)
    if delta < 0 and set(free) - {0xFF}:
        die("the file's own alignment padding is not 0xFF")
    keep = rest[:len(rest) - delta] if delta > 0 else rest
    region = (built + b"\xff" * (new_aligned - len(built)) + keep
              + b"\xff" * max(-delta, 0))
    out = bytearray(d[:off] + region + d[fv_end:])
    if len(out) != len(d):
        die("repack changed the image length: %d -> %d" % (len(d), len(out)))
    return out, delta, len(rest) + len(free)


def runs_of(diffs):
    out, i = [], 0
    while i < len(diffs):
        j = i
        while j + 1 < len(diffs) and diffs[j + 1] == diffs[j] + 1:
            j += 1
        out.append((diffs[i], j - i + 1))
        i = j + 1
    return out


# ------------------------------------------------------------------- main
_FIRMWARE_EXT = re.compile(r"\.(bin|rom|cap|img|fd)$", re.I)


def stem(path):
    r"""Basename with a *firmware* extension removed.  `X9DRGQF8.921` carries its
    version in the trailing `.921`, which a generic `\.[^.]+$` strip would eat."""
    return _FIRMWARE_EXT.sub("", os.path.basename(path))


def main():
    ap = argparse.ArgumentParser(
        description="Shrink the published root-bridge 32-bit MMIO aperture so it no "
                    "longer contains ECAM. Operates on the raw SPI image; the module "
                    "is Tiano-decompressed, patched, recompressed and repacked here.",
        epilog="example:  python patch_aperture.py X9DRGQF8.921 -o patched.bin",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="raw 16 MiB SPI image (e.g. X9DRGQF8.921)")
    ap.add_argument("-o", "--out", help="default: <image>.aperture.bin")
    ap.add_argument("--module-out", metavar="FILE",
                    help="also write the rebuilt module (this image's shape) there")
    ap.add_argument("--guid", default=GUID, help="module GUID (default PciRootBridge)")
    ap.add_argument("--recompress", action="store_true",
                    help="re-compress the patched module with Tiano instead of storing "
                         "it uncompressed. Moves ~16 bytes of FV01 instead of ~45 KB "
                         "and needs no free-space headroom, but the firmware then "
                         "decompresses a stream written by EDK2's encoder rather than "
                         "AMI's. OFF by default: the uncompressed shape is what MMTool's "
                         "/r produces and stock module 022 (BdsS3Logo) proves this volume "
                         "stores raw, so it is the shape to flash.")
    ap.add_argument("--store-uncompressed", action="store_true",
                    help=argparse.SUPPRESS)   # now the default; accepted as a no-op
    ap.add_argument("--from-extract", metavar="FILE",
                    help="take the module payload from an MMTool `/e` extract "
                         "instead of decompressing the image (needs no codec)")
    ap.add_argument("--reference-extract", metavar="FILE",
                    help="gate: the pure-Python rebuild of the UNPATCHED module in "
                         "the uncompressed shape must equal this MMTool `/e` extract "
                         "byte for byte")
    ap.add_argument("--no-write", action="store_true",
                    help="do everything except write the image")
    a = ap.parse_args()

    # The uncompressed shape is the default: it is byte-for-byte what MMTool's /r
    # writes, it is the shape the `--reference-extract` gate is defined against, and
    # stock already ships an uncompressed module in FV01 (022 BdsS3Logo), so the
    # firmware is known to accept it. Recompressing is smaller but hands the board's
    # decompressor a stream from a different encoder than the one that built the ROM.
    recompress = bool(a.recompress)
    if a.store_uncompressed and recompress:
        die("--store-uncompressed and --recompress contradict each other")

    if not os.path.isfile(a.image):
        die("no such file: %s\n"
            "       Pass the raw SPI image from Supermicro (e.g. X9DRGQF8.921), "
            "unpacked from the .zip." % a.image)
    if os.path.getsize(a.image) < 8 << 20:
        die("%s is %d bytes: not a SPI image" % (a.image, os.path.getsize(a.image)))
    guid = uuid.UUID(a.guid)
    img = bytearray(open(a.image, "rb").read())
    stock = bytes(img)

    assert MMCFG_BASE + MMCFG_SIZE == 0x90000000
    assert TOM - (MMCFG_BASE + MMCFG_SIZE) == 0x6C000000

    # ---- locate the module ------------------------------------------------
    fvs = list(find_fvs(img))
    if not fvs:
        die("no firmware volumes found in %s: not an FFS SPI image" % a.image)
    where = None
    for base, ln, hl in fvs:
        for g, gg, size in walk_fv(img, base, ln, hl):
            if gg == guid:
                where = (base, ln, hl, g, size)
                break
        if where:
            break
    if not where:
        die("FFS file %s not found in any volume of %s.\n"
            "       This patcher is specific to Supermicro X9 (C602, Aptio IV) "
            "images. Do not run it on other vendors' firmware."
            % (guid, a.image))
    base, ln, hl, off, size = where
    fv = (base, ln, hl)
    blocks = fv_blocks(img, base, ln, hl)
    if not blocks:
        die("volume %s (len %#x) has no power-of-two block map that sums to its "
            "FvLength: refusing to repack" % (hex(base), ln))
    if off & (ALIGN - 1):
        die("module %s is at %#x, not %d-byte aligned" % (guid, off, ALIGN))
    print("%s  FFS file %s @0x%07x  size 0x%x  (FV @0x%07x len %#x, %d x %d KiB)"
          % (os.path.basename(a.image), guid, off, size, base, ln,
             blocks[0][0], blocks[0][1] // 1024))
    hdr, fil = ffs_checksums(img, off, size)
    print("  stock FFS checksums: header %s (%02x)  file %s (%02x)  attrs %02x  state %02x"
          % ("closes" if hdr else "BROKEN", img[off + 0x10],
             "closes" if fil else "BROKEN", img[off + 0x11], img[off + 0x13], img[off + 0x17]))
    if not (hdr and fil):
        die("the stock module's FFS checksums do not close; the volume is not in "
            "the state this patcher expects")

    mod = Module(img[off:off + size], "module")

    # ---- optional: take the payload from MMTool's own extract -------------
    if a.from_extract:
        ext = Module(open(a.from_extract, "rb").read(), "extract")
        if ext.guid != guid:
            die("--from-extract file is module %s, expected %s" % (ext.guid, guid))
        if ext.ctype is not None:
            die("--from-extract file is still compressed; pass MMTool's `/e` "
                "extract (which is uncompressed), not `/ec`")
        if ext.pe32 is None or ext.pe32[:2] != b"MZ":
            die("--from-extract file has no PE32 image in it")
        mod.pe32, mod.tail, mod.head = ext.pe32, ext.tail, ext.head
        mod.ctype = None
        print("  payload taken from %s (%d B PE32 body, no codec used)"
              % (os.path.basename(a.from_extract), len(mod.pe32)))

    # ---- decode the module (needs the codec unless the payload came from /e)
    ec = None
    if mod.ctype is not None:
        ec = load_codec()
        mod.decode(ec)
        print("  Tiano: %d B decoder buffer -> %d B payload, DestinationSize "
              "matches  OK" % (len(mod.comp_buf), len(mod.payload)))
    print("  sections: %s" % mod.describe())
    if mod.ctype is None and not a.from_extract:
        print("  note: the module is stored UNCOMPRESSED in this image")

    # ---- gate: our (de)composition must equal MMTool's extract ------------
    if a.reference_extract:
        ref = open(a.reference_extract, "rb").read()
        plain = mod.build(recompress=False)
        if plain != ref:
            n = sum(1 for x, y in zip(plain, ref) if x != y)
            die("pure-Python rebuild of the UNPATCHED module does not match %s "
                "(len %d vs %d, %d bytes differ, first at %#x)"
                % (a.reference_extract, len(plain), len(ref), n,
                   next((i for i in range(min(len(plain), len(ref)))
                         if plain[i] != ref[i]), -1)))
        print("  gate: unpatched rebuild == MMTool extract %s, byte for byte (%d B)"
              % (os.path.basename(a.reference_extract), len(ref)))

    if recompress and ec is None:
        ec = load_codec()

    # ---- patch ------------------------------------------------------------
    print()
    pe32_base = 0x18 + sum(len(s) for s in mod.head) + 4
    for nm, o, pat, rep, val in apply_sites(mod):
        print("%s: PE32 body +0x%04x (module +0x%04x)  %s -> %s   "
              "mov r9,[rdi+%#x]  ==>  mov r9d,%#x ; nop"
              % (nm, o, pe32_base + o, pat.hex(), rep.hex(),
                 int.from_bytes(pat[3:7], "little"), val))

    # ---- rebuild ----------------------------------------------------------
    built = mod.build(recompress=recompress, ec=ec)
    chk = Module(built, "rebuilt module")
    chk.decode(ec)
    if chk.pe32 != mod.pe32:
        die("self-check: the rebuilt module does not decode back to the patched "
            "PE32 body")
    if not recompress and chk.ctype is not None:
        die("self-check: the uncompressed output still has a COMPRESSION "
            "section")
    print("\nmodule rebuilt: 0x%x -> 0x%x bytes (%+d), %s"
          % (size, len(built), len(built) - size,
             "Tiano-recompressed" if recompress
             else "uncompressed (MMTool /r shape)"))
    print("  FFS header chksum %02x -> %02x   file chksum %02x -> %02x   "
          "attrs %02x preserved, state %02x preserved"
          % (img[off + 0x10], built[0x10], img[off + 0x11], built[0x11],
             built[0x13], built[0x17]))
    if a.module_out:
        open(a.module_out, "wb").write(built)
        print("  wrote %s (%d bytes)" % (a.module_out, len(built)))
    if a.no_write:
        print("\n--no-write: image not written")
        return 0

    # ---- repack the volume ------------------------------------------------
    out, delta, tail_len = repack(img, fv, off, size, built)
    dst = a.out or (stem(a.image) + ".aperture.bin")
    open(dst, "wb").write(bytes(out))

    # ---- verify what we just wrote, from the bytes ------------------------
    print("\n=== verify %s ===" % dst)
    fin = open(dst, "rb").read()
    bad = []

    def rep(cond, msg):
        if not cond:
            bad.append(msg)
        print("  [%s] %s" % ("PASS" if cond else "FAIL", msg))

    rep(len(fin) == len(stock), "image length unchanged (%d bytes)" % len(fin))
    for lo, hi, nm in [(0, base, "before the volume (descriptor/ME/NCB)"),
                       (base + ln, len(fin), "after the volume (NCB/FV02/boot block)")]:
        rep(fin[lo:hi] == stock[lo:hi],
            "%s %#x..%#x byte-identical to stock" % (nm, lo, hi))
    va, vb = scan_image(stock), scan_image(fin)
    fa = {h: f for h, l, b, f, x, y in va}
    fb = {h: f for h, l, b, f, x, y in vb}
    rep(len(va) == len(vb) == len(fvs), "%d firmware volumes" % len(vb))
    for (h, l, bk_a, la, ha, fa_ok), (h2, l2, bk_b, lb, hb, fb_ok) in zip(va, vb):
        rep((h, l) == (h2, l2) and bk_a and bk_b,
            "FV @ %#x len %#x: geometry intact, block map sums to FvLength"
            % (h2, l2))
        rep((len(la), ha, fa_ok) == (len(lb), hb, fb_ok),
            f"FV @ {h2:#x}: {len(lb)} FFS files; header checksums {hb}/{len(lb)} "
            f"close, file checksums {fb_ok}/{len(lb)} close  "
            f"(stock: {len(la)} files, header {ha}/{len(la)}, file {fa_ok}/{len(la)})")
    g2 = fin.find(guid.bytes_le)
    rep(g2 >= 0, "module %s found at %#x" % (guid, g2))
    if g2 >= 0:
        s2 = int.from_bytes(fin[g2 + 0x14:g2 + 0x17], "little")
        m2 = Module(fin[g2:g2 + s2], "module in the written image")
        m2.decode(ec)
        rep(m2.pe32 == mod.pe32, "module decodes back to the patched PE32 body")
        before = [g for g, _, _ in fa[base] if g > off]
        after = [g for g, _, _ in fb[base] if g > g2]
        rep(len(before) == len(after)
            and all(y - x == delta for x, y in zip(before, after)),
            "%d FFS files after the module in FV %#x shifted by %+d "
            "(a multiple of %d: every file stays %d-byte aligned)"
            % (len(after), base, delta, ALIGN, ALIGN))
        for pat, rep_b, nm, val in SITE:
            rep(m2.pe32.count(rep_b) == 1 and m2.pe32.count(pat) == 0,
                "%s: 'mov r9d,%#x; nop' present once in the module, the original "
                "load is gone" % (nm, val))
    d0 = [i for i in range(len(stock)) if stock[i] != fin[i]]
    rr = runs_of(d0)
    rep(all(base <= s and s + n <= base + ln for s, n in rr),
        "all %d changed bytes are inside FV %#x..%#x (%d run(s): %s)"
        % (len(d0), base, base + ln, len(rr),
           ", ".join("%#x+%d" % (s, n) for s, n in rr[:6])))
    print("\n%-22s %s" % ("module", "%s @0x%07x" % (guid, off)))
    print("%-22s 0x%x -> 0x%x bytes (%+d), %s"
          % ("module size", size, len(built), len(built) - size,
             "Tiano-recompressed" if recompress else "stored uncompressed"))
    print("%-22s %d bytes (%s)" % ("bytes changed", len(d0),
                                   ", ".join("%#x+%d" % (s, n) for s, n in rr[:6])))
    zone = stock[off:base + ln]
    free0 = len(zone) - len(zone.rstrip(b"\xff"))
    print("%-22s volume %#x: %d of %d free bytes given up, %d left"
          % ("repack", base, max(delta, 0), free0, free0 - max(delta, 0)))
    print("%-22s MBB %#010x  MBL %#010x" % ("aperture published",
                                            MMCFG_BASE + MMCFG_SIZE, TOM - MMCFG_BASE - MMCFG_SIZE))
    print("%-22s %#010x .. %#010x  (ECAM %#010x-%#010x excluded)"
          % ("window", MMCFG_BASE + MMCFG_SIZE, TOM - 1, MMCFG_BASE,
             MMCFG_BASE + MMCFG_SIZE - 1))
    print("%-22s header %02x, file %02x (both recomputed, both close)"
          % ("FFS checksums", built[0x10], built[0x11]))
    print("wrote %s (%d bytes)" % (dst, len(fin)))
    print("\n" + ("*** FAILURES PRESENT ***" if bad else "ALL CHECKS PASSED"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
