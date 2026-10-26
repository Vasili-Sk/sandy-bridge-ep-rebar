#!/usr/bin/env python3
"""Replace the POST logo of a Supermicro X9 image, in one command.

    python patch_logo.py X9DRGQF8.921

writes `X9DRGQF8.921.logo.bin`.  With no picture argument it re-embeds the
repo's own `logo/logo.dat`; pass a BMP to use that instead:

    python patch_logo.py X9DRGQF8.921 mypicture.bmp

`logo/logo.dat` is the **compressed logo payload**: the exact byte stream that
goes into the logo FFS file's compression section, in EDK2's
`[CompressedSize][DestinationSize][bitstream]` form.  Produce one from any
suitable BMP with:

    python patch_logo.py X9DRGQF8.921 mypicture.bmp --logo-out logo/logo.dat

THE LAYOUT (measured on X9DRGQF8.921, not assumed)
-------------------------------------------------
One FFS file, in FV01:

    GUID 7BB28B99-61BB-11D5-9A5D-0090273FC14D   type 0x02 FREEFORM
    at 0x61fd68, Size 3,720, Attributes 0x40, State 0xF8
      section EFI_SECTION_COMPRESSION (0x01), 3,696 B
        u32 DestinationSize = 308,284
        u8  CompressionType = 0x01  (Tiano/LZH)
        u32 CompressedSize  = 3,679
        u32 DestinationSize = 308,284   (repeated)
        bitstream
      decompresses to  3A B4 04 19 | BMP | 00 00
                       ^ AMI PIC header (u24 length 308,282, type 0x19)
                       BMP: 640x480, 8 bpp indexed, BI_RGB, bfOffBits 1078
                            (256-entry palette), stride 640, bottom-up

The AMI PIC header must be kept and `biClrUsed` must be 0: AMI's loader sizes
the palette from that field.  A photographic BMP is far less compressible than
the stock near-black one (308,284 -> 3,679 B, ~84:1), so the size of the
repacked volume depends on the picture; FV01 has ~7.2 MiB of free space.

The image is opened read-only and never modified.  Everything is matched by byte
pattern with an occurrence-count assert, both live FFS checksums are recomputed,
and the result is re-read and re-checked before it is reported as good.

Requires: Python 3.10+ and `pip install -r requirements.txt` (uefi-firmware).
"""

import argparse
import os
import re
import struct
import sys
import uuid

GUID = "7BB28B99-61BB-11D5-9A5D-0090273FC14D"
AMI_HEADER = bytes.fromhex("3ab40419")
PAD = b"\x00\x00"
FFS_HDR = 24
SEC_COMPRESSION = 0x01
TIANO = 0x01


def die(msg):
    sys.exit("ABORT: " + msg + "\n")


def load_codec():
    try:
        from uefi_firmware import efi_compressor as ec
    except ImportError:
        die("the logo lives in a Tiano-compressed FFS file, so this needs the EDK2\n"
            "       codecs:   pip install 'uefi-firmware>=1.16'")
    return ec


def find_fvs(d):
    ffs2 = uuid.UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3").bytes_le
    for i in range(0, len(d) - 0x48, 0x10):
        if d[i + 0x10:i + 0x20] == ffs2 and d[i + 0x28:i + 0x2c] == b"_FVH":
            ln = struct.unpack_from("<Q", d, i + 0x20)[0]
            hl = struct.unpack_from("<H", d, i + 0x30)[0]
            if 0x1000 <= ln <= len(d) - i and 0x20 <= hl <= 0x1000:
                yield i, ln, hl


def walk_fv(d, base, ln, hl):
    p = base + hl
    while p < base + ln:
        size = int.from_bytes(d[p + 20:p + 23], "little")
        if size == 0:
            return
        yield p, uuid.UUID(bytes_le=d[p:p + 16]), size, d[p + 18]
        p += (size + 7) & ~7


def fix_checksums(m):
    """Close both live FFS checksums (PI Vol.3 FFS_FILE_HEADER)."""
    m = bytearray(m)
    size = int.from_bytes(m[0x14:0x17], "little")
    if size != len(m):
        die("module Size field (%d) != length (%d)" % (size, len(m)))
    if m[0x13] & 0x40:
        m[0x11] = (-sum(m[0x18:size])) & 0xFF
    else:
        m[0x11] = 0xAA
    h = bytearray(m[:0x18])
    h[0x10] = h[0x11] = h[0x17] = 0
    m[0x10] = (-sum(h)) & 0xFF
    return bytes(m)


def check_bmp(b, label):
    """Validate a BMP against the geometry the AMI loader expects."""
    if len(b) < 54 or b[:2] != b"BM":
        die("%s is not a BMP" % label)
    off = struct.unpack_from("<I", b, 10)[0]
    hdr = struct.unpack_from("<I", b, 14)[0]
    w, h = struct.unpack_from("<ii", b, 18)
    bpp = struct.unpack_from("<H", b, 28)[0]
    comp = struct.unpack_from("<I", b, 30)[0]
    used = struct.unpack_from("<I", b, 32)[0]
    if hdr != 40:
        die("%s: BITMAPINFOHEADER size %d, expected 40" % (label, hdr))
    if bpp != 8:
        die("%s: %d bpp, expected 8-bit indexed (AMI's logo plane)" % (label, bpp))
    if comp != 0:
        die("%s: compression %d, expected BI_RGB (0)" % (label, comp))
    if (w, h) != (640, 480):
        die("%s: %dx%d, expected 640x480 (the panel mode this BIOS drives)" % (label, w, h))
    if h < 0:
        die("%s: top-down BMP, AMI's logo is bottom-up" % label)
    stride = (w * bpp + 31) // 32 * 4
    need = off + stride * h
    # 8 bpp with a full 1024-byte palette: biClrUsed is meaningless here, and
    # AMI's own template ships it as junk (the stock logo carries 0xB0000000).
    # Size the palette from bfOffBits and normalise the field to 0 on write.
    # Refusing junk values would make the tool unable to re-embed its own
    # --extract output, which is the round-trip that validates the codec.
    used = 256
    if off < 54 + used * 4:
        die("%s: pixel data at %d leaves no room for a %d-entry palette" % (label, off, used))
    if len(b) < need:
        die("%s: %d bytes, need %d for the pixel array" % (label, len(b), need))
    if used == 256 and len(b) - off != stride * h:
        die("%s: trailing bytes after the pixel array; strip them and re-save" % label)
    return w, h, bpp, len(b)


def payload_from_bmp(b):
    """AMI PIC payload = AMI header + BMP + 2 pad bytes.

    The header is u24 length + u8 type 0x19, and the length covers the header
    itself plus the BMP: 4 + 308,278 = 308,282 for the stock logo.
    """
    return (4 + len(b)).to_bytes(3, "little") + bytes([AMI_HEADER[3]]) + b + PAD


def payload_bmp(p):
    """Locate the BMP inside an AMI payload and return its extent."""
    if p[:3] != AMI_HEADER[:3]:
        die("payload does not start with the AMI PIC header %s" % AMI_HEADER[:3].hex())
    i = p.find(b"BM")
    if i < 0:
        die("no BMP signature inside the payload")
    off = struct.unpack_from("<I", p, i + 10)[0]
    w, h = struct.unpack_from("<ii", p, i + 18)
    stride = (w * 8 + 31) // 32 * 4
    end = i + off + stride * abs(h)
    if end > len(p):
        die("BMP pixel array runs past the payload")
    return i, end


_FIRMWARE_EXT = re.compile(r"\.(bin|rom|cap|img|fd)$", re.I)


def stem(path):
    """Basename with a *firmware* extension removed.  `X9DRGQF8.921` carries its
    version in the trailing `.921`, which os.path.splitext() would eat."""
    return _FIRMWARE_EXT.sub("", os.path.basename(path))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        prog="patch_logo.py",
        description="Replace the POST logo in a Supermicro X9 BIOS image.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:  python patch_logo.py X9DRGQF8.921")
    ap.add_argument("image", help="the BIOS flash image (e.g. X9DRGQF8.921)")
    ap.add_argument("bmp", nargs="?",
                    help="640x480 8-bit BMP, or a compressed logo payload "
                         "(logo.dat form). Default: logo/logo.dat")
    ap.add_argument("-o", "--out", help="output image (default: <image>.logo.bin)")
    ap.add_argument("--logo-out", metavar="FILE",
                    help="also write the compressed logo payload (logo.dat form) here")
    ap.add_argument("--store-uncompressed", action="store_true",
                    help="store the logo module raw, with no compression section "
                         "(MMTool's /r shape, ~308 KB, and the shape flashed on the "
                         "reference board). Off by default: Tiano-recompressing keeps "
                         "the module at ~154 KB.")
    ap.add_argument("--extract", metavar="FILE",
                    help="extract the current logo BMP to FILE and stop")
    ap.add_argument("--guid", default=GUID, help="logo FFS file GUID")
    a = ap.parse_args()

    src = os.path.abspath(a.image)
    if not os.path.isfile(src):
        die("no such file: %s" % a.image)
    d = open(src, "rb").read()
    g = uuid.UUID(a.guid)

    hit = None
    for base, ln, hl in find_fvs(d):
        for off, gg, size, ty in walk_fv(d, base, ln, hl):
            if gg == g:
                hit = (base, ln, off, size)
                break
        if hit:
            break
    if not hit:
        die("FFS file %s is not in this image" % a.guid)
    fv, fvlen, off, size = hit
    mod = d[off:off + size]

    # split: header + COMPRESSION section
    sec_type = mod[FFS_HDR + 3]
    body = mod[FFS_HDR + 4:]
    if sec_type != SEC_COMPRESSION:
        die("logo module is not stored in a COMPRESSION section (type %#02x)" % sec_type)
    usize = struct.unpack_from("<I", body, 0)[0]
    ctype = body[4]
    csize = struct.unpack_from("<I", body, 5)[0]
    if ctype != TIANO:
        die("logo compression type %#02x, expected 0x01 (Tiano)" % ctype)
    stream = body[5:5 + 8 + csize]        # [CompressedSize][DestinationSize][bitstream]
    ec = load_codec()
    payload = ec.TianoDecompress(stream, len(stream))
    if len(payload) != usize:
        die("decoded %d bytes, section declares %d" % (len(payload), usize))
    print("stock logo  %s @0x%08x  module %s B  stream %s B  payload %s B"
          % (a.guid, off, f"{size:,}", f"{csize:,}", f"{usize:,}"))

    if a.extract:
        i, end = payload_bmp(payload)
        open(a.extract, "wb").write(payload[i:end])
        print("wrote %s (%d bytes)" % (a.extract, end - i))
        return 0

    src_logo = a.bmp if a.bmp else os.path.join(here, "logo", "logo.dat")
    if not os.path.isfile(src_logo):
        die("no picture given and %s does not exist\n"
            "       pass a BMP:  python patch_logo.py %s mypicture.bmp"
            % (os.path.relpath(src_logo, here) if a.bmp else os.path.join("logo", "logo.dat"),
               os.path.basename(src)))
    raw = open(src_logo, "rb").read()
    if raw[:2] == b"BM":
        check_bmp(bytearray(raw), src_logo)
        new_payload = payload_from_bmp(raw)
        print("logo source %s (%s bytes, BMP)" % (src_logo, f"{len(raw):,}"))
    else:
        # the logo.dat form: a compressed AMI payload, exactly the bytes that go
        # into the compression section -- accept it on the command line too
        new_payload = ec.TianoDecompress(raw, len(raw))
        if len(new_payload) < 4 or new_payload[:3] != AMI_HEADER[:3]:
            die("%s is neither a BMP nor a compressed AMI logo payload "
                "(no %s header after decompression)"
                % (src_logo, AMI_HEADER[:3].hex()))
        print("logo source %s (%s bytes, compressed payload)"
              % (src_logo, f"{len(raw):,}"))

    i, end = payload_bmp(new_payload)
    w, h, bpp, blen = check_bmp(bytearray(new_payload[i:end]), "logo BMP")
    # Normalise the header fields on the bytes that are actually written: AMI
    # sizes the palette from biClrUsed (it wants 0 == "all 256"), and the stock
    # template carries junk in biSizeImage/biX/YPelsPerMeter. Zeroing them makes
    # two builds of the same picture byte-identical whatever produced the BMP.
    np = bytearray(new_payload)
    for fld in (32, 34, 38, 42):
        struct.pack_into("<I", np, i + fld, 0)
    new_payload = bytes(np)
    print("new logo    %dx%d %d bpp, BMP %s B, payload %s B (AMI header kept, "
          "biClrUsed/biSizeImage/DPI normalised to 0)"
          % (w, h, bpp, f"{blen:,}", f"{len(new_payload):,}"))

    nstream = ec.TianoCompress(new_payload, len(new_payload))
    if ec.TianoDecompress(nstream, len(nstream)) != new_payload:
        die("self-check: the new stream does not decompress back to the payload")
    if a.store_uncompressed:
        # MMTool's /r shape: no section wrapper at all, and the payload truncated
        # to the AMI PIC length (4 + BMP), which drops the 2 trailing pad bytes
        # that the stock compressed form carries.
        n = int.from_bytes(new_payload[:3], "little")
        if n != len(new_payload) - len(PAD):
            die("self-check: AMI PIC length %d is not payload minus pad (%d)"
                % (n, len(new_payload) - len(PAD)))
        total = FFS_HDR + n
        if total > 0xFFFFFF:
            die("rebuilt module would be %d bytes, past the 24-bit FFS Size field" % total)
        built = fix_checksums(g.bytes_le + struct.pack("<BBBB", 0, 0, mod[FFS_HDR - 6],
                                                       mod[0x13])
                              + total.to_bytes(3, "little") + bytes([mod[0x17]])
                              + new_payload[:n])
        shape = "stored raw, no section wrapper (MMTool /r shape)"
    else:
        inner = struct.pack("<IB", len(new_payload), TIANO) + nstream
        nsec = int(len(inner) + 4).to_bytes(3, "little") + bytes([SEC_COMPRESSION]) + inner
        total = FFS_HDR + len(nsec)
        if total > 0xFFFFFF:
            die("rebuilt module would be %d bytes, past the 24-bit FFS Size field" % total)
        hdr = g.bytes_le + struct.pack("<BBBB", 0, 0, mod[FFS_HDR - 6], mod[0x13]) \
            + total.to_bytes(3, "little") + bytes([mod[0x17]])
        built = fix_checksums(hdr + nsec)
        shape = "Tiano-recompressed"

    aligned = (len(built) + 7) & ~7
    delta = aligned - size
    fv_end = fv + fvlen
    tail = d[off + size:fv_end]
    if delta > 0:
        if len(tail) < delta:
            die("FV %#x has no room: needs %d more bytes" % (fv, delta))
        if set(tail[-delta:]) != {0xff}:
            die("the %d bytes FV %#x would give up are not free space" % (delta, fv))
    region = built + b"\xff" * (aligned - len(built)) + tail[:len(tail) - max(delta, 0)]
    out_img = d[:off] + region + d[fv_end:]
    if len(out_img) != len(d):
        die("self-check: image changed size (%d -> %d)" % (len(d), len(out_img)))

    dst = os.path.abspath(a.out) if a.out else \
        os.path.join(os.path.dirname(src), stem(src) + ".logo.bin")
    if dst == src:
        die("refusing to write over the input image")

    # re-read from the bytes we produced, not from memory
    chk = bytes(out_img)
    hit2 = None
    for base, ln, hl in find_fvs(chk):
        for o2, gg, s2, ty in walk_fv(chk, base, ln, hl):
            if gg == g:
                hit2 = (base, o2, s2)
                break
        if hit2:
            break
    if not hit2:
        die("self-check: the logo module is not findable in the output image")
    b2, o2, s2 = hit2
    if a.store_uncompressed:
        back = chk[o2 + FFS_HDR:o2 + s2]
        c2 = 0
    else:
        body2 = chk[o2 + FFS_HDR + 4:]
        c2 = struct.unpack_from("<I", body2, 5)[0]
        back = ec.TianoDecompress(body2[5:5 + 8 + c2], 8 + c2)
    n = int.from_bytes(new_payload[:3], "little")
    if back != (new_payload[:n] if a.store_uncompressed else new_payload):
        die("self-check: the module in the output image decodes to the wrong payload")
    n = h_ok = f_ok = 0
    for base, ln, hl in find_fvs(chk):
        for o3, gg, s3, ty in walk_fv(chk, base, ln, hl):
            if s3 < FFS_HDR or o3 + s3 > base + ln:
                continue          # the trailing free-space block, not a real file
            n += 1
            hh = bytearray(chk[o3:o3 + 0x18])
            sh, sf = hh[0x10], hh[0x11]
            hh[0x10] = hh[0x11] = hh[0x17] = 0
            h_ok += ((sum(hh) + sh) & 0xFF) == 0
            data = chk[o3 + 0x18:o3 + s3]
            f_ok += (((sum(data) + sf) & 0xFF) == 0) if chk[o3 + 0x13] & 0x40 else sf == 0xAA
    outside = sum(1 for k in range(0, fv) if d[k] != chk[k]) \
        + sum(1 for k in range(fv_end, len(d)) if d[k] != chk[k])
    print("repack      module %s -> %s B (%+d); FV %#x gives up %d free bytes  [%s]"
          % (f"{size:,}", f"{s2:,}", s2 - size, b2, max(delta, 0), shape))
    print("verify      %d FFS files; header checksums %d/%d close, file checksums "
          "%d/%d close" % (n, h_ok, n, f_ok, n))
    print("            %d bytes changed outside FV %#x..%#x" % (outside, fv, fv_end))
    if not (h_ok == n and f_ok == n and outside == 0):
        die("self-check: structural checks failed")
    open(dst, "wb").write(bytes(chk))
    print("wrote %s (%d bytes)" % (dst, len(chk)))

    if a.logo_out:
        open(a.logo_out, "wb").write(nstream)
        print("wrote %s (%d bytes, compressed logo payload)" % (a.logo_out, len(nstream)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
