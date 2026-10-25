#!/usr/bin/env python3
"""Patcher 1/2 - the 64-bit MMIO aperture. This is what actually enables ReBAR.

Target: Supermicro X9DRG-QF (X9 / C602 "Patsburg", AMI Aptio IV), BIOS 3.3
file `X9DRGQF8.921`. Pure Python, no dependencies, no external tools: it reads
the raw 16 MiB SPI image and writes a raw 16 MiB image. 7 code bytes plus one
FFS checksum byte change; nothing moves, no section or volume is resized.

WHAT IT DOES
-----------
The C600 uncore decodes 64-bit MMIO through a base + power-of-two mask. The
aperture size comes from a variable that is **not wired to any setup question**
on X9, so firmware hard-codes it to 1 TiB. A GPU asking for a large BAR (MI210:
64 GiB; RTX 3090 at 32 GiB; any card above the aperture) is then placed one
aperture-width past the end of the decoded window and never responds.

This patch replaces the load of that variable with an immediate, so the window
becomes 8 TiB - the largest value that stays inside the CPU's 46-bit physical
address space. Verified live: `pci_bus 0000:00: root bus resource
[mem 0x380000000000-0x3fffffffffff window]`, MI210 BAR0 at 64 GiB, `VRAM: 65520M`.

The FFS file-data checksum of the patched module is recomputed, because on this
image those checksums are live (see AGENTS.md "FFS checksums"): they close on
167/167 header checksums and 161/167 file-data checksums on stock. Leaving the
byte stale does not stop the firmware booting FV02, but it truncates MMTool's
volume walk (FV02 reports 4 files instead of 26), which is the tripwire that
tells you an image is structurally off.

MEASURED SEMANTICS (IvtQpiandMrcInit, FFS file at 0xe26000)

  0xe30189  mov  dword [ebp-0x28], 0x3800        ; MMIOH base default
  0xe30190  test ax, ax  / je 0xe3019e           ; base var == 0 -> keep default
  0xe30198  shl  eax, 6                          ; else base = var << 6
  0xe3019e  movzx edx, word [esi+0x2c0]          ; MMIOH size var (16-bit)  <== SITE
  0xe301a5  test dx, dx
  0xe301a8  jne  0xe301d7                        ; non-zero -> use it
  0xe301b5  mov  dword [ebp+8], 2                ; zero -> fallback 2
  0xe301d1  mov  edx, dword [ebp+8]
  0xe301d7  movzx edx, dx                        ; 16-bit truncate
  0xe301da  push edx                             ; arg3 = size
  0xe301dd  mov  eax, 0x40000000                 ; arg1:arg2 = 1 GiB
  0xe301e4  call 0xe6dc16                        ; 64-bit mul -> size_bytes
  0xe301ed  call 0xe6dd06                        ; -> size_bytes - 1  (a MASK)

  unit  = GiB (callee multiplies 0x40000000 by the raw value)
  width = 16 bits (movzx edx,dx truncates)          -> size <= 0xFFFF GiB
  mask  = size_bytes - 1, base/mask decoder         -> size MUST be power of two
  base  = 0x3800 in units of 4 GiB = 56 TiB         -> matches Supermicro's
                                                      "MMIOHBase to 56TB" exactly
  window = base .. base + size*GiB - 1
  E5-2690 v2 physical address space = 2^46 = 64 TiB -> base+size must be <= 2^46

The MMIOH size variable is unwired to any setup question (MNL-1309 ch.4 has no
MMIOH Base / MMIO High Granularity Size on X9 - that FAQ applies to X10/X11).
`IvtQpiandMrcInit` writes 0x400 (1 TiB) to it unconditionally at 0x0e26972, so
the `size == 0` fallback path is dead code on a normal boot and the aperture is
always 1 TiB. A MI210 asks for a 64 GiB framebuffer BAR. That is the failure.
"""
import argparse, os, re, sys, uuid

GUID = "5C08C7C8-24C2-4400-9627-CF2869421E06"          # IvtQpiandMrcInit
PAT  = re.escape(bytes.fromhex("0fb796c00200006685d2"))  # movzx edx,[esi+0x2c0]; test dx,dx
PHYS = 46                                              # E5-2690 v2: 46-bit PAE
BASE = 0x3800                                          # default base, units of 4 GiB


def main():
    ap = argparse.ArgumentParser(
        description="Raise the C600-series MMIOH 64-bit MMIO aperture (the ReBAR enabler).",
        epilog="example:  python patch_mmioh.py X9DRGQF8.921 -o patched.bin")
    ap.add_argument("image", help="raw SPI image as downloaded from Supermicro (16 MiB)")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--size", type=lambda s: int(s, 0), default=0x2000,
                    help="MMIOH size in GiB, power of two, <= 0xFFFF (default 0x2000 = 8 TiB)")
    ap.add_argument("--force", action="store_true", help="allow a size that overflows 2^%d" % PHYS)
    a = ap.parse_args()
    a.src = a.image

    def TiB(n): return f"{n/1024:g} TiB"
    def hb(n):
        u = ['B','KB','MB','GB','TB','PB']
        i = 0
        while n >= 1024 and i < 5: n /= 1024; i += 1
        return f"{n:g} {u[i]}"

    # ---- validate the requested size against the measured constraints ----
    if a.size <= 0 or a.size & (a.size - 1):
        sys.exit(f"ABORT: size {a.size:#x} is not a power of two (base/mask decoder)")
    if a.size > 0xFFFF:
        sys.exit(f"ABORT: size {a.size:#x} exceeds the 16-bit field (movzx edx,dx truncates)")
    base_addr  = BASE << 32                            # 0x3800 * 4 GiB = 56 TiB
    size_bytes = a.size << 30
    top        = base_addr + size_bytes
    if top > (1 << PHYS):
        msg = (f"ABORT: window {base_addr:#x}..{top-1:x} ends above 2^{PHYS} "
               f"({hb(1<<PHYS)}), the CPU's physical address limit")
        if not a.force:
            sys.exit(msg + f"\n       max legal size = {(1<<PHYS) - base_addr >> 30:#x} GiB")
        print("WARNING: " + msg, file=sys.stderr)

    if not os.path.isfile(a.src):
        sys.exit(f"ABORT: no such file: {a.src}\n"
                 f"       Pass the raw SPI image you downloaded from Supermicro "
                 f"(e.g. X9DRGQF8.921), unpacked from the .zip.")
    d = bytearray(open(a.src, "rb").read()); orig = bytes(d)
    g = d.find(uuid.UUID(GUID).bytes_le)
    if g < 0:
        sys.exit("ABORT: FFS file IvtQpiandMrcInit not found.\n"
                 "       This patcher is specific to Supermicro X9 (C602/Patsburg, Aptio IV) "
                 "images. Do not run it on other vendors' firmware.")
    fsize = int.from_bytes(d[g+20:g+23], "little")
    if not (0 < fsize <= len(d) - g): sys.exit("ABORT: implausible FFS size")
    hits = [m.start() for m in re.finditer(PAT, orig)]
    if len(hits) != 1: sys.exit(f"ABORT: pattern occurs {len(hits)}x in the image, expected exactly 1")
    off = hits[0]
    if not (g < off < g + fsize): sys.exit("ABORT: unique match is not inside this FFS file")

    repl = b"\xba" + a.size.to_bytes(4, "little") + b"\x66\x90" + b"\x66\x85\xd2"
    assert len(repl) == len(PAT) == 10
    d[off:off+10] = repl

    # ---- FFS integrity of the file we just edited -------------------------
    # Layout as this image stores it (ZeroVector present in the FV, so `g` is
    # the GUID offset and the 24-byte checksummed header is d[g:g+0x18]):
    #   g+0x00 16  Name (GUID)
    #   g+0x10  1   IntegrityCheck.Header
    #   g+0x11  1   IntegrityCheck.File
    #   g+0x12  1   Type
    #   g+0x13  1   Attributes      (bit 0x40 = FFS_ATTRIB_CHECKSUM)
    #   g+0x14  3   Size (LE, measured from the GUID)
    #   g+0x17  1   State
    #   g+0x18 --   file data
    attrs = d[g+0x13]
    if attrs & 0x40:
        want = (-sum(d[g+0x18:g+fsize])) & 0xFF
        print(f"\nFFS file-data checksum: {d[g+0x11]:#04x} -> {want:#04x}")
        d[g+0x11] = want
    assert (sum(d[g+0x18:g+fsize]) + d[g+0x11]) & 0xFF == 0, "file checksum does not close"
    h = bytearray(d[g:g+0x18]); h[0x10] = h[0x11] = h[0x17] = 0
    assert (sum(h) + d[g+0x10]) & 0xFF == 0, "header checksum does not close"
    print(f"FFS header checksum   : {d[g+0x10]:#04x} (unchanged, verified closes)")

    dst = a.out or (re.sub(r"\.[^.]+$", "", os.path.basename(a.src))
                    + f".mmioh-{a.size:#x}.bin")
    open(dst, "wb").write(bytes(d))

    diff = [i for i in range(len(orig)) if orig[i] != d[i]]
    print("=" * 72)
    print(f"IvtQpiandMrcInit   @0x{g:07x}  size 0x{fsize:x}  ends 0x{g+fsize:07x}")
    print(f"patch site         @0x{off:07x}")
    print(f"  before  {orig[off:off+10].hex(' ')}   movzx edx,word [esi+0x2c0] ; test dx,dx")
    print(f"  after   {d[off:off+10].hex(' ')}   mov edx,{a.size:#x} ; xchg ax,ax ; test dx,dx")
    print(f"control flow       test dx,dx -> dx={a.size:#x} nonzero -> jne taken -> "
          f"fallback (2 GiB) skipped -> push edx -> 64-bit mul -> mask")
    print()
    print(f"MMIOH base         {base_addr:#014x}  ({hb(base_addr)})   [default 0x{BASE:x} x 4 GiB]")
    print(f"MMIOH size         {size_bytes:#014x}  ({hb(size_bytes)})   [{a.size:#x} GiB]")
    print(f"MMIOH mask         {size_bytes-1:#014x}   (= size-1, base/mask decoder)")
    print(f"MMIOH window       {base_addr:#014x} .. {top-1:#014x}")
    print(f"top of 46-bit space{((1<<PHYS)-1):#014x}   -> window ends "
          f"{'EXACTLY at' if top == 1<<PHYS else ('above' if top > 1<<PHYS else 'below')} 2^{PHYS}")
    print()
    print(f"bytes changed      {len(diff)}: {[hex(x) for x in diff]}")
    print(f"IntegrityCheck.Header {orig[g+0x10]:#04x} -> {d[g+0x10]:#04x}   (unchanged; verified closes)")
    print(f"IntegrityCheck.File   {orig[g+0x11]:#04x} -> {d[g+0x11]:#04x}   (recomputed)")
    print(f"file length        unchanged ({fsize:#x}); no section/FV resize")
    print(f"MI210 boot BAR     64 GiB -> {'FITS' if size_bytes >= 64 << 30 else 'DOES NOT FIT'}")
    print(f"wrote {dst}")


if __name__ == "__main__":
    main()
