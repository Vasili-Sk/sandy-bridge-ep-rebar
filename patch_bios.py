#!/usr/bin/env python3
"""Apply both ReBAR patches to a Supermicro X9 image, in one command.

    python patch_bios.py X9DRGQF8.921

writes `X9DRGQF8.921.rebar.bin` -- both patches applied -- and then verifies it
against the stock image.  Nothing else is required, and no other arguments are.

What it applies:

  1. MMIOH (64-bit) aperture 1 TiB -> 8 TiB, so a 64 GiB GPU BAR lands inside
     the window the chipset decodes.  7 code bytes in the PEIM IvtQpiandMrcInit
     (FV02) + its FFS file-data checksum byte.
  2. the root-bridge 32-bit aperture published in the DSDT, 0x80000000/0x7C000000
     -> 0x90000000/0x6C000000, so the window the OS allocates PCI BARs from no
     longer contains ECAM (PCI config space).  14 code bytes in PciRootBridge
     (FV01), which is Tiano-compressed, so the module is expanded, patched,
     stored uncompressed and the volume repacked; both FFS checksums recomputed.

Both shapes written here are the ones flashed and POSTed on the reference board.

Everything is done by byte pattern with an occurrence-count assert; the input
image is opened read-only and never modified.  The step scripts remain usable on
their own (patch_mmioh.py, patch_aperture.py, verify_image.py) and take the
options this wrapper deliberately hides.

Requires: Python 3.10+ and `pip install -r requirements.txt`
(uefi-firmware for the Tiano codec, capstone for the verifier's disassembly).
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def run(script, argv, must_succeed):
    """Run one of the step scripts in this directory, streaming its output."""
    exe = [sys.executable, os.path.join(HERE, script)]
    print("\n\x1b[1m==> %s %s\x1b[0m" % (script, " ".join(argv)) if _color()
          else "\n==> %s %s" % (script, " ".join(argv)), flush=True)
    rc = subprocess.run(exe + argv).returncode
    if must_succeed and rc != 0:
        sys.exit("%s failed (exit %d); %s was not written"
                % (script, rc, argv[argv.index("-o") + 1] if "-o" in argv else "output"))
    return rc


def _color():
    return sys.stdout.isatty() and os.name != "nt" or os.environ.get("WT_SESSION")


_FIRMWARE_EXT = re.compile(r"\.(bin|rom|cap|img|fd)$", re.I)


def stem(path):
    """Basename with a *firmware* extension removed.

    X9 images are named `X9DRGQF8.921`: the trailing `.921` is the BIOS version,
    not an extension. os.path.splitext() would drop it and name every artefact
    `X9DRGQF8.*`, losing the version from the file the user has to keep straight.
    """
    return _FIRMWARE_EXT.sub("", os.path.basename(path))


def main():
    ap = argparse.ArgumentParser(
        prog="patch_bios.py",
        description="Apply both ReBAR patches to a Supermicro X9 BIOS image.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:  python patch_bios.py X9DRGQF8.921")
    ap.add_argument("image", help="the BIOS flash image (e.g. X9DRGQF8.921)")
    ap.add_argument("-o", "--out",
                    help="output image (default: <image>.rebar.bin, alongside it)")
    ap.add_argument("--logo", metavar="FILE", nargs="?", const="", default=None,
                    help="install a POST logo: a 640x480 8-bit BMP. With no value, "
                         "install the repo's logo/logo.dat. On by default when that "
                         "file is present; see --nologo.")
    ap.add_argument("--nologo", action="store_true",
                    help="patch only: leave the POST logo exactly as shipped")
    ap.add_argument("--logo-uncompressed", action="store_true",
                    help="store the logo module raw instead of Tiano-recompressed "
                         "(MMTool's /r shape, ~308 KB instead of ~154 KB; this is the "
                         "shape flashed on the reference board)")
    ap.add_argument("--recompress", action="store_true",
                    help="re-compress the patched DXE module instead of storing it "
                         "uncompressed (moves 16 bytes of the volume instead of "
                         "~45 KB). Off by default: the uncompressed shape is the one "
                         "proven on hardware.")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the independent verification pass")
    ap.add_argument("--size", help="MMIOH size in GiB, power of two "
                                   "(default 0x2000 = 8 TiB, the maximum legal here)")
    a = ap.parse_args()

    src = os.path.abspath(a.image)
    if not os.path.isfile(src):
        sys.exit("no such file: %s" % a.image)
    if os.path.getsize(src) == 0:
        sys.exit("empty file: %s" % a.image)
    dst = os.path.abspath(a.out) if a.out else \
        os.path.join(os.path.dirname(src), stem(src) + ".rebar.bin")
    if dst == src:
        sys.exit("refusing to write over the input image")

    here = os.path.dirname(os.path.abspath(__file__))
    stock_logo = os.path.join(here, "logo", "logo.dat")
    if a.nologo:
        logo = None
    elif a.logo:
        logo = a.logo
    elif a.logo is None and os.path.isfile(stock_logo):
        logo = stock_logo
    else:
        logo = None

    stages = []
    extra = ["--recompress"] if a.recompress else []
    msize = ["--size", a.size] if a.size else []

    print("input   %s  (%d bytes)" % (os.path.basename(src), os.path.getsize(src)))
    print("output  %s" % os.path.basename(dst))
    print("logo    %s" % ("left as shipped (--nologo)" if not logo
                          else os.path.basename(logo)))

    try:
        s1 = dst + ".mmioh.tmp"
        stages.append(s1)
        run("patch_mmioh.py", [src] + msize + ["-o", s1], True)

        s2 = dst + ".aperture.tmp"
        stages.append(s2)
        run("patch_aperture.py", [s1] + extra + ["-o", s2], True)

        if logo:
            run("patch_logo.py", [s2, logo, "-o", dst]
                + (["--store-uncompressed"] if a.logo_uncompressed else []), True)
        else:
            import shutil
            shutil.copyfile(s2, dst)
    finally:
        for s in stages:
            if os.path.exists(s):
                os.remove(s)

    if not a.no_verify:
        rc = run("verify_image.py", [src, dst], False)
        if rc != 0:
            sys.exit("\nVERIFICATION FAILED - do not flash %s" % os.path.basename(dst))

    print("\n%s\n  %-24s ready to flash (main BIOS region only)\n%s"
          % ("=" * 66, os.path.basename(dst), "=" * 66))
    print("  patches: MMIOH 1 TiB -> 8 TiB, published aperture ECAM-excluded")
    print("  logo   : %s" % ("replaced" if logo else "unchanged"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
