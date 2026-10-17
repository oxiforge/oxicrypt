#!/usr/bin/env python3
"""Prints the file offset of a byte to flip when testing tamper detection.

Usage: extent-tamper-offset.py <show.txt> <artifact>

Three properties are needed of that byte.

1. It lies inside a range the signer hashed. The ranges are read from the
   signer's own report (`--show`), never guessed, and the chosen offset is
   asserted to be inside one of them.

2. The operating system's loader does not parse it. On ELF the extent begins
   at file offset zero and includes the ELF and program headers; a byte
   flipped there kills the process in the loader, which reads as "tampering
   undetected" while meaning "the test never ran".

3. Nothing executes or reads it before the integrity test. A flipped
   instruction in code that runs during start-up crashes the process the same
   way; a flipped constant that a known-answer test reads before the
   integrity test fails that test with a different diagnosis.

A byte that no section and no loader-parsed header contains satisfies all
three: alignment padding between two sections is mapped, hashed, and
referenced by nothing. A gap of a single byte qualifies. Where the hashed
range lies wholly inside one section, as the code section does on PE, the byte
is instead the middle of the longest run of `int3` (0xCC) padding, of at least
8 bytes, inside an executable section: executing it would trap, and no code
jumps there. The chosen offset is the middle of the longest candidate run, so
it is far from either neighbour. If neither kind of candidate exists, the
script fails rather than fall back to a byte that might be executed.

Prints the offset in decimal, and on stderr which rule chose it.
"""

import re
import struct
import sys

# Any byte between sections is unreferenced, so one byte is enough there; an
# int3 run must be long enough to be inter-function padding.
MIN_GAP = 1
MIN_INT3_RUN = 8


def sections(data):
    """File extents [start, end) of every section that has file bytes, of the
    headers the loader parses, and of the ELF segments other than PT_LOAD that
    the loader or runtime reads (PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_TLS,
    PT_GNU_EH_FRAME): none is ever a candidate. Also returns the extents of
    the executable sections, the only place an int3 run may be taken from."""
    out, code = [], []
    if data[:4] == b"\x7fELF" and data[4] == 2:
        phoff, = struct.unpack_from("<Q", data, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
        out += [(0, 64), (phoff, phoff + phentsize * phnum)]
        for i in range(phnum):
            p_type, _flags, p_offset, _va, _pa, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
            if p_type in (2, 3, 4, 7, 0x6474E550) and p_filesz:
                out.append((p_offset, p_offset + p_filesz))
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
        for i in range(shnum):
            o = shoff + i * shentsize
            if o + 64 > len(data):
                break
            _name, typ, flags, _addr, off, size = struct.unpack_from("<IIQQQQ", data, o)
            if typ not in (0, 8) and size:  # not SHT_NULL, not SHT_NOBITS
                out.append((off, off + size))
                if flags & 0x4:  # SHF_EXECINSTR
                    code.append((off, off + size))
    elif data[:4] == b"\xcf\xfa\xed\xfe":
        ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
        out.append((0, 32 + sizeofcmds))
        o = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", data, o)
            if cmd == 0x19:
                nsects, = struct.unpack_from("<I", data, o + 64)
                for k in range(nsects):
                    s = o + 72 + 80 * k
                    _addr, ssize, soff = struct.unpack_from("<QQI", data, s + 32)
                    flags, = struct.unpack_from("<I", data, s + 64)
                    if flags & 0xFF not in (0x1, 0xC, 0x12) and ssize:  # not zero-fill
                        out.append((soff, soff + ssize))
                        if flags & 0x80000400:  # S_ATTR_PURE_INSTRUCTIONS or SOME_INSTRUCTIONS
                            code.append((soff, soff + ssize))
            o += size
    elif data[:2] == b"MZ":
        pe, = struct.unpack_from("<I", data, 0x3C)
        nsec, = struct.unpack_from("<H", data, pe + 6)
        optsize, = struct.unpack_from("<H", data, pe + 20)
        size_of_headers, = struct.unpack_from("<I", data, pe + 24 + 60)
        out.append((0, size_of_headers))
        for i in range(nsec):
            e = pe + 24 + optsize + 40 * i
            vsize, _va, raw, ptr = struct.unpack_from("<IIII", data, e + 8)
            chars, = struct.unpack_from("<I", data, e + 36)
            # the signer's extent: min(VirtualSize, SizeOfRawData), or the raw
            # size when VirtualSize is 0
            backed = min(vsize, raw) if vsize else raw
            if backed:
                out.append((ptr, ptr + backed))
                if chars & 0x20000020:  # IMAGE_SCN_MEM_EXECUTE or CNT_CODE
                    code.append((ptr, ptr + backed))
    return out, code


def runs_of(data, lo, hi, byte):
    """Maximal runs of `byte` in data[lo:hi], as (start, end)."""
    out, start = [], None
    for i in range(lo, hi):
        if data[i] == byte:
            if start is None:
                start = i
        elif start is not None:
            out.append((start, i))
            start = None
    if start is not None:
        out.append((start, hi))
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: extent-tamper-offset.py <show.txt> <artifact>", file=sys.stderr)
        return 2
    # `[i] rva … file … len N`, or with the entry kind after the index
    # (`[i] Plain rva …`); only Plain entries are hashed as the file holds them
    pattern = re.compile(r"\[\d+\] (?:(\w+) )?rva 0x[0-9a-fA-F]+ file 0x([0-9a-fA-F]+) len (\d+)")
    ranges = []
    with open(sys.argv[1], encoding="utf-8") as handle:
        for line in handle:
            found = pattern.search(line)
            if found and found.group(1) in (None, "Plain"):
                start = int(found.group(2), 16)
                ranges.append((start, start + int(found.group(3))))
    if not ranges:
        print("no range line in the signer's report", file=sys.stderr)
        return 1
    data = open(sys.argv[2], "rb").read()
    secs, code = sections(data)
    if not secs:
        print("no section table: cannot tell padding from code or data", file=sys.stderr)
        return 1

    # Rule 1: bytes between sections, inside a hashed range: the hashed
    # ranges minus the union of the section extents.
    gaps = []
    for lo, hi in ranges:
        hi = min(hi, len(data))
        cursor = lo
        for a, b in sorted(secs):
            if b <= cursor or a >= hi:
                continue
            if a > cursor:
                gaps.append((cursor, a))
            cursor = max(cursor, b)
        if cursor < hi:
            gaps.append((cursor, hi))
    gaps = [g for g in gaps if g[1] - g[0] >= MIN_GAP]
    rule = "between sections"
    candidates = gaps
    if not candidates:
        # Rule 2: int3 padding between functions, inside a hashed range and
        # inside an executable section, never in data.
        rule = "int3 padding between functions"
        candidates = [r for lo, hi in ranges for clo, chi in code
                      for r in runs_of(data, max(lo, clo), min(hi, chi, len(data)), 0xCC)
                      if r[1] - r[0] >= MIN_INT3_RUN]
    if not candidates:
        print("no inter-section gap and no int3 run of at least "
              f"{MIN_INT3_RUN} bytes in code inside a hashed range", file=sys.stderr)
        return 1
    start, end = max(candidates, key=lambda r: (r[1] - r[0], -r[0]))
    offset = start + (end - start) // 2
    # Asserted, not assumed: the byte is inside a hashed range.
    if not any(lo <= offset < hi for lo, hi in ranges):
        print(f"offset {offset} is outside every hashed range", file=sys.stderr)
        return 1
    print(f"tamper byte: {rule}, run {start:#x}..{end:#x} ({end - start} bytes), offset {offset:#x}",
          file=sys.stderr)
    print(offset)
    return 0


if __name__ == "__main__":
    sys.exit(main())
