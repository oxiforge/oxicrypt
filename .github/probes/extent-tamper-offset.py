#!/usr/bin/env python3
"""Prints a file offset deep inside the largest range of a signer report.

Two properties are needed of a byte used to test tamper detection, and only
one of them is obvious.

It must be inside the hashed extent, or flipping it proves nothing — that
much is why the offset is read from the signer's own report rather than
guessed.

It must also not be load-bearing for the operating system's loader. On ELF
the extent begins at file offset zero and therefore *includes* the ELF header
and the program header table; flipping a byte there corrupts the image before
the module ever runs, and the process dies of a segmentation fault rather than
reporting an integrity failure. That reads as "tampering undetected" while
actually meaning "the test never executed".

Choosing the midpoint of the largest range satisfies both: the largest range
is the code and read-only data, and its middle is far from any structure the
loader parses.
"""

import re
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: extent-tamper-offset.py <show.txt>", file=sys.stderr)
        return 2
    pattern = re.compile(r"\[\d+\] rva 0x[0-9a-fA-F]+ file 0x([0-9a-fA-F]+) len (\d+)")
    best = None
    with open(sys.argv[1], encoding="utf-8") as handle:
        for line in handle:
            found = pattern.search(line)
            if not found:
                continue
            offset = int(found.group(1), 16)
            length = int(found.group(2))
            if best is None or length > best[1]:
                best = (offset, length)
    if best is None:
        print("no range line in the signer's report", file=sys.stderr)
        return 1
    offset, length = best
    if length < 2:
        print(f"the largest range is only {length} bytes", file=sys.stderr)
        return 1
    print(offset + length // 2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
