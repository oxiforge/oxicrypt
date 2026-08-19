#!/usr/bin/env python3
"""Inverts one byte of a file, in place.

Used to make a signed artifact differ from what its recorded MAC covers.
"""

import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: flip-byte.py <file> <offset>", file=sys.stderr)
        return 2
    path, offset = sys.argv[1], int(sys.argv[2])
    with open(path, "r+b") as handle:
        handle.seek(offset)
        original = handle.read(1)
        if not original:
            print(f"offset {offset} is past the end of {path}", file=sys.stderr)
            return 1
        handle.seek(offset)
        handle.write(bytes([original[0] ^ 0xFF]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
