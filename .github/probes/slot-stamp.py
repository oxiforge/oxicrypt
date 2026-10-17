#!/usr/bin/env python3
"""Writes slot_rva into the version-2 integrity slot of a fixture ELF.

Usage: slot-stamp.py <elf>

A version-2 probe: `elf-fixture.c` reserves a version-2 slot (16,384 bytes),
and nothing signs it. The slot is located by its header magic and validated
by its footer; its virtual address is derived from the program headers and
written at OFF_SLOT_RVA, the field the probes read, which every version keeps
at the same offset. Prints the slot's file offset and address. Exits 1 when
there is no slot, more than one, or no PT_LOAD maps it.
"""
import struct
import sys

HDR = bytes([0xFC]) + b"OXICRYPT_FIPS_H"
FTR = bytes([0xFD]) + b"OXICRYPT_FIPS_F"
# The version-2 slot's size, and the offsets every version shares.
# tools/integrity-probe/tests/probe_offsets.rs checks each value.
V2_SLOT_SIZE = 16384
MAGIC_LEN = 16
OFF_SLOT_RVA = 28


def main() -> int:
    path = sys.argv[1]
    data = bytearray(open(path, "rb").read())
    hits = []
    at = data.find(HDR)
    while at >= 0:
        if data[at + V2_SLOT_SIZE - MAGIC_LEN:at + V2_SLOT_SIZE] == FTR:
            hits.append(at)
        at = data.find(HDR, at + 1)
    if len(hits) != 1:
        print(f"slot-stamp: expected one slot, found {len(hits)}", file=sys.stderr)
        return 1
    slot = hits[0]
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        p_type, _flags, p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(
            "<IIQQQQ", data, phoff + i * phentsize)
        if p_type == 1 and p_offset <= slot < p_offset + p_filesz:
            rva = p_vaddr + slot - p_offset
            struct.pack_into("<I", data, slot + OFF_SLOT_RVA, rva)
            open(path, "wb").write(data)
            print(f"slot at file offset {slot:#x}, rva {rva:#x}")
            return 0
    print("slot-stamp: no PT_LOAD maps the slot", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
