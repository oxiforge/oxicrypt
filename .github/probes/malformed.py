#!/usr/bin/env python3
"""Writes truncated and malformed copies of a fixture, for the typed probes.

Usage: malformed.py <elf|macho|pe> <fixture> <outdir>

Each copy breaks one structure the probe parses: a size or offset that runs
past the file or wraps 64 bits, a table count far beyond the file, a header
field the probe must validate before trusting. The self-test runs each probe
on each copy and requires a `RESULT` line with a non-zero status and an
ordinary exit: a probe that crashes, hangs or passes on a malformed file
fails. Prints one line per copy written.
"""
import os
import struct
import sys

HUGE = 0xFFFFFFFFFFFFF000


def elf(data):
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)

    def phdr_of(ptype):
        for i in range(phnum):
            o = phoff + i * phentsize
            if struct.unpack_from("<I", data, o)[0] == ptype:
                return o
        raise SystemExit(f"fixture has no program header of type {ptype:#x}")

    def dyn_entry(tag):
        o = phdr_of(2)
        off, filesz = struct.unpack_from("<Q", data, o + 8)[0], struct.unpack_from("<Q", data, o + 32)[0]
        for e in range(off, off + filesz, 16):
            if struct.unpack_from("<q", data, e)[0] == tag:
                return e
        raise SystemExit(f"fixture has no dynamic tag {tag}")

    out = {}
    out["truncated-headers"] = data[:0x200]
    out["truncated-half"] = data[:len(data) // 2]
    d = bytearray(data); struct.pack_into("<H", d, 0x36, 0x20); out["phentsize-wrong"] = d
    d = bytearray(data); struct.pack_into("<H", d, 0x38, 0xFFFF); out["phnum-huge"] = d
    d = bytearray(data); struct.pack_into("<Q", d, 0x20, HUGE); out["phoff-huge"] = d
    d = bytearray(data); struct.pack_into("<Q", d, phdr_of(2) + 32, HUGE); out["dynamic-filesz-huge"] = d
    d = bytearray(data); struct.pack_into("<Q", d, phdr_of(2) + 8, HUGE); out["dynamic-offset-huge"] = d
    d = bytearray(data); struct.pack_into("<Q", d, dyn_entry(8) + 8, HUGE); out["relasz-huge"] = d
    d = bytearray(data); struct.pack_into("<Q", d, dyn_entry(7) + 8, HUGE); out["rela-address-huge"] = d
    d = bytearray(data); struct.pack_into("<Q", d, phdr_of(0x6474E552) + 40, HUGE); out["relro-memsz-huge"] = d
    relasz = struct.unpack_from("<Q", data, dyn_entry(8) + 8)[0]
    d = bytearray(data); struct.pack_into("<Q", d, dyn_entry(8) + 8, relasz - 4); out["rela-partial-record"] = d
    try:
        relr = dyn_entry(35)  # DT_RELRSZ, on the RELR fixture
    except SystemExit:
        relr = None
    if relr is not None:
        d = bytearray(data); struct.pack_into("<Q", d, relr + 8, struct.unpack_from("<Q", data, relr + 8)[0] - 4)
        out["relr-partial-entry"] = d
        d = bytearray(data); struct.pack_into("<Q", d, dyn_entry(36) + 8, HUGE); out["relr-address-huge"] = d
    return out


def macho(data):
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    out = {"truncated-headers": data[:0x100], "truncated-half": data[:len(data) // 2]}
    first_seg = None
    d = bytearray(data); struct.pack_into("<I", d, 20, 0xFFFFFFF0); out["sizeofcmds-huge"] = d
    d = bytearray(data); struct.pack_into("<I", d, 16, 0xFFFF); out["ncmds-huge"] = d
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x19 and "segment-filesize-huge" not in out:
            first_seg = off
            d = bytearray(data); struct.pack_into("<Q", d, off + 48, HUGE); out["segment-filesize-huge"] = d
            d = bytearray(data); struct.pack_into("<I", d, off + 64, 0xFFFF); out["nsects-huge"] = d
        if cmd == 0x19 and data[off + 8:off + 24].rstrip(b"\0") == b"__DATA":
            # fileoff + filesize wraps 64 bits
            d = bytearray(data); struct.pack_into("<QQ", d, off + 40, 2 ** 64 - 0x1000, 0x2000)
            out["segment-extent-wraps"] = d
        if cmd in (0x22, 0x80000022):
            rebase_off, rebase_size = struct.unpack_from("<II", data, off + 8)
            d = bytearray(data); struct.pack_into("<I", d, off + 8, 0x7FFF0000); out["info-rebase-offset-huge"] = d
            d = bytearray(data); struct.pack_into("<I", d, off + 20, 0xFFFFFFF0); out["info-bind-size-huge"] = d
            # a rebase stream, appended to the file: segment 2 at offset 0,
            # then rebase 2^40 times
            stream = bytes([0x22, 0x00, 0x60, 0x80, 0x80, 0x80, 0x80, 0x80, 0x20, 0x00])
            d = bytearray(data) + stream
            struct.pack_into("<II", d, off + 8, len(data), len(stream))
            out["rebase-repeat-huge"] = d
        if cmd == 0x80000034:
            d = bytearray(data); struct.pack_into("<I", d, off + 8, 0xFFFFFFF0); out["chained-offset-huge"] = d
            dataoff, = struct.unpack_from("<I", data, off + 8)
            d = bytearray(data); struct.pack_into("<I", d, dataoff + 4, 0xFFFFFFF0); out["chained-starts-huge"] = d
        if "first-cmdsize-zero" not in out:
            d = bytearray(data); struct.pack_into("<I", d, off + 4, 0); out["first-cmdsize-zero"] = d
        off += size
    return out


def macho_overlaps(data):
    """Segments and fixup streams that point the parser at the wrong segment,
    at 64-bit wraps, or at undefined arithmetic."""
    ncmds, = struct.unpack_from("<I", data, 16)
    segs, cmds, off = {}, [], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        cmds.append((cmd, off))
        if cmd == 0x19:
            name = data[off + 8:off + 24].rstrip(b"\0").decode()
            segs[name] = (off,) + struct.unpack_from("<QQQQ", data, off + 24)
        off += size
    text, dc = segs["__TEXT"], segs["__DATA_CONST"]
    out = {}
    # __TEXT's VM range reaches 4 bytes into __DATA_CONST's first word
    d = bytearray(data); struct.pack_into("<Q", d, text[0] + 24, dc[1] - text[2] + 4); out["overlap-text-into-dataconst"] = d
    # __DATA_CONST placed at the top of the address space: its addresses wrap
    d = bytearray(data); struct.pack_into("<Q", d, dc[0] + 24, 2 ** 64 - 8); out["dataconst-vmaddr-wraps"] = d
    # __DATA_CONST placed on __TEXT
    d = bytearray(data); struct.pack_into("<Q", d, dc[0] + 24, text[1]); out["dataconst-on-text"] = d
    for cmd, off in cmds:
        if cmd in (0x22, 0x80000022):
            # a bind addend as a 10-byte SLEB: a signed shift at bit 63
            stream = bytes([0x11, 0x40]) + b"_x\0" + bytes([0x60] + [0x80] * 9 + [0x7F]) + bytes([0x72, 0x00, 0x90, 0x00])
            d = bytearray(data) + stream; struct.pack_into("<II", d, off + 16, len(data), len(stream)); out["bind-sleb-10byte"] = d
            # rebase-times-skipping whose skip wraps to step on the same word
            stream = bytes([0x22, 0x00, 0x80, 0x80, 0x80, 0x01, 0xF8] + [0xFF] * 8 + [0x01, 0x00])
            d = bytearray(data) + stream; struct.pack_into("<II", d, off + 8, len(data), len(stream)); out["rebase-skip-wraps"] = d
            # a bind library ordinal far beyond the libraries the image names
            stream = bytes([0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x40]) + b"_x\0" + bytes([0x72, 0x00, 0x90, 0x00])
            d = bytearray(data) + stream; struct.pack_into("<II", d, off + 16, len(data), len(stream)); out["bind-ordinal-huge"] = d
        if cmd == 0x80000034:
            dataoff, = struct.unpack_from("<I", data, off + 8)
            starts_off, imports_off = struct.unpack_from("<II", data, dataoff + 4)
            # import format 3 with addend INT64_MAX, plus an inline addend
            d = bytearray(data); struct.pack_into("<I", d, dataoff + 20, 3)
            struct.pack_into("<q", d, dataoff + imports_off + 8, 2 ** 63 - 1)
            v, = struct.unpack_from("<Q", d, dc[3]); struct.pack_into("<Q", d, dc[3], v | (0xFF << 24))
            out["chained-addend64-overflow"] = d
            seg_count, = struct.unpack_from("<I", data, dataoff + starts_off)
            for k in range(seg_count):
                info, = struct.unpack_from("<I", data, dataoff + starts_off + 4 + 4 * k)
                if info:
                    b = dataoff + starts_off + info
                    d = bytearray(data); struct.pack_into("<H", d, b + 4, 0); out["chained-pagesize-zero"] = d
                    d = bytearray(data); struct.pack_into("<H", d, b + 6, 6); struct.pack_into("<Q", d, b + 8, 2 ** 64 - 0x1000)
                    out["chained-segoffset-huge"] = d
                    break
    return out


def pe(data):
    pe_off, = struct.unpack_from("<I", data, 0x3C)
    opt = pe_off + 24
    out = {"truncated-headers": data[:0x100], "truncated-half": data[:len(data) // 2]}
    d = bytearray(data); struct.pack_into("<I", d, 0x3C, 0xFFFFFFF0); out["lfanew-huge"] = d
    d = bytearray(data); struct.pack_into("<H", d, pe_off + 6, 0xFFFF); out["nsections-huge"] = d
    d = bytearray(data); struct.pack_into("<I", d, opt + 112 + 5 * 8 + 4, 0xFFFFFFF0); out["reloc-size-huge"] = d
    d = bytearray(data); struct.pack_into("<I", d, opt + 112 + 1 * 8, 0xFFFFFF00); out["import-rva-huge"] = d
    d = bytearray(data); struct.pack_into("<I", d, opt + 108, 0xFFFFFFFF); out["directory-count-huge"] = d
    # the import directory too small to hold its terminating descriptor
    d = bytearray(data); struct.pack_into("<I", d, opt + 112 + 1 * 8 + 4, 20); out["import-size-no-terminator"] = d
    # a load configuration whose Size runs past the file, and one too short
    lc_rva, lc_size = struct.unpack_from("<II", data, opt + 112 + 10 * 8)
    if lc_size:
        nsec, = struct.unpack_from("<H", data, pe_off + 6)
        optsize, = struct.unpack_from("<H", data, pe_off + 20)
        for i in range(nsec):
            e = opt + optsize + i * 40
            vsize, va, raw, ptr = struct.unpack_from("<IIII", data, e + 8)
            if va <= lc_rva < va + min(vsize, raw):
                lc = ptr + lc_rva - va
                d = bytearray(data); struct.pack_into("<I", d, lc, 0x7FFFFFF0); out["load-config-size-huge"] = d
                d = bytearray(data); struct.pack_into("<I", d, lc, 2); out["load-config-size-tiny"] = d
                # a Size below GuardFlags while the directory covers them
                d = bytearray(data); struct.pack_into("<I", d, lc, 0x70); out["load-config-short-cfg-lost"] = d
    out.update(pe_unmapped(data))
    return out


def pe_unmapped(data):
    """Sections and typed words that no loader would map or that no typed
    region reaches."""
    pe_off, = struct.unpack_from("<I", data, 0x3C)
    opt = pe_off + 24
    nsec, = struct.unpack_from("<H", data, pe_off + 6)
    optsize, = struct.unpack_from("<H", data, pe_off + 20)
    secs = {}
    for i in range(nsec):
        e = opt + optsize + 40 * i
        secs[data[e:e + 8].rstrip(b"\0").decode()] = (e,) + struct.unpack_from("<IIII", data, e + 8)

    def off_of(rva):
        for e, vs, va, rs, rp in secs.values():
            if va <= rva < va + min(vs, rs):
                return rp + rva - va
        return None

    def dirent(i):
        return opt + 112 + 8 * i
    out = {}
    imp = off_of(struct.unpack_from("<I", data, dirent(1))[0])
    # .text at the top of the 32-bit RVA space: section arithmetic wraps
    d = bytearray(data); struct.pack_into("<I", d, secs[".text"][0] + 12, 0xFFFFFFF0); out["text-va-wraps"] = d
    # the IAT at an RVA no section maps, then inside the writable .data
    d = bytearray(data); struct.pack_into("<I", d, imp + 16, 0x7FFF0000); out["iat-unmapped"] = d
    d = bytearray(data); struct.pack_into("<I", d, imp + 16, secs[".data"][2]); out["iat-in-writable"] = d
    # every base relocation block after the first moved to an unmapped page
    rr, rsz = struct.unpack_from("<II", data, dirent(5))
    ro = off_of(rr)
    d = bytearray(data); o, first = ro, True
    while o + 8 <= ro + rsz:
        _page, block = struct.unpack_from("<II", data, o)
        if block < 8:
            break
        if not first:
            struct.pack_into("<I", d, o, 0x7FF00000)
        first = False
        o += block
    out["reloc-pages-unmapped"] = d
    # SizeOfHeaders beyond the file; .rdata at RVA 0, over the headers
    d = bytearray(data); struct.pack_into("<I", d, opt + 60, 0x7FFFFFFF); out["sizeofheaders-huge"] = d
    d = bytearray(data); struct.pack_into("<I", d, secs[".rdata"][0] + 12, 0); out["rdata-va-zero"] = d
    # the lookup table runs to the end of the file with ordinal entries
    ilt = off_of(struct.unpack_from("<I", data, imp)[0])
    d = bytearray(data)
    for k in range(ilt, len(d) - 7, 8):
        struct.pack_into("<Q", d, k, (1 << 63) | 1)
    out["ilt-runs-to-eof"] = d
    # e_lfanew at the last 4 bytes of the file
    d = bytearray(data); struct.pack_into("<I", d, 0x3C, len(data) - 4); d[-4:] = b"PE\0\0"; out["lfanew-at-eof"] = d
    return out


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("elf", "macho", "pe"):
        print(__doc__, file=sys.stderr)
        return 2
    fmt, src, outdir = sys.argv[1:]
    data = open(src, "rb").read()
    os.makedirs(outdir, exist_ok=True)
    cases = {"elf": elf, "macho": macho, "pe": pe}[fmt](data)
    if fmt == "macho":
        cases.update(macho_overlaps(data))
    for name, blob in cases.items():
        path = os.path.join(outdir, f"{fmt}-{name}")
        open(path, "wb").write(bytes(blob))
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
