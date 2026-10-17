#!/usr/bin/env python3
"""Names every zero-initialised module static whose bytes are file-backed.

The pre-operational tests run inside module initialisation, which the service
gates skip once the module state says the tests have run. A zero-initialised
static that the loader maps from the file rather than from zero-fill can
therefore be preset by editing the file. The signer refuses any artifact with
such a static. This report prints the same row independently, from the symbol
table, so the build arrangement that empties it can be measured on artifacts
the signer has not seen.

Usage:
  file-backed-statics.py [--match SUBSTR] [--map FILE] <artifact>
  file-backed-statics.py --selftest <dir-with-fixtures>

A module static is a data symbol whose name contains SUBSTR (default
`oxicrypt`, which every boundary crate's mangled names carry), defined in a
writable segment or section (on ELF, outside PT_GNU_RELRO, which is read-only
once relocated). It is file-backed when any of its bytes lie below the
segment's file size; it is zero-initialised when it sits in a zero-fill section
or all its file bytes are zero and, on ELF, no RELA relocation writes into it.
Initialised statics are FileOnly and are reported as a count only. A Mach-O
pointer bound through LC_DYLD_INFO opcodes also holds zero in the file and
would be named; the chained-fixup builds this report is for encode every
pointer in the file word.

ELF and Mach-O use their own symbol tables. A PE image normally carries none:
pass the linker map (`/MAP`) with --map; a COFF symbol table is used when
present.

Exit status: 0 the row is empty; 1 it is not; 2 no module static matched at
all, so an empty row would mean nothing (a control failure); 3 the artifact
could not be checked (no symbols, unknown format) or the script crashed.
"""
import os
import re
import struct
import sys


class Unchecked(Exception):
    pass


def elf_statics(data, match):
    if data[4] != 2 or data[5] != 1:
        raise Unchecked("only little-endian ELF64 is read")
    e_phoff, e_shoff = struct.unpack_from("<QQ", data, 0x20)
    e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from("<HHHH", data, 0x36)
    loads = []
    relro = (0, 0)
    for i in range(e_phnum):
        p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz = struct.unpack_from(
            "<IIQQQQQ", data, e_phoff + i * e_phentsize)
        if p_type == 1:
            loads.append((p_vaddr, p_memsz, p_offset, p_filesz, bool(p_flags & 2)))
        elif p_type == 0x6474E552:  # PT_GNU_RELRO: read-only once relocated
            relro = (p_vaddr, p_vaddr + p_memsz)
    if not e_shoff:
        raise Unchecked("no section headers")
    shdrs = []
    for i in range(e_shnum):
        shdrs.append(struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize))
    shstr = shdrs[struct.unpack_from("<H", data, 0x3E)[0]]

    def secname(sh):
        off = shstr[4] + sh[0]
        return data[off:data.index(b"\0", off)].decode(errors="replace")

    # A pointer the loader writes through RELA holds zero in the file; it is
    # initialised, not zero-initialised.
    rela_dests = set()
    for sh in shdrs:
        if sh[1] == 4:  # SHT_RELA
            for j in range(sh[5] // 24):
                rela_dests.add(struct.unpack_from("<Q", data, sh[4] + j * 24)[0])
    symtab = [sh for sh in shdrs if sh[1] == 2]  # SHT_SYMTAB
    if not symtab:
        raise Unchecked("no .symtab: the row must be taken before strip")
    sh = symtab[0]
    strtab = shdrs[sh[6]]
    out = []
    for i in range(sh[5] // 24):
        st_name, st_info, _other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", data, sh[4] + i * 24)
        if st_info & 0xF != 1 or st_shndx in (0, 0xFFF1) or st_shndx >= 0xFF00:
            continue  # STT_OBJECT, defined, not ABS/COMMON
        noff = strtab[4] + st_name
        name = data[noff:data.index(b"\0", noff)].decode(errors="replace")
        if match not in name:
            continue
        sec = shdrs[st_shndx]
        seg = next((l for l in loads if l[0] <= st_value < l[0] + l[1]), None)
        if not seg or not seg[4] or relro[0] <= st_value < relro[1]:
            continue
        vaddr, _memsz, offset, filesz, _w = seg
        size = max(st_size, 1)
        backed = max(0, min(st_value + size, vaddr + filesz) - st_value)
        nobits = sec[1] == 8
        fo = offset + st_value - vaddr
        relocated = any(st_value <= d < st_value + size for d in rela_dests)
        zero = nobits or (not relocated and not any(data[fo:fo + backed]))
        out.append((name, st_value, size, secname(sec), backed, zero))
    return out


S_ZEROFILL_TYPES = {0x1, 0xC, 0x12}


def macho_statics(data, match):
    magic, _cpu, _sub, _ft, ncmds, _sz, _flags = struct.unpack_from("<IiiIIII", data, 0)
    if magic != 0xFEEDFACF:
        raise Unchecked("only thin 64-bit Mach-O is read")
    segs, sects = [], []
    symoff = nsyms = stroff = 0
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, nsects, _fl = struct.unpack_from(
                "<QQQQiiII", data, off + 24)
            seg = (segname, vmaddr, vmsize, fileoff, filesize, bool(initprot & 2))
            segs.append(seg)
            for s in range(nsects):
                so = off + 72 + s * 80
                sectname = data[so:so + 16].rstrip(b"\0").decode()
                addr, size, offset = struct.unpack_from("<QQI", data, so + 32)
                flags, = struct.unpack_from("<I", data, so + 64)
                sects.append((f"{segname},{sectname}", addr, size, flags & 0xFF, seg))
        elif cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, _strsize = struct.unpack_from("<IIII", data, off + 8)
        off += cmdsize
    if not nsyms:
        raise Unchecked("no symbol table")
    syms = []
    for i in range(nsyms):
        n_strx, n_type, n_sect, _desc, n_value = struct.unpack_from("<IBBHQ", data, symoff + i * 16)
        if n_type & 0xE0 or n_type & 0x0E != 0x0E or not n_sect:
            continue  # stabs, or not defined in a section
        name = data[stroff + n_strx:data.index(b"\0", stroff + n_strx)].decode(errors="replace")
        syms.append((n_value, n_sect, name))
    # Mach-O symbols carry no size: a symbol extends to the next address in its
    # section, or to the section's end.
    syms.sort()
    out = []
    for idx, (value, nsect, name) in enumerate(syms):
        if match not in name or nsect > len(sects):
            continue
        sname, saddr, ssize, stype, seg = sects[nsect - 1]
        segname, vmaddr, _vmsize, fileoff, filesize, writable = seg
        if not writable or sname.startswith("__TEXT,"):
            continue
        nxt = next((v for v, s, _n in syms[idx + 1:] if s == nsect and v > value), saddr + ssize)
        size = max(nxt - value, 1)
        backed = max(0, min(value + size, vmaddr + filesize) - value)
        fo = fileoff + value - vmaddr
        zero = stype in S_ZEROFILL_TYPES or not any(data[fo:fo + backed])
        out.append((name, value, size, sname, backed, zero))
    return out


def pe_sections(data):
    pe, = struct.unpack_from("<I", data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise Unchecked("not a PE image")
    nsec, = struct.unpack_from("<H", data, pe + 6)
    symptr, nsyms = struct.unpack_from("<II", data, pe + 12)
    optsize, = struct.unpack_from("<H", data, pe + 20)
    image_base, = struct.unpack_from("<Q", data, pe + 24 + 24)
    table = pe + 24 + optsize
    secs = []
    for i in range(nsec):
        e = table + i * 40
        name = data[e:e + 8].rstrip(b"\0").decode(errors="replace")
        vsize, rva, rawsize, rawptr = struct.unpack_from("<IIII", data, e + 8)
        chars, = struct.unpack_from("<I", data, e + 36)
        secs.append((name, rva, vsize, rawptr, rawsize, bool(chars & 0x80000000)))
    return secs, symptr, nsyms, image_base


def pe_statics(data, match, map_path):
    secs, symptr, nsyms, image_base = pe_sections(data)
    found = []  # (name, section index 1-based, offset in section)
    if map_path:
        # MSVC-format map: " 0003:00000010       name   0000000180005010 ..."
        pat = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+(\S+)\s+([0-9A-Fa-f]{8,16})\b")
        for line in open(map_path, encoding="utf-8", errors="replace"):
            m = pat.match(line)
            if m and int(m.group(1), 16):
                found.append((m.group(3), int(m.group(1), 16), int(m.group(2), 16)))
        if not found:
            raise Unchecked(f"{map_path}: no public symbols parsed")
    elif symptr and nsyms:
        strtab = symptr + nsyms * 18
        i = 0
        while i < nsyms:
            e = symptr + i * 18
            raw = data[e:e + 8]
            value, secnum, _typ, _cls, naux = struct.unpack_from("<IhHBB", data, e + 8)
            if raw[:4] == b"\0\0\0\0":
                so = strtab + struct.unpack_from("<I", raw, 4)[0]
                name = data[so:data.index(b"\0", so)].decode(errors="replace")
            else:
                name = raw.rstrip(b"\0").decode(errors="replace")
            if secnum > 0:
                found.append((name, secnum, value))
            i += 1 + naux
    else:
        raise Unchecked("no COFF symbol table and no --map: names need the linker map")
    out = []
    for name, secnum, value in found:
        if match not in name or secnum > len(secs):
            continue
        sname, rva, vsize, rawptr, rawsize, writable = secs[secnum - 1]
        if not writable:
            continue
        backed_len = min(vsize, rawsize)
        # Size unknown: one byte decides whether the static starts in the file.
        backed = 1 if value < backed_len else 0
        zero = not any(data[rawptr + value:rawptr + value + 8]) if backed else True
        out.append((name, rva + value, 1, sname, backed, zero))
    return out


def report(path, match, map_path=None, out=print):
    data = open(path, "rb").read()
    try:
        if data[:4] == b"\x7fELF":
            fmt, rows = "elf", elf_statics(data, match)
        elif data[:4] == b"\xcf\xfa\xed\xfe":
            fmt, rows = "macho", macho_statics(data, match)
        elif data[:2] == b"MZ":
            fmt, rows = "pe", pe_statics(data, match, map_path)
        else:
            raise Unchecked("unknown format")
    except Unchecked as e:
        out(f"{path}: file-backed module statics: NOT CHECKED ({e})")
        return 3
    if not rows:
        out(f"{path}: CONTROL FAILED: no module static matching '{match}' in a writable segment; "
            "an empty row would prove nothing")
        return 2
    backed = [r for r in rows if r[4]]
    zero = [r for r in backed if r[5]]
    out(f"{path}: format={fmt} module statics matching '{match}' in writable segments: {len(rows)}; "
        f"file-backed initialised (FileOnly): {len(backed) - len(zero)}; file-backed zero-initialised: {len(zero)}")
    if not zero:
        out("file-backed module statics: none")
        return 0
    out("file-backed module statics:")
    for name, addr, size, sname, nbacked, _z in zero:
        out(f"  STATIC addr={addr:#x} size={size} file_backed={nbacked} section={sname} name={name}")
    return 1


def selftest(fixtures):
    """Each fixture names the outcome it must produce."""
    cases = [
        ("fixture.so", 0, "oxicrypt"), ("fixture-filebacked.so", 1, "oxicrypt"),
        ("fixture-stripped.so", 3, "oxicrypt"), ("fixture.so", 2, "no_such_module_name"),
        ("fixture.dylib", 0, "oxicrypt"), ("fixture-filebacked.dylib", 1, "oxicrypt"),
        ("fixture.dylib", 2, "no_such_module_name"),
        ("fixture.dll", 1, "oxicrypt"), ("fixture-filebacked.dll", 1, "oxicrypt"),
        ("fixture-initialised.dll", 0, "oxicrypt"), ("fixture.dll", 2, "no_such_module_name"),
    ]
    bad = ran = 0
    for name, want, match in cases:
        path = os.path.join(fixtures, name)
        if not os.path.exists(path):
            print(f"skipped  {name} (not built here)")
            continue
        lines = []
        mp = path[:-4] + ".map" if path.endswith(".dll") and os.path.exists(path[:-4] + ".map") else None
        got = report(path, match, mp, lines.append)
        ran += 1
        verdict = "ok" if got == want else "MISMATCH"
        bad += got != want
        print(f"{verdict:8} {name} (match {match}): expected {want}, got {got}")
        if got != want:
            print("\n".join("    " + l for l in lines))
    if not ran:
        print("control FAILED: no fixture ran")
        return False
    return bad == 0


def main(argv):
    match, map_path = "oxicrypt", None
    while argv and argv[0].startswith("--"):
        if argv[0] == "--selftest" and len(argv) == 2:
            return 0 if selftest(argv[1]) else 2
        if argv[0] == "--match" and len(argv) > 1:
            match = argv[1]
        elif argv[0] == "--map" and len(argv) > 1:
            map_path = argv[1]
        else:
            print(__doc__, file=sys.stderr)
            return 3
        argv = argv[2:]
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 3
    return report(argv[0], match, map_path)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:  # a crash must never read as a row
        import traceback
        traceback.print_exc()
        print("CRASHED: file-backed-statics.py")
        sys.exit(3)
