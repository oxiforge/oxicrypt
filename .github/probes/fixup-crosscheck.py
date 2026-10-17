#!/usr/bin/env python3
"""Cross-checks an artifact's loader fixups between two independent parses.

Every word the loader writes must be typed, and a typing that misses one is
silent. So the set of fixups is taken twice, by different code, and the two
sets must be equal. This script is one side: it parses the artifact's own
loader structures. The other side is the platform's tool, whose output is
passed in:

  elf   <so>    --readelf-r FILE [--readelf-d FILE]
        `readelf -rW` (and `readelf -dW`) output. Tuples: (offset, r_type)
        for every RELA entry and RELR address, and the `.dynamic` tags with
        their numeric values.

  macho <dylib> --tool FILE
        `dyld_info -fixups` or `llvm-objdump --macho --dyld-info` /
        `--rebase --bind --lazy-bind --weak-bind` output. Tuples:
        (address, rebase|bind), from chained fixups or from the rebase and
        bind opcode streams.

  pe    <dll>   --tool FILE
        `win-image-stability-probe --relocs` (RELOCENT lines) or
        `llvm-readobj --coff-basereloc` output. Tuples: (rva, type) for every
        base relocation other than ABSOLUTE padding.

When the sets are equal, the tool's own output is mutated: the line that
prints the lowest-keyed tuple is dropped, and separately its address (or tag)
is moved to an unused value. The tool's output is parsed again each time and
must no longer equal this side's set, or the comparison could not have failed
and the run proves nothing.

Exit status: 0 equal and both controls fired; 1 the sets differ (the measured
verdict); 2 a control did not fire or could not run; 3 an input could not be
parsed, a set was empty, or the script crashed.
"""
import re
import struct
import sys


class Unparsed(Exception):
    pass


# ---- ELF ---------------------------------------------------------------------

def elf_parse(data):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise Unparsed("not little-endian ELF64")
    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    loads, dyn = [], None
    for i in range(e_phnum):
        p_type, _f, p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from("<IIQQQQ", data, e_phoff + i * e_phentsize)
        if p_type == 1:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 2:
            dyn = (p_offset, p_filesz)
    if not dyn:
        raise Unparsed("no PT_DYNAMIC")

    def v2o(va):
        for vaddr, off, filesz in loads:
            if vaddr <= va < vaddr + filesz:
                return off + va - vaddr
        raise Unparsed(f"address {va:#x} is not file-backed")

    tags, d = [], {}
    for o in range(dyn[0], dyn[0] + dyn[1] - 15, 16):
        tag, val = struct.unpack_from("<qQ", data, o)
        if tag == 0:
            break
        tags.append((tag, val))
        d.setdefault(tag, val)
    relocs = set()
    for tab, size in ((7, 8), (23, 2)):  # DT_RELA/DT_RELASZ, DT_JMPREL/DT_PLTRELSZ
        if tab in d:
            base = v2o(d[tab])
            for k in range(d.get(size, 0) // 24):
                r_offset, r_info = struct.unpack_from("<QQ", data, base + k * 24)
                relocs.add((r_offset, r_info & 0xFFFFFFFF))
    for tab, size in ((36, 35), (0x6FFFE000, 0x6FFFE001)):  # DT_RELR, DT_ANDROID_RELR
        if tab in d:
            base, where = v2o(d[tab]), 0
            for k in range(d.get(size, 0) // 8):
                v, = struct.unpack_from("<Q", data, base + k * 8)
                if not v & 1:
                    relocs.add((v, "relr"))
                    where = v + 8
                else:
                    b = 0
                    v >>= 1
                    while v:
                        if v & 1:
                            relocs.add((where + b * 8, "relr"))
                        v >>= 1
                        b += 1
                    where += 63 * 8
    return relocs, tags


def readelf_r(text):
    out = set()
    relr = False
    for line in text.splitlines():
        if line.startswith("Relocation section"):
            relr = ".relr" in line
            continue
        if relr:
            # Two binutils layouts. Up to 2.42 (Ubuntu 24.04's; readelf.c's
            # reltype_relr branch prints `  N offsets` and then each decoded
            # address as "%016" PRIx64 "\n"): one address per line at column 0.
            # From 2.43: `NNNN:  <entry> <address> <symbol>`, with each further
            # address the entry decodes on its own indented line.
            m = re.match(r"^\d+:\s+[0-9a-f]+\s+([0-9a-f]{8,16})\b", line) or \
                re.match(r"^\s+([0-9a-f]{8,16})\b", line) or \
                re.match(r"^([0-9a-f]{8,16})\s*$", line)
            if m:
                out.add((int(m.group(1), 16), "relr"))
            continue
        m = re.match(r"^\s*([0-9a-f]{8,16})\s+([0-9a-f]{8,16})\s+R_\S+", line)
        if m:
            out.add((int(m.group(1), 16), int(m.group(2), 16) & 0xFFFFFFFF))
    return out


def readelf_d(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*0x([0-9a-f]+)\s+\((\w+)\)\s+(.*)$", line)
        if not m:
            continue
        tag = int(m.group(1), 16)
        if tag == 0:
            break
        v = m.group(3).strip()
        num = None
        if re.fullmatch(r"0x[0-9a-f]+", v):
            num = int(v, 16)
        elif re.fullmatch(r"\d+( \(bytes\))?", v):
            num = int(v.split()[0])
        out.append((tag, num))
    return out


# ---- Mach-O ------------------------------------------------------------------

# dyld keeps segment offsets in 64-bit unsigned arithmetic: an ADD_ADDR_ULEB
# of 2^64 - 8 steps back one word. Every offset sum wraps the same way here.
M64 = (1 << 64) - 1


def uleb(data, i):
    v = shift = 0
    while True:
        b = data[i]
        i += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return v, i


def sleb(data, i):
    v = shift = 0
    while True:
        b = data[i]
        i += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            if b & 0x40:
                v -= 1 << shift
            return v, i


def macho_parse(data):
    magic, _cpu, _sub, _ft, ncmds, _sz, _fl = struct.unpack_from("<IiiIIII", data, 0)
    if magic != 0xFEEDFACF:
        raise Unparsed("not a thin 64-bit Mach-O")
    segs, info, chained, off = [], None, None, 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append((vmaddr, fileoff, filesize))
        elif cmd in (0x22, 0x80000022):  # LC_DYLD_INFO(_ONLY)
            info = struct.unpack_from("<10I", data, off + 8)
        elif cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
            chained = struct.unpack_from("<II", data, off + 8)
        off += cmdsize
    out = set()
    if chained:
        out |= macho_chained(data, segs, *chained)
    if info:
        rebase_off, rebase_size, bind_off, bind_size, weak_off, weak_size, lazy_off, lazy_size = info[:8]
        out |= macho_rebase(data[rebase_off:rebase_off + rebase_size], segs)
        out |= macho_bind(data[bind_off:bind_off + bind_size], segs, lazy=False)
        out |= macho_bind(data[weak_off:weak_off + weak_size], segs, lazy=False)
        out |= macho_bind(data[lazy_off:lazy_off + lazy_size], segs, lazy=True)
    if not chained and not info:
        raise Unparsed("neither LC_DYLD_CHAINED_FIXUPS nor LC_DYLD_INFO")
    return out


def macho_rebase(ops, segs):
    out, i, seg, offset = set(), 0, 0, 0

    def emit():
        out.add(((segs[seg][0] + offset) & M64, "rebase"))

    while i < len(ops):
        op, imm = ops[i] & 0xF0, ops[i] & 0x0F
        i += 1
        if op == 0x00:
            break
        elif op == 0x10:
            pass
        elif op == 0x20:
            seg = imm
            offset, i = uleb(ops, i)
        elif op == 0x30:
            v, i = uleb(ops, i)
            offset = (offset + v) & M64
        elif op == 0x40:
            offset = (offset + imm * 8) & M64
        elif op == 0x50:
            for _ in range(imm):
                emit()
                offset = (offset + 8) & M64
        elif op == 0x60:
            n, i = uleb(ops, i)
            for _ in range(n):
                emit()
                offset = (offset + 8) & M64
        elif op == 0x70:
            v, i = uleb(ops, i)
            emit()
            offset = (offset + v + 8) & M64
        elif op == 0x80:
            n, i = uleb(ops, i)
            skip, i = uleb(ops, i)
            for _ in range(n):
                emit()
                offset = (offset + skip + 8) & M64
        else:
            raise Unparsed(f"rebase opcode {op:#x}")
    return out


def macho_bind(ops, segs, lazy):
    out, i, seg, offset = set(), 0, 0, 0
    flags = 0

    def emit():
        if not flags & 0x8:  # BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: no fixup
            out.add(((segs[seg][0] + offset) & M64, "bind"))

    while i < len(ops):
        op, imm = ops[i] & 0xF0, ops[i] & 0x0F
        i += 1
        if op == 0x00:
            if lazy:
                continue
            break
        elif op in (0x10, 0x30, 0x50):
            pass
        elif op == 0x20:
            _v, i = uleb(ops, i)
        elif op == 0x40:
            flags = imm
            i = ops.index(b"\0", i) + 1
        elif op == 0x60:
            _v, i = sleb(ops, i)
        elif op == 0x70:
            seg = imm
            offset, i = uleb(ops, i)
        elif op == 0x80:
            v, i = uleb(ops, i)
            offset = (offset + v) & M64
        elif op == 0x90:
            emit()
            offset = (offset + 8) & M64
        elif op == 0xA0:
            v, i = uleb(ops, i)
            emit()
            offset = (offset + v + 8) & M64
        elif op == 0xB0:
            emit()
            offset = (offset + imm * 8 + 8) & M64
        elif op == 0xC0:
            n, i = uleb(ops, i)
            skip, i = uleb(ops, i)
            for _ in range(n):
                emit()
                offset = (offset + skip + 8) & M64
        else:
            raise Unparsed(f"bind opcode {op:#x}")
    return out


def macho_chained(data, segs, dataoff, datasize):
    blob = data[dataoff:dataoff + datasize]
    _ver, starts_offset = struct.unpack_from("<II", blob, 0)
    seg_count, = struct.unpack_from("<I", blob, starts_offset)
    out = set()
    for s in range(seg_count):
        info_off, = struct.unpack_from("<I", blob, starts_offset + 4 + 4 * s)
        if not info_off:
            continue
        base = starts_offset + info_off
        _size, page_size, fmt, _segoff, _maxv, page_count = struct.unpack_from("<IHHQIH", blob, base)
        if fmt not in (2, 6):  # DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET
            raise Unparsed(f"chained pointer format {fmt}")
        vmaddr, fileoff, _filesize = segs[s]
        for p in range(page_count):
            start, = struct.unpack_from("<H", blob, base + 22 + 2 * p)
            if start == 0xFFFF:
                continue
            if start & 0x8000:
                raise Unparsed("multi-start page")
            o, seen = p * page_size + start, set()
            while True:
                if o in seen:
                    raise Unparsed("chain loop")
                seen.add(o)
                v, = struct.unpack_from("<Q", data, fileoff + o)
                out.add((vmaddr + o, "bind" if v >> 63 else "rebase"))
                nxt = (v >> 51) & 0xFFF
                if not nxt:
                    break
                o += nxt * 4
    return out


def macho_tool(text):
    out = set()
    table = None
    for line in text.splitlines():
        low = line.strip().lower()
        if low.endswith("table:"):
            table = "rebase" if low.startswith("rebase") else "bind"
            continue
        toks = line.split()
        if len(toks) < 3 or not toks[0].startswith("__"):
            continue
        addr = next((t for t in toks[1:4] if re.fullmatch(r"0x[0-9a-fA-F]+", t)), None)
        if addr is None:
            continue
        kinds = [t for t in toks if t in ("rebase", "bind", "weak-bind", "lazy-bind", "auth-rebase", "auth-bind",
                                          "rebase-auth", "bind-auth")]
        kind = kinds[0] if kinds else table
        if kind is None:
            continue
        out.add((int(addr, 16), "bind" if "bind" in kind else "rebase"))
    return out


# ---- PE ----------------------------------------------------------------------

def pe_parse(data):
    if data[:2] != b"MZ":
        raise Unparsed("not a PE image")
    pe, = struct.unpack_from("<I", data, 0x3C)
    nsec, = struct.unpack_from("<H", data, pe + 6)
    optsize, = struct.unpack_from("<H", data, pe + 20)
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        raise Unparsed("not PE32+")
    rva, size = struct.unpack_from("<II", data, opt + 112 + 5 * 8)
    secs = []
    for i in range(nsec):
        e = opt + optsize + i * 40
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, e + 8)
        secs.append((va, max(vsize, rawsize), rawptr))
    fo = next((rawptr + rva - va for va, n, rawptr in secs if va <= rva < va + n), None)
    if not size or fo is None:
        raise Unparsed("no base relocation table")
    out, o = set(), fo
    while o + 8 <= fo + size:
        page, block = struct.unpack_from("<II", data, o)
        if block < 8:
            break
        for k in range((block - 8) // 2):
            ent, = struct.unpack_from("<H", data, o + 8 + 2 * k)
            if ent >> 12:
                out.add((page + (ent & 0xFFF), ent >> 12))
        o += block
    return out


READOBJ_TYPES = {"ABSOLUTE": 0, "HIGH": 1, "LOW": 2, "HIGHLOW": 3, "HIGHADJ": 4, "DIR64": 10}


def pe_tool(text):
    out = set()
    for m in re.finditer(r"RELOCENT rva=0x([0-9a-fA-F]+) type=(\d+)", text):
        out.add((int(m.group(1), 16), int(m.group(2))))
    for m in re.finditer(r"Type:\s*(\w+)\s+Address:\s*0x([0-9a-fA-F]+)", text):
        t = READOBJ_TYPES.get(m.group(1), m.group(1))
        if t != 0:
            out.add((int(m.group(2), 16), t))
    return out


# ---- comparison --------------------------------------------------------------

PASS, UNEQUAL, CONTROL_FAILED, UNREADABLE = 0, 1, 2, 3
HEX = re.compile(r"(?<![0-9A-Za-z_])(0x)?([0-9a-fA-F]+)(?![0-9A-Za-z_])")


def record_line(lines, key):
    """The first tool-output line carrying `key` as a hex token, and that token."""
    for i, line in enumerate(lines):
        for m in HEX.finditer(line):
            if m.group(2) and int(m.group(2), 16) == key:
                return i, m
    return None, None


def compare(name, ours, text, parse_tool, key_of, out=print):
    """Compares this side's tuples with the tool's, then mutates the tool's own
    output text and requires the comparison to see each mutation.

    `parse_tool` turns tool output into tuples; `key_of` gives the integer a
    tuple is printed under in that output (an address, or a tag). The record
    line is found by that integer, not by trying lines until one matters, so a
    tool parser that ignored its own record line would leave the sets equal
    and fail the control.
    """
    theirs = parse_tool(text)
    if not ours or not theirs:
        out(f"UNPARSED: {name}: an empty set ({len(ours)} here, {len(theirs)} from the tool)")
        return UNREADABLE
    if ours != theirs:
        only_ours, only_theirs = sorted(ours - theirs, key=str), sorted(theirs - ours, key=str)
        out(f"FAILED: {name}: {len(ours)} here, {len(theirs)} from the tool; "
            f"{len(only_ours)} only here, {len(only_theirs)} only from the tool")
        for t in only_ours[:5]:
            out(f"  only here:          {t}")
        for t in only_theirs[:5]:
            out(f"  only from the tool: {t}")
        return UNEQUAL
    lines = text.splitlines()
    keys = {key_of(t) for t in ours}
    first = min(ours, key=lambda t: (key_of(t), str(t)))
    i, m = record_line(lines, key_of(first))
    if i is None:
        out(f"CONTROL FAILED: {name}: no line of the tool's output carries {key_of(first):#x}; "
            "the drop and move controls cannot run")
        return CONTROL_FAILED
    new = next(key_of(first) + d for d in range(8, 1 << 24, 8) if key_of(first) + d not in keys)

    def moved(t):  # every token on the line that carries the key, so a column
        if t.group(2) and int(t.group(2), 16) == key_of(first):  # printed twice moves too
            return (t.group(1) or "") + format(new, "x").rjust(len(t.group(2)), "0")
        return t.group(0)
    moved_line = HEX.sub(moved, lines[i])
    controls = {
        "drop": "\n".join(lines[:i] + lines[i + 1:]),
        "move": "\n".join(lines[:i] + [moved_line] + lines[i + 1:]),
    }
    dead = [k for k, t in controls.items() if parse_tool(t) == ours]
    if dead:
        out(f"CONTROL FAILED: {name}: the tool output with its record line "
            f"{' and '.join(dead)}{'ped' if dead == ['drop'] else 'd'} still compared equal (line {i + 1})")
        return CONTROL_FAILED
    out(f"ok: {name}: {len(ours)} tuples equal; dropping and moving the tool's record line "
        f"{i + 1} ({key_of(first):#x}) each made them unequal")
    return PASS


def selftest():
    """A bind stream that steps backwards through 64-bit wrap must land on the
    word below, as dyld lands on it."""
    def enc(v):
        out = bytearray()
        while True:
            b, v = v & 0x7F, v >> 7
            out.append(b | (0x80 if v else 0))
            if not v:
                return bytes(out)
    segs = [(0x0, 0, 0x1000), (0x2AF000, 0x2AF000, 0x1000)]
    # segment 1, offset 0x10: bind; step back 0x18 (wrapping), bind again
    ops = bytes([0x11, 0x40]) + b"_x\0" + bytes([0x71]) + enc(0x10) + bytes([0x90, 0x80]) \
        + enc((1 << 64) - 0x18) + bytes([0x90, 0x00])
    got = macho_bind(ops, segs, lazy=False)
    want = {(0x2AF010, "bind"), (0x2AF000, "bind")}
    ok = got == want
    print(f"{'ok' if ok else 'MISMATCH'} a bind stepped back through 64-bit wrap: {sorted(got)} (want {sorted(want)})")
    return ok


def run(argv):
    if argv == ["--selftest"]:
        return PASS if selftest() else CONTROL_FAILED
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return UNREADABLE
    fmt, path, rest = argv[0], argv[1], argv[2:]
    opts = dict(zip(rest[0::2], rest[1::2]))
    data = open(path, "rb").read()
    try:
        if fmt == "elf":
            relocs, tags = elf_parse(data)
            rc = compare("relocations", relocs, open(opts["--readelf-r"]).read(), readelf_r, lambda t: t[0])
            if rc == PASS and "--readelf-d" in opts:
                text = open(opts["--readelf-d"]).read()
                theirs = readelf_d(text)
                ours = list(tags)
                # readelf prints some values symbolically (names, flags); those
                # entries are compared by tag and position only.
                if len(ours) == len(theirs):
                    ours = [(t, v if n is not None else None) for (t, v), (_t, n) in zip(ours, theirs)]
                rc = compare("dynamic entries", set(enumerate(ours)), text,
                             lambda t: set(enumerate(readelf_d(t))), lambda t: t[1][0])
            return rc
        if fmt == "macho":
            return compare("fixups", macho_parse(data), open(opts["--tool"]).read(), macho_tool, lambda t: t[0])
        if fmt == "pe":
            return compare("base relocations", pe_parse(data), open(opts["--tool"]).read(), pe_tool, lambda t: t[0])
    except Unparsed as e:
        print(f"UNPARSED: {e}")
        return UNREADABLE
    except KeyError as e:
        print(f"missing option {e}", file=sys.stderr)
        return UNREADABLE
    print(__doc__, file=sys.stderr)
    return UNREADABLE


if __name__ == "__main__":
    try:
        sys.exit(run(sys.argv[1:]))
    except Exception:  # a crash must never read as a comparison
        import traceback
        traceback.print_exc()
        print("CRASHED: fixup-crosscheck.py")
        sys.exit(UNREADABLE)
