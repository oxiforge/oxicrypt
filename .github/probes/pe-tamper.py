#!/usr/bin/env python3
"""The PE rows of the integrity tamper matrix.

  rows <dll> <show.txt>
      Prints one row per line: `name offset mask allowed`. `offset` is a file
      offset in the integrity-signed DLL, `mask` the byte to XOR into it, and
      `allowed` the outcomes allowed, comma-separated, each `exit:status`:
      pe-ffi-operational's exit status and the integrity status it prints
      (`-` when it prints none). Offsets come from the DLL's own headers and
      tables and from the signer's `--show` listing of it (`[i] Kind rva ..
      file .. len ..` lines and `slot at file offset ..`). A row whose
      structure the DLL lacks is printed as `name - - -`, which the caller
      treats as a failure.

  cfg <dll>
      Prints `name rva file-value image-base` for each storage word the
      load configuration names for the loader to write (`cfg-check`,
      `cfg-dispatch`, `xfg-check`, `castguard`, `memcpy` and the rest).

  envelope <dll>
      Prints the `rows` line for a byte inside the Authenticode certificate
      table of a DLL signtool signed, which the module never reads.

  apply <file> <offset> <mask>
      XORs `mask`, little-endian, into the bytes from `offset`, in place.

  --selftest
      Checks the row selection that needs no DLL against fixed cases.

Every edited byte is one nothing reads before the integrity test, so the
test, not a crash or an earlier self-test, gives the verdict.

Exit status: 0 done, 1 a self-test case failed, 2 the input could not be read,
3 a crash.
"""
import re
import struct
import sys

# Refused by the integrity test as SignatureInvalid (2) or KeyMismatch (9);
# operational (0:1).
REFUSED = "1:2"
KEY_MISMATCH = "1:9"
OPERATIONAL = "0:1"
# Version-4 slot fields: the ML-DSA-87 signature, then the key fingerprint.
OFF_SIG, OFF_KEY_ID = 32, 4659

# Imports nothing calls before the integrity test: file and console
# services the module's start-up does not use.
COLD_IMPORTS = ["SetFileTime", "FindClose", "FindFirstFileExW", "FormatMessageW",
                "SetFileInformationByHandle"]
# The entry points the harness calls.
CALLED = {b"oxi_init", b"oxi_is_operational", b"oxi_integrity_status"}


class Pe:
    def __init__(self, data):
        if data[:2] != b"MZ":
            raise ValueError("not a PE image")
        self.data = data
        pe, = struct.unpack_from("<I", data, 0x3C)
        nsec, = struct.unpack_from("<H", data, pe + 6)
        optsize, = struct.unpack_from("<H", data, pe + 20)
        self.opt = pe + 24
        self.image_base, = struct.unpack_from("<Q", data, self.opt + 24)
        self.headers, = struct.unpack_from("<I", data, self.opt + 60)
        count, = struct.unpack_from("<I", data, self.opt + 108)
        self.dirs = [struct.unpack_from("<II", data, self.opt + 112 + 8 * i) for i in range(count)]
        self.dirs += [(0, 0)] * (16 - len(self.dirs))
        self.table = self.opt + optsize
        self.sections = []
        for i in range(nsec):
            e = self.table + 40 * i
            name = data[e:e + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, raw, ptr = struct.unpack_from("<IIII", data, e + 8)
            self.sections.append((name, va, vsize, ptr, raw))

    def off(self, rva):
        if rva < self.headers:
            return rva
        for _name, va, vsize, ptr, raw in self.sections:
            if va <= rva < va + min(vsize or raw, raw):
                return ptr + rva - va
        return None

    def cstr(self, rva):
        o = self.off(rva)
        return self.data[o:self.data.index(b"\0", o)]

    def exports(self):
        """(name, function RVA) of every named export."""
        rva, size = self.dirs[0]
        if not size:
            return []
        o = self.off(rva)
        nnames, funcs, names, ords = struct.unpack_from("<IIII", self.data, o + 24)
        out = []
        for i in range(nnames):
            name_rva, = struct.unpack_from("<I", self.data, self.off(names) + 4 * i)
            ordinal, = struct.unpack_from("<H", self.data, self.off(ords) + 2 * i)
            func, = struct.unpack_from("<I", self.data, self.off(funcs) + 4 * ordinal)
            out.append((self.cstr(name_rva), func, name_rva))
        return out

    def export_dll_name(self):
        """The file offset of the middle character of the export
        directory's DLL name."""
        rva, size = self.dirs[0]
        if not size:
            return None
        name_rva, = struct.unpack_from("<I", self.data, self.off(rva) + 12)
        return self.off(name_rva + len(self.cstr(name_rva)) // 2)

    def imports(self):
        """(descriptor RVA, dll, [(lookup entry RVA, name, hint/name RVA)])."""
        rva, size = self.dirs[1]
        out = []
        d = rva
        while size:
            lookup, _stamp, _fwd, name, _thunks = struct.unpack_from("<IIIII", self.data, self.off(d))
            if lookup == 0 and name == 0:
                break
            entries = []
            k = 0
            while True:
                e, = struct.unpack_from("<Q", self.data, self.off(lookup + 8 * k))
                if e == 0:
                    break
                if not e >> 63:
                    entries.append((lookup + 8 * k, self.cstr(e + 2).decode(), e))
                k += 1
            out.append((d, self.cstr(name).decode(), entries))
            d += 20
        return out

    def relocation_padding(self):
        """The file offset of the first ABSOLUTE (padding) base relocation."""
        rva, size = self.dirs[5]
        o = self.off(rva)
        end = o + size if o is not None else 0
        while o is not None and o < end:
            _page, block = struct.unpack_from("<II", self.data, o)
            for k in range((block - 8) // 2):
                ent, = struct.unpack_from("<H", self.data, o + 8 + 2 * k)
                if ent >> 12 == 0:
                    return o + 8 + 2 * k
            o += block
        return None

    def load_config(self):
        rva, size = self.dirs[10]
        return self.off(rva) if size else None


def first_fileonly_in(entries, section):
    """The first file offset inside `section` (start, end) that a FileOnly
    entry covers, or None. The signer merges entries that are contiguous in
    both the file and the image, so an entry can start in the section before
    and run into this one; it counts from the section's first byte."""
    if section is None:
        return None
    start, end = section
    hits = [max(f, start) for k, f, n in entries
            if k == "FileOnly" and f < end and f + n > start]
    return min(hits) if hits else None


def selftest():
    data = (0x2E9A00, 0x2E9C00)
    cases = [
        ("an entry inside the section", first_fileonly_in([("FileOnly", 0x2E9A5A, 422)], data), 0x2E9A5A),
        ("an entry running into the section from the one before",
         first_fileonly_in([("FileOnly", 0x2E99D0, 560)], data), 0x2E9A00),
        ("the lowest of several", first_fileonly_in([("FileOnly", 0x2E9B00, 4), ("FileOnly", 0x2E99F0, 32)], data),
         0x2E9A00),
        ("an entry ending at the section's first byte", first_fileonly_in([("FileOnly", 0x2E9900, 0x100)], data),
         None),
        ("an entry starting at the section's end", first_fileonly_in([("FileOnly", 0x2E9C00, 10)], data), None),
        ("an entry spanning the whole section", first_fileonly_in([("FileOnly", 0x2E9900, 0x400)], data), 0x2E9A00),
        ("another kind", first_fileonly_in([("Plain", 0x2E9A00, 16)], data), None),
        ("no such section", first_fileonly_in([("FileOnly", 0x2E9A00, 16)], None), None),
    ]
    def show(v):
        return hex(v) if v is not None else v

    bad = 0
    for name, got, want in cases:
        ok = got == want
        bad += not ok
        print(f"{'ok' if ok else 'MISMATCH':8} {name}: expected {show(want)}, got {show(got)}")
    return bad == 0


def rows(dll, show, out=print):
    data = open(dll, "rb").read()
    text = open(show).read()
    pe = Pe(data)
    entries = [(m.group(1), int(m.group(2), 16), int(m.group(3)))
               for m in re.finditer(r"\[\d+\] (\w+) rva 0x[0-9a-f]+ file (0x[0-9a-f]+) len (\d+)", text)]
    slot = re.search(r"slot at file offset (0x[0-9a-f]+)", text)
    slot = int(slot.group(1), 16) if slot else None

    def row(name, offset, mask, allowed=REFUSED):
        out(f"{name} - - -" if offset is None else f"{name} {offset} {mask} {allowed}")

    # Code: the fifth byte of the first C-ABI entry point, by name, that the
    # harness does not call.
    exported = sorted((n, f, nr) for n, f, nr in pe.exports() if n.startswith(b"oxi_") and n not in CALLED)
    row("text-code", pe.off(exported[0][1] + 4) if exported else None, 0x01)
    # A section header field the loader does not read: PointerToLinenumbers.
    row("section-table-reserved", pe.table + 28, 0x01)
    # A padding entry of the base relocation table: still padding.
    row("reloc-padding-entry", pe.relocation_padding(), 0x01)
    # A Plain constant: a character of the export directory's own DLL name,
    # which neither the loader nor GetProcAddress reads.
    row("plain-export-dll-name", pe.export_dll_name(), 0x01)
    # The imports: a lookup-table entry of an import nothing calls before the
    # test retargeted to another such import of the same DLL; a hint; a
    # descriptor's ForwarderChain, which the loader reads only for bound
    # imports.
    retarget = hint = descriptor = None
    for d, _dll, lookups in pe.imports():
        named = {n: (at, hn) for at, n, hn in lookups}
        cold = [n for n in COLD_IMPORTS if n in named]
        if len(cold) >= 2 and retarget is None:
            at, hn = named[cold[0]]
            retarget = (pe.off(at), hn ^ named[cold[1]][1])
            hint = pe.off(hn)
            descriptor = pe.off(d + 8)
    row("ilt-entry-retargeted", *(retarget or (None, 0)))
    row("import-hint", hint, 0x01)
    row("descriptor-forwarder-chain", descriptor, 0x01)
    # A Relative word: the load configuration's first XFG pointer, which an
    # image without XFG enabled never uses.
    lc = pe.load_config()
    row("relative-xfg-pointer", lc + 0x118 if lc is not None else None, 0x10)
    # A thunk on disk: the loader overwrites it.
    bind = next(((f, n) for k, f, n in entries if k == "Bind"), None)
    row("iat-thunk-on-disk", bind[0] if bind else None, 0x01, OPERATIONAL)
    # Storage the loader may write, signed from the file: the CFG check
    # pointer's, which the loader rewrites in a process with control-flow
    # guard, and the XFG check pointer's, which nothing calls in an image
    # without XFG; the second keeps its low bits, so a call through it
    # would still land on an instruction boundary.
    def storage(field):
        if lc is None:
            return None
        va, = struct.unpack_from("<Q", data, lc + field)
        return pe.off(va - pe.image_base) if va else None
    row("cfg-check-storage", storage(0x70), 0x01)
    row("xfg-check-storage", storage(0x118), 0x10)
    # FileOnly: the first byte of `.data` that a FileOnly entry covers.
    data_sec = next(((ptr, ptr + raw) for n, _va, _vs, ptr, raw in pe.sections if n == ".data"), None)
    row("fileonly-byte", first_fileonly_in(entries, data_sec), 0x01)
    row("signature", slot + OFF_SIG if slot is not None else None, 0x01)
    row("key-id", slot + OFF_KEY_ID if slot is not None else None, 0x01, KEY_MISMATCH)
    # Alignment padding past a section's VirtualSize, signed from the file.
    pad = next((ptr + vsize for _n, _va, vsize, ptr, raw in pe.sections if 0 < vsize < raw), None)
    row("alignment-padding", pad, 0x01)
    return 0


def envelope(dll, out=print):
    pe = Pe(open(dll, "rb").read())
    offset, size = pe.dirs[4]
    out(f"envelope-certificate {offset + size // 2} 1 {OPERATIONAL}" if size else "envelope-certificate - - -")
    return 0


def cfg(dll, out=print):
    """One line per storage word the load configuration names for the
    loader to write:
    `name rva file-value image-base`, the value the word holds in the file
    and the base it was linked at, so a reader of the loaded word can tell
    the relocated file value from one the loader wrote."""
    pe = Pe(open(dll, "rb").read())
    lc = pe.load_config()
    if lc is None:
        return 2
    size, = struct.unpack_from("<I", pe.data, lc)
    for name, field in (("cfg-check", 0x70), ("cfg-dispatch", 0x78), ("rf-failure", 0xD8),
                        ("rf-verify-sp", 0xE8), ("xfg-check", 0x118), ("xfg-dispatch", 0x120),
                        ("xfg-table-dispatch", 0x128), ("castguard", 0x130), ("memcpy", 0x138)):
        if field + 8 > size:
            continue
        va, = struct.unpack_from("<Q", pe.data, lc + field)
        if va:
            value, = struct.unpack_from("<Q", pe.data, pe.off(va - pe.image_base))
            out(f"{name} {va - pe.image_base:#x} {value:#x} {pe.image_base:#x}")
    return 0


def apply(path, offset, mask):
    width = max(1, (mask.bit_length() + 7) // 8)
    with open(path, "r+b") as handle:
        handle.seek(offset)
        old = handle.read(width)
        if len(old) != width:
            print(f"offset {offset} is past the end of {path}", file=sys.stderr)
            return 2
        handle.seek(offset)
        handle.write(bytes(b ^ m for b, m in zip(old, mask.to_bytes(width, "little"))))
    return 0


def main(argv):
    if argv[1:] == ["--selftest"]:
        return 0 if selftest() else 1
    try:
        if len(argv) == 4 and argv[1] == "rows":
            return rows(argv[2], argv[3])
        if len(argv) == 3 and argv[1] == "envelope":
            return envelope(argv[2])
        if len(argv) == 3 and argv[1] == "cfg":
            return cfg(argv[2])
        if len(argv) == 5 and argv[1] == "apply":
            return apply(argv[2], int(argv[3], 0), int(argv[4], 0))
    except (OSError, ValueError, struct.error) as e:
        print(f"UNPARSED: {e}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    # Line ends are `\n` on every runner: Windows Python would otherwise
    # write `\r\n`, and the caller's last field would carry the `\r`.
    sys.stdout.reconfigure(newline="\n")
    try:
        sys.exit(main(sys.argv))
    except Exception as e:  # noqa: BLE001 - a crash must not read as a verdict
        print(f"CRASH: {e!r}", file=sys.stderr)
        sys.exit(3)
