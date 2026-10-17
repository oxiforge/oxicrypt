#!/usr/bin/env python3
"""The Mach-O rows of the integrity tamper matrix.

  rows <dylib> <show.txt>
      Prints one row per line: `name offset mask renew arm64 x86_64`.
      `offset` is a file offset in the signed and code-signed dylib, `mask`
      the byte to XOR into it, and `renew` is 1 when the code signature is
      renewed after the edit and 0 when it is not. `arm64` and `x86_64` are
      the outcomes allowed on each architecture, comma-separated, each
      `exit:status`: ffi-operational's exit status and the integrity status
      it prints (`-` when it prints none). Offsets come from the dylib's own
      load commands and from the signer's `--show` listing of it (`[i] Kind
      rva .. file .. len ..` lines and `slot at file offset ..`). A row
      whose structure the dylib lacks is printed as `name - - - - -`, which
      the caller treats as a failure.

  apply <file> <offset> <mask>
      XORs `mask`, little-endian, into the bytes from `offset`, in place.

Exit status: 0 done, 2 the input could not be read, 3 a crash.
"""
import re
import struct
import sys


def rows(dylib, show, out=print):
    data = open(dylib, "rb").read()
    text = open(show).read()
    magic, cpu, _sub, _ft, ncmds, sizeofcmds, _fl = struct.unpack_from("<IiiIIII", data, 0)
    if magic != 0xFEEDFACF:
        print("UNPARSED: not a thin 64-bit Mach-O", file=sys.stderr)
        return 2
    cmds_end = 32 + sizeofcmds
    first_sect = None
    const = code = id_name = fstarts = linkedit = codesig = symtab = None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            seg = data[off + 8:off + 24].rstrip(b"\0").decode()
            nsects, = struct.unpack_from("<I", data, off + 64)
            if seg == "__LINKEDIT":
                linkedit = off
            for s in range(nsects):
                so = off + 72 + s * 80
                name = data[so:so + 16].rstrip(b"\0").decode()
                _addr, size, offset = struct.unpack_from("<QQI", data, so + 32)
                if seg == "__TEXT" and offset and (first_sect is None or offset < first_sect):
                    first_sect = offset
                if seg == "__TEXT" and name == "__const":
                    const = (offset, size)
                if seg == "__TEXT" and name == "__text":
                    code = (offset, size)
        elif cmd == 0x2:
            symtab = struct.unpack_from("<IIII", data, off + 8)
        elif cmd == 0xD:
            id_name = off + struct.unpack_from("<I", data, off + 8)[0]
        elif cmd == 0x26:
            fstarts = struct.unpack_from("<II", data, off + 8)
        elif cmd == 0x1D:
            codesig = struct.unpack_from("<II", data, off + 8)
        off += cmdsize
    entries = [(m.group(1), int(m.group(2), 16), int(m.group(3)))
               for m in re.finditer(r"\[\d+\] (\w+) rva 0x[0-9a-f]+ file (0x[0-9a-f]+) len (\d+)", text)]
    first = {}
    for kind, f_off, length in entries:
        first.setdefault(kind, (f_off, length))
    slot = re.search(r"slot at file offset (0x[0-9a-f]+)", text)
    slot = int(slot.group(1), 16) if slot else None

    def row(name, offset, mask, renew, arm64=REFUSED, x86_64=REFUSED):
        if offset is None:
            out(f"{name} - - - - -")
        else:
            out(f"{name} {offset} {mask} {renew} {arm64} {x86_64}")

    row("load-command-pad", (cmds_end + first_sect) // 2 if first_sect and first_sect > cmds_end else None, 0x01, 1)
    row("id-dylib-name", id_name + 1 if id_name else None, 0x01, 1)
    row("linkedit-table", fstarts[0] + fstarts[1] // 2 if fstarts and fstarts[1] else None, 0x01, 1)
    row("text-code", cold_code(data, code, symtab), 0x01, 1)
    row("plain-constant", const[0] + const[1] // 2 if const and const[1] else None, 0x01, 1)
    rel = first.get("Relative")
    row("relative-target", rel[0] if rel else None, 0x10, 1)
    bind = first.get("Bind")
    row("bind-ordinal", bind[0] if bind else None, 0x01, 1)
    row("bind-addend-16", bind[0] + 3 if bind else None, 0x10, 1)
    # The ordinal of closedir's bind edited to opendir's: the loader binds
    # opendir where closedir is recorded, which the export trie never names
    # as closedir's stub, so the integrity test refuses it (1:2). Neither
    # function is called before the integrity test runs, so the test, not
    # an earlier self-test calling the wrong function, gives the verdict.
    row("bind-ordinal-closedir-to-opendir", *retarget(data, text, "closedir", "opendir"), 1)
    # A resolver stub substituted for another by ordinal, memcmp to memset:
    # on x86_64 both are stubs, and the word becomes memset's, which the
    # export tries never lead to from `_memcmp`. Both functions are called
    # during start-up, so the module may stop at an earlier self-test that
    # sees the wrong function (status 0) before the integrity test refuses
    # it (status 2); either way it is not operational.
    # x86_64 only: on arm64 neither is a stub, and memset is not bound.
    if cpu == 0x01000007:
        row("bind-ordinal-memcmp-to-memset", *retarget(data, text, "memcmp", "memset"), 1,
            REFUSED + ",1:0", REFUSED + ",1:0")
    fo = first.get("FileOnly")
    row("fileonly-byte", fo[0] + fo[1] // 2 if fo else None, 0x01, 1)
    row("signature", slot + OFF_SIG if slot is not None else None, 0x01, 1)
    row("key-id", slot + OFF_KEY_ID if slot is not None else None, 0x01, 1, KEY_MISMATCH, KEY_MISMATCH)
    # Not renewed: the operating system's own code-signature check decides
    # on arm64, which refuses the load (or kills the process); on x86_64 the
    # module's test does, or the blob edit is outside the module's image.
    row("linkedit-filesize-no-renewal", linkedit + 48 if linkedit else None, 0x01, 0,
        NOT_LOADED, REFUSED + "," + NOT_LOADED)
    row("envelope-no-renewal", codesig[0] + 0x40 if codesig else None, 0x01, 0,
        NOT_LOADED, "0:1," + NOT_LOADED)
    return 0


# The outcomes a row may have: refused by the integrity test as
# SignatureInvalid (2) or KeyMismatch (9); or not loaded at all, which
# ffi-operational reports as exit 2, or the kernel's SIGKILL (137).
REFUSED = "1:2"
KEY_MISMATCH = "1:9"
NOT_LOADED = "2:-,137:-"
# Version-4 slot fields: the ML-DSA-87 signature, then the key fingerprint.
OFF_SIG, OFF_KEY_ID = 32, 4659


def retarget(data, text, src, dst):
    """The offset of the first word bound to `src`, and the mask that makes
    its import index `dst`'s, read from a word bound to `dst`."""
    records = {int(i): sym for i, sym in
               re.findall(r"^\s+record \[(\d+)\] \S+ (\S+) addend", text, re.M)}
    binds = [(int(f, 16), records.get(int(r))) for f, r in
             re.findall(r"\] Bind rva 0x[0-9a-f]+ file (0x[0-9a-f]+) len \d+ hole \d+ record (\d+)", text)]
    # The symbol, or a variant of it (`opendir$INODE64` on x86_64).
    named = lambda sym, want: sym is not None and (sym == want or sym.startswith(want + "$"))
    at_src = next((f for f, sym in binds if named(sym, src)), None)
    at_dst = next((f for f, sym in binds if named(sym, dst)), None)
    if at_src is None or at_dst is None:
        return None, 0
    index = lambda at: struct.unpack_from("<Q", data, at)[0] & 0xFFFFFF
    mask = index(at_src) ^ index(at_dst)
    # The ordinal must change, or the row edits nothing.
    return (at_src, mask) if mask else (None, 0)


def cold_code(data, code, symtab):
    """A byte of an instruction nothing runs before the integrity test: the
    fifth byte of the first C-ABI service entry point, in name order, that
    ffi-operational does not call (`oxi_*` exported from `__text`, the
    ones it calls excepted), else alignment padding inside `__text`. The
    module's power-up tests reach algorithms through their own crates,
    never through these entry points."""
    if code and symtab:
        symoff, nsyms, stroff, _strsize = symtab
        start, size = code
        called = {b"_oxi_init", b"_oxi_is_operational", b"_oxi_integrity_status"}
        names = []
        for i in range(nsyms):
            strx, ntype, _sect, _desc, value = struct.unpack_from("<IBBHQ", data, symoff + 16 * i)
            name = data[stroff + strx:data.index(b"\0", stroff + strx)]
            if (ntype & 0x0F) == 0x0F and name.startswith(b"_oxi_") and name not in called \
                    and start <= value < start + size:
                names.append((name, value))
        if names:
            return min(names)[1] + 4
    return padding(data, code)


def padding(data, text):
    """The middle of the longest run of padding inside `__text`: zero bytes
    (an undefined instruction on arm64) or 0xCC (int3 on x86_64), at least
    8 bytes long. Executable bytes that no code reaches."""
    if not text:
        return None
    start, size = text
    best = None
    i = start
    while i < start + size:
        if data[i] in (0x00, 0xCC):
            j = i
            while j < start + size and data[j] == data[i]:
                j += 1
            if j - i >= 8 and (best is None or j - i > best[1] - best[0]):
                best = (i, j)
            i = j
        else:
            i += 1
    return None if best is None else (best[0] + best[1]) // 2


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
    if len(argv) == 3 and argv[0] == "rows":
        return rows(argv[1], argv[2])
    if len(argv) == 4 and argv[0] == "apply":
        return apply(argv[1], int(argv[2]), int(argv[3]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:  # a crash must never read as a verdict
        import traceback
        traceback.print_exc()
        print("CRASHED: macho-tamper.py")
        sys.exit(3)
