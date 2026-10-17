#!/usr/bin/env python3
"""Byte-level diffs for the signing order: which bytes each signing step writes.

The integrity signature must not cover a byte that a later signing step
rewrites, and must cover every other byte. These commands compare two copies of
one artifact across a signing step and fail when a byte changed outside the
set that step is allowed to write.

  slot-only BEFORE AFTER
      The integrity signer's step: the files have the same length and every
      differing byte lies inside the integrity slot. For ELF, the ELF header
      [0, 64) is also required to be identical. Prints the slot version, and
      for a version-4 slot checks its file_len against the file.

  macho-whitelist A B
      Two consecutive `codesign` runs with the final identity and options. Over
      the header and load commands [0, 32 + sizeofcmds) the only bytes allowed
      to differ are four fields: LC_CODE_SIGNATURE dataoff and datasize, and
      __LINKEDIT vmsize and filesize. Every byte before A's signature blob
      (`dataoff`) outside the header must be identical. Prints
      `derived-holes: <fields>`, the whitelist fields that did differ.

  macho-final C D [--allow FIELD,...]
      The final `codesign` after the integrity signer: bytes before C's
      `dataoff` may differ only in the allowed fields (default: all four).

  pe-whitelist A B
  pe-final C D [--allow FIELD,...]
      The same for Authenticode: within [0, SizeOfHeaders) only CheckSum and
      the Security directory entry may differ; every byte from SizeOfHeaders to
      the certificate table (or the end of the file) must be identical.

  --selftest
      Runs each command on synthetic images and on mutations of them, each of
      which must give the stated verdict.

Every changed range outside the allowed set is printed as `RANGE start end`
(end exclusive), so a control can check that its own flipped byte was found.

Exit status: 0 allowed, 1 a byte changed outside the allowed set (or, for
slot-only, no slot byte changed), 2 the input could not be parsed, 3 the
script crashed.
"""
import struct
import sys

HDR = bytes([0xFC]) + b"OXICRYPT_FIPS_H"
FTR = bytes([0xFD]) + b"OXICRYPT_FIPS_F"
SLOT_SIZES = {2: 16384, 4: 65536}
# Version-4 slot fields (the module's slot layout): the 4627-byte ML-DSA-87
# signature at 32, the verifying key's SHA-256 at 4659, slot_file_off at
# 4707, file_len at 4711.
OFF_SIG, OFF_KEY_ID, OFF_SLOT_FILE_OFF, OFF_FILE_LEN = 32, 4659, 4707, 4711
# The format version, at the same offset in every version.
OFF_VERSION = 16


class Unparsed(Exception):
    pass


def find_slot(data):
    hits = []
    at = data.find(HDR)
    while at >= 0:
        if at + OFF_VERSION + 4 <= len(data):
            ver, = struct.unpack_from("<I", data, at + OFF_VERSION)
            size = SLOT_SIZES.get(ver)
            if size and data[at + size - len(FTR):at + size] == FTR:
                hits.append((at, ver, size))
        at = data.find(HDR, at + 1)
    if len(hits) != 1:
        raise Unparsed(f"expected one integrity slot, found {len(hits)}")
    return hits[0]


def diff_ranges(a, b, lo, hi):
    """Maximal runs of differing bytes in [lo, hi)."""
    out, start = [], None
    for i in range(lo, hi):
        d = a[i] != b[i]
        if d and start is None:
            start = i
        elif not d and start is not None:
            out.append((start, i))
            start = None
    if start is not None:
        out.append((start, hi))
    return out


def report_ranges(ranges, out, limit=200):
    """One `RANGE start end` line per changed range (end exclusive)."""
    for a, b in ranges[:limit]:
        out(f"RANGE {a:#x} {b:#x}")
    if len(ranges) > limit:
        out(f"RANGE ... {len(ranges) - limit} more")


def image_length(data):
    """The image's length without the platform's signature envelope, which is
    what a version-4 slot records as file_len: a Mach-O ends at its code
    signature's dataoff, a PE at its certificate table, an ELF at its end."""
    try:
        if data[:4] == b"\xcf\xfa\xed\xfe":
            return macho_fields(data)[2]
        if data[:2] == b"MZ":
            return pe_fields(data)[2]
    except Unparsed:
        pass  # unsigned by the platform: the whole file
    return len(data)


def slot_only(before, after, out):
    if len(before) != len(after):
        out(f"FAILED: length changed {len(before)} -> {len(after)}")
        return 1
    off, ver, size = find_slot(after)
    key = f", verify key sha256:{after[off + OFF_KEY_ID:off + OFF_KEY_ID + 32].hex()}" if ver == 4 else ""
    out(f"slot version {ver} at file offset {off:#x}, {size} bytes{key}")
    ranges = diff_ranges(before, after, 0, len(after))
    bad = [r for r in ranges if r[0] < off or r[1] > off + size]
    rc = 0
    if not any(r[0] < off + size and r[1] > off for r in ranges):
        out("FAILED: no byte of the slot changed: the signing step wrote nothing")
        rc = 1
    if after[:4] == b"\x7fELF" and before[:64] != after[:64]:
        out("FAILED: the ELF header [0, 64) changed")
        rc = 1
    if bad:
        out(f"FAILED: {len(bad)} changed range(s) outside the slot, first at {bad[0][0]:#x}..{bad[0][1]:#x}")
        report_ranges(bad, out)
        rc = 1
    if ver == 4:
        file_len, = struct.unpack_from("<I", after, off + OFF_FILE_LEN)
        slot_file_off, = struct.unpack_from("<I", after, off + OFF_SLOT_FILE_OFF)
        image_len = image_length(after)
        if file_len != image_len or slot_file_off != off:
            out(f"FAILED: slot file_len {file_len} / slot_file_off {slot_file_off:#x} disagree with the image "
                f"({image_len} bytes before any signature envelope, slot at {off:#x})")
            rc = 1
        else:
            out(f"ok: slot file_len {file_len} is the image before any signature envelope")
    else:
        out("measurement: a version-2 slot carries no file_len")
    if rc == 0:
        out("ok: only the slot changed")
    return rc


MACHO_FIELDS = ("codesig.dataoff", "codesig.datasize", "linkedit.vmsize", "linkedit.filesize")


def macho_fields(data):
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xFEEDFACF:
        raise Unparsed("not a thin 64-bit Mach-O")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    fields, off = {}, 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19 and data[off + 8:off + 24].rstrip(b"\0") == b"__LINKEDIT":
            fields["linkedit.vmsize"] = (off + 32, 8)
            fields["linkedit.filesize"] = (off + 48, 8)
        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            fields["codesig.dataoff"] = (off + 8, 4)
            fields["codesig.datasize"] = (off + 12, 4)
        off += cmdsize
    if "codesig.dataoff" not in fields:
        raise Unparsed("no LC_CODE_SIGNATURE: not code-signed")
    if "linkedit.vmsize" not in fields:
        raise Unparsed("no __LINKEDIT segment")
    dataoff, = struct.unpack_from("<I", data, fields["codesig.dataoff"][0])
    return 32 + sizeofcmds, fields, dataoff


def pe_fields(data):
    if data[:2] != b"MZ":
        raise Unparsed("not a PE image")
    pe, = struct.unpack_from("<I", data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise Unparsed("not a PE image")
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        raise Unparsed("not PE32+")
    size_of_headers, = struct.unpack_from("<I", data, opt + 60)
    fields = {"checksum": (opt + 64, 4), "security-directory": (opt + 112 + 4 * 8, 8)}
    cert_off, cert_len = struct.unpack_from("<II", data, opt + 112 + 4 * 8)
    file_len = cert_off if cert_len else len(data)
    return size_of_headers, fields, file_len


def whitelist(a, b, parse, allowed, out):
    try:
        hdr_a, fields_a, end_a = parse(a)
        hdr_b, fields_b, end_b = parse(b)
    except Unparsed as e:
        out(f"UNPARSED: {e}")
        return 2, []
    if hdr_a != hdr_b or fields_a != fields_b:
        out("FAILED: the header layout differs (size or field positions)")
        return 1, []
    differed = []
    covered = set()
    for name, (off, n) in sorted(fields_a.items()):
        same = a[off:off + n] == b[off:off + n]
        if not same:
            differed.append(name)
        if name in allowed:
            covered.update(range(off, off + n))
        out(f"field {name:20} at {off:#x}+{n} {'same' if same else 'differs'}")
    # The reference is A's envelope: every byte before it must be unchanged,
    # including any that B's envelope, starting earlier, now overwrites.
    end = end_a
    if len(b) < end:
        out(f"FAILED: B is {len(b)} bytes, shorter than A's envelope offset {end:#x}")
        return 1, []
    other = [r for r in diff_ranges(a, b, 0, min(hdr_a, end)) if any(i not in covered for i in range(*r))]
    body = diff_ranges(a, b, hdr_a, end)
    rc = 0
    if other:
        out(f"FAILED: {len(other)} header range(s) changed outside the allowed fields, first at {other[0][0]:#x}")
        report_ranges(other, out)
        rc = 1
    if body:
        out(f"FAILED: {len(body)} range(s) changed between the header and the envelope at {end:#x}, "
            f"first at {body[0][0]:#x}")
        report_ranges(body, out)
        rc = 1
    out(f"envelope begins at {end:#x} (A) / {end_b:#x} (B)")
    out("derived-holes: " + (",".join(differed) or "none"))
    if rc == 0:
        out("ok: only allowed fields and the envelope changed")
    return rc, differed


def selftest():
    def macho(linkedit_filesize=0x4000, datasize=0x200, body=b"\x11" * 64):
        cmds = bytearray()
        seg = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__LINKEDIT", 0x10000, 0x4000, 0x200,
                          linkedit_filesize, 1, 1, 0, 0)
        cmds += seg
        cmds += struct.pack("<IIII", 0x1D, 16, 0x200 + len(body), datasize)
        hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 6, 2, len(cmds), 0, 0)
        img = bytearray(hdr + cmds)
        img += b"\0" * (0x200 - len(img)) + body + b"\xEE" * datasize
        return img

    def pe(checksum=0, cert=(0, 0), body=b"\x22" * 64):
        img = bytearray(0x400)
        img[0:2] = b"MZ"
        struct.pack_into("<I", img, 0x3C, 0x80)
        img[0x80:0x84] = b"PE\0\0"
        opt = 0x80 + 24
        struct.pack_into("<H", img, opt, 0x20B)
        struct.pack_into("<I", img, opt + 60, 0x400)
        struct.pack_into("<I", img, opt + 64, checksum)
        struct.pack_into("<II", img, opt + 112 + 32, *cert)
        img += body
        if cert[1]:
            img += b"\xCC" * cert[1]
        return img

    # Where `slotted` puts the slot: after a 64-byte ELF header and 512
    # bytes of body.
    SLOT_AT = 576

    def slotted(byte_at=None, ver=2):
        size = SLOT_SIZES[ver]
        img = bytearray(b"\x7fELF" + b"\x02" * 60 + b"\x33" * 512)
        slot = bytearray(size)
        slot[:16] = HDR
        struct.pack_into("<I", slot, OFF_VERSION, ver)
        slot[-16:] = FTR
        img += slot + b"\x44" * 512
        if ver == 4:
            struct.pack_into("<I", img, SLOT_AT + OFF_SLOT_FILE_OFF, SLOT_AT)
            struct.pack_into("<I", img, SLOT_AT + OFF_FILE_LEN, len(img))
        if byte_at is not None:
            img[byte_at] ^= 1
        return img

    q = lambda _s: None
    m0 = macho()
    m_grown = macho(linkedit_filesize=0x4400, datasize=0x600)
    m_other = bytearray(m_grown)
    m_other[0x210] ^= 1  # a body byte before dataoff
    m_hdr = bytearray(m_grown)
    m_hdr[8] ^= 1  # cpusubtype
    p0 = pe(cert=(0x440, 0x100))
    p1 = pe(checksum=0x1234, cert=(0x440, 0x180))
    p_body = bytearray(p1)
    p_body[0x420] ^= 1
    s0 = slotted()
    cases = [
        ("slot-only, a byte inside the slot", slot_only(s0, slotted(byte_at=SLOT_AT + OFF_SIG + 8), q), 0),
        ("slot-only, nothing changed", slot_only(s0, slotted(), q), 1),
        ("macho-whitelist, envelope moved earlier over body bytes",
         whitelist(m0, macho(body=b"\x11" * 32), macho_fields, MACHO_FIELDS, q)[0], 1),
        ("slot-only, a byte outside the slot", slot_only(s0, slotted(byte_at=100), q), 1),
        ("slot-only, the ELF header", slot_only(s0, slotted(byte_at=8), q), 1),
        ("slot-only, a version-4 slot with a true file_len", slot_only(slotted(ver=4), slotted(ver=4, byte_at=SLOT_AT + OFF_SIG + 32), q), 0),
        ("slot-only, a version-4 slot whose file_len is not the image's",
         slot_only(slotted(ver=4), slotted(ver=4, byte_at=SLOT_AT + OFF_FILE_LEN), q), 1),
        ("image length of a code-signed Mach-O is its signature's dataoff", image_length(m0) == 0x240, True),
        ("image length of an Authenticode-signed PE is its certificate offset", image_length(p0) == 0x440, True),
        ("macho-whitelist, identical", whitelist(m0, m0, macho_fields, MACHO_FIELDS, q)[0], 0),
        ("macho-whitelist, the four fields grew", whitelist(m0, m_grown, macho_fields, MACHO_FIELDS, q)[0], 0),
        ("macho-whitelist, a body byte before dataoff", whitelist(m0, m_other, macho_fields, MACHO_FIELDS, q)[0], 1),
        ("macho-whitelist, a header byte outside the fields", whitelist(m0, m_hdr, macho_fields, MACHO_FIELDS, q)[0], 1),
        ("macho-final, a field outside --allow", whitelist(m0, m_grown, macho_fields, ("codesig.datasize",), q)[0], 1),
        ("macho-whitelist, derived holes named",
         whitelist(m0, m_grown, macho_fields, MACHO_FIELDS, q)[1] == ["codesig.datasize", "linkedit.filesize"], True),
        ("pe-whitelist, CheckSum and the certificate entry", whitelist(p0, p1, pe_fields, PE_FIELDS, q)[0], 0),
        ("pe-whitelist, a section byte", whitelist(p0, p_body, pe_fields, PE_FIELDS, q)[0], 1),
        ("pe-final, CheckSum not allowed", whitelist(p0, p1, pe_fields, ("security-directory",), q)[0], 1),
        ("unparsed input", whitelist(b"\0" * 64, b"\0" * 64, macho_fields, MACHO_FIELDS, q)[0], 2),
    ]
    bad = 0
    for name, got, want in cases:
        ok = got == want
        bad += not ok
        print(f"{'ok' if ok else 'MISMATCH':8} {name}: expected {want}, got {got}")
    return bad == 0


PE_FIELDS = ("checksum", "security-directory")


def main(argv):
    if argv == ["--selftest"]:
        return 0 if selftest() else 1
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, pa, pb = argv[0], argv[1], argv[2]
    allowed = None
    if len(argv) == 5 and argv[3] == "--allow":
        allowed = tuple(f for f in argv[4].split(",") if f and f != "none")
    elif len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    a, b = open(pa, "rb").read(), open(pb, "rb").read()
    try:
        if cmd == "slot-only":
            return slot_only(a, b, print)
        if cmd in ("macho-whitelist", "macho-final"):
            return whitelist(a, b, macho_fields, MACHO_FIELDS if allowed is None else allowed, print)[0]
        if cmd in ("pe-whitelist", "pe-final"):
            return whitelist(a, b, pe_fields, PE_FIELDS if allowed is None else allowed, print)[0]
    except Unparsed as e:
        print(f"UNPARSED: {e}")
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    # Line ends are `\n` on every runner: Windows Python would otherwise
    # write `\r\n`, and the caller's fields would carry the `\r`.
    sys.stdout.reconfigure(newline="\n")
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:  # a crash must never read as a verdict
        import traceback
        traceback.print_exc()
        print("CRASHED: reservation.py")
        sys.exit(3)
