"""Builds an APK-shaped zip with native libraries STORED and page-aligned, as
bundletool does for extractNativeLibs=false, plus a stored resource entry.

bionic maps only the entry it dlopens, so a decoy stored in the archive is
mapped only when the probe dlopens it too (--also). The decoy must carry no
integrity-slot magic: use the NDK's libc++_shared.so, never a copy of the
subject. The script refuses a decoy containing the slot header magic.

Usage: python3 -I apk_fixture.py <out.apk> <abi> <subject.so> [decoy.so ...] [--align N]
Prints each entry's data offset and checks the verifier's arithmetic: bytes at
data_off + file_off equal the standalone library's, image_len fits the archive."""
import os, struct, sys, zlib
MAGIC = bytes([0xfc]) + b"OXICRYPT_FIPS_H"
args = sys.argv[1:]; align = 16384
if "--align" in args: i = args.index("--align"); align = int(args[i + 1]); del args[i:i + 2]
out, abi, subject, *decoys = args
def image_len(data):
    e_phoff, = struct.unpack_from("<Q", data, 0x20); e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36); end = 0
    for i in range(e_phnum):
        t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i * e_phentsize)
        if t == 1: end = max(end, off + fsz)
    return end
entries = [(b"assets/resource.bin", os.urandom(65536), False)]
for dpath in decoys:
    data = open(dpath, "rb").read()
    if MAGIC in data: raise SystemExit(f"decoy {dpath} carries the slot magic: use a library without one")
    entries.append((f"lib/{abi}/{os.path.basename(dpath)}".encode(), data, True))
entries.append((f"lib/{abi}/{os.path.basename(subject)}".encode(), open(subject, "rb").read(), True))
buf = bytearray(); central = bytearray(); report = []
for name, data, is_lib in entries:
    crc = zlib.crc32(data) & 0xffffffff
    hdr = 30 + len(name); pad = (-(len(buf) + hdr)) % align if is_lib else 0
    local = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, 0, 0, 0, crc, len(data), len(data), len(name), pad) + name + b"\0" * pad
    local_off = len(buf); data_off = local_off + len(local)
    central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, 0, 0, 0, 0, crc, len(data), len(data), len(name), 0, 0, 0, 0, 0, local_off) + name
    buf += local + data; report.append((name.decode(), data_off, len(data), is_lib))
cd_off = len(buf); buf += central + struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(entries), len(entries), len(central), cd_off, 0)
open(out, "wb").write(buf)
subj = entries[-1][1]; sname, soff, slen, _ = report[-1]; ilen = image_len(subj)
ok = all(buf[soff + o] == subj[o] for o in (0, 0x40, slen // 2, slen - 1)) and soff % align == 0 and soff + ilen <= len(buf)
for n, o, l, lib in report: print(f"entry={n} data_off={o:#x} size={l} {'lib' if lib else 'resource'}")
print(f"apk={out} archive_len={len(buf)} subject={sname} apk_base={soff:#x} image_len={ilen} elf_len={slen} arithmetic_ok={ok}")
dec = f" --also /data/local/tmp/{os.path.basename(out)}!/{report[1][0]}" if decoys else ""
print(f"device: ./probe --loader bionic{dec} /data/local/tmp/{os.path.basename(out)}!/{sname}")
