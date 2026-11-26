"""Hashes, signs and establishes a shared secret through the oxicrypt C
library, checking each result against the line examples/README.md expects.

    python3 example.py <bundle-dir> <out-dir>
    python3 example.py <bundle-dir> decaps <dk-file> <ct-file>
"""

import ctypes
import hmac
import os
import sys

MESSAGE = b"The quick brown fox jumps over the lazy dog"
SIG_FLIP_BYTE = 0
CT_FLIP_BYTE = 0
PERSONALIZATION = b"oxicrypt example"
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

PK_LEN, SK_LEN, SIG_LEN = 2592, 4896, 4627
EK_LEN, DK_LEN, CT_LEN, SS_LEN = 1568, 3168, 1568, 32

NAMES = {"linux": "liboxicrypt_ffi.so.4", "darwin": "liboxicrypt_ffi.4.dylib", "win32": "oxicrypt_ffi.dll"}

u8p = ctypes.POINTER(ctypes.c_uint8)
size = ctypes.c_size_t
PROTOTYPES = {
    "oxi_init": [ctypes.c_int],
    "oxi_integrity_status": [],
    "oxi_integrity_key_fingerprint": [u8p, size],
    "oxi_sha256": [u8p, size, u8p],
    "oxi_hmac_drbg_sha256_new_rbg": [ctypes.POINTER(ctypes.c_void_p)],
    "oxi_drbg_instantiate": [ctypes.c_void_p, u8p, size],
    "oxi_ml_dsa_87_keygen_rbg": [ctypes.c_void_p, u8p, u8p, u8p],
    "oxi_ml_dsa_87_sign": [u8p, u8p, size, u8p, size, u8p],
    "oxi_ml_dsa_87_verify": [u8p, u8p, size, u8p, size, u8p],
    "oxi_ml_kem_1024_keygen_rbg": [ctypes.c_void_p, u8p, u8p, u8p],
    "oxi_ml_kem_1024_encapsulate_rbg": [u8p, ctypes.c_void_p, u8p, u8p],
    "oxi_ml_kem_1024_decapsulate": [u8p, u8p, u8p],
}


def buf(n, data=b""):
    b = (ctypes.c_uint8 * n)()
    ctypes.memmove(b, data, len(data))
    return b


class Example:
    def __init__(self, bundle):
        platform = "linux" if sys.platform.startswith("linux") else sys.platform
        self.lib = ctypes.CDLL(os.path.join(bundle, NAMES[platform]))
        for name, args in PROTOTYPES.items():
            f = getattr(self.lib, name)
            f.argtypes = args
            f.restype = ctypes.c_int
        self.lib.oxi_drbg_free.argtypes = [ctypes.c_void_p]
        self.lib.oxi_drbg_free.restype = None
        self.rbg = ctypes.c_void_p()
        self.sk, self.dk = buf(SK_LEN), buf(DK_LEN)
        self.ss, self.ss2 = buf(SS_LEN), buf(SS_LEN)

    def release(self):
        """Frees the DRBG handle, which wipes its state, and wipes every secret.

        The secrets live in ctypes buffers, which are wiped here; the hex
        string printed for the shared secret is a Python str, which cannot be."""
        self.lib.oxi_drbg_free(self.rbg)
        self.rbg = ctypes.c_void_p()
        for secret in (self.sk, self.dk, self.ss, self.ss2):
            ctypes.memset(secret, 0, len(secret))

    def fail(self):
        """Exits 1; the `finally` in main releases."""
        sys.exit(1)

    def expect(self, want, got):
        """Prints `got` when it equals `want`; otherwise prints both and exits 1."""
        if want != got:
            print(f"expected: {want}\n     got: {got}", file=sys.stderr)
            self.fail()
        print(got)

    def expect_ok(self, what, rc):
        self.expect(f"{what} ok", f"{what} ok" if rc == 0 else f"{what} returned {rc}")

    def check(self, call, rc):
        """Exits 1 naming the call when it returned other than Ok."""
        if rc != 0:
            print(f"{call} returned {rc}", file=sys.stderr)
            self.fail()

    def write(self, out, name, data, owner_only=False):
        """Writes the file, readable and writable by its owner only when
        `owner_only` is set, as the decapsulation key is. On Windows the file
        takes the access control list of its directory."""
        try:
            fd = os.open(os.path.join(out, name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0),
                         0o600 if owner_only else 0o644)
            with os.fdopen(fd, "wb") as f:
                if owner_only and hasattr(os, "fchmod"):
                    os.fchmod(f.fileno(), 0o600)
                f.write(data)
        except OSError as e:
            print(e, file=sys.stderr)
            self.fail()

    def read(self, path, into):
        try:
            with open(path, "rb") as f:
                n = f.readinto(into)
                extra = f.read(1)
        except OSError as e:
            print(e, file=sys.stderr)
            self.fail()
        if n != len(into) or extra:
            print(f"{path}: expected {len(into)} bytes", file=sys.stderr)
            self.fail()

    def init(self):
        """Starts the module and reads its integrity result. Prints the
        fingerprint of the key the library trusts to stderr, and exits 1
        unless the module is operational with its integrity test passed
        (status 1), leading with the condition that failed."""
        rc = self.lib.oxi_init(0)
        status = self.lib.oxi_integrity_status()
        fp = buf(32)
        fp_rc = self.lib.oxi_integrity_key_fingerprint(fp, len(fp))
        fp_line = f"verify key sha256:{bytes(fp).hex()}"
        if rc == 0 and status == 1 and fp_rc == 0:
            print(fp_line, file=sys.stderr)
            return
        if rc != 0:
            print(f"oxi_init returned {rc}: the module refused to start", file=sys.stderr)
        elif status != 1:
            print(f"oxi_init returned 0 but the integrity test reported status {status}, not 1 (passed)",
                  file=sys.stderr)
        else:
            print(f"oxi_integrity_key_fingerprint returned {fp_rc} after the integrity test passed", file=sys.stderr)
            self.fail()
        print(f"integrity status {status}", file=sys.stderr)
        print(fp_line if fp_rc == 0 else f"oxi_integrity_key_fingerprint returned {fp_rc}", file=sys.stderr)
        self.fail()

    def decaps(self, dk_path, ct_path):
        self.init()
        ct = buf(CT_LEN)
        self.read(dk_path, self.dk)
        self.read(ct_path, ct)
        self.check("oxi_ml_kem_1024_decapsulate", self.lib.oxi_ml_kem_1024_decapsulate(self.dk, ct, self.ss))
        print(f"ml-kem-1024 ss {memoryview(self.ss).hex()}")

    def run(self, out):
        lib = self.lib
        self.init()

        abc, digest = buf(3, b"abc"), buf(32)
        self.check("oxi_sha256", lib.oxi_sha256(abc, 3, digest))
        self.expect(f"sha256 abc {SHA256_ABC}", f"sha256 abc {bytes(digest).hex()}")

        self.check("oxi_hmac_drbg_sha256_new_rbg", lib.oxi_hmac_drbg_sha256_new_rbg(ctypes.byref(self.rbg)))
        perso = buf(len(PERSONALIZATION), PERSONALIZATION)
        self.check("oxi_drbg_instantiate", lib.oxi_drbg_instantiate(self.rbg, perso, len(perso)))
        print("drbg instantiated")

        message = buf(len(MESSAGE), MESSAGE)
        pk, sig = buf(PK_LEN), buf(SIG_LEN)
        self.expect_ok("ml-dsa-87 keygen", lib.oxi_ml_dsa_87_keygen_rbg(self.rbg, pk, self.sk, None))
        self.check("oxi_ml_dsa_87_sign", lib.oxi_ml_dsa_87_sign(self.sk, message, len(message), None, 0, sig))
        self.write(out, "pk.bin", pk)
        self.write(out, "message.txt", MESSAGE)
        self.write(out, "sig.bin", sig)
        self.expect_ok("ml-dsa-87 verify", lib.oxi_ml_dsa_87_verify(pk, message, len(message), None, 0, sig))
        tampered_sig = buf(SIG_LEN, bytes(sig))
        tampered_sig[SIG_FLIP_BYTE] ^= 0x01
        rc = lib.oxi_ml_dsa_87_verify(pk, message, len(message), None, 0, tampered_sig)
        got = "ml-dsa-87 verify-tampered accepted" if rc == 0 else f"ml-dsa-87 verify-tampered rejected {rc}"
        self.expect("ml-dsa-87 verify-tampered rejected 22", got)

        ek, ct = buf(EK_LEN), buf(CT_LEN)
        self.expect_ok("ml-kem-1024 keygen", lib.oxi_ml_kem_1024_keygen_rbg(self.rbg, ek, self.dk, None))
        self.check("oxi_ml_kem_1024_encapsulate_rbg", lib.oxi_ml_kem_1024_encapsulate_rbg(ek, self.rbg, self.ss, ct))
        self.write(out, "ek.bin", ek)
        self.write(out, "dk.bin", self.dk, owner_only=True)
        self.write(out, "ct.bin", ct)
        rc = lib.oxi_ml_kem_1024_decapsulate(self.dk, ct, self.ss2)
        same = hmac.compare_digest(memoryview(self.ss), memoryview(self.ss2))
        got = f"ml-kem-1024 decaps {'match' if same else 'differs'}" if rc == 0 else f"ml-kem-1024 decaps returned {rc}"
        self.expect("ml-kem-1024 decaps match", got)
        tampered_ct = buf(CT_LEN, bytes(ct))
        tampered_ct[CT_FLIP_BYTE] ^= 0x01
        rc = lib.oxi_ml_kem_1024_decapsulate(self.dk, tampered_ct, self.ss2)
        same = hmac.compare_digest(memoryview(self.ss), memoryview(self.ss2))
        got = (
            f"ml-kem-1024 decaps-tampered {'match' if same else 'differs'}"
            if rc == 0
            else f"ml-kem-1024 decaps-tampered returned {rc}"
        )
        self.expect("ml-kem-1024 decaps-tampered differs", got)

        print(f"ml-kem-1024 ss {memoryview(self.ss).hex()}")


def main():
    args = sys.argv[1:]
    decaps_mode = len(args) == 4 and args[1] == "decaps"
    if not decaps_mode and len(args) != 2:
        print("usage: example.py <bundle-dir> <out-dir>\n"
              "       example.py <bundle-dir> decaps <dk-file> <ct-file>", file=sys.stderr)
        sys.exit(2)
    example = Example(args[0])
    try:
        if decaps_mode:
            example.decaps(args[2], args[3])
        else:
            example.run(args[1])
    finally:
        example.release()


if __name__ == "__main__":
    main()
