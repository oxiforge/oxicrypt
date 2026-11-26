# Go

`main.go` calls the library through cgo, including `oxicrypt.h` from the bundle. It starts the module, hashes, signs and verifies with ML-DSA-87, and establishes a shared secret with ML-KEM-1024, checking each result against the line [`examples/README.md`](../README.md) expects.

Prerequisites: Go 1.24 or later (the `go` directive of `go.mod`), the C compiler `go env CC` names for cgo, and the library bundle and CLI archive for your platform. On Windows, MinGW's `gcc` on `PATH`.

Verified on Linux x86_64 with Go 1.26.11 and GCC 15.2.0, against a `linux-x86_64` library bundle and CLI archive built and signed from the same source tree.

This how-to gets a first call of each kind right; the [integration guide](../../docs/integration.md) covers the rest: process lifetime, every return code, randomness, keys and shipping.

## Get the bundle

Each release publishes, for each platform, a library bundle and a CLI archive of the same version, each with a `.sha256` file beside it:

```text
https://github.com/oxiforge/oxicrypt/releases/download/<tag>/oxicrypt-ffi-<tag>-<platform>.tar.gz
https://github.com/oxiforge/oxicrypt/releases/download/<tag>/oxicrypt-cli-<tag>-<platform>.tar.gz
```

`<tag>` is the release tag, `v` followed by the version, and `<platform>` is one of `linux-x86_64`, `linux-aarch64`, `macos-x86_64`, `macos-aarch64` and `windows-x86_64`. The Android bundles `android-x86_64` and `android-aarch64` have no CLI archive. Download both archives and their `.sha256` files, check them and extract them, with `TAG` and `PLATFORM` set to yours:

```bash
TAG=vX.Y.Z                                                    # the release tag
PLATFORM=linux-x86_64                                         # one of the platforms above
base=https://github.com/oxiforge/oxicrypt/releases/download/$TAG
for f in "oxicrypt-ffi-$TAG-$PLATFORM.tar.gz" "oxicrypt-cli-$TAG-$PLATFORM.tar.gz"; do
    curl -fLO "$base/$f" && curl -fLO "$base/$f.sha256"
    sha256sum -c "$f.sha256"                                  # macOS: shasum -a 256 -c "$f.sha256"
    tar -xzf "$f"
done
DIR=$PWD/oxicrypt-ffi-$TAG-$PLATFORM                          # the library bundle
export PATH="$PWD/oxicrypt-cli-$TAG-$PLATFORM:$PATH"          # puts oxi on PATH for step 6
```

The library bundle holds the shared library under its versioned name, `liboxicrypt_ffi.so.4` on Linux (`liboxicrypt_ffi.4.dylib` on macOS, `oxicrypt_ffi.dll` with the import library `oxicrypt_ffi.dll.lib` on Windows), with `liboxicrypt_ffi.so` (`liboxicrypt_ffi.dylib`) a link to it for linking; the static library `liboxicrypt_ffi.a` (`oxicrypt_ffi.lib`); the header `oxicrypt.h`; `LICENSE-APACHE` and `LICENSE-MIT`; and `BUILD-PROVENANCE.txt`. The CLI archive holds `oxi` (`oxi.exe`), the licences and its own `BUILD-PROVENANCE.txt`.

Each `BUILD-PROVENANCE.txt` records the integrity signature and the fingerprint of the key that signed the file, on a line `  verify key: sha256:<hex>`. The project's release key is [`keys/release-integrity-verify.pub`](../../keys/release-integrity-verify.pub) in this repository, and its fingerprint is the SHA-256 of that file:

```bash
sha256sum keys/release-integrity-verify.pub          # in a checkout of this repository; macOS: shasum -a 256
grep 'verify key:' "$DIR/BUILD-PROVENANCE.txt"
```

Both must name the same fingerprint. Then confirm that the `oxi` used in step 6 is the signed release:

```bash
oxi --integrity
```

It exits 0 and prints `integrity: passed — this binary matches the signature recorded inside it` and `  verify key: sha256:<hex>`, the same fingerprint.

## Load and start the module

cgo links the library when the program is built, so the bundle directory is given to the build, not to the program: `CGO_CFLAGS` names the header's directory and `CGO_LDFLAGS` the library. On Linux and macOS the build records the bundle directory as the program's run-time search path. The program takes the bundle directory as its first argument, as every example does, and does not read it:

```bash
CGO_ENABLED=1 CGO_CFLAGS="-I$DIR" CGO_LDFLAGS="-L$DIR -loxicrypt_ffi -Wl,-rpath,$DIR" go build -o example .
mkdir out
./example "$DIR" out
```

On Windows `CGO_LDFLAGS` names the DLL itself and the loader finds `oxicrypt_ffi.dll` through `PATH`; `run.sh` does both. `./run.sh "$DIR" out` does the same on every platform, and `./run.sh "$DIR"` uses a temporary output directory.

`oxi_init(0)` runs the power-up self-tests and the integrity test and selects the unrestricted profile. Any return other than 0 means the module refused to start: it serves nothing, and every later call returns `OXI_RESULT_NOT_OPERATIONAL` (1) until the process restarts. `oxi_integrity_status` tells why (1 is passed; the header lists every value), and `oxi_integrity_key_fingerprint` writes the fingerprint of the key the library trusts, which an application pinning the release key compares with the one from step 1:

```go
	rc := C.oxi_init(0)
	status := C.oxi_integrity_status()
	fp := make([]byte, 32)
	fpRC := C.oxi_integrity_key_fingerprint(ptr(fp), C.uintptr_t(len(fp)))
	if rc == C.OXI_RESULT_OK && status == 1 && fpRC == C.OXI_RESULT_OK {
		fmt.Fprintf(os.Stderr, "verify key sha256:%x\n", fp)
		return
	}
```

The program prints the fingerprint to standard error as `verify key sha256:<hex>` on every run, to compare with the `verify key` line of `BUILD-PROVENANCE.txt` from step 1; standard output stays the nine lines. On a library whose signed bytes were altered the program prints, leading with the condition that failed, and exits 1:

```text
oxi_init returned 2: the module refused to start
integrity status 2
verify key sha256:<hex>
```

## Hash

```go
	abc := []byte("abc")
	digest := make([]byte, 32)
	check("oxi_sha256", C.oxi_sha256(ptr(abc), C.uintptr_t(len(abc)), ptr(digest)))
```

prints

```text
sha256 abc ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## Sign and verify

The fixed inputs, as [`examples/README.md`](../README.md) states them:

| Constant | Value |
|---|---|
| `MESSAGE` | `The quick brown fox jumps over the lazy dog` (43 ASCII bytes, signed with the empty context) |
| `SIG_FLIP_BYTE` | 0: the signature byte XORed with `0x01` before the second verification |
| `PERSONALIZATION` | `oxicrypt example` (16 ASCII bytes, the personalization string given to `oxi_drbg_instantiate`) |

The program builds one of the module's DRBGs and has the module seed it; it supplies no seed and reads no entropy itself. Key generation draws its seed from that DRBG, and the program never writes the secret key to a file:

```go
	check("oxi_hmac_drbg_sha256_new_rbg", C.oxi_hmac_drbg_sha256_new_rbg(&rbg))
	perso := []byte(PERSONALIZATION)
	check("oxi_drbg_instantiate", C.oxi_drbg_instantiate(rbg, ptr(perso), C.uintptr_t(len(perso))))
	say("drbg instantiated")

	message := []byte(MESSAGE)
	msgLen := C.uintptr_t(len(message))
	pk, sig := make([]byte, pkLen), make([]byte, sigLen)
	expectOK("ml-dsa-87 keygen", C.oxi_ml_dsa_87_keygen_rbg(rbg, ptr(pk), ptr(sk), nil))
	check("oxi_ml_dsa_87_sign", C.oxi_ml_dsa_87_sign(ptr(sk), ptr(message), msgLen, nil, 0, ptr(sig)))
	write(out, "pk.bin", pk)
	write(out, "message.txt", message)
	write(out, "sig.bin", sig)
	expectOK("ml-dsa-87 verify", C.oxi_ml_dsa_87_verify(ptr(pk), ptr(message), msgLen, nil, 0, ptr(sig)))
	tamperedSig := bytes.Clone(sig)
	tamperedSig[SIG_FLIP_BYTE] ^= 0x01
	rc := C.oxi_ml_dsa_87_verify(ptr(pk), ptr(message), msgLen, nil, 0, ptr(tamperedSig))
```

prints

```text
drbg instantiated
ml-dsa-87 keygen ok
ml-dsa-87 verify ok
ml-dsa-87 verify-tampered rejected 22
```

22 is `OXI_RESULT_TAG_MISMATCH`, which `oxi_ml_dsa_87_verify` returns for any signature that does not verify. The program writes the public key, the message and the signature to `out/pk.bin`, `out/message.txt` and `out/sig.bin`.

## Establish a shared secret

| Constant | Value |
|---|---|
| `CT_FLIP_BYTE` | 0: the ciphertext byte XORed with `0x01` before the second decapsulation |

Key generation and encapsulation draw from the same DRBG:

```go
	ek, ct := make([]byte, ekLen), make([]byte, ctLen)
	expectOK("ml-kem-1024 keygen", C.oxi_ml_kem_1024_keygen_rbg(rbg, ptr(ek), ptr(dk), nil))
	check("oxi_ml_kem_1024_encapsulate_rbg", C.oxi_ml_kem_1024_encapsulate_rbg(ptr(ek), rbg, ptr(ss), ptr(ct)))
	write(out, "ek.bin", ek)
	write(out, "dk.bin", dk)
	write(out, "ct.bin", ct)
	expect("ml-kem-1024 decaps match", decapsLine("ml-kem-1024 decaps", ct))
```

where `decapsLine` calls `C.oxi_ml_kem_1024_decapsulate(ptr(dk), ptr(ct), ptr(ss2))` and compares the two secrets in constant time. The tampered ciphertext is decapsulated the same way, after `tamperedCT[CT_FLIP_BYTE] ^= 0x01`. The program prints

```text
ml-kem-1024 keygen ok
ml-kem-1024 decaps match
ml-kem-1024 decaps-tampered differs
ml-kem-1024 ss <64 lowercase hex digits>
```

The tampered ciphertext decapsulates without an error, to a different secret. FIPS 203 implicit rejection (§6.3) keeps a tampered ciphertext from revealing anything through the result; a real protocol detects the mismatch by key confirmation, not by an error from decapsulation. The program writes the encapsulation key, the decapsulation key and the ciphertext to `out/ek.bin`, `out/dk.bin` (readable and writable by its owner only) and `out/ct.bin`, and clears the secret key, the decapsulation key and the shared secrets before it exits; the hex string it prints for the shared secret is a Go `string`, which cannot be wiped.

## Check your output against `oxi`

In the output directory, with the `oxi` from step 1 on `PATH`:

```bash
cd out
oxi ml-dsa verify 87 --pk pk.bin --sig sig.bin message.txt        # exits 0
oxi ml-kem decaps 1024 --dk dk.bin --ct ct.bin                    # prints the program's ml-kem-1024 ss
```

Then the reverse direction, `oxi` encapsulating to the program's key and the program decapsulating:

```bash
oxi ml-kem encaps 1024 --ek ek.bin --ct oxi-ct.bin                # prints oxi's secret
../example "$DIR" decaps dk.bin oxi-ct.bin                        # prints ml-kem-1024 ss <oxi's secret>
```

`../run.sh "$DIR" decaps dk.bin oxi-ct.bin` builds the program and runs its decaps mode the same way on every platform. `oxi` never overwrites a file, so a second pass through this section needs a fresh output directory or new output names.

This proves that the program's buffers, lengths and calls agree with an independent consumer of the same library on every byte of every object, with no shared seed.

Last, the one known answer from NIST: key generation from the seed of the ML-DSA-87 ACVP key-generation vector that [`examples/README.md`](../README.md) records, and the SHA-256 of the public key:

```bash
oxi ml-dsa keygen 87 --seed f7052fbb921759cd8716773ba6355630121d6927899fdda5768e2bc240fccb7b --pk nist.pk --sk nist.sk
oxi hash sha256 nist.pk
```

The second command prints

```text
40298270777d3306d2fcb6b4691d7a7ab799cd1069eea88f843cf0ec26d4b01f  nist.pk
```

the digest `examples/README.md` records. `scripts/release-archive-check.sh crosscheck <cli-archive> <library-archive>` runs the checks of this section against each example.
