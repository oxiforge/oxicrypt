# Examples

Each directory holds a program that loads the oxicrypt C library from an extracted release bundle and makes a first call of each kind right:

1. starts the module with `oxi_init(0)` and reads its integrity result with `oxi_integrity_status` and `oxi_integrity_key_fingerprint`;
2. computes SHA-256 of `"abc"` with `oxi_sha256`;
3. builds one HMAC_DRBG-SHA-256 handle with `oxi_hmac_drbg_sha256_new_rbg` and instantiates it with `oxi_drbg_instantiate`, which seeds it from the module's own entropy source;
4. generates an ML-DSA-87 key pair drawing from that DRBG, signs a fixed message with the empty context, verifies the signature, and verifies it again with one byte flipped;
5. generates an ML-KEM-1024 key pair and encapsulates to it, both drawing from the same DRBG, decapsulates, compares the two shared secrets, and decapsulates again with one ciphertext byte flipped.

No program supplies a seed or reads the operating system's entropy: every key and every encapsulation draws from the DRBG the module seeded.

| Directory | Language | Binding |
|---|---|---|
| [`c/`](c/) | C | the header `oxicrypt.h`, linked against the shared library |
| [`python/`](python/) | Python | `ctypes` |
| [`go/`](go/) | Go | cgo against `oxicrypt.h` |
| [`node/`](node/) | Node.js | `koffi` |
| [`java/`](java/) | Java | Foreign Function & Memory API |
| [`csharp/`](csharp/) | C# | P/Invoke (`DllImport`) |

## Fixed inputs

Every program defines these constants under these names, with these values:

| Constant | Value |
|---|---|
| `MESSAGE` | `The quick brown fox jumps over the lazy dog` (43 ASCII bytes, signed with the empty context) |
| `SIG_FLIP_BYTE` | 0: the signature byte XORed with `0x01` before the second verification |
| `CT_FLIP_BYTE` | 0: the ciphertext byte XORed with `0x01` before the second decapsulation |
| `PERSONALIZATION` | `oxicrypt example` (16 ASCII bytes, the personalization string given to `oxi_drbg_instantiate`) |

`scripts/check-example-inputs.sh` checks that the message and the two byte positions agree across every program and every how-to.

## Output

`<program> <bundle-dir> <out-dir>` prints these nine lines and writes `pk.bin`, `message.txt`, `sig.bin`, `ek.bin`, `dk.bin` and `ct.bin` into `<out-dir>`:

```text
sha256 abc ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
drbg instantiated
ml-dsa-87 keygen ok
ml-dsa-87 verify ok
ml-dsa-87 verify-tampered rejected 22
ml-kem-1024 keygen ok
ml-kem-1024 decaps match
ml-kem-1024 decaps-tampered differs
ml-kem-1024 ss <64 lowercase hex digits>
```

The first eight lines are fixed. The ninth is the shared secret of this run, fresh each time. `22` is `OXI_RESULT_TAG_MISMATCH`, the code `oxi_ml_dsa_87_verify` returns for any signature that does not verify. The tampered ciphertext decapsulates without an error to a different secret: FIPS 203 implicit rejection (§6.3) returns a pseudorandom secret rather than revealing through the result that the ciphertext was altered.

`<program> <bundle-dir> decaps <dk-file> <ct-file>` decapsulates the ciphertext in `<ct-file>` under the decapsulation key in `<dk-file>` and prints only `ml-kem-1024 ss <64 lowercase hex digits>`.

A program exits 0 only when it printed every line. It exits 1 at the first result that differs from its expected line, printing the expected and the actual line; and it exits 1 printing the return code when `oxi_init`, `oxi_drbg_instantiate` or any other call fails, with the integrity status and the verify key's fingerprint when the module refused to start. A wrong number of arguments exits 2.

Each directory's `run.sh <bundle-dir> [out-dir]` builds the program if it needs building and runs it against the bundle. Without `<out-dir>` it writes the files to a temporary directory and removes it afterwards; with one it leaves them there. The release workflow runs, against every library it ships for a host it can execute on, each example whose toolchain that host has, and fails if a toolchain the host is known to have is missing.

## A known answer from NIST

The ML-DSA-87 key-generation vector tgId 3, tcId 51 of the NIST ACVP `ML-DSA-keyGen-FIPS204` test vectors, the vector the module's own self-test embeds, has the seed

```text
f7052fbb921759cd8716773ba6355630121d6927899fdda5768e2bc240fccb7b
```

and its public key has the SHA-256 digest

```text
40298270777d3306d2fcb6b4691d7a7ab799cd1069eea88f843cf0ec26d4b01f
```

The seed and the public key are committed as `oxi/tests/data/ml-dsa-87-keygen-tg3-tc51.seed` and `.pk`.
