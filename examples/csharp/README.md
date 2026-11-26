# C#

`Program.cs` declares each function it calls with `DllImport` and registers a `NativeLibrary.SetDllImportResolver` that loads the library from the bundle directory given as the program's first argument, so no search path has to be set. It starts the module, hashes, signs and verifies with ML-DSA-87, and establishes a shared secret with ML-KEM-1024, checking each result against the line [`examples/README.md`](../README.md) expects.

Prerequisites: the .NET SDK 10 or later and the library bundle and CLI archive for your platform. The project targets .NET 10; `RollForward` set to `Major` lets the program run on a later runtime when .NET 10 is not installed.

Verified on Linux x86_64 with the .NET SDK 10.0.404, against a `linux-x86_64` library bundle and CLI archive built and signed from the same source tree.

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

Build the program and run it against the bundle, with an output directory for the files steps 4 and 5 write:

```bash
dotnet build -o bin/out
mkdir out
dotnet bin/out/Example.dll "$DIR" out
```

`./run.sh "$DIR" out` does the same on every platform with a temporary build directory, and `./run.sh "$DIR"` also uses a temporary output directory. The resolver loads the library by its delivered name:

```csharp
string name = OperatingSystem.IsWindows() ? "oxicrypt_ffi.dll"
    : OperatingSystem.IsMacOS() ? "liboxicrypt_ffi.4.dylib"
    : "liboxicrypt_ffi.so.4";
string path = Path.Combine(args[0], name);
NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(),
    (library, _, _) => library == Oxi.Library ? NativeLibrary.Load(path) : IntPtr.Zero);
```

`oxi_init(0)` runs the power-up self-tests and the integrity test and selects the unrestricted profile. Any return other than 0 means the module refused to start: it serves nothing, and every later call returns `OXI_RESULT_NOT_OPERATIONAL` (1) until the process restarts. `oxi_integrity_status` tells why (1 is passed; the header lists every value), and `oxi_integrity_key_fingerprint` writes the fingerprint of the key the library trusts, which an application pinning the release key compares with the one from step 1:

```csharp
        int rc = Oxi.Init(0);
        int status = Oxi.IntegrityStatus();
        byte[] fp = new byte[32];
        int fpRc = Oxi.IntegrityKeyFingerprint(fp, (nuint)fp.Length);
        string fpLine = $"verify key sha256:{Hex(fp)}";
        if (rc == 0 && status == 1 && fpRc == 0)
        {
            Console.Error.WriteLine(fpLine);
            return;
        }
```

The program prints the fingerprint to standard error as `verify key sha256:<hex>` on every run, to compare with the `verify key` line of `BUILD-PROVENANCE.txt` from step 1; standard output stays the nine lines. On a library whose signed bytes were altered the program prints, leading with the condition that failed, and exits 1:

```text
oxi_init returned 2: the module refused to start
integrity status 2
verify key sha256:<hex>
```

## Hash

```csharp
        byte[] abc = Encoding.ASCII.GetBytes("abc");
        byte[] digest = new byte[32];
        Check("oxi_sha256", Oxi.Sha256(abc, (nuint)abc.Length, digest));
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

The program builds one of the module's DRBGs and has the module seed it; it supplies no seed and reads no entropy itself. The handle comes back as an `out IntPtr`. Key generation draws its seed from that DRBG, and the program never writes the secret key to a file:

```csharp
        Check("oxi_hmac_drbg_sha256_new_rbg", Oxi.HmacDrbgSha256NewRbg(out rbg));
        byte[] perso = Encoding.ASCII.GetBytes(PERSONALIZATION);
        Check("oxi_drbg_instantiate", Oxi.DrbgInstantiate(rbg, perso, (nuint)perso.Length));
        Console.WriteLine("drbg instantiated");

        byte[] message = Encoding.ASCII.GetBytes(MESSAGE);
        nuint msgLen = (nuint)message.Length;
        byte[] pk = new byte[PkLen], sig = new byte[SigLen];
        ExpectOk("ml-dsa-87 keygen", Oxi.MlDsa87KeygenRbg(rbg, pk, sk, null));
        Check("oxi_ml_dsa_87_sign", Oxi.MlDsa87Sign(sk, message, msgLen, null, 0, sig));
        Write(outDir, "pk.bin", pk);
        Write(outDir, "message.txt", message);
        Write(outDir, "sig.bin", sig);
        ExpectOk("ml-dsa-87 verify", Oxi.MlDsa87Verify(pk, message, msgLen, null, 0, sig));
        byte[] tamperedSig = (byte[])sig.Clone();
        tamperedSig[SIG_FLIP_BYTE] ^= 0x01;
        int rc = Oxi.MlDsa87Verify(pk, message, msgLen, null, 0, tamperedSig);
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

```csharp
        byte[] ek = new byte[EkLen], ct = new byte[CtLen];
        ExpectOk("ml-kem-1024 keygen", Oxi.MlKem1024KeygenRbg(rbg, ek, dk, null));
        Check("oxi_ml_kem_1024_encapsulate_rbg", Oxi.MlKem1024EncapsulateRbg(ek, rbg, ss, ct));
        Write(outDir, "ek.bin", ek);
        Write(outDir, "dk.bin", dk, ownerOnly: true);
        Write(outDir, "ct.bin", ct);
```

Decapsulation writes into a second array, which `CryptographicOperations.FixedTimeEquals` compares with the first; the tampered ciphertext is decapsulated the same way, after `tamperedCt[CT_FLIP_BYTE] ^= 0x01`. The program prints

```text
ml-kem-1024 keygen ok
ml-kem-1024 decaps match
ml-kem-1024 decaps-tampered differs
ml-kem-1024 ss <64 lowercase hex digits>
```

The tampered ciphertext decapsulates without an error, to a different secret. FIPS 203 implicit rejection (§6.3) keeps a tampered ciphertext from revealing anything through the result; a real protocol detects the mismatch by key confirmation, not by an error from decapsulation. The program writes the encapsulation key, the decapsulation key and the ciphertext to `out/ek.bin`, `out/dk.bin` (readable and writable by its owner only) and `out/ct.bin`. The secret key, the decapsulation key and the shared secrets live in arrays allocated pinned, so the collector never copies them, and `CryptographicOperations.ZeroMemory` wipes them before the program exits; the hex string it prints for the shared secret is a .NET `string`, which cannot be wiped.

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
dotnet ../bin/out/Example.dll "$DIR" decaps dk.bin oxi-ct.bin     # prints ml-kem-1024 ss <oxi's secret>
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
