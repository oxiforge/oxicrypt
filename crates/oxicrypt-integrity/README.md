# oxicrypt-integrity

Pre-operational software integrity self-test (ISO/IEC 19790:2012 §7.10.2.2): an
ML-DSA-87 signature (FIPS 204) over the module's loaded image, verified at power-up
with a public key compiled into the module. The signature is made under the context
string `oxicrypt-integrity`, which separates it from signatures the same key makes
under any other context string.

## The verifying key is a build input

Set `OXICRYPT_INTEGRITY_VERIFY_KEY` to the path of a 2,592-byte ML-DSA-87 public
key (or `OXICRYPT_INTEGRITY_VERIFY_KEY_HEX` to its 5,184 hex digits) when you build.
Any other length stops the build. A build without either compiles, but the module reports `NoVerifyKey` at power-up and
never becomes operational. `oxicrypt-integrity-sign --keygen` generates a pair, and
`oxicrypt-integrity-sign --sign --key` signs the built artifact with the private half.

Part of [oxicrypt](https://github.com/oxiforge/oxicrypt) — a cryptographic module targeting
FIPS 140-3 Level 1, written entirely in Rust. No C, and no FFI into legacy
cryptographic libraries.

## Documentation

**[API documentation on docs.rs](https://docs.rs/oxicrypt-integrity)** — every public item,
with the standard each one implements.

## Installing

```sh
cargo add oxicrypt-integrity
```

New to oxicrypt? Start with
[`oxicrypt-module`](https://crates.io/crates/oxicrypt-module) — it defines the
cryptographic boundary and runs the power-up self-tests.

## Validation status

oxicrypt holds **no NIST certificate**. Its algorithms are graded on NIST's ACVP
*demonstration* server — the real protocol against NIST's own vectors, but not a
route to a CAVP certificate, which is open only to accredited laboratories. Module
validation (CMVP) has not been submitted. The full position, including what that
does and does not entitle you to claim, is in the
[validation status](https://github.com/oxiforge/oxicrypt#validation-status) section.

## Licence

Apache-2.0 OR MIT, at your option. The licences grant rights in the code, not in
the oxicrypt™ name.
