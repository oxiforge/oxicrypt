# oxicrypt-cmac

AES-CMAC per SP 800-38B

Part of [oxicrypt](https://github.com/oxiforge/oxicrypt) — a cryptographic module targeting
FIPS 140-3 Level 1, written entirely in Rust. No C, and no FFI into legacy
cryptographic libraries.

## Documentation

**[API documentation on docs.rs](https://docs.rs/oxicrypt-cmac)** — every public item,
with the standard each one implements.

## Installing

```sh
cargo add oxicrypt-cmac
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
