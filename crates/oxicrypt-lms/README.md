# oxicrypt-lms

LMS signature verification (SP 800-208) for CNSA 2.0 firmware signing

Verifies LMS signatures for all 80 (LMS, LM-OTS) parameter-set pairs that
SP 800-208 §4.1–§4.4 approve. Key generation and signing are not offered:
SP 800-208 §8.1 confines them to hardware modules, and FIPS 140-3 IG C.N
resolutions 6 and 9 rule out offering them in a software module at all.

Part of [oxicrypt](https://github.com/oxiforge/oxicrypt) — a cryptographic module targeting
FIPS 140-3 Level 1, written entirely in Rust. No C, and no FFI into legacy
cryptographic libraries.

## Documentation

**[API documentation on docs.rs](https://docs.rs/oxicrypt-lms)** — every public item,
with the standard each one implements.

## Installing

```sh
cargo add oxicrypt-lms
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
