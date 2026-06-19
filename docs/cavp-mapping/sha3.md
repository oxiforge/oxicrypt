# SHA-3 handler-dispatch map

The FIPS 202 fixed-output SHA-3 family. SHA3-256 lives in its own
module (`handlers/sha3_256.rs`) for historical wiring reasons; the
other three members share `handlers/sha3.rs`. All handlers are
registered in `acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `SHA3-224` | — | `Sha3_224Handler` | `acvp-harness/src/handlers/sha3.rs` |
| `SHA3-256` | — | `Sha3_256Handler` | `acvp-harness/src/handlers/sha3_256.rs` |
| `SHA3-384` | — | `Sha3_384Handler` | `acvp-harness/src/handlers/sha3.rs` |
| `SHA3-512` | — | `Sha3_512Handler` | `acvp-harness/src/handlers/sha3.rs` |
