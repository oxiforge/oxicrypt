# SHA-1 / SHA-2 handler-dispatch map

The FIPS 180-4 hashing family. Each handler covers one fixed-output
SHA-1/SHA-2 digest length and processes the ACVP `AFT`, `MCT`, and
`LDT` test types. All handlers are registered in
`acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `SHA-1` | — | `Sha1Handler` | `acvp-harness/src/handlers/sha2.rs` |
| `SHA2-224` | — | `Sha2_224Handler` | `acvp-harness/src/handlers/sha2.rs` |
| `SHA2-256` | — | `Sha2_256Handler` | `acvp-harness/src/handlers/sha2.rs` |
| `SHA2-384` | — | `Sha2_384Handler` | `acvp-harness/src/handlers/sha2.rs` |
| `SHA2-512` | — | `Sha2_512Handler` | `acvp-harness/src/handlers/sha2.rs` |
| `SHA2-512/224` | — | `Sha2_512_224Handler` | `acvp-harness/src/handlers/sha2.rs` |
| `SHA2-512/256` | — | `Sha2_512_256Handler` | `acvp-harness/src/handlers/sha2.rs` |
