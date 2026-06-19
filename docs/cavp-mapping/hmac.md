# HMAC handler-dispatch map

The FIPS 198-1 keyed-hash MAC family over the SHA-2 and SHA-3 digests.
HMAC-SHA2-256 lives in its own module (`handlers/hmac_sha2_256.rs`);
every other variant shares `handlers/hmac.rs`. All handlers are
registered in `acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `HMAC-SHA-1` | — | `HmacSha1Handler` | `acvp-harness/src/handlers/hmac.rs` |
| `HMAC-SHA2-224` | — | `HmacSha2_224Handler` | `acvp-harness/src/handlers/hmac.rs` |
| `HMAC-SHA2-256` | — | `HmacSha2_256Handler` | `acvp-harness/src/handlers/hmac_sha2_256.rs` |
| `HMAC-SHA2-384` | — | `HmacSha2_384Handler` | `acvp-harness/src/handlers/hmac.rs` |
| `HMAC-SHA2-512` | — | `HmacSha2_512Handler` | `acvp-harness/src/handlers/hmac.rs` |
| `HMAC-SHA2-512/224` | — | `HmacSha2_512_224Handler` | `acvp-harness/src/handlers/hmac.rs` |
| `HMAC-SHA2-512/256` | — | `HmacSha2_512_256Handler` | `acvp-harness/src/handlers/hmac.rs` |
| `HMAC-SHA3-224` | — | `HmacSha3_224Handler` | `acvp-harness/src/handlers/hmac.rs` |
| `HMAC-SHA3-256` | — | `HmacSha3_256Handler` | `acvp-harness/src/handlers/hmac.rs` |
| `HMAC-SHA3-384` | — | `HmacSha3_384Handler` | `acvp-harness/src/handlers/hmac.rs` |
| `HMAC-SHA3-512` | — | `HmacSha3_512Handler` | `acvp-harness/src/handlers/hmac.rs` |
