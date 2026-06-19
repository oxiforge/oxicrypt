# AES handler-dispatch map

The AES block-cipher mode family per FIPS 197 + SP 800-38A/C/D/F. The
`ACVP-AES-*` algorithms are a single-field family; each handler
processes the relevant AFT (and, for ECB/CBC, MCT) test types. All
handlers are registered in `acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `ACVP-AES-ECB` | — | `AesEcbHandler` | `acvp-harness/src/handlers/aes.rs` |
| `ACVP-AES-CBC` | — | `AesCbcHandler` | `acvp-harness/src/handlers/aes.rs` |
| `ACVP-AES-CTR` | — | `AesCtrHandler` | `acvp-harness/src/handlers/aes.rs` |
| `ACVP-AES-GCM` | — | `AesGcmHandler` | `acvp-harness/src/handlers/aes.rs` |
| `ACVP-AES-CCM` | — | `AesCcmHandler` | `acvp-harness/src/handlers/aes.rs` |
| `ACVP-AES-KW` | — | `AesKwHandler` | `acvp-harness/src/handlers/aes.rs` |
| `ACVP-AES-KWP` | — | `AesKwpHandler` | `acvp-harness/src/handlers/aes.rs` |
