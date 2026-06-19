# ECDSA handler-dispatch map

The FIPS 186-5 ECDSA family. The ACVP `ECDSA` algorithm publishes
across the envelope `mode` field; each of the four operations is a
separate handler keyed on `(algorithm, mode, revision)`. All handlers
are registered in `acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `ECDSA` | `keyGen` | `EcdsaKeyGenHandler` | `acvp-harness/src/handlers/ecdsa.rs` |
| `ECDSA` | `keyVer` | `EcdsaKeyVerHandler` | `acvp-harness/src/handlers/ecdsa.rs` |
| `ECDSA` | `sigGen` | `EcdsaSigGenHandler` | `acvp-harness/src/handlers/ecdsa.rs` |
| `ECDSA` | `sigVer` | `EcdsaSigVerHandler` | `acvp-harness/src/handlers/ecdsa.rs` |
