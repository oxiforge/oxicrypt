# EdDSA handler-dispatch map

The EdDSA family (Ed25519, pure) per FIPS 186-5. The ACVP `EDDSA`
algorithm publishes across the envelope `mode` field; each of the four
operations is a separate handler keyed on `(algorithm, mode,
revision)`. All handlers are registered in
`acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `EDDSA` | `keyGen` | `EddsaKeyGenHandler` | `acvp-harness/src/handlers/eddsa.rs` |
| `EDDSA` | `keyVer` | `EddsaKeyVerHandler` | `acvp-harness/src/handlers/eddsa.rs` |
| `EDDSA` | `sigGen` | `EddsaSigGenHandler` | `acvp-harness/src/handlers/eddsa.rs` |
| `EDDSA` | `sigVer` | `EddsaSigVerHandler` | `acvp-harness/src/handlers/eddsa.rs` |
