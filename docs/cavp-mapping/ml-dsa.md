# ML-DSA handler-dispatch map

The post-quantum digital-signature algorithm ML-DSA per FIPS 204. The
ACVP `ML-DSA` algorithm publishes its operation across the envelope
`mode` field; each handler keys on `(algorithm, mode, revision)`. All
handlers are registered in `acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `ML-DSA` | `keyGen` | `MlDsaKeyGenHandler` | `acvp-harness/src/handlers/ml_dsa.rs` |
| `ML-DSA` | `sigGen` | `MlDsaSigGenHandler` | `acvp-harness/src/handlers/ml_dsa.rs` |
| `ML-DSA` | `sigVer` | `MlDsaSigVerHandler` | `acvp-harness/src/handlers/ml_dsa.rs` |
