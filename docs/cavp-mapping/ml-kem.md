# ML-KEM handler-dispatch map

The post-quantum key-encapsulation mechanism ML-KEM per FIPS 203. The
ACVP `ML-KEM` algorithm publishes its operation across the envelope
`mode` field; each handler keys on `(algorithm, mode, revision)`. Both
handlers are registered in `acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `ML-KEM` | `keyGen` | `MlKemKeyGenHandler` | `acvp-harness/src/handlers/ml_kem.rs` |
| `ML-KEM` | `encapDecap` | `MlKemEncapDecapHandler` | `acvp-harness/src/handlers/ml_kem.rs` |
