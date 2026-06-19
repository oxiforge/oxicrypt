# SLH-DSA handler-dispatch map

The post-quantum stateless hash-based signature algorithm SLH-DSA per
FIPS 205. The ACVP `SLH-DSA` algorithm publishes its operation across
the envelope `mode` field; each handler keys on `(algorithm, mode,
revision)`. All handlers are registered in
`acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `SLH-DSA` | `keyGen` | `SlhDsaKeyGenHandler` | `acvp-harness/src/handlers/slh_dsa.rs` |
| `SLH-DSA` | `sigGen` | `SlhDsaSigGenHandler` | `acvp-harness/src/handlers/slh_dsa.rs` |
| `SLH-DSA` | `sigVer` | `SlhDsaSigVerHandler` | `acvp-harness/src/handlers/slh_dsa.rs` |
