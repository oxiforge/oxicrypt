# SHAKE handler-dispatch map

The FIPS 202 extendable-output (XOF) SHAKE family. Each handler
processes the ACVP `AFT`, `VOT`, `MCT`, and `LDT` test types with
per-case `outLen`. Both handlers are registered in
`acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `SHAKE-128` | — | `Shake128Handler` | `acvp-harness/src/handlers/shake.rs` |
| `SHAKE-256` | — | `Shake256Handler` | `acvp-harness/src/handlers/shake.rs` |
