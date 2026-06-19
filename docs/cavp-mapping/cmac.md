# CMAC handler-dispatch map

The SP 800-38B AES-CMAC family. A single handler covers both the
generate (`gen`) and verify (`ver`) directions across all three AES
key sizes. It is registered in `acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `CMAC-AES` | — | `CmacAesHandler` | `acvp-harness/src/handlers/cmac.rs` |
