# KAS-SSC handler-dispatch map

The shared-secret-computation (SSC) key-agreement family per
SP 800-56Ar3 — elliptic-curve (ECC) and finite-field (FFC) variants.
Both algorithms register with **no** `mode` field (the ACVTS demo
algorithm catalog lists them mode-less), so each keys on
`(algorithm, None, revision)`. Both handlers are registered in
`acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `KAS-ECC-SSC` | — | `KasEccSscHandler` | `acvp-harness/src/handlers/kas_ecc_ssc.rs` |
| `KAS-FFC-SSC` | — | `KasFfcSscHandler` | `acvp-harness/src/handlers/kas_ffc_ssc.rs` |
