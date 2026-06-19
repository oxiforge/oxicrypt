# KTS-IFC handler-dispatch map

The integer-factorization key-transport family per SP 800-56Br2
(RSAES-OAEP key transport, KTS-OAEP basic form, §7.2.2.2). The ACVTS
demo algorithm catalog registers this algorithm with **no** `mode`
field, so the handler keys on `(algorithm, None, revision)`. It is
registered in `acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `KTS-IFC` | — | `KtsIfcHandler` | `acvp-harness/src/handlers/kts_ifc.rs` |
