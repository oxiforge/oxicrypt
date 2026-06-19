# KDF handler-dispatch map

The key-derivation-function families: SP 800-108r1 KBKDF, SP 800-56Cr2
KDA-HKDF, the TLS 1.2 / 1.3 KDFs, the TLS kdf-components KDF, and
PBKDF2 (SP 800-132 / RFC 8018). These do **not** share a single ACVP
algorithm string — each handler reports its own `(algorithm, mode,
revision)` triple, and some are mode-less. All handlers are registered
in `acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `KDF` | — | `KbkdfHandler` | `acvp-harness/src/handlers/kbkdf.rs` |
| `KDA` | `HKDF` | `KdaHkdfHandler` | `acvp-harness/src/handlers/kda_hkdf.rs` |
| `TLS-v1.2` | `KDF` | `Tls12KdfRfc7627Handler` | `acvp-harness/src/handlers/tls12_kdf.rs` |
| `TLS-v1.3` | `KDF` | `Tls13KdfHandler` | `acvp-harness/src/handlers/tls13_kdf.rs` |
| `kdf-components` | `tls` | `KdfComponentsTlsHandler` | `acvp-harness/src/handlers/kdf_comp_tls.rs` |
| `PBKDF` | — | `Pbkdf2Handler` | `acvp-harness/src/handlers/pbkdf2.rs` |

The `revision` string returned by each handler:

| Handler struct | ACVP revision |
| --- | --- |
| `KbkdfHandler` | `1.0` |
| `KdaHkdfHandler` | `Sp800-56Cr2` |
| `Tls12KdfRfc7627Handler` | `RFC7627` |
| `Tls13KdfHandler` | `RFC8446` |
| `KdfComponentsTlsHandler` | `1.0` |
| `Pbkdf2Handler` | `1.0` |
