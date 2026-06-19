# RSA handler-dispatch map

The RSA family per FIPS 186-5 (signatures), RFC 8017 (OAEP), and
SP 800-56Br2 (decryption primitive). The ACVP `RSA` algorithm
publishes its operation across the envelope `mode` field; each handler
keys on `(algorithm, mode, revision)`. Note that the `revision` is not
uniform across RSA operations — it tracks the standard governing each
operation. All handlers are registered in
`acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `RSA` | `keyGen` | `RsaKeyGenHandler` | `acvp-harness/src/handlers/rsa_keygen.rs` |
| `RSA` | `sigGen` | `RsaSigGenHandler` | `acvp-harness/src/handlers/rsa_siggen.rs` |
| `RSA` | `sigVer` | `RsaSigVerHandler` | `acvp-harness/src/handlers/rsa.rs` |
| `RSA` | `signaturePrimitive` | `RsaSigPrimHandler` | `acvp-harness/src/handlers/rsa_sigprim.rs` |
| `RSA` | `decryptionPrimitive` | `RsaDecPrimHandler` | `acvp-harness/src/handlers/rsa_decprim.rs` |
| `RSA` | `OAEP` | `RsaOaepHandler` | `acvp-harness/src/handlers/rsa_oaep.rs` |

The `revision` string returned by each handler:

| Handler struct | ACVP revision |
| --- | --- |
| `RsaKeyGenHandler` | `FIPS186-5` |
| `RsaSigGenHandler` | `FIPS186-5` |
| `RsaSigVerHandler` | `FIPS186-5` |
| `RsaSigPrimHandler` | `2.0` |
| `RsaDecPrimHandler` | `Sp800-56Br2` |
| `RsaOaepHandler` | `RFC8017` |
