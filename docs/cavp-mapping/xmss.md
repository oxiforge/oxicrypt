# XMSS handler-dispatch map

The eXtended Merkle Signature Scheme XMSS per SP 800-208 (RFC 8391).
The ACVP `XMSS` algorithm publishes its operation across the envelope
`mode` field; each handler keys on `(algorithm, mode, revision)`. All
handlers are registered in `acvp-harness/src/dispatch.rs`.
The module verifies XMSS signatures and neither generates keys nor signs,
per SP 800-208 §8.2, so `sigVer` is the only mode dispatched.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `XMSS` | `sigVer` | `XmssSigVerHandler` | `acvp-harness/src/handlers/xmss.rs` |
