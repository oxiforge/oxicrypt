# LMS handler-dispatch map

The hash-based signature scheme LMS per SP 800-208 (RFC 8554), over the
80 (LMS, LM-OTS) parameter pairs of SP 800-208 §4.1–§4.4. The ACVP `LMS`
algorithm publishes its operation across the envelope `mode` field; each
handler keys on `(algorithm, mode, revision)`. All handlers are
registered in `acvp-harness/src/dispatch.rs`.
The module verifies LMS signatures and neither generates keys nor signs,
per SP 800-208 §8.2, so `sigVer` is the only mode dispatched. It is
served under both ACVP revisions the server advertises for it.

| ACVP algorithm | ACVP mode | Revision | Handler struct | Source file |
| --- | --- | --- | --- | --- |
| `LMS` | `sigVer` | `1.0` | `LmsSigVerHandler` | `acvp-harness/src/handlers/lms.rs` |
| `LMS` | `sigVer` | `SP800-208` | `LmsSigVerSp800208Handler` | `acvp-harness/src/handlers/lms.rs` |
