# LMS handler-dispatch map

The stateful hash-based signature scheme LMS per SP 800-208 (RFC 8554
+ RFC 8708). The ACVP `LMS` algorithm publishes its operation across
the envelope `mode` field; each handler keys on `(algorithm, mode,
revision)`. All handlers are registered in
`acvp-harness/src/dispatch.rs`.

| ACVP algorithm | ACVP mode | Handler struct | Source file |
| --- | --- | --- | --- |
| `LMS` | `keyGen` | `LmsKeyGenHandler` | `acvp-harness/src/handlers/lms.rs` |
| `LMS` | `sigGen` | `LmsSigGenHandler` | `acvp-harness/src/handlers/lms.rs` |
| `LMS` | `sigVer` | `LmsSigVerHandler` | `acvp-harness/src/handlers/lms.rs` |
