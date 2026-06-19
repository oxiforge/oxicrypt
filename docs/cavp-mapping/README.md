# CAVP mapping

This directory maps ACVP/CAVP algorithm families to the oxicrypt
crates and harness machinery that implement and validate them.

Two flavors of mapping note live here:

- **Handler-dispatch maps** (this index) — one note per ACVP algorithm
  family, mapping each ACVP algorithm/mode string to the
  `acvp-harness` handler struct that processes it. Every handler is
  registered in `acvp-harness/src/dispatch.rs` and implements the
  `AlgorithmHandler` trait; the literal strings in each table are the
  values returned by that handler's `fn algorithm()` and
  `fn mode()`.
- **KAT vendor traceability** — [`drbg.md`](drbg.md) is the
  pre-existing companion of a different flavor: it traces every
  power-up known-answer test in `oxicrypt-drbg` back to its exact
  vendored NIST CAVP `.rsp` source file, section, and line.

## Handler-dispatch family notes

### Hashing and XOFs

- [`sha2.md`](sha2.md) — SHA-1 / SHA-2 fixed-output hashing (FIPS 180-4).
- [`sha3.md`](sha3.md) — SHA-3 fixed-output hashing (FIPS 202).
- [`shake.md`](shake.md) — SHAKE extendable-output functions (FIPS 202).
- [`xof-sp800-185.md`](xof-sp800-185.md) — cSHAKE / KMAC / TupleHash / ParallelHash and their XOF forms (SP 800-185).

### Message authentication

- [`hmac.md`](hmac.md) — HMAC over SHA-2 and SHA-3 (FIPS 198-1).
- [`cmac.md`](cmac.md) — AES-CMAC (SP 800-38B).

### Symmetric ciphers

- [`aes.md`](aes.md) — AES block-cipher modes (FIPS 197 + SP 800-38A/C/D/F).

### Asymmetric signatures and keys

- [`ecdsa.md`](ecdsa.md) — ECDSA keyGen / keyVer / sigGen / sigVer (FIPS 186-5).
- [`eddsa.md`](eddsa.md) — EdDSA keyGen / keyVer / sigGen / sigVer.
- [`rsa.md`](rsa.md) — RSA keyGen / sigGen / sigVer / primitives / OAEP (FIPS 186-5, RFC 8017, SP 800-56Br2).

### Key agreement and transport

- [`kas.md`](kas.md) — KAS-ECC-SSC / KAS-FFC-SSC shared-secret computation (SP 800-56Ar3).
- [`kts-ifc.md`](kts-ifc.md) — KTS-IFC RSAES-OAEP key transport (SP 800-56Br2).

### Key derivation

- [`kdf.md`](kdf.md) — KBKDF / KDA-HKDF / TLS 1.2 / TLS 1.3 / kdf-components / PBKDF2.

### Post-quantum

- [`ml-kem.md`](ml-kem.md) — ML-KEM keyGen / encapDecap (FIPS 203).
- [`ml-dsa.md`](ml-dsa.md) — ML-DSA keyGen / sigGen / sigVer (FIPS 204).
- [`slh-dsa.md`](slh-dsa.md) — SLH-DSA keyGen / sigGen / sigVer (FIPS 205).
- [`lms.md`](lms.md) — LMS keyGen / sigGen / sigVer (SP 800-208 / RFC 8554).
- [`xmss.md`](xmss.md) — XMSS keyGen / sigGen / sigVer (SP 800-208 / RFC 8391).
