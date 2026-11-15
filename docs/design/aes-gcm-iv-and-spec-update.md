# Design: module-generated GCM IVs and the AES conformance update

Design-of-record for one update to `oxicrypt-aes`, `oxicrypt-cmac` and the C
interface that brings the AES services into line with FIPS 140-3
Implementation Guidance C.H (last modified 2026-08-19) and the SP 800-38
series, and closes the other gaps in that surface so the crate changes once.
Issue #295 (the GCM IV) and issue #296 (the GCM input limits) are covered
here together with the gaps listed under "Gaps closed".

Status: DRAFT, revision 2, under review. Nothing here is implemented.

## Problem

SP 800-38D requires that the probability of the authenticated encryption
function ever being invoked with the same key and IV on two distinct inputs is
no greater than 2^-32 (§8), that the IV generation unit sits inside the
cryptographic module (§9.1), and that the IV is a critical security parameter
until the encryption consumes it (§9.1 item 2). IG C.H lists the five ways a
module may produce a GCM IV for an approved encryption service. Today
`gcm_encrypt` takes the whole 96-bit IV from the caller. No scenario of C.H
covers that, and the crate documentation says the opposite of §9.1: that IVs
are never SSPs.

Three further facts shape the design. The module's DRBGs are instances the
caller creates and seeds; the module owns no DRBG of its own. The AES key
types are `Clone`, so nothing can count how often a key has been used. And
one key type serves every mode, while SP 800-38D §5.1, SP 800-38C §5.1 and
SP 800-38B §5.3 each require a key to be used exclusively for that mode.

## Requirements

Each row names the decision that satisfies it.

| ID | Source | Requirement | Satisfied by |
|---|---|---|---|
| R1 | IG C.H Scenario 2 | The IV is generated internally, in its entirety, at random, by an approved DRBG internal to the module's boundary. | D1, D2 |
| R2 | IG C.H Scenario 2; SP 800-38D §8.2.2 | The random field is at least 96 bits; the free field is recommended empty, so the random field is the whole IV. | D1 |
| R3 | IG C.H Scenario 2 | The Security Policy carries a statement to that effect in its Section 2.7 (SP 800-140B: Algorithm Specific Information). | D8 |
| R4 | IG C.H Additional Comments 4 and 5 | The DRBG is inside the boundary; its entropy may come from outside; the IG 9.3.A entropy caveat is documented. | D2, D8 |
| R5 | IG C.H Additional Comment 7 | Decryption is exempt: the IV for decryption comes from the encrypting party. | D6 |
| R6 | IG C.H Additional Comment 10; SP 800-38D §9.1 item 2 | The IV is an SSP until the authenticated encryption function is invoked with it (a CSP before, a PSP after), with the same protection as other CSPs. | D5 |
| R7 | SP 800-38D §8.3 | With the RBG-based construction the total number of authenticated-encryption invocations with a given key, across all instances, shall not exceed 2^32. | D3 |
| R8 | SP 800-38D §8.2.2 | RBG instantiations in distinct devices are independent: each instantiation has a distinct seed. | D2, D8 |
| R9 | SP 800-38D §9.1 item 3, §9.2 | Loss of power shall not cause IV repetition; if the generation unit cannot recover, the encryption function enters a failure state until a fresh key is established. | D3, D8 |
| R10 | SP 800-38D §5.2.1.1 | len(P) ≤ 2^39−256 bits; len(A) ≤ 2^64−1 bits. | D7 |
| R11 | SP 800-38D §8.2.2 | The RBG has sufficient security strength for the IV. | D2 |
| R12 | IG 10.3.A | Every approved algorithm the module offers has a CAST before first use. | D9 |
| R13 | SP 800-38D §5.1; SP 800-38C §5.1; SP 800-38B §5.3 | A key is used exclusively for the one mode it was established for. | D3 |

The clauses in the "Gaps closed" table are further requirements and are not
repeated here.

## Threat model

The adversary observes ciphertexts and tags, may call the module's services
with chosen inputs, and may hold a copy of the key, as a legitimate second
party does. The property GCM must keep is that no two encryptions under one
key share an IV: a repeat leaks the XOR of plaintexts and, with the
authentication key H recoverable from two tags, forgeries. The module can
enforce that property only for the IVs it generates itself and only within
the key instances it can observe. Everything else is stated as an operator
obligation in the Security Policy.

The module does not defend against a caller that copies key material out of
its own process and uses it elsewhere; that is the key owner's choice, as it
is for any imported key.

## Design

### D1. The approved GCM encryption service generates the whole 96-bit IV

`gcm_encrypt` takes no IV. It draws 12 bytes from the DRBG the caller hands
it, encrypts, and returns the IV to the caller beside the ciphertext and tag.
The free field of SP 800-38D §8.2.2 is empty. The tag stays 128 bits.

The entry point that encrypts under a caller-supplied IV leaves the public
API. The power-up known-answer test needs a fixed IV; it calls a
`pub(crate)` core that `gcm_encrypt` wraps, and nothing outside the crate can
reach that core. The ACVP harness is a separate crate and needs no fixed IV:
under `ivGen: internal` (`ivGenMode: 8.2.2`) the test server expects the
implementation to produce the IV, so the harness calls `gcm_encrypt` with a
DRBG and returns the IV it gets back. The capability registration and the
generator that checks it change from `external` to `internal`; the
machine-readable evidence file is regenerated after the next graded run.

Rejected: keeping a caller-IV encryption function as a non-approved service
with an indicator. It would be the same code path a laboratory must then see
is unreachable in the approved mode, it keeps the misuse surface that
motivated the IG, and the module has no other non-approved AES service to
keep it company. The cost of removal falls on callers that construct their
own IVs, addressed under Migration.

### D2. The DRBG is a caller-owned instance of one of the module's DRBGs

The encryption takes `&mut` a DRBG instance: any of HMAC_DRBG (SHA-256, -384,
-512), Hash_DRBG (SHA-256, -384, -512) or CTR_DRBG (AES-128, -192, -256) from
`oxicrypt-drbg`, through a trait, `GcmIvSource`, with one method that
generates into a fixed-size buffer with no additional input (for CTR_DRBG,
the derivation-function variant the instance was instantiated with).
`oxicrypt-drbg` already depends on `oxicrypt-aes` (CTR_DRBG uses the block
cipher), so the trait is defined in `oxicrypt-aes` and implemented in
`oxicrypt-drbg` for the nine types; no dependency is added in the other
direction. A trait implemented in a second crate cannot be sealed, so in the
Rust crates a consumer could in principle implement it. Where that matters
is stated under "The boundary, as a laboratory would ask it" below. The instance must be instantiated and healthy; an uninstantiated or
errored DRBG fails the encryption before any key material is touched, with
the DRBG's own error (`Uninstantiated`, `ReseedRequired`, the module error
state) passed through so the caller can recover as it would from the DRBG
directly.

Why this and not a module-owned DRBG. The repository already does randomness
this way: ECDSA key generation takes `&mut HmacDrbgSha256`, and the C
interface passes a DRBG handle. The DRBG code, its state type with private
fields, and its health tests are inside the boundary, which is what Comment
5 requires, and the state is held as a value of that type that no caller can
read or construct except through the module's own entry points. The caller
chooses the seed; Comment 4 permits that and recommends an in-boundary
entropy source without requiring it. A module-owned DRBG would need a global
instance, a lock that `no_std` does not provide, a seeding entry point, a
reseed policy and a shutdown story, all new assurance surface with no gain in
collision probability over an instance the caller already had to seed.

Why any DRBG family and not only HMAC_DRBG-SHA-256. The CNSA 2.0 profile
does not permit HMAC_DRBG-SHA-256, and a GCM encryption that could not run
under that profile would be a regression. Every DRBG the module offers has a
security strength of at least 128 bits, above the 96-bit IV (R11).

Independence of instantiations (R8) is the DRBG's own rule (fresh entropy and
a nonce per instantiation) and becomes two operator duties in the user
guide: two processes that must not share IVs under one key seed their DRBGs
independently, and a process that is duplicated after instantiation (a fork,
a snapshot of a virtual machine) must re-instantiate its DRBG in each copy
before encrypting, since the copies would otherwise emit the same next IV.
The C DRBG handle additionally records the process id at instantiation and
refuses to generate in a child process, which turns the fork case from a
duty into an error.

The boundary, as a laboratory would ask it. Who can substitute the
generator: through the C interface, nobody; `oxi_aes256_gcm_seal` accepts
only a module-allocated DRBG handle, and the shared library is the form of
the module the Security Policy describes. In the Rust crates a consumer
could implement `GcmIvSource` on a type of its own; that consumer is
building and signing a module of its own, and the crate documentation and
the policy list the trait's module implementations as the approved sources
and any other as outside the approved service. Who can reset or copy the
state: only the instance's owner, through `instantiate` and `reseed`; none
of the nine types is `Clone`, so safe code cannot duplicate state inside a
process. Which implementation and which self-test stand behind every IV: the
DRBG type the instance has, whose CAST ran at power-up and whose health
tests run on every generate.

Rejected: a per-key DRBG inside the key handle. It needs entropy at key
creation, doubles the CSP state the module holds per key, and adds a reseed
obligation per key with no gain over a shared, properly seeded instance.
Rejected for now: seeding from the in-boundary SP 800-90B source, which
Comment 4 recommends. That source is not yet an approved service of the
module; when it is, it becomes the recommended seed and this design does not
change.

### D3. Mode-bound keys that count their invocations

The single `Aes*Key` type that serves every mode is replaced, at the public
surface, by mode-bound key types built from raw key bytes: `GcmKey`,
`CcmKey`, `CbcKey`, `CtrKey`, `KwKey`, `CmacKey` (names open), each
non-`Clone`, each gated on its own `Service` at construction. A key is
therefore used for one mode by construction (R13), and the module can hold
per-key state. The round-key schedule is expanded in place inside the new
type, so no second copy of it exists to clone.

`GcmKey` carries a 64-bit atomic invocation count. Before generating an IV,
`gcm_encrypt` reserves one invocation with a compare-and-swap that fails
once the count has reached 2^32; a reserved invocation that later fails
stays spent, so no sequence of concurrent calls can pass the limit, and the
limit is checked before any IV exists. At 2^32 the key returns a new error,
`KeyExhausted`, and never produces output; an exhausted key stays exhausted.
Decryption takes `&GcmKey` and does not count.

The limit in §8.3 is per key across all instances. A key imported into
several processes, or reused across restarts, has several counts. Two
functions make that an operator decision rather than an accident:
`GcmKey::new_with_count(key, used)` preloads the count from a value the
operator carried, and `GcmKey::invocations(&self)` reads it back. The user
guide states the rule: a key used in more than one process or across a
restart has its invocations summed by the operator and is re-established
before the sum reaches 2^32; where that cannot be done, each instance is
constructed with a share of the budget (`new_with_limit`); and the same key
bytes are never constructed as a key of a second mode (R13 applies to the
key material, which the module cannot see across two constructions). This is
SP 800-38D §9.2's operator responsibility, stated rather than assumed.

The C interface replaces `OxiAes256Key` (one handle for every mode) with one
handle type per mode, each from a mode-specific constructor; the GCM handle
holds the count. The handles stay module-allocated and opaque, and a handle
passed to a function of another mode is refused by type at compile time in C
and by a kind check inside the module at run time.

Power loss (R9): the RBG-based construction recovers because a fresh
instantiation takes fresh entropy, so the next IV is independent of every IV
before the loss. The invocation count is the operator's to carry, as above.

Rejected: a counter inside the existing `Clone` key types (a clone splits the
budget silently); a counter that only saturates without reservation (N
threads pass the check at 2^32−1 together); a documented 2^32 limit with no
enforcement (the weaker reading).

### D4. API shapes

Rust, in `oxicrypt-aes`:

```rust
pub struct GcmKey { /* round keys, atomic count; not Clone */ }
impl GcmKey {
    pub fn new(key: &[u8]) -> Result<Self, Error>;            // 16, 24 or 32 bytes
    pub fn new_with_count(key: &[u8], used: u64) -> Result<Self, Error>;
    pub fn invocations(&self) -> u64;
}

pub struct GcmSealed { pub iv: [u8; 12], pub tag: [u8; 16] }

pub fn gcm_encrypt<R: GcmIvSource>(
    key: &GcmKey,
    drbg: &mut R,
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<GcmSealed, ModeError>;

pub fn gcm_decrypt(
    key: &GcmKey,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError>;
```

C, in `oxicrypt.h`. The GCM encrypt symbol is renamed, because C symbols
carry no signature: an object compiled against the old header and linked
against the new library must fail to link rather than pass an IV pointer
where a DRBG handle is expected. The decrypt symbol keeps its shape but takes
the new key handle, so it is renamed too.

```c
int oxi_aes256_gcm_key_new(const uint8_t *key, uintptr_t key_len,
                           OxiAesGcmKey **out);
int oxi_aes256_gcm_seal(const OxiAesGcmKey *key,
                        OxiDrbg *drbg,
                        const uint8_t *aad, uintptr_t aad_len,
                        const uint8_t *plaintext, uintptr_t pt_len,
                        uint8_t *ciphertext,           /* pt_len bytes */
                        uint8_t *iv_out,               /* 12 bytes */
                        uint8_t *tag_out);             /* 16 bytes */
int oxi_aes256_gcm_open(const OxiAesGcmKey *key,
                        const uint8_t *iv, /* 12 */ const uint8_t *aad, uintptr_t aad_len,
                        const uint8_t *ciphertext, uintptr_t ct_len,
                        const uint8_t *tag, uint8_t *plaintext);
void oxi_aes_gcm_key_free(OxiAesGcmKey *key);
```

`OxiDrbg` is an opaque, module-allocated handle whose kind is written only
by the module: each existing `oxi_*_drbg_*_new` constructor gains a sibling
that returns an `OxiDrbg`, or the nine handle types gain an `as_drbg`
accessor that borrows them as one; which of the two is chosen in review.
The caller never fills a kind field. The handle is freed by the constructor's
matching free function. Before any Rust reference is built, the shim checks
every pointer and length pair: no NULL with a non-zero length, no length
above `isize::MAX`, no pointer arithmetic overflow, and no overlap between
any writable range (`ciphertext`, `iv_out`, `tag_out`, an output-length
word) and any other range, input or output (G16). `oxi_abi_version()`
advances and the SONAME with it.

### D5. The IV's life as a CSP

Inside `gcm_encrypt` the order is: input length checks (D7); invocation
reservation (D3); IV generation into a stack buffer that is zeroized on every
exit; encryption; output. Once the authenticated encryption function has run
with the IV, the IV is a public parameter (§9.1 item 2 ends its CSP status at
invocation) and is copied to the caller. If anything fails between
generation and use, the buffer is zeroized and no IV leaves the module.

The DRBGs' own temporaries hold the output block too: HMAC_DRBG and CTR_DRBG
leave it in working buffers after `generate`, while Hash_DRBG wipes. G4
extends to those buffers, so the IV exists nowhere unzeroized before use.
The crate's SSP section is rewritten to say this, listing the GCM IV as a
CSP from generation to use and a PSP after, and dropping the sentence that
IVs are never SSPs.

### D6. Decryption is unchanged in behaviour

`gcm_decrypt` keeps its behaviour. Its IV comes from the party that
encrypted (R5). It takes the mode-bound key (D3) and gains the length checks
of D7; nothing else about it changes, and the existing decrypt known-answer
and C integration tests must pass against it with only the key type
replaced.

### D7. Input length limits

A length check over `(aad_len, text_len)` as `u64`, shared by encrypt and
decrypt, runs before any key material is used or any output written:
text longer than 2^36−32 bytes returns `InvalidPayloadLength`, AAD longer
than 2^61−1 bytes returns `InvalidAadLength`. With those bounds the 32-bit
block counter cannot wrap and the GHASH length block cannot overflow.
Boundary tests use arithmetic on the constants, since a 64 GiB buffer is not
practical in a test.

### D8. Security Policy statements

Section 2.7 gains the IG C.H Scenario 2 statement: the module generates the
AES-GCM IV internally and at random using an approved DRBG inside the
module's boundary, with a 96-bit IV, and no approved service encrypts under
a caller-supplied IV. The IG 9.3.A entropy caveat is stated for the DRBG
seed, which the caller supplies. Section 9 lists the GCM IV as a CSP from
generation to use. The user guide states: each DRBG instance is seeded
independently and re-instantiated in a duplicated process; a key used in
more than one process or across a restart has its invocation counts summed
by the operator and is re-established before 2^32; the module refuses the
2^32nd invocation of one instance. Section 2.7 also carries the SP 800-38D §8.1 key-freshness
duty (a GCM key is established fresh by an approved method and never reused
with a second IV construction) and the §8.2 statement that the module
supports one IV construction and one IV length. The same statements appear
in the Validation Test Report entry TE02.20.01. The approved-services table's
AES rows name the mode-bound key types and the new entry points; the KTS
rows (G12) cite the algorithm certificates and the strength of each
transport. The ACVP section's `ivGen` value changes with the registration.

### D9. Self-tests

The GCM CAST continues to use the fixed-IV `pub(crate)` core so that the
known-answer test remains a known answer. The IV generation needs no CAST of
its own: the DRBG that produces it has its own CAST and health tests (IG
10.3.A). The CASTs run in the self-test state, before the module is
operational and before any profile applies, so the gated public wrappers of
G3 are not what they call; they call the ungated cores.

## Gaps closed in the same update

Each gap names its clause, what the update does, and whether it changes
behaviour (B), only documentation or the Security Policy (P), or both.

| ID | Clause | Gap | Resolution |
|---|---|---|---|
| G1 | SP 800-38F §6.2 Alg. 4 step 3, §6.3 Alg. 6 steps 4, 7, 8 ("return FAIL and stop") | KW and KWP unwrap compute W⁻¹ into the caller's output buffer, then return an error on an ICV, length or padding failure and leave the unverified bytes there. | B. The crate is `no_std` with no allocator, so in Rust the unwrap runs in the caller's buffer and the buffer is volatile-wiped on every FAIL path before return. The C shim stages into a heap buffer and copies to the caller only on success; the header states that nothing is written on failure. |
| G2 | SP 800-38C §6.2 ("the payload P shall not be revealed" on INVALID) | CCM decrypt writes the CTR plaintext to the caller's buffer, then runs the MAC and clears on mismatch, so unverified plaintext is visible in caller memory during the MAC pass. | B. Verify first: MAC over the decrypted blocks held in a 16-byte local, write the output only after the tag compares equal. |
| G3 | Crate contract (`lib.rs`: every public entry point calls `require_operational` and `require_allowed`); module profile gating | Only the C shim gates the per-mode services; the Rust mode functions check the self-test token alone, and the internal key constructors are public, so a Rust caller under a restricting profile can run a forbidden mode. | B. Every public mode function is a gated wrapper over a `pub(crate)` ungated core; the CASTs call the cores. The mode-bound constructors of D3 gate on their `Service`. The internal constructors other crates use (the CTR_DRBG and CMAC crates) stay public, `#[doc(hidden)]`, and are listed in the policy as non-service interfaces. The `lib.rs` claim is then true. |
| G4 | SP 800-38D §5.3 (intermediate values shall be secret); SP 800-38B §6.1 (L, K1, K2 secret). Zeroization of SSPs on demand applies at every level; automatic zeroization of temporary SSPs is a Level 2 and above requirement (AS09.32, IG 9.7.B). Here the automatic part is hardening on top of the secrecy clauses, and the policy states the Level 1 obligations as they stand rather than claiming the higher level. | H, E(J0), J0 and the running counter, keystream blocks, the computed tag, CCM Y and S0, CMAC L, K1, K2, the KW working block (which holds the key being transported), the DRBG generate temporaries, and the round-key schedule's moved-from stack copies are never zeroized; only the final schedule is. | B, P. Every intermediate lives in a zeroize-on-drop wrapper or is wiped before return on all paths; the schedule is expanded in place into its final home. The SSP section lists each intermediate. |
| G5 | SP 800-38D §8.3 | No invocation count per GCM key. | B. D3. |
| G6 | IG C.H Comment 10; SP 800-38D §9.1 | Crate says IVs are never SSPs. | B, P. D5. |
| G7 | SP 800-38C §6.2 step 1 ("If Clen ≤ Tlen, return INVALID") | CCM decrypt rejects only Clen < Tlen, so a ciphertext consisting of the tag alone is processed. | P. Kept as is, and the deviation is stated in the crate documentation and the policy: read literally, step 1 would make the module's own encryption of an empty payload (C = T, so Clen = Tlen) undecryptable, and the CCM test vectors include zero-length payloads. Equality is accepted and decrypts to an empty payload; the tag is verified as for any length. |
| G8 | SP 800-38C §6.2 (a step 7 failure shall be indistinguishable from a step 10 failure) | CCM decrypt returns distinct errors for parameter faults before any cipher work and for tag mismatch after it; the C interface maps them to distinct codes. | B. On decrypt, every validity fault of the formatted input and a tag mismatch return the one error `TagMismatch`, in Rust and C; buffer-contract errors (NULL, output length mismatch) stay distinct because they are the caller's own arguments, not the ciphertext. Timing: a validity fault is detected from the nonce length, tag length and ciphertext length, which the adversary already knows, so the time to reject it reveals nothing beyond those lengths; the MAC pass on a well-formed input runs to completion regardless of where the tag differs. Encrypt keeps its distinct errors. |
| G9 | SP 800-38C §5.3 (Tlen fixed per key), Appendix B (Tlen < 64 bits only with analysis); SP 800-38B §5.4 and Appendix A | CCM takes the tag length per call and accepts 32- and 48-bit tags unconditionally; CMAC documentation invites truncation to 32 bits without the Appendix A conditions. | B. `CcmKey` carries the tag length, fixed at construction, and refuses lengths below 64 bits; `CmacKey` likewise carries its MAC length (full, or fixed at 64 bits or more). The ACVP registrations drop the 32- and 48-bit CCM tags. |
| G10 | SP 800-38B §6.3, Appendix A | No CMAC verify function, so callers compare tags themselves; message-count guidance (2^48, a recommendation) unstated. | B, P. Add a constant-time `cmac_verify` in Rust and C that accepts the key's fixed MAC length; state the limit. |
| G11 | SP 800-38A Appendix B (CTR counter discipline), Appendix C (CBC IV unpredictable); SP 800-38F §5.3.1 Table 1 (KW plaintext and KW-AD ciphertext below 2^54 semiblocks) | CTR documentation says the low 32 bits increment while the code carries 128 bits and states no counter duty; CBC documentation says nothing about unpredictability; KW has no upper length check in either direction. On 32-bit targets the KWP length arithmetic can wrap. | B (the KW wrap bound of fewer than 2^54 semiblocks and the unwrap bound of at most 2^54, in both the forward and inverse-cipher variants; ECB and CBC reject an empty input, since SP 800-38A Appendix A requires a positive number of blocks; checked arithmetic on all targets), P (the two statements, and the CTR text corrected to the 128-bit carry). |
| G12 | IG D.G (KTS entries, strength caveat, Additional Comments 2, 4, 6, 8) | KW and KWP are listed as plain services; no KTS statement, no strength caveat; GCM and CCM used for key wrapping are also KTS. | P. Security Policy approved-services and KTS tables. |
| G13 | IG 10.3.A General Note 1 (multiple implementations) | With `accel-aes` the CAST exercises only the dispatched path; the policy does not list the two implementations. | P. The configuration the Security Policy defines excludes `accel-aes` (it is default-off and no shipped library enables it); the CAST statement names the portable implementation. |
| G14 | SP 800-38D §5.3 (H secret); crate side-channel statement | Portable GHASH branches on bits of the accumulator and of H; `gmul` in MixColumns branches on a state byte; CMAC subkey derivation branches on the top bit of L. The crate statement admits only S-box indexing. | B, P. Replace each branch with mask arithmetic; the statement then lists S-box indexing as the single residual. A bitsliced or computed-S-box AES would remove that residual too; it is a separate piece of work with its own verification cost and is recorded as the next step, not part of this update. |
| G15 | Reachable panic | `ctr_xor` does not check that input and output lengths match; a shorter output indexes out of bounds and aborts the process. | B. Return `LengthMismatch` like the other modes. |
| G16 | Rust aliasing rules (undefined behaviour); `slice::from_raw_parts` preconditions | No C entry point forbids overlapping input and output buffers; the shim builds `&[u8]` and `&mut [u8]` over the same memory when a caller encrypts in place; a length above `isize::MAX` is not rejected. | B. The shim rejects overlapping ranges and over-long lengths with `InvalidInput` before any work, and the header says so. Output buffers are written through raw pointers (or treated as possibly uninitialised memory) rather than through a `&mut [u8]` built over bytes the caller never initialised, which Rust does not permit. In-place calls become errors (Migration). |
| G17 | Self-test evidence (goes beyond IG 10.3.A, which one CAST per algorithm satisfies) | GCM KATs use empty AAD and block-aligned plaintext; CCM KATs use one nonce length, one tag length and one AAD size; CTR KATs are block-aligned; the inverse-cipher KW and KWP have no known answer; no AEAD or KW KAT has a negative case. | B. Add one GCM KAT with AAD and a partial block (McGrew-Viega case 4), one CCM KAT with a 7-byte nonce and a partial payload block, a partial-block CTR vector, known-answer vectors for inverse-cipher KW and KWP, and one rejected-tag case each for GCM, CCM and KW. |
| G18 | Timing | KWP unwrap returns at two points after the ICV compare, separating an ICV failure from a padding failure, and the padding loop starts at the decrypted length indicator, so its access pattern depends on unauthenticated plaintext. | B. Scan the last seven octets, the only positions padding can occupy, with masked comparisons that do not depend on the indicator; accumulate the ICV, range and padding failures; one exit. An indicator outside its range is folded into the accumulator, never used as an index. |
| G19 | Module state model | A `SelfTestStarted` token obtained while operational outlives a transition to the error state, so a held token can still drive the hidden block methods. | B. The public block methods re-check the module state word on entry (one atomic load); the token remains the proof that the self-tests started. |
| G20 | Documentation accuracy | Several rustdoc statements do not match the code (GCM plaintext "undefined" on mismatch when nothing is written; "three KATs per key size"; the CCM AAD bound comment). | P. Corrected with the code they describe. |
| G21 | SP 800-38C §5.1 (2^61 block-cipher invocations per CCM key, "shall be limited"); SP 800-38B Appendix B (2^48 messages per CMAC key, a recommendation); SP 800-38C Appendix B (count of INVALID results) | Per-key limits unstated; nothing counts CCM INVALID results. | B, P. `CcmKey` counts block-cipher invocations in both directions, including failed decryptions and the second pass that G2 adds, and refuses at 2^61 as `GcmKey` does at 2^32; the count can be preloaded and read like the GCM count. The CMAC figure (a recommendation) and the CCM INVALID-count duty are stated in the user guide. |

## Migration

Every caller changes. In Rust the compiler finds every site: key construction
moves to the mode-bound types, GCM encryption drops its IV argument and
gains a DRBG, CCM and CMAC fix their tag length at the key, in-place C calls
become errors (G16), KW and KWP unwrap leave nothing in the output on
failure (G1), CCM decrypt reports one error for any invalid input (G8), and
a forbidden mode under a profile now fails in Rust as it already did in C
(G3). In C the old symbols are removed and the new ones have new names, so a
stale object fails to link; `oxi_abi_version()` and the SONAME advance.
The `oxicrypt` Rust binding crate, which links the shared library, wraps
`oxi_aes256_new`, `oxi_aes256_gcm_encrypt` and `oxi_aes256_gcm_decrypt`
today; it moves to the new symbols in the same release, its `aes256_key`
and GCM methods take a DRBG and return the IV, and its header-drift test
pins the new names. The C integration tests and the ACVP harness move with
it.

`oxicrypt-aes-accel` is not changed in function: the mode-bound key types
keep the same round-key arrays, so the dispatch into the accelerated block
and GHASH kernels, their shape guards and their cross-path oracle tests are
untouched, and the accelerated GHASH is already branch-free (G14 applies to
the portable path). What changes for it is only the statement in G13 that
the configuration the policy describes does not enable it.
Callers that need a protocol-defined IV construction (TLS, IPsec, SSH, SPDM:
IG C.H Scenario 1) are outside this generic service. Scenario 1 allows the
protocol application to run outside the module provided the counter part of
the IV is managed inside the module and the laboratory checks the IG names
are met; a future protocol-bound service would add that in-boundary counter
management, and until one exists, no entry point here claims Scenario 1.

## Test plan

- Two encryptions under one `GcmKey` return different IVs; the returned IV
  decrypts the returned ciphertext; the IV is 12 bytes.
- Encryption refuses an uninstantiated DRBG and a DRBG in its error state
  before any output is written, and passes the DRBG's error through.
- A `GcmKey` built with `new_with_count(key, 2^32 − 1)` encrypts once more
  and then returns `KeyExhausted` with the output buffers untouched; a
  failed encryption after reservation leaves the count spent; concurrent
  encryptions never exceed the count (a threaded test on the atomic).
- The fixed-IV core is not reachable from outside the crate (a
  compile-fail test).
- The D7 boundary tests; existing GCM decrypt known-answer, round-trip and
  C integration tests pass with only the key type replaced.
- Zeroization of the IV buffer and of each G4 intermediate on every failure
  path, through a test seam the test module owns.
- Each G-row with a B has a test that fails on the current code and passes
  on the new one, so every gap has a probe that would have caught it.

## Decisions

1. Names: `GcmKey`, `CcmKey`, `CbcKey`, `CtrKey`, `KwKey`, `CmacKey`;
   `GcmSealed` for the IV-and-tag return. Rejected: keeping a mode-neutral
   key type with a mode tag, which cannot express exclusive use at compile
   time.
2. `OxiDrbg` as sibling constructors that return the opaque handle (D4).
   Rejected: a borrowing accessor on the nine existing handle types, which
   leaves two lifetimes for the caller to manage.
3. CCM's nonce stays caller-supplied: SP 800-38C requires a unique nonce but
   no IG constrains its generation and the nonce is not a CSP under 38C. The
   policy states the caller's duty. Rejected: routing it through the DRBG,
   which changes CCM's API with no clause requiring it.
4. G8 and G9 as written: CCM decrypt returns one error for any invalid
   input; `CcmKey` fixes the tag length at construction with 64 bits the
   minimum, and `CmacKey` fixes its MAC length. Rejected: distinct decrypt
   errors and per-call tag lengths with a policy statement, the weaker
   reading of §6.2 and §5.3.

## References

- FIPS 140-3 Implementation Guidance: C.H Key/IV Pair Uniqueness
  Requirements from SP 800-38D (last modified 2026-08-19); 10.3.A
  Cryptographic Algorithm Self-Test Requirements; D.G Key Transport Methods;
  9.3.A Entropy Caveats.
- NIST SP 800-38A (ECB, CBC, CTR), 38B (CMAC), 38C (CCM), 38D (GCM), 38F
  (KW, KWP).
- NIST SP 800-140B, Section 2.7 Algorithm Specific Information.
