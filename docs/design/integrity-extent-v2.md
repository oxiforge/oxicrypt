# Design: the typed integrity extent and its ML-DSA-87 signature

Design-of-record for the pre-operational software integrity test: what part of
a module artifact the test covers, how each byte is checked, how the result is
signed and verified, and what lies outside the claim. The test itself is
`oxicrypt_integrity::integrity_self_test`; the signer that prepares an artifact
for it is `oxicrypt-integrity-sign`, a build tool outside the cryptographic
boundary. The procedure for building and signing a module is in
[`docs/integrity-signing.md`](../integrity-signing.md); this document records
why the mechanism is shaped the way it is.

## Problem

ISO/IEC 19790:2012 §7.10.2.2 requires every software component inside the
cryptographic boundary to be verified with an approved integrity technique
before the module offers any service (`[10.17]`), and the test to fail if the
verification fails (`[10.18]`). At Security Level 2 for §7.5, `[05.17]` asks for
an approved digital signature or keyed MAC over all software in the boundary;
§7.5 then exempts the expected referenced output, the signature itself, from
the integrity technique, and nothing else.

An executable image is not the file it was loaded from. The loader rebases
pointers, binds imports, writes relocation targets it never reads, and maps
zero-fill memory the file does not contain. A test that compares the loaded
image with the file byte for byte fails on every load; a test that covers only
the bytes the loader leaves alone leaves out exactly the headers, tables and
pointers an edit would target. The design covers every byte of the file the
loader maps and gives each a check that matches what the loader does to it.

## Threat model

The test detects **accidental or unauthorised modification** of the module's
executable image after it was signed: corruption at rest or in transit, a
partial or mismatched install, a faulty build step, or an edit by someone who
does not hold the signing key.

It does not resist an adversary who controls both the file and the launch (who
could, for example, restore an edited file between load and test), nor
modification of process memory after load. It does not detect an edit that
keeps it from running: an edit to the code that runs it, or to the image's
layout so that the module state starts already set, such as widening the file
size of the segment that holds the state word. No test a module runs on itself
can detect a change to whether it runs. Origin, meaning that an artifact is
the one a particular vendor produced, is not established by this test. For a
project release it rests on the release channel, the SHA-256 checksum published
with each artifact, and the verifying-key fingerprint the artifact reports. The
release does not rely on platform code signing for it: macOS artifacts are
code signed ad hoc, and Windows artifacts carry no Authenticode signature. Nothing in the boundary offers a
debugging route around the test (`[05.16]`), and the artifact is compiled
machine code only (`[05.15]`).

## The extent

### The rule

1. **Candidates.** Every file-backed byte the loader maps, per segment or
   section: ELF `[p_offset, p_offset + p_filesz)`, PE the raw data of each
   section, Mach-O each segment's file extent. Memory beyond the file extent is
   zero-fill supplied by the kernel and is not a file byte.
2. **Kinds.** Each candidate byte gets exactly one kind, classified from the
   loader's own structures, never from section names:

   | Kind | Value | Signature input | Runtime check |
   |---|---|---|---|
   | `Plain` | 0 | the bytes | the loaded bytes equal the file bytes |
   | `Hole` | 1 | nothing | nothing |
   | `Relative` | 2 | each 8-byte word's unslid value | loaded word minus the slide |
   | `Bind` | 3 | nothing | loaded word equals the resolved import plus its addend (one Darwin x86_64 exception below) |
   | `FileOnly` | 4 | the bytes of the image file | read from the file the loader reports |

   - `Plain`: code, constants, headers, load commands, and every table the
     loader reads (relocations, symbols, strings, import descriptors).
   - `Relative`: an address the loader rebases. The file holds its unslid
     value, so the verifier subtracts the slide and hashes the result.
   - `Bind`: a pointer the loader sets to an imported symbol. Its record
     (library, symbol or ordinal, addend, weak flag) is in the slot's string
     table, which is signed; the verifier resolves the record through the
     platform's binding interface and requires exact equality. An unresolved
     import is accepted only if it is weak and the word is zero. One exception,
     on Darwin x86_64 alone: an export implemented by a resolver function is
     bound to a stub (`jmp *disp32(%rip)`, bytes `FF 25`) in the exporting
     library, while the lookup returns the implementation the resolver chose.
     Such a word is accepted when the record has no addend and the import's
     name, followed through the export tries as dyld follows it, leads to a
     stub-and-resolver export whose stub is at the word. A library that is not
     loaded or a trie that cannot be read is `Unreadable`; on arm64 every
     word must equal its resolution.
   - `FileOnly`: initialised writable data, which the loader or the module may
     rewrite before the test. It is hashed from the image file the loader
     reports, so an edit to the file is detected.
   - `Hole`: a word the loader overwrites without reading. Only the word is
     unchecked; the relocation entry that determines its value is `Plain`, so
     its value is covered by effect. The header fields the platform's code
     signing rewrites are also `Hole`, but only those measured to change (the
     Mach-O and PE sections below).
3. **The signature field** of the slot is the one exclusion §7.5 permits:
   the expected referenced output is not subject to the integrity technique. Every other slot byte is signed.
4. **Anything the signer cannot classify is refused by name.** An artifact
   using a structure the typing does not describe is never signed with that
   structure left untyped.

The signer's `--show` prints the typed table, the covered fraction of the
mapped image, and the slot budget, for any artifact.

### ELF (glibc and bionic)

Typed from `PT_DYNAMIC` and the relocation tables it names.

| Bytes | Kind |
|---|---|
| read-only `PT_LOAD`s, including the ELF and program headers | `Plain` |
| `PT_GNU_RELRO`'s file-backed bytes | `Plain`, except the words below |
| `RELA` and `JMPREL` destinations in RELRO | `Hole` (16 bytes for `TLSDESC`) |
| `RELR` destinations (glibc) | `Relative` |
| `.dynamic` `d_val` of `DT_DEBUG`, where the loader writes it: a glibc main executable (`PT_INTERP`, or `DF_1_PIE` for a static PIE), or any object under bionic whose `PT_DYNAMIC` is writable | `Hole`; otherwise `Plain` |
| `.dynamic` pointers glibc adjusts in place when `PT_DYNAMIC` is writable | `Relative` |
| every other file-backed byte of a writable `PT_LOAD` | `FileOnly` |

glibc adds the load bias to the `d_val` of `DT_HASH`, `DT_PLTGOT`, `DT_STRTAB`,
`DT_SYMTAB`, `DT_RELA`, `DT_REL`, `DT_JMPREL`, `DT_VERSYM`, `DT_GNU_HASH` and
`DT_RELR`; bionic adjusts none. The loader is inferred from the
`.note.android.ident` note, can be overridden with `--loader`, and is recorded
in the slot's flags. Android libraries are linked with
`-z max-page-size=16384`.

The section-header table, `.shstrtab` and `.comment` are never mapped and are
outside the extent. glibc never reads them. bionic's loader does read the
section-header table: it follows the `SHT_DYNAMIC` section's `sh_link` to find
the string section it takes dependency names from. The signer refuses an
artifact whose `sh_link` string section is not exactly
`[DT_STRTAB, DT_STRTAB + DT_STRSZ)`, which is covered, so the table as signed
names the covered `.dynstr`. The table itself is not signed: an edit to it after
signing changes an input to bionic's loader without changing the signature.
That edit is outside the claim (see below). Debug sections and symbol tables
are stripped before signing.

Refused: a `PT_LOAD` both writable and executable, packed relocations,
`RELR` under bionic, the x86-64 PLT-rewrite tags (`-z mark-plt`), lazy
binding (no `BIND_NOW`), a second `DT_FLAGS_1`, text relocations, `REL`-form
relocations, `COPY` relocations under bionic (which refuses to load them) and
under glibc when the destination is file-backed (a destination in zero-fill is
not a file byte and needs no entry), relocation types outside the accepted set, a relocation destination in
read-only bytes, overlapping relocations, a `PT_DYNAMIC` whose placement or
`PF_W` disagrees with its segment, a table `.dynamic` names that lies
outside `Plain` bytes, and, under glibc, a TLS relocation against an
undefined weak symbol, whose word glibc may leave unwritten. bionic writes
that word in every case, so under bionic it is a `Hole`.

### Mach-O (the `.dylib` form, arm64 and x86_64)

Typed from the chained fixups. The build must use chained fixups
(`-Wl,-fixup_chains`), with deployment targets of at least 12.0 on arm64 and
13.0 on x86_64, and must place the zero-fill sections in a segment of their
own so no module static is a byte of the file.

| Region | Kind |
|---|---|
| `mach_header_64`, the load-command table and its pad | `Plain`, less the envelope locator holes |
| `__TEXT`, and every other segment mapped read-only | `Plain` |
| `__DATA_CONST`, or a writable segment flagged `SG_READ_ONLY` | `Plain`; chained rebases `Relative`, chained binds `Bind` |
| `__LINKEDIT` up to `LC_CODE_SIGNATURE`'s `dataoff` | `Plain` |
| `__DATA,__thread_data` | `Plain`, fixups typed as above |
| `__DATA`, every other file-backed byte | `FileOnly` |
| `[dataoff, end of __LINKEDIT)` | the code-signature envelope, outside the signed image |

A rebase contributes `target` with `high8` restored in the top byte, plus the
link base for `DYLD_CHAINED_PTR_64_OFFSET`. A bind's record names the library
by its ordinal, the symbol with one leading `_` removed, the summed addend and
the weak flag.

`codesign` can rewrite four fields in the load-command table:
`LC_CODE_SIGNATURE`'s `dataoff` and `datasize` and `__LINKEDIT`'s `vmsize` and
`filesize`. Which of them change is measured per artifact, not assumed and not
fixed per architecture. `--reserved-against <reference>` names a copy of the
same artifact code signed once more by the same identity and options; the
signer compares the two, each of the four fields that differs becomes a
`Hole`, each that does not stays `Plain`, and any other difference is refused.
Without a reference all four are `Plain`. `--show` prints which fields an
artifact carries as holes.
The signing order is: link, `codesign` twice, integrity-sign against the first
as reference, `codesign` again, then `--verify`.

Refused: opcode fixups (`LC_DYLD_INFO`), lazy pointer sections, `arm64e` and
pointer-authenticated chains, any chain format but `DYLD_CHAINED_PTR_64` and
`DYLD_CHAINED_PTR_64_OFFSET`, binds through special ordinals, malformed chains,
fixups outside a writable segment, classic relocations, unexpected writable
segments, a `__LINKEDIT` table outside `Plain` bytes, and an unexpected
reservation difference.

### PE32+ (the `.dll` form, x86_64)

Typed from the headers, base relocations, import directory and load
configuration.

| Region | Kind |
|---|---|
| headers, `[0, SizeOfHeaders)` | `Plain`; `ImageBase` `Relative`; `CheckSum` and the Security directory entry `Hole` when measured to vary |
| every section mapped read-only (`.text`, `.rdata`, `.pdata`, `.reloc`) | `Plain` |
| a `DIR64` base-relocation destination in `Plain` bytes, load configuration pointers among them | `Relative` |
| an IAT thunk the import directory enumerates | `Bind` |
| storage words the load configuration names for the loader to write, and file alignment padding | `FileOnly` |
| the TLS template | `Plain`, `DIR64` words `Relative` |
| every other file-backed byte of a writable section | `FileOnly` |

Every import descriptor must carry a zero `TimeDateStamp` and a lookup table,
so each thunk the loader writes is named by a signed lookup-table entry. A
thunk edited on disk is overwritten at load and changes nothing; an edit of
what names it changes signed bytes. The signed image ends at the certificate
table, where Authenticode appends its signature, and Authenticode signing
follows integrity signing.

`CheckSum` and the Security directory entry are measured against a different
reference than on Mach-O. Two `signtool` runs over the same bytes write the
same `CheckSum`, so a signed-versus-signed comparison cannot show it changing.
The reference is the image as linked, before `signtool`, compared with the
artifact after `signtool` with the final certificate and options: each of the
two fields that differs becomes a `Hole`, and any other difference before the
certificate table is refused.

Refused: any machine but x86_64, misaligned or overlapping geometry, base
relocations other than `DIR64`, a relocation outside the file-backed bytes,
bound imports, a missing lookup table, import tables outside `Plain` bytes,
delay-load IATs or module handles in `Plain` bytes, a TLS index slot
(`AddressOfIndex`) in `Plain` bytes, XFG, relocated words found only in
`FileOnly` bytes, and an unexpected reservation difference.

### Module state is never a file byte

The test runs during initialisation (`initialize_with_tests` or
`initialize_with_profile`), and the module's state word decides whether it
runs. If that word were a byte of the file, an edit could preset it. The
signer finds the module's statics in the artifact's own symbol table or, for
a stripped artifact, in the debug file split off before stripping: the file
its `.gnu_debuglink` names on ELF, `<artifact>.dSYM` on Mach-O, the program
database its CodeView record names on PE, each required to match the
artifact. Stripping comes first and signing after. A PE image linked by a
GNU toolchain is not stripped: with no file of its program database's name
beside it, the signer reads its statics from the DWARF in its own
`.debug_info`, `.debug_abbrev` and `.debug_str` sections, which then lie in
the signed extent. The signer refuses with `FileBackedStatic` while any
zero-initialised module static lies in the file's bytes, and with
`StaticsUnchecked` when it cannot name them from a symbol table or debug
file. Read from DWARF, it refuses with `NoDwarf` an image that names no
program database and carries no DWARF or whose DWARF is malformed,
`DwarfForm` a form it does not read, `DuplicateStatic` a pinned static named
twice, `StaticOutsideImage` a module static outside every section,
`StaticUnlocated` a module static located by anything but a single
`DW_OP_addr` or a pinned static not located in a writable section, and
`StaticUnsized` a module static in writable memory whose type gives no size.
For the four pinned statics this coverage holds unconditionally: each must
be named by exactly one located DWARF entry, at a single `DW_OP_addr` in a
writable section, and anything else is refused. For the other module
statics it rests on two assumptions the reader cannot detect a breach of:
the compiler never leaves a static that has storage without a
`DW_AT_location`, and every module crate is built with full debug
information. A static with storage that has no DWARF entry, or an entry
with no location, is not seen, where a program database would list it. The
refusal is a property of the artifact as signed: an edit after signing that
moves the state word into the file's bytes keeps the test from running, which
the threat model excludes.

## The slot (format version 4)

A 65,536-byte `#[used]` static reserved at link time and patched by the signer.
The verifier never dereferences it: it takes the static's address and reads the
bytes through the same acquisition route as the rest of the image, so the
compiler's view of the unpatched static cannot be constant-folded into the
check.

```text
offset  size          field
0       16            header magic
16      4             version        (4)
20      4             flags          (bit 0: the loader is bionic)
24      4             count          (number of entries)
28      4             slot_rva       (slot offset from the image base)
32      4627          signature      (ML-DSA-87)
4659    32            key_id         (SHA-256 of the verifying key)
4691    8             link_base      (the image base the file was linked at)
4699    4             strtab_off
4703    4             strtab_len
4707    4             slot_file_off
4711    4             file_len       (length of the signed file image)
4715    count * 16    entry table
…                     zero bytes, the string table, zero bytes
65520   16            footer magic
```

Each entry is `rva u32 | file_off u32 | len u32 | kind u8 | run u8 | meta u16`,
little-endian on every target. A `Plain` entry may carry the 8-byte `Hole` or
`Relative` words that follow it (`meta` counts them, `run` bit 7 makes them
`Relative`) and repeat that period up to 127 more times (`run` bits 0–6), which
keeps a table of pointers into constant data to one entry. The table holds at
most 3,800 stored entries and 65,536 expanded ones. The parser accepts exactly
one encoding of any extent: entries ascending and disjoint, mergeable entries
merged, every unused byte zero. Slots of earlier format versions are refused.

The load base is the slot's runtime address minus `slot_rva`; the slide is the
load base minus `link_base`.

## The signature

**Scheme.** Pure ML-DSA-87 (FIPS 204), external interface, with a context
string. The message `M` is the slot without its signature field, followed by
each entry's payload in table order. The signed message is
`M′ = 0x00 ‖ len(ctx) ‖ ctx ‖ M`, with `ctx` the 18 ASCII bytes
`oxicrypt-integrity` (`oxicrypt_integrity::SIGNATURE_CONTEXT`,
`MESSAGE_PREFIX`). The context separates integrity signatures from any other
use of the key: an integrity signature does not verify under another context,
nor over the unframed input.

The module verifies with `ML-DSA.Verify_internal` (FIPS 204 Algorithm 8),
because the gated `verify` service requires the operational state the test
precedes. The signer signs `M` with the external `ML-DSA.Sign` (FIPS 204
Algorithm 2) under the same context string, which frames it as `M′`, with the
all-zero `rnd`, so signing is deterministic.
HashML-DSA was not chosen: the verifier already holds `M` in memory, so a
pre-hash saves nothing and would add code to the module.

**The private key** is the 32-byte seed `ξ` from which ML-DSA.KeyGen derives
the pair. `--keygen` draws it from the approved DRBG seeded by the operating
system, writes it `0600` as `integrity-signing.key`, and writes the 2,592-byte
public key as `integrity-verify.pub`. Reading a key runs a pairwise
consistency test.

## The verifying key is a build input

`crates/oxicrypt-integrity/build.rs` reads `OXICRYPT_INTEGRITY_VERIFY_KEY`, the
path of a 2,592-byte ML-DSA-87 public key, or `OXICRYPT_INTEGRITY_VERIFY_KEY_HEX`,
its 5,184 hex digits, and embeds a 2,624-byte key record in read-only data.
Any other length stops the build. Without either, the build compiles with an
all-zero record and the module reports `NoVerifyKey` and never becomes
operational; there is no default key.

The key record is `Plain`, inside the signed extent, so replacing the key
changes signed bytes. The slot's `key_id` is the SHA-256 of the key the
signature was made for; a slot whose `key_id` is not the embedded key's
fingerprint is refused as `KeyMismatch` before the signature is checked.

The fingerprint is the module's statement of whose key it trusts.
`oxicrypt_integrity::verify_key_fingerprint()`, the C function
`oxi_integrity_key_fingerprint()`, `oxi --integrity` and
`oxicrypt-integrity-sign --show` all report it. A project release embeds the
project's key; a source builder generates a pair, builds with the public half
and signs with the private half, and the module then reports that builder's
fingerprint. Integrity is therefore proven relative to the key a build
embeds. Rotating the key is a new build input and a new module.

## Self-tests that precede the test

`oxicrypt_integrity::KATS`, the integrity group the module runs first, holds
three entries in order:

1. the ML-DSA-87 signature-verification CAST (`ml_dsa_cast`, which runs
   `oxicrypt_ml_dsa::verify_cast`: a NIST-published valid signature must
   verify, and the same signature with one bit flipped must not);
2. the SHA-256 CAST (`sha256_cast`), for the key fingerprint the test computes;
3. the integrity test (`integrity_self_test`).

IG 10.2.A and `[10.20]` require an algorithm's self-test to pass before the
algorithm is used. The order is also enforced in code: the test refuses with
`CastNotRun` unless both CASTs have passed in this process. All three run while
the module is in `SelfTest`, through the `*_internal` primitives that admit that
state.

`oxicrypt_module::initialize_with_tests` takes the integrity group as a
separate argument, so a caller cannot drop it by passing a shorter list; an
empty group moves the module to the terminal `IntegrityUnverified` state. The
state word packs the state with the operating-system id of the thread running
the power-up self-tests, so during `SelfTest` only that thread is admitted to
the `*_internal` primitives. A failed initialisation is terminal until the
process restarts, and a self-test that unwinds leaves the module in `Error`.

## Runtime routes

The verifier does not parse the artifact's executable format: it reads the
entries the signed table gives it. The one exception is on Darwin x86_64,
where a `Bind` word bound to a resolver stub is checked by walking the export
tries and re-exports of the loaded libraries, read from their `__LINKEDIT` as
loaded (see `Bind` above). Every read goes through `oxicrypt-imageread`, the one crate that makes the system calls, so
`oxicrypt-integrity` keeps `#![forbid(unsafe_code)]`.

| Operational environment | Memory route | File route (`FileOnly`) | `Bind` resolution |
|---|---|---|---|
| Linux, Android | `/proc/self/mem`, then `process_vm_readv` | the `/proc/self/maps` line holding the slot | not used |
| Darwin | `mach_vm_read_overwrite` | `dladdr` | `dlopen(RTLD_NOLOAD)` + `dlsym` |
| Windows | `ReadProcessMemory` | `GetModuleHandleExW` + `GetModuleFileNameW` | `GetModuleHandleExW` + `GetProcAddress` |

Memory reads are kernel-mediated copies: an address from a corrupt table fails
with a status instead of faulting the process. `process_vm_readv` passes the
same access check a process always passes against itself, so a non-dumpable
process still verifies itself. Both memory routes failing, or the image file
not opening, is `Unreadable`: the test was not performed and the module does not
become operational. The image file is never read in place of the loaded image.

A library loaded from inside an Android APK is mapped from `base.apk` at an
archive offset. The verifier derives that offset from the mapping that contains
its own slot, requires it page-aligned and within the archive, and reads
`FileOnly` bytes at that offset.

## Status indicator

`oxicrypt_integrity::status()` and the C function `oxi_integrity_status()`:

| Value | Status | Meaning |
|---|---|---|
| 0 | `NotRun` | the test has not run in this process |
| 1 | `Passed` | the signature over the image verified |
| 2 | `SignatureInvalid` | the image is not the one that was signed |
| 3 | `SlotInvalid` | the slot is the unsigned template the build emits |
| 4 | `Unreadable` | the module's own bytes could not be obtained; not performed |
| 5 | `CastNotRun` | reached before both CASTs passed |
| 6 | `Unknown` | the recorded value is not one the module writes |
| 7 | `Refused` | the module refused a primitive the test uses; not performed |
| 8 | `NoVerifyKey` | the module carries no verifying key |
| 9 | `KeyMismatch` | the slot was signed for a different key |
| 10 | `SlotDamaged` | the slot, the key record or a bound import is damaged |

No status is on its own a reason to sign an artifact. `SlotInvalid` is what
an unsigned build reports, and also a signed one whose slot was overwritten
with the template: the two carry the same bytes. `NoVerifyKey` is what a build
without a key reports, and also a signed one whose key record was zeroed.
`SlotDamaged` means the slot, key record or a bound import holds contents the
signer never writes, so the module is corrupt and signing it again would
record the damage as correct.

## The signer's refusals

Besides the per-format refusals above, `oxicrypt-integrity-sign --sign`:

- refuses with `SigningKeyAbsent`, before touching any artifact (exit 3), when
  `--key` is missing, unreadable, not a 32-byte seed, or fails its pairwise
  consistency test;
- refuses with `SigningKeyAbsent`, for that artifact (exit 2), when the key is
  not the one the artifact embeds;
- refuses with `NoVerifyKey` an artifact built without a verifying key;
- refuses with `FileBackedStatic` an artifact whose module state is a file
  byte;
- refuses with `StaticsUnchecked` an artifact whose module statics it cannot
  name: no symbol table and no matching debug file (on PE, a program
  database named but not found and no DWARF), a debug file that fails its
  CRC, UUID or GUID and age check, or a symbol table that does not name the
  module's statics in writable memory;
- refuses a PE artifact whose statics it reads from DWARF, with no program
  database beside it, as `NoDwarf`, `DwarfForm`, `DuplicateStatic`,
  `StaticOutsideImage`, `StaticUnlocated` or `StaticUnsized` when that DWARF
  does not locate each module static exactly and each pinned static once;
- never generates a key implicitly and never embeds a default.

It writes the signed copy beside the artifact, verifies it, and only then
replaces the original. `--verify` rebuilds the signature input from the file
and verifies it with the embedded key; on Mach-O it also decodes every chain
word against its kind and record, so an edited ordinal, chain link or bind bit
is refused even though those bits are not hashed.

## Outside the claim

| Component | Why |
|---|---|
| the platform's code-signature envelope (Mach-O Code Directory, PE certificate table) and the locator fields measured to change with it | applied and checked by the operating system, rewritten at every platform re-sign, and not part of the module file |
| the signature field | the expected referenced output, which §7.5 exempts from the integrity technique |
| on Darwin x86_64, an ordinal edit between two imports exported through one resolver stub, such as `memcpy` and `memmove` | the loader binds both to the same stub, so the loaded word is bit for bit the same and the edit changes nothing the loader does |
| bytes the loader never maps: the section-header table, `.shstrtab`, `.comment`, stripped debug and symbol sections, PE certificate data | never mapped; glibc and the Windows loader never read them |
| under bionic, an edit to the ELF section-header table after signing | bionic reads the table to find its dependency-name strings, but the table is not mapped and not signed; the signer checks only that the table as signed names the covered `.dynstr` |
| memory beyond each segment's file extent | kernel-supplied zero pages, not file bytes |
| modification of process memory after load | outside the threat model |
| an adversary who controls the file and the launch, including restoring a file between load and test | outside the threat model |
| interposition, IAT hooks and shims | resolver agreement is consistency, not detection |

Environments in which neither memory route is permitted (a seccomp-confined,
non-dumpable process) report `Unreadable` and are not claimed.

## Test plan: the tamper matrix

Each row signs an artifact with a test key, changes one thing, renews the
platform code signature unless the row is about that signature, and loads the
artifact through `oxi_init`. **1** means the module refuses to become
operational, **0** that it becomes operational, **2** that the operating system
refuses to run it.

Each cell names the test that observes it, or is marked *expected*: the
outcome the typing above determines, which no test observes.

- **M**, the Mach-O rows of the `integrity-image-probe` workflow
  (`.github/probes/macho-tamper.py`), on macOS arm64 and x86_64 runners.
- **P**, the PE rows of the same workflow (`.github/probes/pe-tamper.py`), on
  Windows runners.
- **E**, `tools/integrity-probe/tests/signed_artifact.rs`, on a Linux (glibc)
  host.
- **S**, the signer's unit tests in `tools/oxicrypt-integrity-sign`.

| Change | Mach-O | ELF (glibc, bionic) | PE |
|---|---|---|---|
| a byte of code | 1 (M) | 1 (E, a byte inside the signed extent) | 1 (P) |
| a load command, the load-command pad | 1 (M) | | |
| an inserted weak dylib | 1, *expected* | | |
| a program-header reserved bit | | 1, *expected* | |
| a section-table field | | glibc: 0, *expected*; bionic: depends on the field, *expected* (the ELF section-header table is outside the extent) | 1 (P) |
| a fixup or relocation table entry: the chained-fixup table, a `.rela.dyn` addend, a `.reloc` padding entry, a lookup-table entry, an import hint, an import descriptor | 1 (M) | 1, *expected* | 1 (P) |
| a `Plain` constant | 1 (M) | 1, *expected* | 1 (P) |
| a `Relative` word, load configuration pointers included | 1 (M) | 1 (E) | 1 (P) |
| a `Bind` word on disk: its ordinal; its addend plus 16; its ordinal changed to name another import | 1 (M); on x86_64, 0 for an edit between two imports bound to the same resolver stub, *expected* | | |
| a `Bind` word: weak, with a wrong non-zero target | 1, *expected* | | |
| an IAT thunk on disk | | | 0 (P, overwritten at load) |
| a `FileOnly` byte of initialised data | 1 (M) | 1 (E) | 1 (P) |
| a file byte under the zero-fill tail, a TLV descriptor | 1, *expected* | 1, *expected* | |
| loader-written storage the load configuration names, file alignment padding | | | 1 (P) |
| the signature field | 1 (M) | 1 (E) | 1 (P) |
| the `key_id` | 1 (M), `KeyMismatch` | 1, *expected* | 1 (P), `KeyMismatch` |
| the embedded key record, or a build embedding a different key | 1, *expected* | 1 (E), `KeyMismatch` | 1, *expected* |
| re-signed with a different key | 1, *expected* | 1, *expected* | 1, *expected* |
| built with no verifying key | the signer refuses (S); `NoVerifyKey`, *expected* | the signer refuses (S); `NoVerifyKey` (E) | the signer refuses (S); `NoVerifyKey`, *expected* |
| a `Hole` word | | 0 (E) | |
| the code-signature envelope, without renewal | 2 on arm64; 0 or 2 on x86_64 (M) | | 0 (P) |
| `__LINKEDIT.filesize`, without renewal | 2 on arm64; 1 or 2 on x86_64 (M) | | |
| a byte the loader never maps | | 0, *expected* | 0, *expected* |
| an APK-mapped library: a `FileOnly` byte in its entry; a byte in another entry | | 1; 0, *expected* | |

The two rows without renewal have more than one allowed outcome on x86_64. On
arm64 the operating system checks the stale code signature at load and refuses
the library first. On x86_64 that check may or may not refuse it (2); when it
does not, the outcome follows the typing. `__LINKEDIT.filesize` is `Plain`
unless `--reserved-against` measured it to vary, so its edit is refused by the
module (1). The envelope lies outside the signed image, so its edit leaves the
module operational (0).

M also changes, on x86_64, a bound word's ordinal from `memcmp` to `memset`,
two imports bound to different resolver stubs: the module does not become
operational, refused either by the integrity test or by an earlier algorithm
self-test that calls the wrong function.

The state gate has its own tests, in
`crates/oxicrypt-module/tests/selftest_gate.rs`: two threads start
initialisation (one wins), a worker's `*_internal` call while initialisation is
paused (refused), a worker's service call after initialisation (admitted), and
a failed and an unwinding initialisation (both terminal).

## References

- ISO/IEC 19790:2012 §7.5 (the expected-referenced-output exemption,
  `[05.15]`–`[05.18]`), §7.10.2
  (`[10.17]`, `[10.18]`, `[10.20]`).
- FIPS 140-3 Implementation Guidance 10.2.A, 10.3.A, 2.3.D.
- FIPS 204, Module-Lattice-Based Digital Signature Standard.
- [`docs/integrity-signing.md`](../integrity-signing.md): building and signing
  a module, per platform.
- `oxicrypt_integrity` and `oxicrypt_integrity::slot` rustdoc: the verifier and
  the slot format as built.
- `tools/oxicrypt-integrity-sign` rustdoc for `elf`, `macho` and `pe`: each
  format's classifier and its refusals.
