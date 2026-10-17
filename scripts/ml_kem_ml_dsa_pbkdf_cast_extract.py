#!/usr/bin/env python3
"""Extract the ML-KEM, ML-DSA and PBKDF power-up self-test vectors from NIST
ACVP data.

Regenerates:

  - vendor/nist/acvp-server/gen-val/json-files/ML-KEM-keyGen-FIPS203/cast-slice.json
  - vendor/nist/acvp-server/gen-val/json-files/ML-KEM-encapDecap-FIPS203/cast-slice.json
  - vendor/nist/acvp-server/gen-val/json-files/ML-DSA-keyGen-FIPS204/cast-slice.json
  - vendor/nist/acvp-server/gen-val/json-files/ML-DSA-sigGen-FIPS204/cast-slice.json
  - vendor/nist/acvp-server/gen-val/json-files/ML-DSA-sigVer-FIPS204/cast-slice.json
  - vendor/nist/acvp-server/gen-val/json-files/PBKDF-1.0/cast-slice.json
  - vendor/nist/acvp-ml-dsa-spec/sign-internal-rejection-cast.json
  - crates/oxicrypt-ml-kem/src/cast_vectors.rs
  - crates/oxicrypt-ml-dsa/src/cast_vectors.rs
  - crates/oxicrypt-kdf/src/pbkdf2_cast_vector.rs

Three modes:

`slice DIR` reads `internalProjection.json` from the ACVP-Server directories
`ML-KEM-keyGen-FIPS203`, `ML-KEM-encapDecap-FIPS203`, `ML-DSA-keyGen-FIPS204`,
`ML-DSA-sigGen-FIPS204`, `ML-DSA-sigVer-FIPS204` and `PBKDF-1.0` under DIR,
taken at the commit pinned in vendor/nist/MANIFEST.toml, and writes the
`cast-slice.json` files. It prints the SHA-256 of each source and each slice
for the MANIFEST.toml rows.

`rejection` reads CELI_PAGE, the vendored copy of the NIST ACVP ML-DSA
specification CELI_DOC (published at CELI_URL), takes rows CELI_ROWS of Table 1
in section 6.1.2, "ML-DSA Algorithm 7 ML-DSA.Sign_internal() Known Answer Tests
for Rejection Cases", and writes CELI_SLICE. The table publishes, per row, the key-generation seed,
SHA2-256(pk || sk), the formatted message M' and SHA2-256(signature) of a
deterministic Algorithm 7 signature whose loop rejects a candidate on every
check applicable to the parameter set.

`cast` reads the vendored slices and writes the three Rust files.

Selection:

  - ML-KEM-1024, approved under the CNSA 2.0, Migration and Unrestricted
    profiles, so the self-tested set is one that CNSA 2.0 uses:
    keyGen, the first test case of the group; encapsulation, the first test
    case of the encapsulation group; decapsulation, the first test case of
    the decapsulation group whose reason is "valid decapsulation" and the
    first whose reason is "modified ciphertext" (the implicit-rejection path).
  - ML-DSA-87, approved under the CNSA 2.0, Migration and Unrestricted
    profiles, so the self-tested set is one that CNSA 2.0 uses:
    keyGen, the first test case of the group; sigGen, test case
    DSA_SIGGEN_TCID of the deterministic, internal-interface,
    non-external-mu group (Algorithm 7 with rnd = 0), compared in full;
    signing for the rejection paths, a Table 1 row of the ACVP ML-DSA
    specification (see CELI_ROWS), plus one ML-DSA-44 row for the ct0
    check, compared as digests; sigVer, the
    internal-interface, non-external-mu group (Algorithm 8), the test case
    expected to pass with the shortest message, lowest tcId on a tie.
  - PBKDF: among test cases with an iteration count of at least two, a salt
    of at least 128 bits and a key of at least 112 bits, the one with the
    fewest PRF calls (iteration count times output blocks), lowest tcId on
    a tie.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(os.environ.get("OXICRYPT_ROOT", Path(__file__).resolve().parents[1]))
JSON_FILES = REPO_ROOT / "vendor" / "nist" / "acvp-server" / "gen-val" / "json-files"
MANIFEST = REPO_ROOT / "vendor" / "nist" / "MANIFEST.toml"

KEM_KEYGEN = "ML-KEM-keyGen-FIPS203"
KEM_ENCDEC = "ML-KEM-encapDecap-FIPS203"
DSA_KEYGEN = "ML-DSA-keyGen-FIPS204"
DSA_SIGGEN = "ML-DSA-sigGen-FIPS204"
DSA_SIGVER = "ML-DSA-sigVer-FIPS204"
# Signing this test case rejects candidates on the z bound and on the r0
# bound before it returns: `cast::tests::signing_casts_drive_the_rejection_paths`
# in oxicrypt-ml-dsa requires at least three z and two r0 rejections. Its
# message is 1 byte. The hint-count path is left to the Table 1 rows below.
DSA_SIGGEN_TCID = 177
PBKDF = "PBKDF-1.0"

KEM_SET = "ML-KEM-1024"
KEM_MODULE = "ml_kem_1024"
DSA_SET = "ML-DSA-87"
DSA_MODULE = "ml_dsa_87"
CELI_URL = "https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html"
CELI_DOC = "draft-celi-acvp-ml-dsa-01"
CELI_PAGE = REPO_ROOT / "vendor" / "nist" / "acvp-ml-dsa-spec" / f"{CELI_DOC}.html"
# 1-based rows of Table 1, one per parameter set: row 13 (ML-DSA-87) and
# row 1 (ML-DSA-44). `cast::tests::signing_casts_drive_the_rejection_paths` in
# oxicrypt-ml-dsa requires row 13 to reject at least two candidates on the z
# bound, three on the r0 bound and one on the hint count, and row 1 at least
# one on each of the z, r0, ct0 and hint-count checks. ML-DSA-44 is the only
# parameter set whose ct0 check can reject (draft-celi-acvp-ml-dsa-01
# §6.1.2).
CELI_ROWS = [("ML-DSA-87", 13), ("ML-DSA-44", 1)]
CELI_SLICE = REPO_ROOT / "vendor" / "nist" / "acvp-ml-dsa-spec" / "sign-internal-rejection-cast.json"
PBKDF_PRF = "SHA2-224"
# Output length in bits of the PBKDF PRF above.
PBKDF_PRF_BITS = 224

SLICE = "cast-slice.json"
KEM_RS = REPO_ROOT / "crates" / "oxicrypt-ml-kem" / "src" / "cast_vectors.rs"
DSA_RS = REPO_ROOT / "crates" / "oxicrypt-ml-dsa" / "src" / "cast_vectors.rs"
PBKDF_RS = REPO_ROOT / "crates" / "oxicrypt-kdf" / "src" / "pbkdf2_cast_vector.rs"


def pinned_commit() -> str:
    m = re.search(r'^\[acvp_server\]\s*\ncommit = "([0-9a-f]{40})"', MANIFEST.read_text(), re.M)
    if not m:
        raise SystemExit(f"no [acvp_server] commit in {MANIFEST}")
    return m.group(1)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path, algorithm: str, mode) -> dict:
    data = json.loads(path.read_text())
    if data.get("algorithm") != algorithm or data.get("mode") != mode:
        raise SystemExit(f"{path}: not an {algorithm} {mode} projection")
    return data


def one_group(doc: dict, what: str, **want) -> dict:
    groups = [g for g in doc["testGroups"] if all(g.get(k) == v for k, v in want.items())]
    if len(groups) != 1:
        raise SystemExit(f"{what}: expected one group matching {want}, found {len(groups)}")
    return groups[0]


def first(tests: list, what: str, key=lambda t: t["tcId"]) -> dict:
    if not tests:
        raise SystemExit(f"{what}: no usable test case")
    return min(tests, key=key)


def picks(src: Path) -> dict:
    """Return {directory: (source path, document, [(group, test case), ...])}."""
    out = {}

    path = src / KEM_KEYGEN / "internalProjection.json"
    doc = load(path, "ML-KEM", "keyGen")
    g = one_group(doc, "ML-KEM keyGen", parameterSet=KEM_SET)
    out[KEM_KEYGEN] = (path, doc, [(g, first(g["tests"], "ML-KEM keyGen"))])

    path = src / KEM_ENCDEC / "internalProjection.json"
    doc = load(path, "ML-KEM", "encapDecap")
    enc = one_group(doc, "ML-KEM encapsulation", parameterSet=KEM_SET, function="encapsulation")
    dec = one_group(doc, "ML-KEM decapsulation", parameterSet=KEM_SET, function="decapsulation")
    valid = first([t for t in dec["tests"] if t.get("reason") == "valid decapsulation"], "valid decapsulation")
    reject = first([t for t in dec["tests"] if t.get("reason") == "modified ciphertext"], "modified ciphertext")
    out[KEM_ENCDEC] = (path, doc, [(enc, first(enc["tests"], "ML-KEM encapsulation")), (dec, valid), (dec, reject)])

    path = src / DSA_KEYGEN / "internalProjection.json"
    doc = load(path, "ML-DSA", "keyGen")
    g = one_group(doc, "ML-DSA keyGen", parameterSet=DSA_SET)
    out[DSA_KEYGEN] = (path, doc, [(g, first(g["tests"], "ML-DSA keyGen"))])

    shortest = lambda t: (len(t["message"]), t["tcId"])  # noqa: E731
    path = src / DSA_SIGGEN / "internalProjection.json"
    doc = load(path, "ML-DSA", "sigGen")
    g = one_group(
        doc,
        "ML-DSA sigGen",
        parameterSet=DSA_SET,
        deterministic=True,
        signatureInterface="internal",
        externalMu=False,
    )
    if g.get("cornerCase", "none") != "none":
        raise SystemExit("ML-DSA sigGen: selected group is a corner-case group")
    tests = [
        t
        for t in g["tests"]
        if t["tcId"] == DSA_SIGGEN_TCID and "rnd" not in t and "context" not in t and "mu" not in t
    ]
    out[DSA_SIGGEN] = (path, doc, [(g, first(tests, "ML-DSA sigGen"))])

    path = src / DSA_SIGVER / "internalProjection.json"
    doc = load(path, "ML-DSA", "sigVer")
    g = one_group(doc, "ML-DSA sigVer", parameterSet=DSA_SET, signatureInterface="internal", externalMu=False)
    tests = [t for t in g["tests"] if t.get("testPassed") is True and "context" not in t and "mu" not in t]
    out[DSA_SIGVER] = (path, doc, [(g, first(tests, "ML-DSA sigVer", shortest))])

    path = src / PBKDF / "internalProjection.json"
    doc = load(path, "PBKDF", None)
    g = one_group(doc, "PBKDF", hmacAlg=PBKDF_PRF)
    tests = [
        t
        for t in g["tests"]
        if t["iterationCount"] >= 2 and len(t["salt"]) * 4 >= 128 and t["keyLen"] >= 112
    ]
    cost = lambda t: (t["iterationCount"] * -(-t["keyLen"] // PBKDF_PRF_BITS), t["tcId"])  # noqa: E731
    out[PBKDF] = (path, doc, [(g, first(tests, "PBKDF", cost))])
    return out


def group_header(g: dict) -> dict:
    return {k: v for k, v in g.items() if k != "tests"}


def slice_(src: Path):
    commit = pinned_commit()
    for directory, (path, doc, chosen) in picks(src).items():
        groups = {}
        for g, tc in chosen:
            groups.setdefault(g["tgId"], {**group_header(g), "tests": []})["tests"].append(tc)
        slice_doc = {
            "_source": {
                "repo": "usnistgov/ACVP-Server",
                "commit": commit,
                "path": f"gen-val/json-files/{directory}/internalProjection.json",
                "sha256": sha256_of(path),
                "selected": [{"tgId": g["tgId"], "tcId": tc["tcId"]} for g, tc in chosen],
                "note": "power-up self-test vectors; generated by scripts/ml_kem_ml_dsa_pbkdf_cast_extract.py",
            },
            **{k: doc[k] for k in ("algorithm", "mode", "revision") if k in doc},
            "testGroups": list(groups.values()),
        }
        out = JSON_FILES / directory / SLICE
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(slice_doc, indent=2) + "\n")
        print(f"wrote {out.relative_to(REPO_ROOT)} sha256={sha256_of(out)}")
        print(f"  source sha256={sha256_of(path)}")
        for g, tc in chosen:
            print(f"  tgId={g['tgId']} tcId={tc['tcId']} {tc.get('reason', '')}")


# Bytes per line: the most rustfmt keeps on one line at this indent.
ROW = 15


def rust_array(name: str, doc: str, data: bytes) -> str:
    head = f"    pub(crate) const {name}: [u8; {len(data)}] = ["
    one_line = head + ", ".join(f"0x{b:02x}" for b in data) + "];"
    if len(one_line) <= 100:
        return f"    /// {doc}\n{one_line}"
    lines = [f"    /// {doc}", head]
    for i in range(0, len(data), ROW):
        lines.append("        " + " ".join(f"0x{b:02x}," for b in data[i : i + ROW]))
    lines.append("    ];")
    return "\n".join(lines)


def rust_u32(name: str, doc: str, value: int) -> str:
    return f"    /// {doc}\n    pub(crate) const {name}: u32 = {value};"


def read_slice(directory: str) -> tuple[dict, list]:
    doc = json.loads((JSON_FILES / directory / SLICE).read_text())
    if doc["_source"]["commit"] != pinned_commit():
        raise SystemExit(f"{directory}/{SLICE} and MANIFEST.toml name different ACVP-Server commits")
    tests = [(g, t) for g in doc["testGroups"] for t in g["tests"]]
    order = [(s["tgId"], s["tcId"]) for s in doc["_source"]["selected"]]
    tests.sort(key=lambda gt: order.index((gt[0]["tgId"], gt[1]["tcId"])))
    return doc, tests


def tid(g: dict, t: dict) -> str:
    return f"tgId {g['tgId']}, tcId {t['tcId']}"


def header(title: str, dirs: list, commit: str, rows: list, extra: list = ()) -> list:
    out = [
        f"//! Power-up self-test vectors for {title}.",
        "//!",
        "//! Source: NIST ACVP-Server, `internalProjection.json` in",
    ]
    out += [f"//! `gen-val/json-files/{d}/`" + ("," if i + 1 < len(dirs) else "") for i, d in enumerate(dirs)]
    out += [
        f"//! at commit `{commit}`, pinned in",
        "//! `vendor/nist/MANIFEST.toml`. The selected test cases are vendored as",
        "//! `cast-slice.json` in " + ("each directory" if len(dirs) > 1 else "that directory") + ". Generated by",
        "//! `scripts/ml_kem_ml_dsa_pbkdf_cast_extract.py cast`.",
        "//!",
        "//! | Self-test | tgId / tcId |",
        "//! |---|---|",
    ]
    out += [f"//! | {what} | {g['tgId']} / {t['tcId']} |" for what, g, t in rows]
    out += list(extra)
    out += [
        "//!",
        "//! The values are compiled into the module rather than read at run time.",
        "//! ISO/IEC 19790:2012 §7.10.1 requires a self-test to reach its verdict",
        "//! without externally provided test vectors or expected results; a constant",
        "//! linked into the binary is inside the cryptographic boundary, a file read",
        "//! during the test would not be. Nothing here was produced by this crate.",
    ]
    return out


def module(doc: str, name: str, fields: list) -> list:
    body = "\n\n".join(rust_array(n, d, bytes.fromhex(hx)) if isinstance(hx, str) else rust_u32(n, d, hx) for n, d, hx in fields)
    return ["", f"/// {doc}", f"pub(crate) mod {name} {{", body, "}"]


def table1_rows(page: str) -> list:
    """Return Table 1 of section 6.1.2 as [level, seed, key hash, M', sig hash]."""
    import html as html_mod

    start = page.index('id="name-ml-dsa-algorithm-7-ml-dsasi"')
    end = page.index('id="rejections_table"', start)
    rows = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", page[start:end], re.S):
        cells = [
            re.sub(r"\s+", "", html_mod.unescape(re.sub(r"<[^>]+>", " ", c)))
            for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        ]
        if cells:
            if len(cells) != 5 or any(len(c) != 64 or not re.fullmatch("[0-9A-F]+", c) for c in cells[1:]):
                raise SystemExit(f"Table 1: unexpected row {cells}")
            rows.append(cells)
    return rows


def rejection():
    page_path = CELI_PAGE
    page = page_path.read_text()
    rows = table1_rows(page)
    if len(rows) != 15:
        raise SystemExit(f"Table 1: expected 15 rows, found {len(rows)}")
    cases = []
    for want, row in CELI_ROWS:
        level, seed, key_hash, message, sig_hash = rows[row - 1]
        if level != want:
            raise SystemExit(f"Table 1 row {row} is {level}, not {want}")
        cases.append(
            {
                "row": row,
                "parameterSet": level,
                "seed": seed,
                "keyHash": key_hash,
                "message": message,
                "signatureHash": sig_hash,
            }
        )
    doc = {
        "_source": {
            "document": CELI_DOC,
            "url": CELI_URL,
            "file": str(page_path.relative_to(REPO_ROOT)),
            "section": "6.1.2, Table 1: ML-DSA Algorithm 7 ML-DSA.Sign_internal() Known Answer Tests for Rejection Cases",
            "sha256": sha256_of(page_path),
            "note": "power-up self-test vectors; generated by scripts/ml_kem_ml_dsa_pbkdf_cast_extract.py",
        },
        "cases": cases,
    }
    CELI_SLICE.parent.mkdir(exist_ok=True)
    CELI_SLICE.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {CELI_SLICE.relative_to(REPO_ROOT)} sha256={sha256_of(CELI_SLICE)}")
    print(f"  {CELI_DOC} sha256={sha256_of(page_path)} rows={CELI_ROWS}")


def cast():
    commit = pinned_commit()

    _, [(kg, kt)] = read_slice(KEM_KEYGEN)
    _, [(eg, et), (dg, dv), (_, dr)] = read_slice(KEM_ENCDEC)
    if dv.get("reason") != "valid decapsulation" or dr.get("reason") != "modified ciphertext":
        raise SystemExit("ML-KEM decapsulation slice is not one valid and one modified-ciphertext case")
    out = header(
        "ML-KEM",
        [KEM_KEYGEN, KEM_ENCDEC],
        commit,
        [
            ("Key generation", kg, kt),
            ("Encapsulation", eg, et),
            ("Decapsulation, valid ciphertext", dg, dv),
            ("Decapsulation, implicit rejection", dg, dr),
        ],
    )
    out += module(
        f"{KEM_SET}.",
        KEM_MODULE,
        [
            ("KEYGEN_D", f"keyGen seed d, {tid(kg, kt)}.", kt["d"]),
            ("KEYGEN_Z", f"keyGen seed z, {tid(kg, kt)}.", kt["z"]),
            ("KEYGEN_DK", f"keyGen expected decapsulation key, {tid(kg, kt)}.", kt["dk"]),
            ("ENCAPS_EK", f"Encapsulation key, {tid(eg, et)}.", et["ek"]),
            ("ENCAPS_M", f"Encapsulation randomness m, {tid(eg, et)}.", et["m"]),
            ("ENCAPS_C", f"Expected ciphertext, {tid(eg, et)}.", et["c"]),
            ("ENCAPS_K", f"Expected shared secret, {tid(eg, et)}.", et["k"]),
            ("DECAPS_DK", f"Decapsulation key, {tid(dg, dv)}.", dv["dk"]),
            ("DECAPS_C", f"Valid ciphertext, {tid(dg, dv)}.", dv["c"]),
            ("DECAPS_K", f"Expected shared secret, {tid(dg, dv)}.", dv["k"]),
            ("REJECT_DK", f"Decapsulation key, {tid(dg, dr)}.", dr["dk"]),
            ("REJECT_C", f"Modified ciphertext, {tid(dg, dr)}.", dr["c"]),
            ("REJECT_K", f"Expected implicit-rejection shared secret, {tid(dg, dr)}.", dr["k"]),
        ],
    )
    KEM_RS.write_text("\n".join(out) + "\n")
    print(f"wrote {KEM_RS.relative_to(REPO_ROOT)}")

    _, [(kg, kt)] = read_slice(DSA_KEYGEN)
    rjs = json.loads(CELI_SLICE.read_text())["cases"]
    if [(c["parameterSet"], c["row"]) for c in rjs] != CELI_ROWS:
        raise SystemExit(f"{CELI_SLICE.name} does not hold Table 1 rows {CELI_ROWS}")

    def sign_fields(c):
        row = f"ACVP ML-DSA specification §6.1.2 Table 1, row {c['row']}"
        return [
            ("REJ_SEED", f"Signing key-generation seed ξ, {row}.", c["seed"]),
            ("REJ_KEY_HASH", f"Expected SHA2-256(pk ‖ sk) of the signing key pair, {row}.", c["keyHash"]),
            ("REJ_MSG", f"Signing message M′, {row}.", c["message"]),
            ("REJ_SIG_HASH", f"Expected SHA2-256(σ), {row}.", c["signatureHash"]),
        ]
    _, [(sg, st)] = read_slice(DSA_SIGGEN)
    if sg.get("deterministic") is not True or sg.get("signatureInterface") != "internal" or sg.get("externalMu"):
        raise SystemExit("ML-DSA sigGen slice is not deterministic, internal, without external mu")
    _, [(vg, vt)] = read_slice(DSA_SIGVER)
    if vg.get("signatureInterface") != "internal" or vg.get("externalMu") or vt.get("testPassed") is not True:
        raise SystemExit("ML-DSA sigVer slice is not an internal, passing case")
    out = header(
        "ML-DSA",
        [DSA_KEYGEN, DSA_SIGGEN, DSA_SIGVER],
        commit,
        [("Key generation", kg, kt), ("Signature generation", sg, st), ("Signature verification", vg, vt)],
        [
            "//!",
            "//! The rejection-path signature-generation vectors are rows "
            + " and ".join(f"{r} ({ps})" for ps, r in CELI_ROWS)
            + " of Table 1 in section 6.1.2",
            f"//! of the NIST ACVP ML-DSA specification {CELI_DOC}, <{CELI_URL}>,",
            f"//! vendored as `{CELI_PAGE.relative_to(REPO_ROOT)}` and cut to",
            "//! `vendor/nist/acvp-ml-dsa-spec/sign-internal-rejection-cast.json`.",
            "//! The table lists deterministic `ML-DSA.Sign_internal` cases whose loop",
            "//! rejects a candidate on every applicable check: the z bound, the r0",
            "//! bound and the number of hints, and for ML-DSA-44 also the ct0 bound.",
            "//! It publishes the key-generation seed, SHA2-256(pk ‖ sk), M′ and",
            "//! SHA2-256(σ), not the keys or σ themselves.",
        ],
    )
    out += module(
        f"{DSA_SET}.",
        DSA_MODULE,
        [
            ("KEYGEN_XI", f"keyGen seed ξ, {tid(kg, kt)}.", kt["seed"]),
            ("KEYGEN_SK", f"keyGen expected private key, {tid(kg, kt)}.", kt["sk"]),
            ("SIGN_SK", f"sigGen private key, {tid(sg, st)}.", st["sk"]),
            ("SIGN_MSG", f"sigGen message M′, {tid(sg, st)}.", st["message"]),
            ("SIGN_SIG", f"sigGen expected signature, {tid(sg, st)}.", st["signature"]),
            *sign_fields(rjs[0]),
            ("VERIFY_PK", f"sigVer public key, {tid(vg, vt)}.", vt["pk"]),
            ("VERIFY_MSG", f"sigVer message M′, {tid(vg, vt)}.", vt["message"]),
            ("VERIFY_SIG", f"sigVer signature, valid, {tid(vg, vt)}.", vt["signature"]),
        ],
    )
    out += module(f"{rjs[1]['parameterSet']}, for the ct0 check.", "ml_dsa_44", sign_fields(rjs[1]))
    DSA_RS.write_text("\n".join(out) + "\n")
    print(f"wrote {DSA_RS.relative_to(REPO_ROOT)}")

    _, [(pg, pt)] = read_slice(PBKDF)
    if pg.get("hmacAlg") != PBKDF_PRF or pt["keyLen"] % 8:
        raise SystemExit("PBKDF slice is not a whole-byte SHA2-224 case")
    out = header("PBKDF2", [PBKDF], commit, [(f"PBKDF2-HMAC-{PBKDF_PRF}", pg, pt)])
    out += module(
        f"PBKDF2 with HMAC-{PBKDF_PRF}.",
        "pbkdf2_hmac_sha2_224",
        [
            ("PASSWORD", f"Password (ASCII), {tid(pg, pt)}.", pt["password"].encode("ascii").hex()),
            ("SALT", f"Salt, {tid(pg, pt)}.", pt["salt"]),
            ("ITERATIONS", f"Iteration count, {tid(pg, pt)}.", pt["iterationCount"]),
            ("DERIVED_KEY", f"Expected master key ({pt['keyLen']} bits), {tid(pg, pt)}.", pt["derivedKey"]),
        ],
    )
    PBKDF_RS.write_text("\n".join(out) + "\n")
    print(f"wrote {PBKDF_RS.relative_to(REPO_ROOT)}")


def main():
    args = sys.argv[1:]
    if args[:1] == ["slice"] and len(args) == 2:
        slice_(Path(args[1]))
    elif args == ["rejection"]:
        rejection()
    elif args == ["cast"]:
        cast()
    else:
        sys.exit("usage: ml_kem_ml_dsa_pbkdf_cast_extract.py slice DIR | rejection | cast")


if __name__ == "__main__":
    main()
