#!/usr/bin/env python3
"""Extract LMS sigVer known-answer vectors from the ACVP-Server projection.

Two outputs, both drawn from `LMS-sigVer-1.0/internalProjection.json`:

`fixtures` (the default) — for each (lmsMode, lmOtsMode) pair, the first
passing test case (testPassed=true) as three binary fixtures under
crates/oxicrypt-lms/tests/data/:

  - <pair>_sigver_pk.bin   (from group-level publicKey, hex-decoded)
  - <pair>_sigver_msg.bin  (from test message, hex-decoded)
  - <pair>_sigver_sig.bin  (from test signature, hex-decoded)

Parameter-table errors (U/V/P/LS) surface in sigVer because the signature
parse length depends on them: a wrong P aborts before any hash chain runs.
Optional family filter for this mode, via argv:
`python3 lms_kat_extract.py fixtures sha256_m32 shake_m24`.

`cast` — the power-up self-test vectors, written to
crates/oxicrypt-lms/src/kat.rs. One group per hash adapter (SHA-256/N=32,
SHA-256/N=24, SHAKE/N=32, SHAKE/N=24), each at H = 5 and W = 1, the
cheapest verification in the grid. From each group it takes the passing
test case and the "modify message" reject case. A "modify signature
header" case is never used: it changes the typecode, which the verifier
rejects before any hash runs, so it would test nothing.

Source: usnistgov/ACVP-Server at the commit pinned in
vendor/nist/MANIFEST.toml. The projection is vendored byte-for-byte under
vendor/nist/acvp-server/gen-val/json-files/LMS-sigVer-1.0/; set
ACVP_SERVER_ROOT to read a different checkout instead.
"""
import json
import os
import re
import sys
from pathlib import Path

# Repo root, derived from this script's own location so the tool runs from any
# checkout. Override with OXICRYPT_ROOT when running against a worktree.
REPO_ROOT = Path(os.environ.get("OXICRYPT_ROOT", Path(__file__).resolve().parents[1]))
DATA_DIR = REPO_ROOT / "crates" / "oxicrypt-lms" / "tests" / "data"
KAT_RS = REPO_ROOT / "crates" / "oxicrypt-lms" / "src" / "kat.rs"

# Clone of usnistgov/ACVP-Server holding the gen-val JSON fixtures; defaults to
# the vendored copy in this repository.
ACVP_ROOT = Path(
    os.environ.get("ACVP_SERVER_ROOT", REPO_ROOT / "vendor" / "nist" / "acvp-server")
) / "gen-val" / "json-files"

MANIFEST = REPO_ROOT / "vendor" / "nist" / "MANIFEST.toml"

LMS_MODE_RE = re.compile(r"^LMS_(SHA256|SHAKE)_M(\d+)_H(\d+)$")
LMOTS_MODE_RE = re.compile(r"^LMOTS_(SHA256|SHAKE)_N(\d+)_W(\d+)$")

# (constant prefix, adapter label, lmsMode, lmOtsMode, per-pair module)
CAST_GROUPS = [
    ("SHA256_N32", "SHA-256/N=32", "LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W1", "lms_sha256_m32_h5_w1"),
    ("SHA256_N24", "SHA-256/N=24", "LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1", "lms_sha256_m24_h5_w1"),
    ("SHAKE_N32", "SHAKE/N=32", "LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1", "lms_shake_m32_h5_w1"),
    ("SHAKE_N24", "SHAKE/N=24", "LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1", "lms_shake_m24_h5_w1"),
]
CAST_REJECT_REASON = "modify message"


def pair_slug(lms_mode: str, lmots_mode: str):
    m_lms = LMS_MODE_RE.match(lms_mode)
    m_lmots = LMOTS_MODE_RE.match(lmots_mode)
    if not (m_lms and m_lmots):
        return None
    fam_lms, m, h = m_lms.groups()
    fam_lmots, n, w = m_lmots.groups()
    if fam_lms != fam_lmots or m != n:
        return None  # cross-family pair — invalid per SP 800-208 §4
    fam_canon = {"SHA256": "sha256", "SHAKE": "shake"}[fam_lms]
    return f"lms_{fam_canon}_m{m}_h{h}_w{w}"


def family_key(slug: str) -> str:
    parts = slug.split("_")
    return f"{parts[1]}_{parts[2]}"


def load(name: str):
    path = ACVP_ROOT / name / "internalProjection.json"
    with path.open() as f:
        data = json.load(f)
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and "testGroups" in entry:
                return entry
        raise SystemExit(f"no testGroups in {path}")
    if "testGroups" not in data:
        raise SystemExit(f"no testGroups key in {path}")
    return data


def pinned_commit() -> str:
    m = re.search(r'^\[acvp_server\]\s*\ncommit = "([0-9a-f]{40})"', MANIFEST.read_text(), re.M)
    if not m:
        raise SystemExit(f"no [acvp_server] commit in {MANIFEST}")
    return m.group(1)


def fixtures(families):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    sigver = load("LMS-sigVer-1.0")

    emitted = 0
    skipped = 0
    for grp in sigver["testGroups"]:
        slug = pair_slug(grp.get("lmsMode", ""), grp.get("lmOtsMode", ""))
        if not slug:
            continue
        if families and family_key(slug) not in families:
            continue
        pk = grp.get("publicKey")
        passing = next((tc for tc in grp.get("tests", []) if tc.get("testPassed", False)), None)
        if not (pk and passing):
            skipped += 1
            continue
        (DATA_DIR / f"{slug}_sigver_pk.bin").write_bytes(bytes.fromhex(pk))
        (DATA_DIR / f"{slug}_sigver_msg.bin").write_bytes(bytes.fromhex(passing["message"]))
        (DATA_DIR / f"{slug}_sigver_sig.bin").write_bytes(bytes.fromhex(passing["signature"]))
        emitted += 1

    print(f"families={families or 'all'}")
    print(f"sigver fixtures emitted: {emitted}")
    if emitted == 0:
        sys.exit("no sigver fixtures emitted")
    print(f"groups skipped: {skipped}")


def rust_array(name: str, doc: str, data: bytes) -> str:
    lines = [f"/// {doc}", f"pub(crate) const {name}: [u8; {len(data)}] = ["]
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        lines.append("    " + " ".join(f"0x{b:02x}," for b in chunk))
    lines.append("];")
    return "\n".join(lines)


def cast():
    sigver = load("LMS-sigVer-1.0")
    commit = pinned_commit()
    groups = {(g["lmsMode"], g["lmOtsMode"]): g for g in sigver["testGroups"]}

    out = [
        "//! Power-up known-answer test data for LMS signature verification.",
        "//!",
        "//! Source: NIST ACVP-Server, `gen-val/json-files/LMS-sigVer-1.0/internalProjection.json`",
        f"//! at commit `{commit}`, vendored",
        "//! byte-for-byte under `vendor/nist/acvp-server/` and pinned in",
        "//! `vendor/nist/MANIFEST.toml`. Generated by `scripts/lms_kat_extract.py cast`.",
        "//!",
        "//! One test group per hash adapter, each at H = 5 and W = 1. From each group:",
        "//! the public key, the test case NIST marks `testPassed: true`, and the test",
        f"//! case it marks `testPassed: false` with reason \"{CAST_REJECT_REASON}\". The",
        "//! reject case carries a well-formed signature, so the verifier runs every",
        "//! hash chain and the Merkle path before it can refuse it.",
        "//!",
        "//! | Adapter | lmsMode / lmOtsMode | tgId | accept tcId | reject tcId |",
        "//! |---|---|---|---|---|",
    ]
    picks = []
    for prefix, label, lms_mode, lmots_mode, module in CAST_GROUPS:
        g = groups[(lms_mode, lmots_mode)]
        accept = [t for t in g["tests"] if t["testPassed"]]
        reject = [t for t in g["tests"] if not t["testPassed"] and t.get("reason") == CAST_REJECT_REASON]
        if len(accept) != 1 or len(reject) != 1:
            raise SystemExit(f"{lms_mode}/{lmots_mode}: expected one accept and one reject case")
        accept, reject = accept[0], reject[0]
        if bytes.fromhex(accept["message"]) == bytes.fromhex(reject["message"]):
            raise SystemExit(f"{lms_mode}/{lmots_mode}: reject case carries the accept message")
        out.append(
            f"//! | {label} | {lms_mode} / {lmots_mode} | {g['tgId']} | {accept['tcId']} | {reject['tcId']} |"
        )
        picks.append((prefix, label, lms_mode, lmots_mode, g, accept, reject))
    out += [
        "//!",
        "//! The values are compiled into the module rather than read at run time.",
        "//! ISO/IEC 19790:2012 §7.10.1 requires a self-test to reach its verdict",
        "//! without externally provided test vectors or expected results; a constant",
        "//! linked into the binary is inside the cryptographic boundary, a file read",
        "//! during the test would not be. Nothing here was produced by this crate.",
    ]
    for prefix, label, lms_mode, lmots_mode, g, accept, reject in picks:
        tg = g["tgId"]
        out.append("")
        out.append(f"// ── {label}: {lms_mode} / {lmots_mode}, tgId {tg} ──")
        out.append("")
        out.append(rust_array(f"{prefix}_PUBLIC_KEY", f"Public key, tgId {tg}.", bytes.fromhex(g["publicKey"])))
        out.append("")
        out.append(rust_array(f"{prefix}_ACCEPT_MSG", f"Message, tcId {accept['tcId']} (testPassed: true).", bytes.fromhex(accept["message"])))
        out.append("")
        out.append(rust_array(f"{prefix}_ACCEPT_SIG", f"Signature, tcId {accept['tcId']} (testPassed: true).", bytes.fromhex(accept["signature"])))
        out.append("")
        out.append(rust_array(f"{prefix}_REJECT_MSG", f"Message, tcId {reject['tcId']} (testPassed: false, {CAST_REJECT_REASON}).", bytes.fromhex(reject["message"])))
        out.append("")
        out.append(rust_array(f"{prefix}_REJECT_SIG", f"Signature, tcId {reject['tcId']} (testPassed: false, {CAST_REJECT_REASON}).", bytes.fromhex(reject["signature"])))
    KAT_RS.write_text("\n".join(out) + "\n")
    print(f"wrote {KAT_RS}")
    for prefix, label, lms_mode, lmots_mode, g, accept, reject in picks:
        print(f"  {label}: tgId={g['tgId']} accept={accept['tcId']} reject={reject['tcId']}")


FAMILIES = ["sha256_m32", "sha256_m24", "shake_m32", "shake_m24"]


def main():
    args = sys.argv[1:]
    mode = args[0] if args and args[0] in ("fixtures", "cast") else "fixtures"
    rest = args[1:] if args and args[0] in ("fixtures", "cast") else args
    if mode == "cast":
        if rest:
            sys.exit(f"cast takes no arguments, got {rest}")
        cast()
    else:
        unknown = [f for f in rest if f not in FAMILIES]
        if unknown:
            sys.exit(f"unknown argument {unknown}; expected 'fixtures' or 'cast', then any of {FAMILIES}")
        fixtures(rest)


if __name__ == "__main__":
    main()
