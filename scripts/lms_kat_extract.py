#!/usr/bin/env python3
"""Extract per-variant canonical sigVer KAT vectors from ACVP-Server LMS JSON.

For each (lmsMode, lmOtsMode) pair in the SP 800-208 grid, picks the
first passing-verification testcase (testPassed=true) and emits three
binary fixtures matching the existing baseline pattern at
crates/oxicrypt-lms/tests/data/:

  - <pair>_sigver_pk.bin   (from group-level publicKey, hex-decoded)
  - <pair>_sigver_msg.bin  (from test message, hex-decoded)
  - <pair>_sigver_sig.bin  (from test signature, hex-decoded)

keyGen KAT vectors are NOT extracted here: ACVP-Server's LMS-keyGen-1.0
internalProjection.json encodes only the IUT-generated public-key shape
(group-level publicKey + per-test message/signature), not the (seed, I)
inputs that a deterministic IUT-side KAT would need. The single baseline
pair's keyGen KAT (seed, I, expected_pk for LMS_SHA256_M32_H10 /
LMOTS_SHA256_N32_W4) already lives in tests/data/ from a prior arc; the
remaining 79 pairs are covered by sigVer alone. Parameter-table errors
(U/V/P/LS) surface in sigVer because the signature parse length depends
on them — a wrong P aborts before any hash chain runs.

Family filter — limit which families this run emits fixtures for.
B2 = sha256_m32 only. B3 = sha256_m24 + shake_m32 + shake_m24.
Pass via argv: `python3 lms_kat_extract.py sha256_m32`.

Source: usnistgov/ACVP-Server @ 112690e8 (pinned 2026-05-16).
"""
import json
import os
import re
import sys
from pathlib import Path

# Local clone of usnistgov/ACVP-Server holding the gen-val JSON fixtures.
# Set ACVP_SERVER_ROOT to wherever that repository is checked out.
ACVP_ROOT = Path(
    os.environ.get("ACVP_SERVER_ROOT", Path.home() / "ACVP-Server")
) / "gen-val" / "json-files"

# Repo root, derived from this script's own location so the tool runs from any
# checkout. Override with OXICRYPT_ROOT when running against a worktree.
REPO_ROOT = Path(os.environ.get("OXICRYPT_ROOT", Path(__file__).resolve().parents[1]))
DATA_DIR = REPO_ROOT / "crates" / "oxicrypt-lms" / "tests" / "data"

LMS_MODE_RE = re.compile(r"^LMS_(SHA256|SHAKE)_M(\d+)_H(\d+)$")
LMOTS_MODE_RE = re.compile(r"^LMOTS_(SHA256|SHAKE)_N(\d+)_W(\d+)$")

ALLOWED_FAMILIES = sys.argv[1:] if len(sys.argv) > 1 else ["sha256_m32"]


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


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    sigver = load("LMS-sigVer-1.0")

    emitted = 0
    skipped = 0
    for grp in sigver["testGroups"]:
        slug = pair_slug(grp.get("lmsMode", ""), grp.get("lmOtsMode", ""))
        if not slug:
            continue
        if family_key(slug) not in ALLOWED_FAMILIES:
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

    print(f"families={ALLOWED_FAMILIES}")
    print(f"sigver fixtures emitted: {emitted}")
    print(f"groups skipped: {skipped}")


if __name__ == "__main__":
    main()
