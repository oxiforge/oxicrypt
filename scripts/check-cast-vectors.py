#!/usr/bin/env python3
"""Check the provenance of the vendored NIST vectors the power-up CASTs use.

Two checks, both of which must pass:

1. vendor/nist/MANIFEST.toml has exactly the CAST rows in CAST_ROWS (a key
   ending in `_CAST`, or a row of `[acvp_ml_dsa_spec]`), each naming a
   vendored `file` whose SHA-256 is the row's `sha256`. A missing or extra
   row, or a row without `file` or `sha256`, fails. A row with `dir` names
   `vendor/nist/acvp-server/gen-val/json-files/<dir>/<file>`; a row without
   one names `vendor/nist/<file>`. The rows tools/acvp-gen/generate.py
   writes record the SHA-256 of the upstream file a slice was cut from,
   which is not vendored, so they are not checked here.
2. The CAST vector files compiled into the crates are exactly what the
   extraction scripts generate from the vendored slices:
   `scripts/slh_dsa_cast_extract.py cast`,
   `scripts/ml_kem_ml_dsa_pbkdf_cast_extract.py rejection`,
   `scripts/ml_kem_ml_dsa_pbkdf_cast_extract.py cast` and
   `scripts/lms_kat_extract.py cast` run against a copy of `vendor/nist/`
   and their output is compared byte for byte with the rejection slice and
   the five Rust files in the tree.

So a hand edit to a compiled vector or to a vendored source fails here, and
so does a change to a CAST row's `file` or `sha256`, unless the vendored file
changes to match. Other fields of a row (`tgId`, `tcIds` and the like) are
records for a reader and are not checked. Editing a source, its row's
`sha256` and the compiled vectors together is a change of provenance,
visible as a MANIFEST.toml change.

Usage: python3 scripts/check-cast-vectors.py [<repo-root>]
Exit codes: 0 consistent, 1 a mismatch or a check that could not run.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "nist"
JSON_FILES = VENDOR / "acvp-server" / "gen-val" / "json-files"

GENERATED = [
    "vendor/nist/acvp-ml-dsa-spec/sign-internal-rejection-cast.json",
    "crates/oxicrypt-slh-dsa/src/cast_vectors.rs",
    "crates/oxicrypt-ml-kem/src/cast_vectors.rs",
    "crates/oxicrypt-ml-dsa/src/cast_vectors.rs",
    "crates/oxicrypt-kdf/src/pbkdf2_cast_vector.rs",
    "crates/oxicrypt-lms/src/kat.rs",
]
RUNS = [
    ["scripts/slh_dsa_cast_extract.py", "cast"],
    ["scripts/ml_kem_ml_dsa_pbkdf_cast_extract.py", "rejection"],
    ["scripts/ml_kem_ml_dsa_pbkdf_cast_extract.py", "cast"],
    ["scripts/lms_kat_extract.py", "cast"],
]
# Every CAST row MANIFEST.toml must carry, and no others.
CAST_ROWS = {
    "ML_DSA_spec_draft_01",
    "ML_DSA_sign_internal_rejection_CAST",
    "PBKDF2_HMAC_SHA2_224_CAST",
    "ML_KEM_1024_keyGen_CAST",
    "ML_KEM_1024_encaps_CAST",
    "ML_KEM_1024_decaps_CAST",
    "ML_DSA_87_keyGen_CAST",
    "ML_DSA_87_sigGen_CAST",
    "ML_DSA_87_sigVer_CAST",
    "SLH_DSA_SHA2_128f_keyGen_CAST",
    "SLH_DSA_SHAKE_128f_keyGen_CAST",
    "SLH_DSA_SHA2_128f_sigGen_CAST",
    "SLH_DSA_SHAKE_128f_sigGen_CAST",
    "LMS_SHA256_N32_CAST",
    "LMS_SHA256_N24_CAST",
    "LMS_SHAKE_N32_CAST",
    "LMS_SHAKE_N24_CAST",
}

ROW = re.compile(r"^([A-Za-z0-9_]+)\s*=\s*\{(.*)\}\s*$")
FIELD = re.compile(r'\b(dir|file|sha256)\s*=\s*"([^"]*)"')

failures = []


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_manifest() -> int:
    checked = 0
    seen = set()
    section = None
    for n, line in enumerate((VENDOR / "MANIFEST.toml").read_text().splitlines(), 1):
        if line.startswith("["):
            section = line.strip()
            continue
        m = ROW.match(line)
        if not m or not (m.group(1).endswith("_CAST") or section == "[acvp_ml_dsa_spec]"):
            continue
        fields = dict(FIELD.findall(m.group(2)))
        seen.add(m.group(1))
        missing = [k for k in ("file", "sha256") if k not in fields]
        if missing:
            failures.append(f"MANIFEST.toml:{n} {m.group(1)}: no {' or '.join(missing)}")
            continue
        path = JSON_FILES / fields["dir"] / fields["file"] if "dir" in fields else VENDOR / fields["file"]
        rel = path.relative_to(ROOT)
        if not path.is_file():
            failures.append(f"MANIFEST.toml:{n} {m.group(1)}: {rel} does not exist")
        elif sha256_of(path) != fields["sha256"]:
            failures.append(f"MANIFEST.toml:{n} {m.group(1)}: {rel} has SHA-256 {sha256_of(path)}, not {fields['sha256']}")
        checked += 1
    for key in sorted(CAST_ROWS - seen):
        failures.append(f"MANIFEST.toml has no CAST row {key}")
    for key in sorted(seen - CAST_ROWS):
        failures.append(f"MANIFEST.toml has CAST row {key}, which this check does not list")
    return checked


def check_generated() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp)
        shutil.copytree(VENDOR, copy / "vendor" / "nist")
        (copy / "scripts").mkdir()
        for script in {r[0] for r in RUNS}:
            shutil.copy(ROOT / script, copy / script)
        for rel in GENERATED:
            (copy / rel).parent.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, OXICRYPT_ROOT=str(copy))
        for run in RUNS:
            r = subprocess.run([sys.executable, "-I", str(copy / run[0]), *run[1:]], env=env, capture_output=True, text=True)
            if r.returncode != 0:
                failures.append(f"{' '.join(run)} failed ({r.returncode}): {r.stderr.strip() or r.stdout.strip()}")
                return
        for rel in GENERATED:
            if (copy / rel).read_bytes() != (ROOT / rel).read_bytes():
                failures.append(f"{rel} differs from what the extraction scripts generate from vendor/nist/")


rows = check_manifest()
check_generated()
for f in failures:
    print(f"  ✗ {f}")
if failures:
    print(f"check-cast-vectors: FAILED — {len(failures)} problem(s).", file=sys.stderr)
    sys.exit(1)
print(f"check-cast-vectors: OK ({rows} MANIFEST.toml CAST rows hashed, {len(GENERATED)} generated files reproduced).")
