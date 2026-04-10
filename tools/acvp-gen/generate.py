#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
Generator for pqclib NIST-derived power-up KAT constants.

This tool produces:
  - crates/fips-test-vectors/src/generated.rs
  - vendor/nist/acvp-server/gen-val/json-files/<dir>/kat-slice.json (slim)
  - vendor/nist/MANIFEST.toml

Sources:
  - CAVP Secure Hash Standard byte test vectors (SHA-1, SHA-2 family)
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
  - NIST ACVP-Server internalProjection.json at a pinned commit
    https://github.com/usnistgov/ACVP-Server

Selection policy: for each algorithm/PRF variant we pick a single
byte-aligned AFT (Algorithm Functional Test) case. Whenever ACVP
tests only a truncated output (HMAC, truncated KBKDF), the KAT in
Rust truncates the primitive output to the ACVP macLen / keyOutLength
before comparing, so the KAT still validates the primitive using
an unmodified NIST-supplied vector.

Re-run from the repo root with the working cache directories:
  python3 tools/acvp-gen/generate.py \\
      --acvp-cache /tmp/acvp \\
      --cavp-shs /tmp/shs/shabytetestvectors

ACVP-Server is pinned to the commit recorded in
vendor/nist/MANIFEST.toml; update it there and re-run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

# ACVP-Server commit pinned for this generator run.
ACVP_COMMIT = "3611942ea10c070dd8bc6afec5682d56c307de8a"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def rust_byte_array(name: str, data: bytes, comment: str) -> str:
    """Emit a `pub const NAME: [u8; N] = [ .. ];` Rust declaration."""
    lines = [f"/// {comment}", f"pub const {name}: [u8; {len(data)}] = ["]
    # 12 bytes per line
    for i in range(0, len(data), 12):
        chunk = data[i : i + 12]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("];")
    return "\n".join(lines)


def rust_empty_array(name: str, comment: str) -> str:
    return (
        f"/// {comment}\n"
        f"pub const {name}: [u8; 0] = [];"
    )


def rust_usize_const(name: str, value: int, comment: str) -> str:
    return f"/// {comment}\npub const {name}: usize = {value};"


# ---------------------------------------------------------------------------
# CAVP SHS (SHA-1 / SHA-2) parser
# ---------------------------------------------------------------------------


def parse_shs_rsp(path: Path) -> list[dict]:
    """Parse a CAVS ShortMsg.rsp file into a list of {Len, Msg, MD}."""
    out: list[dict] = []
    current: dict = {}
    with path.open() as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip()
                if k == "Len":
                    current = {"Len": int(v)}
                elif k == "Msg":
                    current["Msg"] = v
                elif k == "MD":
                    current["MD"] = v
                    out.append(current)
                    current = {}
    return out


def pick_shs_vector(path: Path) -> dict:
    """Pick the first byte-aligned ShortMsg test case with a non-empty msg."""
    tests = parse_shs_rsp(path)
    for tc in tests:
        if tc["Len"] > 0 and tc["Len"] % 8 == 0:
            tc["msg_bytes"] = bytes.fromhex(tc["Msg"])
            tc["md_bytes"] = bytes.fromhex(tc["MD"])
            return tc
    raise RuntimeError(f"no byte-aligned ShortMsg in {path}")


# ---------------------------------------------------------------------------
# ACVP SHA-3 / SHAKE selection
# ---------------------------------------------------------------------------


def pick_sha3_vector(json_path: Path) -> dict:
    d = json.loads(json_path.read_text())
    tg = d["testGroups"][0]
    for tc in tg["tests"]:
        ml = int(tc["len"])
        if 0 < ml <= 64 and ml % 8 == 0:
            return {
                "algorithm": d["algorithm"],
                "revision": d["revision"],
                "tgId": tg["tgId"],
                "tcId": tc["tcId"],
                "len_bits": ml,
                "msg_bytes": bytes.fromhex(tc["msg"]),
                "md_bytes": bytes.fromhex(tc["md"]),
            }
    raise RuntimeError(f"no byte-aligned SHA-3 test in {json_path}")


def pick_shake_vector(json_path: Path, prefer_max_out: int = 600) -> dict:
    d = json.loads(json_path.read_text())
    tg = d["testGroups"][0]
    candidates = []
    for tc in tg["tests"]:
        ml = int(tc["len"])
        ol = int(tc["outLen"])
        if ml > 0 and ml % 8 == 0 and ol > 0 and ol % 8 == 0:
            candidates.append(tc)
    if not candidates:
        raise RuntimeError(f"no byte-aligned SHAKE tests in {json_path}")
    # Prefer small message AND small output below the preferred cap.
    filtered = [tc for tc in candidates if int(tc["outLen"]) <= prefer_max_out]
    pool = filtered if filtered else candidates
    pool.sort(key=lambda t: (int(t["len"]), int(t["outLen"]), int(t["tcId"])))
    tc = pool[0]
    return {
        "algorithm": d["algorithm"],
        "revision": d["revision"],
        "tgId": tg["tgId"],
        "tcId": int(tc["tcId"]),
        "msg_len_bits": int(tc["len"]),
        "out_len_bits": int(tc["outLen"]),
        "msg_bytes": bytes.fromhex(tc["msg"]),
        "md_bytes": bytes.fromhex(tc["md"]),
    }


# ---------------------------------------------------------------------------
# ACVP HMAC selection
# ---------------------------------------------------------------------------


def pick_hmac_vector(json_path: Path) -> dict:
    """Pick the smallest byte-aligned HMAC AFT test from the first group."""
    d = json.loads(json_path.read_text())
    alg = d["algorithm"]
    best = None
    best_tg = None
    for tg in d["testGroups"]:
        if tg.get("testType") != "AFT":
            continue
        # Per-group params (ACVP 1.0 HMAC) carry keyLen/msgLen/macLen.
        grp_key_len = tg.get("keyLen")
        grp_msg_len = tg.get("msgLen")
        grp_mac_len = tg.get("macLen")
        if (
            grp_key_len is None
            or grp_msg_len is None
            or grp_mac_len is None
            or grp_key_len % 8 != 0
            or grp_msg_len % 8 != 0
            or grp_mac_len % 8 != 0
            or grp_key_len == 0
            or grp_msg_len == 0
        ):
            continue
        for tc in tg["tests"]:
            key = bytes.fromhex(tc["key"])
            msg = bytes.fromhex(tc["msg"])
            mac = bytes.fromhex(tc["mac"])
            total = len(key) + len(msg)
            if best is None or total < best["_total"]:
                best = {
                    "algorithm": alg,
                    "tgId": tg["tgId"],
                    "tcId": tc["tcId"],
                    "key_len_bits": grp_key_len,
                    "msg_len_bits": grp_msg_len,
                    "mac_len_bits": grp_mac_len,
                    "key_bytes": key,
                    "msg_bytes": msg,
                    "mac_prefix_bytes": mac,
                    "_total": total,
                }
                best_tg = tg
            break  # smallest per group is its first tc
    if best is None:
        raise RuntimeError(f"no HMAC AFT vector in {json_path}")
    best.pop("_total")
    return best


# ---------------------------------------------------------------------------
# ACVP KDF-1.0 (SP 800-108 Counter Mode) selection
# ---------------------------------------------------------------------------


def pick_kbkdf_counter_vector(kdf_json: dict, mac_mode: str) -> dict:
    """Pick a counter-mode, before-fixed-data, counterLength=32 AFT test case
    for the given macMode. Prefer groups whose keyOutLength is a multiple of
    8 and >= 8 bits (we only need a byte-aligned output)."""
    best = None
    for tg in kdf_json["testGroups"]:
        if (
            tg.get("kdfMode") == "counter"
            and tg.get("counterLocation") == "before fixed data"
            and tg.get("counterLength") == 32
            and tg.get("macMode") == mac_mode
            and tg.get("testType") == "AFT"
        ):
            key_out_len = tg.get("keyOutLength", 0)
            if key_out_len == 0 or key_out_len % 8 != 0:
                continue
            for tc in tg["tests"]:
                key_in = bytes.fromhex(tc["keyIn"])
                fixed = bytes.fromhex(tc["fixedData"])
                key_out = bytes.fromhex(tc["keyOut"])
                if best is None or key_out_len < best["key_out_len_bits"]:
                    best = {
                        "macMode": mac_mode,
                        "tgId": tg["tgId"],
                        "tcId": int(tc["tcId"]),
                        "key_out_len_bits": key_out_len,
                        "key_in_bytes": key_in,
                        "fixed_data_bytes": fixed,
                        "key_out_bytes": key_out,
                    }
                break  # one tc per group is enough
    if best is None:
        raise RuntimeError(f"no KDF counter AFT for {mac_mode}")
    return best


# ---------------------------------------------------------------------------
# Slim JSON slice writers
# ---------------------------------------------------------------------------


def write_sha3_slice(out_dir: Path, algo_dir: str, tc: dict, src_sha256: str) -> None:
    d = out_dir / "acvp-server" / "gen-val" / "json-files" / algo_dir
    d.mkdir(parents=True, exist_ok=True)
    slim = {
        "_source": {
            "repo": "usnistgov/ACVP-Server",
            "commit": ACVP_COMMIT,
            "path": f"gen-val/json-files/{algo_dir}/internalProjection.json",
            "internalProjection_sha256": src_sha256,
            "selected_tgId": tc["tgId"],
            "selected_tcId": tc["tcId"],
        },
        "algorithm": tc["algorithm"],
        "revision": tc["revision"],
        "testGroups": [
            {
                "tgId": tc["tgId"],
                "testType": "AFT",
                "tests": [
                    {
                        "tcId": tc["tcId"],
                        "len": tc["len_bits"],
                        "msg": tc["msg_bytes"].hex().upper(),
                        "md": tc["md_bytes"].hex().upper(),
                    }
                ],
            }
        ],
    }
    (d / "kat-slice.json").write_text(json.dumps(slim, indent=2) + "\n")


def write_shake_slice(out_dir: Path, algo_dir: str, tc: dict, src_sha256: str) -> None:
    d = out_dir / "acvp-server" / "gen-val" / "json-files" / algo_dir
    d.mkdir(parents=True, exist_ok=True)
    slim = {
        "_source": {
            "repo": "usnistgov/ACVP-Server",
            "commit": ACVP_COMMIT,
            "path": f"gen-val/json-files/{algo_dir}/internalProjection.json",
            "internalProjection_sha256": src_sha256,
            "selected_tgId": tc["tgId"],
            "selected_tcId": tc["tcId"],
        },
        "algorithm": tc["algorithm"],
        "revision": tc["revision"],
        "testGroups": [
            {
                "tgId": tc["tgId"],
                "testType": "AFT",
                "tests": [
                    {
                        "tcId": tc["tcId"],
                        "len": tc["msg_len_bits"],
                        "outLen": tc["out_len_bits"],
                        "msg": tc["msg_bytes"].hex().upper(),
                        "md": tc["md_bytes"].hex().upper(),
                    }
                ],
            }
        ],
    }
    (d / "kat-slice.json").write_text(json.dumps(slim, indent=2) + "\n")


def write_hmac_slice(out_dir: Path, algo_dir: str, tc: dict, src_sha256: str) -> None:
    d = out_dir / "acvp-server" / "gen-val" / "json-files" / algo_dir
    d.mkdir(parents=True, exist_ok=True)
    slim = {
        "_source": {
            "repo": "usnistgov/ACVP-Server",
            "commit": ACVP_COMMIT,
            "path": f"gen-val/json-files/{algo_dir}/internalProjection.json",
            "internalProjection_sha256": src_sha256,
            "selected_tgId": tc["tgId"],
            "selected_tcId": tc["tcId"],
        },
        "algorithm": tc["algorithm"],
        "revision": "1.0",
        "testGroups": [
            {
                "tgId": tc["tgId"],
                "testType": "AFT",
                "keyLen": tc["key_len_bits"],
                "msgLen": tc["msg_len_bits"],
                "macLen": tc["mac_len_bits"],
                "tests": [
                    {
                        "tcId": tc["tcId"],
                        "keyLen": tc["key_len_bits"],
                        "msgLen": tc["msg_len_bits"],
                        "macLen": tc["mac_len_bits"],
                        "key": tc["key_bytes"].hex().upper(),
                        "msg": tc["msg_bytes"].hex().upper(),
                        "mac": tc["mac_prefix_bytes"].hex().upper(),
                    }
                ],
            }
        ],
    }
    (d / "kat-slice.json").write_text(json.dumps(slim, indent=2) + "\n")


def write_kdf_slice(
    out_dir: Path,
    algo_dir: str,
    picks: list[dict],
    src_sha256: str,
) -> None:
    d = out_dir / "acvp-server" / "gen-val" / "json-files" / algo_dir
    d.mkdir(parents=True, exist_ok=True)
    slim = {
        "_source": {
            "repo": "usnistgov/ACVP-Server",
            "commit": ACVP_COMMIT,
            "path": f"gen-val/json-files/{algo_dir}/internalProjection.json",
            "internalProjection_sha256": src_sha256,
        },
        "algorithm": "KDF",
        "revision": "1.0",
        "testGroups": [
            {
                "tgId": p["tgId"],
                "kdfMode": "counter",
                "counterLocation": "before fixed data",
                "counterLength": 32,
                "macMode": p["macMode"],
                "keyOutLength": p["key_out_len_bits"],
                "testType": "AFT",
                "tests": [
                    {
                        "tcId": p["tcId"],
                        "keyIn": p["key_in_bytes"].hex().upper(),
                        "fixedData": p["fixed_data_bytes"].hex().upper(),
                        "keyOut": p["key_out_bytes"].hex().upper(),
                    }
                ],
            }
            for p in picks
        ],
    }
    (d / "kat-slice.json").write_text(json.dumps(slim, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


SHA_CAVP_FILES = [
    ("SHA_1", "SHA1ShortMsg.rsp", "SHA-1"),
    ("SHA_224", "SHA224ShortMsg.rsp", "SHA-224"),
    ("SHA_256", "SHA256ShortMsg.rsp", "SHA-256"),
    ("SHA_384", "SHA384ShortMsg.rsp", "SHA-384"),
    ("SHA_512", "SHA512ShortMsg.rsp", "SHA-512"),
    ("SHA_512_224", "SHA512_224ShortMsg.rsp", "SHA-512/224"),
    ("SHA_512_256", "SHA512_256ShortMsg.rsp", "SHA-512/256"),
]

SHA3_ACVP_DIRS = [
    ("SHA3_224", "SHA3-224-2.0"),
    ("SHA3_256", "SHA3-256-2.0"),
    ("SHA3_384", "SHA3-384-2.0"),
    ("SHA3_512", "SHA3-512-2.0"),
]

SHAKE_ACVP_DIRS = [
    ("SHAKE128", "SHAKE-128-FIPS202"),
    ("SHAKE256", "SHAKE-256-FIPS202"),
]

HMAC_ACVP_DIRS = [
    ("HMAC_SHA_1", "HMAC-SHA-1-1.0", "HMAC-SHA-1"),
    ("HMAC_SHA2_224", "HMAC-SHA2-224-1.0", "HMAC-SHA2-224"),
    ("HMAC_SHA2_256", "HMAC-SHA2-256-1.0", "HMAC-SHA2-256"),
    ("HMAC_SHA2_384", "HMAC-SHA2-384-1.0", "HMAC-SHA2-384"),
    ("HMAC_SHA2_512", "HMAC-SHA2-512-1.0", "HMAC-SHA2-512"),
    ("HMAC_SHA2_512_224", "HMAC-SHA2-512-224-1.0", "HMAC-SHA2-512/224"),
    ("HMAC_SHA2_512_256", "HMAC-SHA2-512-256-1.0", "HMAC-SHA2-512/256"),
    ("HMAC_SHA3_224", "HMAC-SHA3-224-1.0", "HMAC-SHA3-224"),
    ("HMAC_SHA3_256", "HMAC-SHA3-256-1.0", "HMAC-SHA3-256"),
    ("HMAC_SHA3_384", "HMAC-SHA3-384-1.0", "HMAC-SHA3-384"),
    ("HMAC_SHA3_512", "HMAC-SHA3-512-1.0", "HMAC-SHA3-512"),
]

KBKDF_MAC_MODES = [
    ("HMAC_SHA_1", "HMAC-SHA-1"),
    ("HMAC_SHA2_224", "HMAC-SHA2-224"),
    ("HMAC_SHA2_256", "HMAC-SHA2-256"),
    ("HMAC_SHA2_384", "HMAC-SHA2-384"),
    ("HMAC_SHA2_512", "HMAC-SHA2-512"),
    ("HMAC_SHA2_512_224", "HMAC-SHA2-512/224"),
    ("HMAC_SHA2_512_256", "HMAC-SHA2-512/256"),
    ("HMAC_SHA3_224", "HMAC-SHA3-224"),
    ("HMAC_SHA3_256", "HMAC-SHA3-256"),
    ("HMAC_SHA3_384", "HMAC-SHA3-384"),
    ("HMAC_SHA3_512", "HMAC-SHA3-512"),
]


GENERATED_HEADER = """\
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// @generated by tools/acvp-gen/generate.py — DO NOT EDIT MANUALLY.
//
// This file is generated from NIST-supplied test vectors and committed
// to the repository. Regenerate with:
//
//     python3 tools/acvp-gen/generate.py
//
// Source manifests and selected tcId values are recorded in
// vendor/nist/MANIFEST.toml and vendor/nist/acvp-server/gen-val/
// json-files/<algo>/kat-slice.json.
//
// Sources:
//   * NIST CAVP Secure Hash Standard byte test vectors for SHA-1
//     and the SHA-2 family (SHS ShortMsg).
//   * NIST ACVP-Server gen-val/json-files for SHA-3, SHAKE, HMAC,
//     and SP 800-108 Counter Mode KDF, pinned to commit
//     """ + ACVP_COMMIT + """.
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--acvp-cache", required=True, type=Path)
    ap.add_argument("--cavp-shs", required=True, type=Path)
    ap.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    args = ap.parse_args()

    repo = args.repo_root
    vendor = repo / "vendor" / "nist"
    vendor.mkdir(parents=True, exist_ok=True)

    rust_parts: list[str] = [GENERATED_HEADER, ""]
    manifest: list[str] = [
        "# @generated — do not edit manually.",
        "# Source pins for NIST-derived KAT vectors.",
        "",
        '[acvp_server]',
        f'commit = "{ACVP_COMMIT}"',
        'url = "https://github.com/usnistgov/ACVP-Server"',
        "",
        "[cavp_shs]",
        'zip_url = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip"',
        "",
    ]

    # --- SHA-1 / SHA-2 (CAVP SHS) --------------------------------------
    rust_parts.append("// ===== SHA-1 / SHA-2 family (NIST CAVP SHS) =====\n")
    manifest.append("[cavp_shs.vectors]")
    for stem, filename, display in SHA_CAVP_FILES:
        src = args.cavp_shs / filename
        if not src.exists():
            print(f"missing CAVP file: {src}", file=sys.stderr)
            return 1
        sha = sha256_file(src)
        tc = pick_shs_vector(src)
        # Copy the source .rsp to vendor/
        dst = vendor / "cavp-shs" / "shabytetestvectors" / filename
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        rust_parts.append(
            f"// {display} — CAVP {filename} Len={tc['Len']}\n"
            f"// Source: vendor/nist/cavp-shs/shabytetestvectors/{filename}\n"
            f"// Source-SHA256: {sha}"
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_MSG",
                tc["msg_bytes"],
                f"{display} message for the power-up KAT.",
            )
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_MD",
                tc["md_bytes"],
                f"{display} expected digest.",
            )
        )
        rust_parts.append("")
        manifest.append(
            f'{stem} = {{ file = "cavp-shs/shabytetestvectors/{filename}", '
            f'len_bits = {tc["Len"]}, sha256 = "{sha}" }}'
        )
    manifest.append("")

    # --- SHA-3 family (ACVP) -------------------------------------------
    rust_parts.append("// ===== SHA-3 family (NIST ACVP-Server) =====\n")
    manifest.append("[acvp_server.sha3]")
    for stem, algo_dir in SHA3_ACVP_DIRS:
        src = args.acvp_cache / f"{algo_dir}.json"
        if not src.exists():
            print(f"missing ACVP file: {src}", file=sys.stderr)
            return 1
        sha = sha256_file(src)
        tc = pick_sha3_vector(src)
        write_sha3_slice(vendor, algo_dir, tc, sha)
        display = tc["algorithm"]
        rust_parts.append(
            f"// {display} — ACVP-Server {algo_dir} tgId={tc['tgId']} tcId={tc['tcId']}\n"
            f"// Source: vendor/nist/acvp-server/gen-val/json-files/{algo_dir}/kat-slice.json\n"
            f"// Source-SHA256: {sha}"
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_MSG",
                tc["msg_bytes"],
                f"{display} message for the power-up KAT.",
            )
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_MD",
                tc["md_bytes"],
                f"{display} expected digest.",
            )
        )
        rust_parts.append("")
        manifest.append(
            f'{stem} = {{ dir = "{algo_dir}", tgId = {tc["tgId"]}, '
            f'tcId = {tc["tcId"]}, sha256 = "{sha}" }}'
        )
    manifest.append("")

    # --- SHAKE (ACVP) ---------------------------------------------------
    rust_parts.append("// ===== SHAKE XOF (NIST ACVP-Server) =====\n")
    manifest.append("[acvp_server.shake]")
    for stem, algo_dir in SHAKE_ACVP_DIRS:
        src = args.acvp_cache / f"{algo_dir}.json"
        if not src.exists():
            print(f"missing ACVP file: {src}", file=sys.stderr)
            return 1
        sha = sha256_file(src)
        tc = pick_shake_vector(src)
        write_shake_slice(vendor, algo_dir, tc, sha)
        display = tc["algorithm"]
        rust_parts.append(
            f"// {display} — ACVP-Server {algo_dir} tgId={tc['tgId']} tcId={tc['tcId']}\n"
            f"// Source: vendor/nist/acvp-server/gen-val/json-files/{algo_dir}/kat-slice.json\n"
            f"// Source-SHA256: {sha}"
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_MSG",
                tc["msg_bytes"],
                f"{display} message for the power-up KAT.",
            )
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_OUT",
                tc["md_bytes"],
                f"{display} expected XOF output ({len(tc['md_bytes'])} bytes).",
            )
        )
        rust_parts.append("")
        manifest.append(
            f'{stem} = {{ dir = "{algo_dir}", tgId = {tc["tgId"]}, '
            f'tcId = {tc["tcId"]}, out_bytes = {len(tc["md_bytes"])}, '
            f'sha256 = "{sha}" }}'
        )
    manifest.append("")

    # --- HMAC (ACVP 1.0) -------------------------------------------------
    rust_parts.append("// ===== HMAC family (NIST ACVP-Server HMAC-*-1.0) =====\n")
    rust_parts.append(
        "// ACVP HMAC test vectors validate MAC truncation: each `*_MAC_PREFIX`\n"
        "// is the first `*_MAC_PREFIX_LEN` bytes of the full HMAC output that\n"
        "// the primitive must produce for (key, msg). The power-up KAT computes\n"
        "// the full MAC and compares its prefix against this constant, which\n"
        "// exercises the full HMAC primitive using an unmodified NIST vector.\n"
    )
    manifest.append("[acvp_server.hmac]")
    for stem, algo_dir, display in HMAC_ACVP_DIRS:
        src = args.acvp_cache / f"{algo_dir}.json"
        if not src.exists():
            print(f"missing ACVP file: {src}", file=sys.stderr)
            return 1
        sha = sha256_file(src)
        tc = pick_hmac_vector(src)
        write_hmac_slice(vendor, algo_dir, tc, sha)
        rust_parts.append(
            f"// {display} — ACVP-Server {algo_dir} tgId={tc['tgId']} tcId={tc['tcId']}\n"
            f"// macLen={tc['mac_len_bits']} bits, keyLen={tc['key_len_bits']} bits, "
            f"msgLen={tc['msg_len_bits']} bits\n"
            f"// Source: vendor/nist/acvp-server/gen-val/json-files/{algo_dir}/kat-slice.json\n"
            f"// Source-SHA256: {sha}"
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_KEY",
                tc["key_bytes"],
                f"{display} key for the power-up KAT.",
            )
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_MSG",
                tc["msg_bytes"],
                f"{display} message for the power-up KAT.",
            )
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_MAC_PREFIX",
                tc["mac_prefix_bytes"],
                f"{display} expected MAC prefix "
                f"({tc['mac_len_bits']} bits = first {tc['mac_len_bits'] // 8} bytes).",
            )
        )
        rust_parts.append("")
        manifest.append(
            f'{stem} = {{ dir = "{algo_dir}", tgId = {tc["tgId"]}, '
            f'tcId = {tc["tcId"]}, key_bits = {tc["key_len_bits"]}, '
            f'msg_bits = {tc["msg_len_bits"]}, mac_bits = {tc["mac_len_bits"]}, '
            f'sha256 = "{sha}" }}'
        )
    manifest.append("")

    # --- KBKDF Counter Mode (ACVP KDF-1.0) ------------------------------
    rust_parts.append(
        "// ===== SP 800-108 Counter Mode (NIST ACVP-Server KDF-1.0) =====\n"
    )
    rust_parts.append(
        "// Each entry is a counter-mode, before-fixed-data, counterLength=32\n"
        "// ACVP test case. The fixedData blob is passed to the derivation as a\n"
        "// pre-built fixed input string (Label || 0x00 || Context || [L]_32 is\n"
        "// already baked into `fixedData` by the ACVP generator). The power-up\n"
        "// KAT feeds this fixedData directly into `derive_with_fixed_data_internal`\n"
        "// and compares the full output block run against `*_KEY_OUT`, truncated\n"
        "// to `*_KEY_OUT_LEN` bytes.\n"
    )
    kdf_src = args.acvp_cache / "KDF-1.0.json"
    if not kdf_src.exists():
        print(f"missing ACVP file: {kdf_src}", file=sys.stderr)
        return 1
    kdf_sha = sha256_file(kdf_src)
    kdf_doc = json.loads(kdf_src.read_text())
    manifest.append("[acvp_server.kbkdf_counter]")
    manifest.append(f'dir = "KDF-1.0"')
    manifest.append(f'sha256 = "{kdf_sha}"')
    picks: list[dict] = []
    for stem, mac_mode in KBKDF_MAC_MODES:
        p = pick_kbkdf_counter_vector(kdf_doc, mac_mode)
        picks.append(p)
        rust_parts.append(
            f"// SP 800-108 Counter {mac_mode} — ACVP-Server KDF-1.0 "
            f"tgId={p['tgId']} tcId={p['tcId']}\n"
            f"// keyOutLength = {p['key_out_len_bits']} bits "
            f"({p['key_out_len_bits'] // 8} bytes)"
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_KBKDF_KEY_IN",
                p["key_in_bytes"],
                f"SP 800-108 Counter {mac_mode} keyIn for the power-up KAT.",
            )
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_KBKDF_FIXED_DATA",
                p["fixed_data_bytes"],
                f"SP 800-108 Counter {mac_mode} fixedData.",
            )
        )
        rust_parts.append(
            rust_byte_array(
                f"{stem}_KBKDF_KEY_OUT",
                p["key_out_bytes"],
                f"SP 800-108 Counter {mac_mode} expected keyOut "
                f"({p['key_out_len_bits']} bits).",
            )
        )
        rust_parts.append("")
        manifest.append(
            f'{stem} = {{ tgId = {p["tgId"]}, tcId = {p["tcId"]}, '
            f'key_out_bits = {p["key_out_len_bits"]} }}'
        )
    write_kdf_slice(vendor, "KDF-1.0", picks, kdf_sha)
    manifest.append("")

    # --- Write outputs --------------------------------------------------
    (vendor / "MANIFEST.toml").write_text("\n".join(manifest) + "\n")
    out_rs = repo / "crates" / "fips-test-vectors" / "src" / "generated.rs"
    out_rs.parent.mkdir(parents=True, exist_ok=True)
    out_rs.write_text("\n".join(rust_parts) + "\n")
    print(f"wrote {out_rs}")
    print(f"wrote {vendor / 'MANIFEST.toml'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
