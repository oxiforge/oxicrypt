#!/usr/bin/env python3
"""B4 one-shot: emit per-pair Service variants + Display arms + rewire 80 per-pair files.

Discriminant layout (decided in PRD-D2):
- 500-539: SHA-256/M=32 family (20 pairs)
- 540-579: SHA-256/M=24 family (20 pairs)
- 580-619: SHAKE/M=32 family   (20 pairs)
- 620-659: SHAKE/M=24 family   (20 pairs)

Within each family: (H ascending, W ascending) canonical order. Sign+Verify alternate per pair.

CNSA 2.0 subset = LMS_SHA256_M32_H{10,15,20,25} x LMOTS_SHA256_N32_W{4,8} = 8 pairs.
CNSA 1.0 mirrors CNSA-2 exactly (PRD-D4).

Modes:
  python lms_b4_rewire.py emit-enum             # variant declarations (stdout)
  python lms_b4_rewire.py emit-display          # Display impl arms (stdout)
  python lms_b4_rewire.py emit-cnsa2            # CNSA-2 service list for is_cnsa2_allowed (stdout)
  python lms_b4_rewire.py emit-all-160-array    # 160-element [Service; _] array (stdout)
  python lms_b4_rewire.py emit-cnsa2-set-array  # 16-element CNSA-2 array (stdout)
  python lms_b4_rewire.py preview-baseline      # debug: show baseline pair tuple
  python lms_b4_rewire.py rewire                # rewrite svc_sign/svc_verify in 80 per-pair files (in place)
"""
from __future__ import annotations
import os

import sys
from pathlib import Path

# Repo root, derived from this script's own location so the tool runs from any
# checkout. Override with OXICRYPT_ROOT when running against a worktree.
WORKTREE = Path(os.environ.get("OXICRYPT_ROOT", Path(__file__).resolve().parents[1]))
LMS_SRC = WORKTREE / "crates" / "oxicrypt-lms" / "src"

FAMILY_ORDER = [
    ("sha256", 32, "Sha256M32", "SHA-256", "M=32"),
    ("sha256", 24, "Sha256M24", "SHA-256", "M=24"),
    ("shake", 32, "ShakeM32", "SHAKE", "M=32"),
    ("shake", 24, "ShakeM24", "SHAKE", "M=24"),
]
HEIGHTS = [5, 10, 15, 20, 25]
WINTERNITZ = [1, 2, 4, 8]

DISCRIMINANT_BASE = 500


def pairs():
    """Yield (file_stem, variant_stem, display_h_family, display_w_family, h, w, family_tag) for each of 80 pairs."""
    for family, m, variant_family_tag, hash_human, m_tag in FAMILY_ORDER:
        for h in HEIGHTS:
            for w in WINTERNITZ:
                file_stem = f"lms_{family}_m{m}_h{h}_w{w}"
                variant_stem = f"Lms{variant_family_tag}H{h}W{w}"
                display = f"LMS {hash_human} {m_tag} H={h} W={w}"
                yield (file_stem, variant_stem, display, h, w, family, m)


def is_cnsa2(file_stem, h, w, family, m):
    return family == "sha256" and m == 32 and h in (10, 15, 20, 25) and w in (4, 8)


def emit_enum():
    lines = []
    lines.append("    // ----- oxicrypt-lms: SP 800-208 (RFC 8554 / RFC 8708) -----")
    lines.append("    // 160 per-pair entries (80 pairs × Sign + Verify), discriminants 500-659.")
    lines.append("    // Layout: 500-539 SHA-256/M=32, 540-579 SHA-256/M=24,")
    lines.append("    // 580-619 SHAKE/M=32, 620-659 SHAKE/M=24.")
    lines.append("    // Within each family: (H ascending, W ascending), Sign/Verify alternating.")
    lines.append("    // The 8 CNSA-2 permitted pairs (SHA-256/M=32 H{10,15,20,25} W{4,8}) are")
    lines.append("    // flagged inline; all other 72 pairs are Unrestricted-only.")
    disc = DISCRIMINANT_BASE
    prev_family_tag = None
    for file_stem, variant_stem, display, h, w, family, m in pairs():
        family_tag = (family, m)
        if family_tag != prev_family_tag:
            if family == "sha256" and m == 32:
                lines.append("")
                lines.append("    // SHA-256 / N=32 family (RFC 8554 §A.1+§A.2)")
            elif family == "sha256" and m == 24:
                lines.append("")
                lines.append("    // SHA-256 / N=24 family (RFC 8708 §4.1)")
            elif family == "shake" and m == 32:
                lines.append("")
                lines.append("    // SHAKE-256 / N=32 family (RFC 8708 §3.1)")
            elif family == "shake" and m == 24:
                lines.append("")
                lines.append("    // SHAKE-256 / N=24 family (RFC 8708 §4.2)")
            prev_family_tag = family_tag
        cnsa = " // CNSA 2.0" if is_cnsa2(file_stem, h, w, family, m) else ""
        lines.append(f"    {variant_stem}Sign = {disc},{cnsa}")
        disc += 1
        lines.append(f"    {variant_stem}Verify = {disc},{cnsa}")
        disc += 1
    assert disc == DISCRIMINANT_BASE + 160, f"disc ended at {disc}, expected {DISCRIMINANT_BASE+160}"
    return "\n".join(lines)


def emit_display():
    lines = []
    for file_stem, variant_stem, display, h, w, family, m in pairs():
        lines.append(f'            Self::{variant_stem}Sign => "{display} sign",')
        lines.append(f'            Self::{variant_stem}Verify => "{display} verify",')
    return "\n".join(lines)


def emit_cnsa2():
    lines = []
    for file_stem, variant_stem, display, h, w, family, m in pairs():
        if is_cnsa2(file_stem, h, w, family, m):
            lines.append(f"            | Service::{variant_stem}Sign")
            lines.append(f"            | Service::{variant_stem}Verify")
    return "\n".join(lines)


def emit_all_160_array():
    lines = []
    prev_family_tag = None
    for file_stem, variant_stem, display, h, w, family, m in pairs():
        family_tag = (family, m)
        if family_tag != prev_family_tag:
            if family == "sha256" and m == 32:
                lines.append("            // SHA-256 / N=32 family (20 pairs, 40 entries).")
            elif family == "sha256" and m == 24:
                lines.append("            // SHA-256 / N=24 family (20 pairs, 40 entries).")
            elif family == "shake" and m == 32:
                lines.append("            // SHAKE-256 / N=32 family (20 pairs, 40 entries).")
            elif family == "shake" and m == 24:
                lines.append("            // SHAKE-256 / N=24 family (20 pairs, 40 entries).")
            prev_family_tag = family_tag
        lines.append(f"            Service::{variant_stem}Sign,")
        lines.append(f"            Service::{variant_stem}Verify,")
    return "\n".join(lines)


def emit_cnsa2_set_array():
    lines = []
    for file_stem, variant_stem, display, h, w, family, m in pairs():
        if is_cnsa2(file_stem, h, w, family, m):
            lines.append(f"            Service::{variant_stem}Sign,")
            lines.append(f"            Service::{variant_stem}Verify,")
    return "\n".join(lines)


def rewire():
    """Rewrite svc_sign = Service::LmsSign; -> per-pair entries in each of 80 files."""
    touched = 0
    for file_stem, variant_stem, display, h, w, family, m in pairs():
        path = LMS_SRC / f"{file_stem}.rs"
        if not path.exists():
            print(f"MISSING: {path}", file=sys.stderr)
            continue
        text = path.read_text()
        if "Service::LmsSign" not in text or "Service::LmsVerify" not in text:
            print(f"SKIP (already rewired or unexpected shape): {path}", file=sys.stderr)
            continue
        new_text = text.replace(
            "svc_sign = Service::LmsSign;",
            f"svc_sign = Service::{variant_stem}Sign;",
        ).replace(
            "svc_verify = Service::LmsVerify;",
            f"svc_verify = Service::{variant_stem}Verify;",
        )
        if new_text == text:
            print(f"NO-OP (replace failed): {path}", file=sys.stderr)
            continue
        path.write_text(new_text)
        touched += 1
    print(f"rewired {touched} files", file=sys.stderr)
    return touched


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "emit-enum":
        print(emit_enum())
    elif cmd == "emit-display":
        print(emit_display())
    elif cmd == "emit-cnsa2":
        print(emit_cnsa2())
    elif cmd == "emit-all-160-array":
        print(emit_all_160_array())
    elif cmd == "emit-cnsa2-set-array":
        print(emit_cnsa2_set_array())
    elif cmd == "rewire":
        rewire()
    elif cmd == "preview-baseline":
        for fs, vs, d, h, w, fam, m in pairs():
            if fs == "lms_sha256_m32_h10_w4":
                print(f"file={fs} variant={vs} display='{d}' h={h} w={w}")
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
