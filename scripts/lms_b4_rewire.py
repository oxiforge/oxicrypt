#!/usr/bin/env python3
"""Emit the LMS `Service` variants, `Display` arms and enumeration array
for `crates/oxicrypt-module/src/lib.rs`.

One `Lms<Family>M<N>H<H>W<W>Verify` service per (LMS, LM-OTS) pair, on the
odd discriminants 501-659. The even values in 500-658 stay unassigned:
SP 800-208 §8.1 confines LMS signing to hardware modules, so the module
offers no signing service.

Layout (odd values only):
- 501-539: SHA-256/M=32 family (20 pairs, SP 800-208 §4.1)
- 541-579: SHA-256/M=24 family (20 pairs, SP 800-208 §4.2)
- 581-619: SHAKE/M=32 family   (20 pairs, SP 800-208 §4.3)
- 621-659: SHAKE/M=24 family   (20 pairs, SP 800-208 §4.4)

Within each family: (H ascending, W ascending) canonical order. Every pair
is permitted under CNSA 2.0, Migration and Unrestricted, and refused under
CNSA 1.0; the CNSA 2.0 gate tests the block arithmetically
(`is_lms_service`) rather than enumerating it.

Modes:
  python lms_b4_rewire.py emit-enum            # variant declarations (stdout)
  python lms_b4_rewire.py emit-display         # Display impl arms (stdout)
  python lms_b4_rewire.py emit-all-80-array    # 80-element [Service; _] array (stdout)
  python lms_b4_rewire.py preview-baseline     # debug: show baseline pair tuple
"""
from __future__ import annotations

import sys

FAMILY_ORDER = [
    ("sha256", 32, "Sha256M32", "SHA-256", "M=32", "SHA-256 / N=32 family (SP 800-208 §4.1)"),
    ("sha256", 24, "Sha256M24", "SHA-256", "M=24", "SHA-256 / N=24 family (SP 800-208 §4.2)"),
    ("shake", 32, "ShakeM32", "SHAKE", "M=32", "SHAKE-256 / N=32 family (SP 800-208 §4.3)"),
    ("shake", 24, "ShakeM24", "SHAKE", "M=24", "SHAKE-256 / N=24 family (SP 800-208 §4.4)"),
]
HEIGHTS = [5, 10, 15, 20, 25]
WINTERNITZ = [1, 2, 4, 8]

FIRST_DISCRIMINANT = 501


def pairs():
    """Yield (file_stem, variant_stem, display, h, w, family, m, family_heading) for each of 80 pairs."""
    for family, m, variant_family_tag, hash_human, m_tag, heading in FAMILY_ORDER:
        for h in HEIGHTS:
            for w in WINTERNITZ:
                file_stem = f"lms_{family}_m{m}_h{h}_w{w}"
                variant_stem = f"Lms{variant_family_tag}H{h}W{w}"
                display = f"LMS {hash_human} {m_tag} H={h} W={w}"
                yield (file_stem, variant_stem, display, h, w, family, m, heading)


def emit_enum():
    lines = []
    lines.append("    // ----- oxicrypt-lms: SP 800-208 §4.1–§4.4, verification only -----")
    lines.append("    // 80 per-pair entries on the odd discriminants 501-659.")
    disc = FIRST_DISCRIMINANT
    prev_heading = None
    for _stem, variant_stem, _display, _h, _w, _family, _m, heading in pairs():
        if heading != prev_heading:
            lines.append("")
            lines.append(f"    // {heading}")
            prev_heading = heading
        lines.append(f"    {variant_stem}Verify = {disc},")
        disc += 2
    assert disc == FIRST_DISCRIMINANT + 160, f"disc ended at {disc}"
    return "\n".join(lines)


def emit_display():
    lines = []
    for _stem, variant_stem, display, *_ in pairs():
        lines.append(f'            Self::{variant_stem}Verify => "{display} verify",')
    return "\n".join(lines)


def emit_all_80_array():
    lines = []
    prev_heading = None
    for _stem, variant_stem, _display, _h, _w, _family, _m, heading in pairs():
        if heading != prev_heading:
            family = heading.split(" family")[0]
            lines.append(f"            // {family} family (20 pairs).")
            prev_heading = heading
        lines.append(f"            Service::{variant_stem}Verify,")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "emit-enum":
        print(emit_enum())
    elif cmd == "emit-display":
        print(emit_display())
    elif cmd == "emit-all-80-array":
        print(emit_all_80_array())
    elif cmd == "preview-baseline":
        for fs, vs, d, h, w, *_ in pairs():
            if fs == "lms_sha256_m32_h10_w4":
                print(f"file={fs} variant={vs} display='{d}' h={h} w={w}")
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
