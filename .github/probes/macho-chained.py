#!/usr/bin/env python3
"""Mach-O build assertions and the extent v2 entry count.

  assert OTOOL_L_OUTPUT --minos VERSION
      Reads `otool -l` output (or `llvm-objdump --macho --private-headers`,
      which prints the same load commands) and requires chained fixups:
      LC_DYLD_CHAINED_FIXUPS present, LC_DYLD_INFO and LC_DYLD_INFO_ONLY
      absent, and LC_BUILD_VERSION's minos equal to VERSION. Exit 0 when all
      hold, 1 when any does not, 2 when no load commands were read, 3 on a
      crash.

  count ARTIFACT --signer SIGNER
      Reports whether the dylib's extent fits its slot, as the signer itself
      encodes it: runs `SIGNER --show ARTIFACT` and reads its `slot budget:`
      line (stored entries, string-table bytes, capacity, fits). Nothing is
      re-derived here. Exit 0 when the extent fits, 1 when it does not, 2 when
      the artifact could not be read or the signer printed no budget.
"""
import re
import subprocess
import sys

BUDGET = re.compile(
    r"^  slot budget: stored (\d+) string-table (\d+) capacity (\d+) fits (yes|no)$", re.M)


def assert_chained(text, minos, out=print):
    cmds = re.findall(r"^\s*cmd (LC_\w+)", text, re.M)
    if not cmds:
        out("UNPARSED: no load commands in the input")
        return 2
    ok = True
    if "LC_DYLD_CHAINED_FIXUPS" in cmds:
        out("ok: LC_DYLD_CHAINED_FIXUPS present")
    else:
        out("FAILED: LC_DYLD_CHAINED_FIXUPS absent")
        ok = False
    legacy = sorted({c for c in cmds if c in ("LC_DYLD_INFO", "LC_DYLD_INFO_ONLY")})
    if legacy:
        out(f"FAILED: {', '.join(legacy)} present: fixups are opcode-encoded")
        ok = False
    found = re.findall(r"^\s*minos (\S+)", text, re.M)
    if found == [minos]:
        out(f"ok: minos {minos}")
    else:
        out(f"FAILED: minos {found or 'absent'}, expected {minos}")
        ok = False
    return 0 if ok else 1


def count(artifact, signer, out=print):
    try:
        run = subprocess.run([signer, "--show", artifact], capture_output=True, text=True, timeout=600)
    except OSError as e:
        out(f"UNPARSED: the signer could not be run: {e}")
        return 2
    found = BUDGET.findall(run.stdout)
    if run.returncode != 0 or len(found) != 1:
        out(f"UNPARSED: the signer read no slot budget for {artifact} (exit {run.returncode}): "
            f"{run.stderr.strip() or run.stdout.strip()[-400:]}")
        return 2
    stored, strtab, capacity, fits = found[0]
    out(f"measurement: entries stored {stored}; string table {strtab} bytes; capacity {capacity}; "
        f"fits={'yes' if fits == 'yes' else 'NO'}")
    return 0 if fits == "yes" else 1


def main(argv):
    if len(argv) == 4 and argv[0] == "assert" and argv[2] == "--minos":
        return assert_chained(open(argv[1]).read(), argv[3])
    if len(argv) == 4 and argv[0] == "count" and argv[2] == "--signer":
        return count(argv[1], argv[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:  # a crash must never read as a verdict
        import traceback
        traceback.print_exc()
        print("CRASHED: macho-chained.py")
        sys.exit(3)
