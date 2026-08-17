#!/usr/bin/env python3
"""Group image-stability-probe output across runs and report per-region verdicts.

Reads probe output on stdin, where each run's lines are prefixed `run<N> `.
Prints a table, the stable-byte total, and asserts both positive controls:

  1. load addresses actually differed across runs (else ASLR is not moving the
     image and a STABLE verdict means nothing);
  2. at least one region VARIES (else the probe cannot detect instability and a
     STABLE verdict is indistinguishable from a broken probe).

Exit 0 only if both controls hold. A green run with no controls is exactly the
failure mode this workstream exists to stop.
"""
import collections
import sys

regions = collections.OrderedDict()
bases = []
runs = set()
# Windows only: sections the base relocation table targets, name -> fixup count.
fixup_sections = {}

for line in sys.stdin:
    p = line.split()
    if len(p) < 2:
        continue
    run = p[0]
    if p[1] == "LOADBASE":
        bases.append(p[2])
        runs.add(run)
        continue
    if p[1] == "RELOC":
        kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
        if "section" in kv and "fixups" in kv:
            fixup_sections[kv["section"]] = int(kv["fixups"])
        continue
    if p[1] == "IMAGEBASE":
        continue  # informational; the loader rewrites the field, see the probe
    if p[1] != "REGION":
        continue
    kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
    key = (kv.get("name", "-"), kv.get("perms", "?"), kv.get("fileoff", "?"), int(kv["size"]))
    regions.setdefault(key, {"mem": [], "cmp": []})
    regions[key]["mem"].append(kv.get("mem", ""))
    regions[key]["cmp"].append(kv.get("cmp", ""))

nruns = len(runs)
print(f"runs: {nruns}   distinct load bases: {len(set(bases))}\n")
print(f"{'segment':16} {'perms':6} {'fileoff':>10} {'size':>10} {'uniq':>5}  {'stable':7} {'mem==file'}")
print("-" * 78)

total = stable = stable_and_matching = 0
varies_seen = False
for (name, perms, off, size), d in regions.items():
    uniq = len(set(d["mem"]))
    is_stable = uniq == 1
    cmps = set(d["cmp"])
    matching = cmps == {"MATCH"}
    total += size
    if is_stable:
        stable += size
        if matching:
            stable_and_matching += size
    else:
        varies_seen = True
    print(f"{name:16} {perms:6} {off:>10} {size:>10} {uniq:>5}  "
          f"{'STABLE' if is_stable else 'varies':7} {'/'.join(sorted(cmps))}")

print("-" * 78)
print(f"total loaded      : {total:,} bytes")
if total:
    print(f"stable            : {stable:,} bytes ({100*stable/total:.2f}%)")
    print(f"stable AND ==file : {stable_and_matching:,} bytes ({100*stable_and_matching/total:.2f}%)")
    print("                    ^ this is the hashable region: build-time signer reads the file,")
    print("                      runtime verifier reads memory, same value.")

print()
ok = True

# Control 1 has two platform-appropriate forms, and picking the wrong one is a
# correction rather than a relaxation. On per-process-ASLR platforms (Linux, macOS)
# the test is that the load base moved across runs. Windows randomises a DLL's base
# once per boot and reuses it for every process, so that test can never fire there.
#
# The PE form asks instead whether relocations were actually APPLIED, which is what a
# MATCH on the code section has to survive to mean anything. Evidence: a base
# relocation table exists AND at least one section it targets differs from the file.
# Fixups can only differ from the file image if the loader wrote them.
#
# An earlier attempt read the ImageBase field back from the loaded header and compared
# it with the actual base. That control could not fire — the loader rewrites the field
# — and it is kept here only as a worked example of a check that reads as passing
# because it is incapable of failing.
if fixup_sections:
    targeted = [n for n, c in fixup_sections.items() if c > 0]
    differing = [
        name
        for (name, _perms, _off, _size), d in regions.items()
        if name in targeted and "DIFFER" in set(d["cmp"])
    ]
    total_fixups = sum(fixup_sections.values())
    if differing:
        print(f"control ok: {total_fixups} fixups present and {', '.join(differing)} differs from")
        print("            the file, so the loader demonstrably applied relocations")
    else:
        print(f"CONTROL FAILED: {total_fixups} fixups present but no targeted section "
              f"({', '.join(targeted) or 'none'}) differs")
        print("                from the file — cannot establish that relocations were applied,")
        print("                so a MATCH on the code section proves nothing.")
        ok = False
elif len(set(bases)) < 2:
    print("CONTROL FAILED: load base did not vary across runs — ASLR is not moving the image,")
    print("                so a STABLE verdict proves nothing.")
    ok = False
else:
    print(f"control ok: {len(set(bases))} distinct load bases across {nruns} runs")
if not varies_seen:
    print("CONTROL FAILED: no region varied — the probe has not been shown capable of")
    print("                detecting instability, so STABLE is indistinguishable from broken.")
    ok = False
else:
    print("control ok: at least one region varied, so the probe detects instability")

sys.exit(0 if ok else 1)
