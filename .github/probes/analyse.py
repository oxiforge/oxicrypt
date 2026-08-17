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

for line in sys.stdin:
    p = line.split()
    if len(p) < 2:
        continue
    run = p[0]
    if p[1] == "LOADBASE":
        bases.append(p[2])
        runs.add(run)
        continue
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
if len(set(bases)) < 2:
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
