#!/usr/bin/env python3
"""Group probe output across runs and report per-region verdicts.

Reads probe output on stdin, where each run's lines are prefixed `run<N> `.

Default mode reads `image-stability-probe` output. It prints a table, the
stable-byte total, and asserts both positive controls:

  1. load addresses actually differed across runs (else ASLR is not moving the
     image and a STABLE verdict means nothing);
  2. at least one region VARIES (else the probe cannot detect instability and a
     STABLE verdict is indistinguishable from a broken probe).

  --require SPEC   (repeatable) a region that must be present in every run,
                   STABLE and equal to the file. SPEC is a region name
                   (`__TEXT`, `.text`) or `perms@fileoff` (`r-xp@0xe5000`).
                   Required regions are the ones the extent types `Plain`
                   throughout; a region with loader-written words is typed by
                   `extent-v2-probe` instead.

  --typed N        read typed-probe output instead (ELF, Mach-O or PE), joined
                   by run id: runs run1..runN, each with one RESULT, one IMAGE
                   bias and the same summary lines, none with zero Plain
                   bytes; at least two distinct biases; every run passed with
                   the same typed byte counts.

  --bias-may-repeat
                   with --typed, accept one bias for every run. Windows
                   randomises a DLL's base once per boot, so the PE probe's
                   own control (a non-zero load delta that moved a relocated
                   word) stands in for the bias control there.

  --selftest       run each assertion against synthetic input that must pass
                   and against mutations of it that must fail.

Exit status: 0 every control and assertion holds; 1 the measured verdict
failed (a required region, a typed run); 2 a control failed, so no verdict
can be read; 3 the input could not be read or the script crashed. A green run
with no controls is exactly the failure this exists to stop.
"""
import collections
import sys
import traceback

PASS, VERDICT, CONTROL_FAILED, CRASHED = 0, 1, 2, 3


def parse_stability(lines):
    regions = collections.OrderedDict()
    bases = []
    runs = set()
    # Windows only: sections the base relocation table targets, name -> count.
    fixup_sections = {}
    per_run = collections.defaultdict(dict)
    for line in lines:
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
        if p[1] != "REGION":
            continue
        kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
        key = (kv.get("name", "-"), kv.get("perms", "?"), kv.get("fileoff", "?"), int(kv["size"]))
        regions.setdefault(key, {"mem": [], "cmp": []})
        regions[key]["mem"].append(kv.get("mem", ""))
        regions[key]["cmp"].append(kv.get("cmp", ""))
        per_run[run][key] = True
    return regions, bases, runs, fixup_sections, per_run


def spec_matches(spec, key):
    name, perms, off, _size = key
    if "@" in spec:
        want_perms, want_off = spec.split("@", 1)
        try:
            return perms == want_perms and int(off, 16) == int(want_off, 16)
        except ValueError:
            return False
    return name == spec


def stability(lines, required, out):
    regions, bases, runs, fixup_sections, per_run = parse_stability(lines)
    nruns = len(runs)
    out(f"runs: {nruns}   distinct load bases: {len(set(bases))}\n")
    out(f"{'segment':16} {'perms':6} {'fileoff':>10} {'size':>10} {'uniq':>5}  {'stable':7} {'mem==file'}")
    out("-" * 78)

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
        out(f"{name:16} {perms:6} {off:>10} {size:>10} {uniq:>5}  "
            f"{'STABLE' if is_stable else 'varies':7} {'/'.join(sorted(cmps))}")

    out("-" * 78)
    out(f"total loaded      : {total:,} bytes")
    if total:
        out(f"stable            : {stable:,} bytes ({100*stable/total:.2f}%)")
        out(f"stable AND ==file : {stable_and_matching:,} bytes ({100*stable_and_matching/total:.2f}%)")
        out("                    ^ this is the hashable region: build-time signer reads the file,")
        out("                      runtime verifier reads memory, same value.")

    out("")
    ok = True       # the required-region verdicts
    control = True  # the controls; a dead control voids the verdicts

    # Control 1 has two platform-appropriate forms, and picking the wrong one is
    # a correction rather than a relaxation. On per-process-ASLR platforms
    # (Linux, macOS) the test is that the load base moved across runs. Windows
    # randomises a DLL's base once per boot and reuses it for every process, so
    # that test can never fire there.
    #
    # The PE form asks instead whether relocations were actually APPLIED, which
    # is what a MATCH on the code section has to survive to mean anything.
    # Evidence: a base relocation table exists AND at least one section it
    # targets differs from the file. Fixups can only differ from the file image
    # if the loader wrote them.
    #
    # Reading the ImageBase field back from the loaded header and comparing it
    # with the actual base is not a control: the loader rewrites the field, so
    # that check cannot fail.
    if fixup_sections:
        targeted = [n for n, c in fixup_sections.items() if c > 0]
        differing = [
            name
            for (name, _perms, _off, _size), d in regions.items()
            if name in targeted and "DIFFER" in set(d["cmp"])
        ]
        total_fixups = sum(fixup_sections.values())
        if differing:
            out(f"control ok: {total_fixups} fixups present and {', '.join(differing)} differs from")
            out("            the file, so the loader demonstrably applied relocations")
        else:
            out(f"CONTROL FAILED: {total_fixups} fixups present but no targeted section "
                f"({', '.join(targeted) or 'none'}) differs")
            out("                from the file — cannot establish that relocations were applied,")
            out("                so a MATCH on the code section proves nothing.")
            control = False
    elif len(set(bases)) < 2:
        out("CONTROL FAILED: load base did not vary across runs — ASLR is not moving the image,")
        out("                so a STABLE verdict proves nothing.")
        control = False
    else:
        out(f"control ok: {len(set(bases))} distinct load bases across {nruns} runs")
    if not varies_seen:
        out("CONTROL FAILED: no region varied — the probe has not been shown capable of")
        out("                detecting instability, so STABLE is indistinguishable from broken.")
        control = False
    else:
        out("control ok: at least one region varied, so the probe detects instability")

    for spec in required:
        keys = [k for k in regions if spec_matches(spec, k)]
        if not keys:
            out(f"REQUIRED FAILED: {spec}: no such region")
            ok = False
            continue
        for key in keys:
            d = regions[key]
            present = sum(1 for r in runs if key in per_run[r])
            problems = []
            if present != nruns:
                problems.append(f"present in {present} of {nruns} runs")
            if len(set(d["mem"])) != 1:
                problems.append("varies across runs")
            if set(d["cmp"]) != {"MATCH"}:
                problems.append("differs from the file: " + "/".join(sorted(set(d["cmp"]))))
            if problems:
                out(f"REQUIRED FAILED: {spec} at fileoff {key[2]}: " + "; ".join(problems))
                ok = False
            else:
                out(f"required ok: {spec} at fileoff {key[2]}, {key[3]:,} bytes, STABLE and ==file")
    return CONTROL_FAILED if not control else (PASS if ok else VERDICT)




# The summary lines each typed probe prints, by format. A run set whose
# summaries match none of these is not a typed run of any probe.
FORMAT_SUMMARIES = {
    "elf": {"LOAD_SUMMARY", "DYNAMIC_SUMMARY", "RELRO_SUMMARY"},
    "macho": {"MACHO_SUMMARY"},
    "pe": {"PE_SUMMARY"},
}


def typed(lines, want_runs, out, bias_may_repeat=False):
    """Reads typed-probe output from want_runs runs, joined by run id.

    Every run run1..runN must have exactly one RESULT, one IMAGE bias and the
    same set of *_SUMMARY lines, each with non-zero Plain bytes; anything
    missing, extra or vacuous is a control failure, because records from
    different or incomplete runs must not combine into a pass. A run that did
    not pass, or typed byte counts that differ between runs, is the verdict.
    """
    runs = collections.defaultdict(lambda: {"result": [], "bias": [], "summary": {}})
    for line in lines:
        p = line.split()
        if len(p) < 2:
            continue
        run, tag = p[0], p[1]
        kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
        if tag == "RESULT":
            runs[run]["result"].append(kv.get("status"))
        elif tag == "IMAGE" and "bias" in kv:
            runs[run]["bias"].append(kv["bias"])
        elif tag.endswith("_SUMMARY"):
            if tag in runs[run]["summary"]:
                runs[run]["summary"][tag] = None  # a repeated summary is unusable
            else:
                runs[run]["summary"][tag] = tuple(sorted((k, v) for k, v in kv.items()
                                                         if k.startswith(("plain", "relative_ok", "holes", "bind_ok"))))
    want = {f"run{i}" for i in range(1, want_runs + 1)}
    control, ok = True, True
    out(f"typed runs: {len(runs)} (expected {want_runs})")
    if set(runs) != want:
        out(f"CONTROL FAILED: run ids {sorted(set(runs) - want)[:5]} unexpected, "
            f"{sorted(want - set(runs))[:5]} missing")
        control = False
    tags = None
    for run in sorted(want & set(runs)):
        r = runs[run]
        problems = []
        if len(r["result"]) != 1:
            problems.append(f"{len(r['result'])} RESULT lines")
        if len(r["bias"]) != 1:
            problems.append(f"{len(r['bias'])} IMAGE bias lines")
        if not r["summary"] or None in r["summary"].values():
            problems.append("no usable summary lines")
        else:
            if tags is None:
                tags = set(r["summary"])
            if set(r["summary"]) != tags:
                problems.append(f"summaries {sorted(r['summary'])}, other runs {sorted(tags)}")
            for tag, kv in r["summary"].items():
                plain = dict(kv).get("plain_bytes")
                if plain is None or int(plain) == 0:
                    problems.append(f"{tag} has no Plain bytes")
        if problems:
            out(f"CONTROL FAILED: {run}: " + "; ".join(problems))
            control = False
    fmt = next((f for f, need in FORMAT_SUMMARIES.items() if tags == need), None)
    if control and fmt is None:
        out(f"CONTROL FAILED: the runs' summaries {sorted(tags or [])} are not those of any typed probe "
            f"({', '.join(f'{f}: {sorted(n)}' for f, n in FORMAT_SUMMARIES.items())})")
        control = False
    if not control:
        return CONTROL_FAILED
    out(f"format: {fmt}")
    biases = {runs[r]["bias"][0] for r in want}
    out(f"distinct biases: {len(biases)}")
    if len(biases) < 2 and not bias_may_repeat:
        out("CONTROL FAILED: the load bias did not vary across runs, so a typed match proves nothing")
        return CONTROL_FAILED
    # bit 6 (setup) or bit 5 (the run's own control) means the run measured
    # nothing: a dead control, never a verdict
    void = sorted((r for r in want if (runs[r]["result"][0] or "").isdigit() and int(runs[r]["result"][0]) & 96),
                  key=lambda r: int(r[3:]))
    if void:
        shown = ", ".join(r + "=" + runs[r]["result"][0] for r in void[:5])
        out(f"CONTROL FAILED: {len(void)} run(s) report a setup failure or a dead control (status & 96): {shown}")
        return CONTROL_FAILED
    failed = sorted((r for r in want if runs[r]["result"][0] != "0"), key=lambda r: int(r[3:]))
    if failed:
        out(f"TYPED FAILED: {len(failed)} run(s) did not pass: {', '.join(failed[:10])}")
        ok = False
    shapes = {tuple(sorted((t, kv) for t, kv in runs[r]["summary"].items())) for r in want}
    if len(shapes) != 1:
        out(f"TYPED FAILED: the typed byte counts differ across runs ({len(shapes)} distinct)")
        ok = False
    if ok:
        flat = " ".join(f"{t}:{k}={v}" for t, kv in next(iter(shapes)) for k, v in kv)
        out(f"typed ok: every run passed with the same typed byte counts: {flat}")
    return PASS if ok else VERDICT


def selftest():
    def stab(run, base, regs, fixups=None):
        lines = [f"{run} LOADBASE {base} REGIONS {len(regs)}"]
        for name, perms, off, mem, cmp in regs:
            lines.append(f"{run} REGION name={name} perms={perms} fileoff={off} size=4096 mem={mem} file={mem} cmp={cmp}")
        for sec, n in (fixups or {}).items():
            lines.append(f"{run} RELOC section={sec} fixups={n}")
        return lines

    def good_stab(text_mem="aa", text_cmp="MATCH", drop_text_in=None, same_base=False, data_varies=True,
                  fixups=None, data_cmp="DIFFER"):
        lines = []
        for i, base in enumerate(["0x1000", "0x2000", "0x3000"]):
            run = f"run{i+1}"
            regs = [("__DATA", "rw-", "0x8000", f"d{i}" if data_varies else "dd", data_cmp)]
            if drop_text_in != run:
                regs.insert(0, ("__TEXT", "r-x", "0x0", text_mem if i == 0 else "aa", text_cmp))
            lines += stab(run, "0x1000" if same_base else base, regs, fixups)
        return lines

    def typed_lines(n=3, status1="0", same_bias=False, plain1="100", drop=None, extra=None):
        lines = []
        for i in range(n):
            run = f"run{i+1}"
            b = "0x7000" if same_bias else f"0x{7+i}000"
            rows = [("IMAGE", f"apk_base=0x0 bias={b}"),
                    ("LOAD_SUMMARY", f"plain_bytes={plain1 if i == 0 else '100'} differing=0"),
                    ("DYNAMIC_SUMMARY", "plain_bytes=40 relative_ok=7 holes=0"),
                    ("RELRO_SUMMARY", "plain_bytes=8 relative_ok=0"),
                    ("RESULT", f"status={status1 if i == 0 else '0'} PASS")]
            lines += [f"{run} {t} {v}" for t, v in rows if not (drop and drop == (run, t))]
        return lines + (extra or [])

    q = lambda _s: None
    cases = [
        ("stability, required region present and stable", stability(good_stab(), ["__TEXT"], q), PASS),
        ("stability, required region varies", stability(good_stab(text_mem="bb"), ["__TEXT"], q), VERDICT),
        ("stability, required region differs from the file", stability(good_stab(text_cmp="DIFFER"), ["__TEXT"], q), VERDICT),
        ("stability, required region missing from one run", stability(good_stab(drop_text_in="run2"), ["__TEXT"], q), VERDICT),
        ("stability, required region absent", stability(good_stab(), ["__LINKEDIT"], q), VERDICT),
        ("stability, required by perms@fileoff", stability(good_stab(), ["r-x@0x0"], q), PASS),
        ("stability, load base did not move", stability(good_stab(same_base=True), [], q), CONTROL_FAILED),
        ("stability, no region varies", stability(good_stab(data_varies=False), [], q), CONTROL_FAILED),
        ("stability, PE form: a targeted section differs",
         stability(good_stab(same_base=True, fixups={"__DATA": 4}), [], q), PASS),
        ("stability, PE form: no targeted section differs",
         stability(good_stab(same_base=True, fixups={"__DATA": 4}, data_cmp="MATCH"), [], q), CONTROL_FAILED),
        ("stability, no input at all", stability([], [], q), CONTROL_FAILED),
        ("typed, three passing runs", typed(typed_lines(), 3, q), PASS),
        ("typed, one run failed", typed(typed_lines(status1="1"), 3, q), VERDICT),
        ("typed, one run's setup failed", typed(typed_lines(status1="64"), 3, q), CONTROL_FAILED),
        ("typed, one run's own control dead", typed(typed_lines(status1="36"), 3, q), CONTROL_FAILED),
        ("typed, bias never moved", typed(typed_lines(same_bias=True), 3, q), CONTROL_FAILED),
        ("typed, bias never moved where it may repeat", typed(typed_lines(same_bias=True), 3, q, True), PASS),
        ("typed, counts differ across runs", typed(typed_lines(plain1="99"), 3, q), VERDICT),
        ("typed, a run missing", typed(typed_lines(), 4, q), CONTROL_FAILED),
        ("typed, a run without its IMAGE line", typed(typed_lines(drop=("run2", "IMAGE")), 3, q), CONTROL_FAILED),
        ("typed, a run without its RESULT line", typed(typed_lines(drop=("run3", "RESULT")), 3, q), CONTROL_FAILED),
        ("typed, a run without one summary", typed(typed_lines(drop=("run1", "RELRO_SUMMARY")), 3, q), CONTROL_FAILED),
        ("typed, zero Plain bytes in every run", typed(typed_lines(plain1="0"), 3, q), CONTROL_FAILED),
        ("typed, a stray run id", typed(typed_lines(extra=["run9 RESULT status=0 PASS"]), 3, q), CONTROL_FAILED),
        ("typed, a second RESULT for one run", typed(typed_lines(extra=["run1 RESULT status=0 PASS"]), 3, q), CONTROL_FAILED),
        ("typed, twenty runs with only an unrelated summary",
         typed([f"run{i} {t}" for i in range(1, 21) for t in
                (f"IMAGE bias=0x{i}000", "FOO_SUMMARY plain_bytes=1", "RESULT status=0 PASS")], 20, q), CONTROL_FAILED),
        ("typed, Mach-O runs", typed([f"run{i} {t}" for i in range(1, 4) for t in
                (f"IMAGE bias=0x{i}000", "MACHO_SUMMARY plain_bytes=9 relative_ok=4", "RESULT status=0 PASS")], 3, q), PASS),
        ("typed, ELF runs missing RELRO_SUMMARY in every run",
         typed([l for l in typed_lines() if "RELRO_SUMMARY" not in l], 3, q), CONTROL_FAILED),
    ]
    bad = 0
    for name, got, want in cases:
        verdict = "ok" if got == want else "MISMATCH"
        bad += got != want
        print(f"{verdict:8} expected {want}, got {got}: {name}")
    return bad == 0


def main(argv):
    required = []
    typed_runs = None
    bias_may_repeat = False
    i = 0
    while i < len(argv):
        if argv[i] == "--require" and i + 1 < len(argv):
            required.append(argv[i + 1])
            i += 2
        elif argv[i] == "--typed" and i + 1 < len(argv):
            typed_runs = int(argv[i + 1])
            i += 2
        elif argv[i] == "--bias-may-repeat":
            bias_may_repeat = True
            i += 1
        elif argv[i] == "--selftest":
            return PASS if selftest() else CONTROL_FAILED
        else:
            print(f"unknown argument {argv[i]}", file=sys.stderr)
            return CRASHED
    lines = sys.stdin.read().splitlines()
    if typed_runs is not None:
        return typed(lines, typed_runs, print, bias_may_repeat)
    return stability(lines, required, print)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:  # a crash must never read as a verdict
        traceback.print_exc()
        print("CRASHED: analyse.py")
        sys.exit(CRASHED)
