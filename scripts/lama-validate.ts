#!/usr/bin/env bun
// lama-validate — a dependency-free LAMA conformance linter.
//
// Checks a LAMA manifest (root `lama.yaml` or a full `docs/.../llm-api.yaml`)
// against the machine-checkable rules in the LAMA spec — chiefly Design
// Principle #2 (declarative, not narrative): `description:` is one line, the
// `families:` legend carries no member lists, and the root file is a concise
// summary + pointer, not the full manifest.
//
// Zero npm dependencies — the conformance rules are text-pattern checks, so it
// runs with nothing but `bun`. Usage:
//     bun lama-validate.ts [--strict] <manifest.yaml> [<manifest.yaml> ...]
//
// Exit code 1 if any ERROR is found, 0 otherwise.
//
// `--strict` (or `LAMA_STRICT=1` in the environment) also exits 1 on WARN.
// Four of the six rules are advisory by default because they encode a
// stylistic preference the spec states as a preference — a manifest that trips
// them is still a valid manifest. An adopter wiring this into a gate wants the
// opposite default: having reached zero findings, they want to stay there.
// Without it, such a gate enforces only the two ERROR rules while appearing to
// enforce all six, because the other four never move the exit code.
//
// The environment variable exists because the flag can be swallowed before it
// ever arrives. `bun --strict lama-validate.ts f.yaml` — the flag one position
// too far left — is consumed by the runtime, not passed on, and bun does not
// reject it. The command reads as correct, warnings still print, and the exit
// code is 0: a silently vacuous gate, which is the exact failure this option
// was added to prevent. An env var cannot be positionally misplaced.
//
// The total line prints [strict] only when strictness actually took effect, so
// a gate can assert that substring and hold a positive control on its own
// contract rather than trusting that the request arrived.

type Severity = "ERROR" | "WARN";
interface Finding {
  file: string;
  line: number;
  rule: string;
  severity: Severity;
  message: string;
  snippet: string;
}

// `used to` is deliberately narrowed to its historical sense. The bare phrase
// also matches the present tense of purpose — "a parameter used to select the
// cutoff" — which states what something does rather than what it once was, and
// is exactly the kind of description this rule should leave alone. `previously`
// and `formerly` already catch the historical reading directly, so the bare
// phrase was carrying almost nothing the pattern did not otherwise have.
//
// A false positive matters more here than it did before `--strict`: an advisory
// rule that is occasionally wrong is lived with, while one that fails a push
// gets the gate switched off.
const NARRATIVE =
  /\b(because|so that|in order to|the reason|previously|formerly|used to\s+(?:be|been|have|do)\b|replaces?|mirrors?|analogous to|the request half of|same as|note that|see\s+\S+\s+for)\b/i;

const FAMILY_MEMBERLIST =
  /\bCovers\b|\b(?:two|three|four|five|six|seven|eight|nine|ten|\d+)\s+\w+\s+(?:variants?|entries|functions?|types?)\b/i;

function unquote(v: string): string {
  const t = v.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")))
    return t.slice(1, -1);
  return t;
}

// Multi-sentence heuristic: a single sentence has no internal ". <Capital>".
// Tolerant of "Rev. 2"/"No. 3" (digit follows) — only a capital letter starts a new sentence.
function isMultiSentence(v: string): boolean {
  const m = v.match(/[.!?]\s+[A-Z(]/g);
  return !!m && m.length >= 1;
}

function detectMode(lines: string[]): "root" | "full" | "unknown" {
  const top = new Set(lines.filter((l) => /^[a-z_]+:/.test(l)).map((l) => l.split(":")[0]));
  // Root is tested FIRST, on its own positive signal. Testing the
  // full-manifest signal first meant a root file that wrongly carried
  // `functions:` was classified "full", so R-ROOTFULL — the rule whose whole
  // job is catching exactly that — could never fire on it.
  if (top.has("capabilities") && top.has("manifest")) return "root";
  if (top.has("functions") || top.has("types")) return "full";
  return "unknown";
}

function validate(file: string): Finding[] {
  const text = require("fs").readFileSync(file, "utf8");
  const lines: string[] = text.split("\n");
  const findings: Finding[] = [];
  const add = (line: number, rule: string, severity: Severity, message: string, snippet: string) =>
    findings.push({ file, line, rule, severity, message, snippet: snippet.trim().slice(0, 100) });

  const mode = detectMode(lines);
  let inFamilies = false;

  lines.forEach((raw, i) => {
    const ln = i + 1;

    // track the families: block (top-level key → next top-level key)
    if (/^families:/.test(raw)) inFamilies = true;
    else if (/^[a-z_]+:/.test(raw)) inFamilies = false;

    // block-scalar description → violates the one-line rule
    const block = raw.match(/^(\s*)description:\s*[|>]/);
    if (block) {
      add(ln, "R-BLOCKDESC", "ERROR", "description must be one line, not a block scalar", raw);
      return;
    }

    // single-line description (key form, not inline flow params)
    const single = raw.match(/^(\s*)description:\s*(\S.*)$/);
    if (single) {
      const val = unquote(single[2]);
      if (inFamilies) {
        if (FAMILY_MEMBERLIST.test(val))
          add(ln, "R-FAMILYLIST", "WARN", "families description must not enumerate members/counts", val);
      } else {
        if (isMultiSentence(val))
          add(ln, "R-MULTISENT", "WARN", "description should be a single declarative sentence", val);
        if (NARRATIVE.test(val))
          add(ln, "R-NARRATIVE", "WARN", "description carries narrative/rationale; state the fact", val);
      }
    }

    // root-file specific
    if (mode === "root" && /^(functions|types|parameters|error_variants):/.test(raw))
      add(ln, "R-ROOTFULL", "ERROR", "root lama.yaml is a summary+pointer; full-manifest entries belong in the manifest", raw);
  });

  if (mode === "unknown")
    add(1, "R-MODE", "WARN", "could not detect root vs full manifest (missing functions:/capabilities:+manifest:)", "");

  return findings;
}

// ── main ──
const argv = process.argv.slice(2);
const envStrict = /^(1|true|yes)$/i.test(process.env.LAMA_STRICT ?? "");
const strict = argv.includes("--strict") || envStrict;
const unknownFlag = argv.find((a) => a.startsWith("-") && a !== "--strict");
if (unknownFlag) {
  console.error(`unknown flag: ${unknownFlag}`);
  console.error("usage: bun lama-validate.ts [--strict] <manifest.yaml> [...]");
  process.exit(2);
}
const files = argv.filter((a) => a !== "--strict");
if (files.length === 0) {
  console.error("usage: bun lama-validate.ts [--strict] <manifest.yaml> [...]");
  process.exit(2);
}

let errors = 0,
  warns = 0;
for (const file of files) {
  const found = validate(file);
  const errs = found.filter((f) => f.severity === "ERROR");
  const wrns = found.filter((f) => f.severity === "WARN");
  errors += errs.length;
  warns += wrns.length;
  const mode = detectMode(require("fs").readFileSync(file, "utf8").split("\n"));
  console.log(`\n${file}  [${mode} manifest]  ${errs.length} error(s), ${wrns.length} warning(s)`);
  for (const f of found)
    console.log(`  ${f.severity === "ERROR" ? "✗" : "·"} ${f.file}:${f.line}  ${f.rule}  ${f.message}\n      | ${f.snippet}`);
  if (found.length === 0) console.log("  ✓ conformant");
}

console.log(
  `\n── total: ${errors} error(s), ${warns} warning(s)${strict ? " [strict]" : ""} ──`,
);
process.exit((strict ? errors + warns : errors) > 0 ? 1 : 0);
