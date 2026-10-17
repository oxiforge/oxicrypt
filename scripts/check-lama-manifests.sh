#!/usr/bin/env bash
#
# check-lama-manifests.sh [<revision>]
#
# Runs the LAMA conformance linter over every manifest in this repository and
# fails if any finding is reported. With no argument it reads the working tree;
# with a revision it reads that revision's tree, which is what the pre-push hook
# passes so the check applies to what is being published rather than to whatever
# happens to be checked out.
#
# Exit codes: 0 conformant · 1 findings, or the check could not be trusted ·
# 2 bun is not installed.
#
# ---------------------------------------------------------------------------
# Why this exists
#
# AGENTS.md already requires the manifest to move with any public-item change,
# and the pre-commit hook enforces it — but only that the file is STAGED, never
# that its content conforms. A manifest can be dutifully updated into prose that
# defeats the point of having one. This closes that gap mechanically.
#
# It then checks coverage with scripts/check-lama-coverage.ts: every public
# fn, struct, enum, union, trait, type alias, const and static of a publishable
# crate must have an entry in the full manifest, apart from the exclusions in
# the coverage rule in AGENTS.md and the items listed in
# docs/llm-api-manifest/coverage-baseline.txt. The baseline only shrinks: a
# line that no longer names an undocumented item fails the check, and so does
# a line the baseline at its merge base with origin/main (or $LAMA_BASE_REF)
# does not have. The scan reads source text and does not see items whose
# names come from macro arguments, so a green result is not proof that the
# manifest is complete.
#
# ---------------------------------------------------------------------------
# Three positive controls, because a linter that silently checks nothing
# produces output indistinguishable from one that checked everything and
# approved it.
#
#   1. Discovery must find manifests. A glob that matches nothing reports no
#      findings, which reads exactly like conformance.
#   2. The linter binary must match its recorded checksum. A vendored copy that
#      has been edited locally is no longer the upstream contract, and a
#      weakened rule set also reports no findings.
#   3. The output must carry the [strict] marker. Four of the six LAMA rules are
#      advisory and never move the exit code, so without strictness this gate
#      would enforce two rules while appearing to enforce six. The marker is
#      printed only when strictness actually took effect, so asserting it proves
#      the contract arrived rather than assuming it did.
# ---------------------------------------------------------------------------

set -uo pipefail

toplevel="$(git rev-parse --show-toplevel 2>/dev/null || true)"
# `cd ""` succeeds, so testing cd's status alone would not catch a failed
# rev-parse; the emptiness has to be tested directly.
if [[ -z "$toplevel" ]] || ! cd "$toplevel"; then
    echo "check-lama-manifests: FAILED — not inside a git repository." >&2
    exit 1
fi

rev="${1:-}"
linter='scripts/lama-validate.ts'
provenance='scripts/lama-validate.provenance'

if ! command -v bun >/dev/null 2>&1; then
    echo "check-lama-manifests: bun is not installed." >&2
    echo "  The LAMA conformance linter is a dependency-free TypeScript file and" >&2
    echo "  needs a bun runtime. See https://bun.sh — or skip this check only if" >&2
    echo "  your change does not touch a manifest." >&2
    exit 2
fi

# --- control 2: the linter is the one whose behaviour was recorded ------------
if [[ ! -f "$linter" || ! -f "$provenance" ]]; then
    echo "check-lama-manifests: FAILED — $linter or $provenance is missing." >&2
    echo "  A guard that silently disappears is the failure it exists to prevent." >&2
    exit 1
fi

expected_sha="$(sed -n 's/^sha256[[:space:]]*=[[:space:]]*//p' "$provenance" | tr -d '[:space:]')"
actual_sha="$(sha256sum "$linter" | cut -d' ' -f1)"
if [[ -z "$expected_sha" ]]; then
    echo "check-lama-manifests: FAILED — no sha256 recorded in $provenance." >&2
    exit 1
fi
if [[ "$expected_sha" != "$actual_sha" ]]; then
    echo "check-lama-manifests: FAILED — the vendored linter does not match its provenance." >&2
    echo "  recorded: $expected_sha" >&2
    echo "  actual:   $actual_sha" >&2
    echo "  The linter is a byte-identical copy of an upstream file and is not" >&2
    echo "  maintained here. If it was re-vendored deliberately, update $provenance;" >&2
    echo "  if it was edited locally, revert it and take the change upstream." >&2
    exit 1
fi

# --- collect the manifests ---------------------------------------------------
# Discovered, not hardcoded, so a manifest added later is gated without anyone
# remembering to add it here. Symlinks are skipped: several crate directories
# carry one pointing at the canonical manifest, and linting a file through each
# of its aliases reports the same findings repeatedly.
#
# Mode 120000 is a symlink in git's index and tree listings.
if [[ -n "$rev" ]]; then
    mapfile -t manifests < <(
        git ls-tree -r "$rev" 2>/dev/null \
            | awk '$1 != "120000" && $2 == "blob" { $1=""; $2=""; $3=""; sub(/^[ \t]+/, ""); print }' \
            | grep -E '(^|/)(lama\.yaml|llm-api[a-z-]*\.yaml)$' || true
    )
else
    mapfile -t manifests < <(
        git ls-files -s \
            | awk '$1 != "120000" { $1=""; $2=""; $3=""; sub(/^[ \t]+/, ""); print }' \
            | grep -E '(^|/)(lama\.yaml|llm-api[a-z-]*\.yaml)$' || true
    )
fi

# --- control 1: discovery found something ------------------------------------
if [[ "${#manifests[@]}" -eq 0 ]]; then
    echo "check-lama-manifests: FAILED — no manifests found${rev:+ in ${rev:0:12}}." >&2
    echo "  This repository has at least a root lama.yaml and a full manifest, so" >&2
    echo "  finding none means the discovery pattern is broken, not that the tree" >&2
    echo "  is clean. A search that matches nothing reports no findings." >&2
    exit 1
fi

# --- control 1b: every root file's manifest: pointer was discovered ----------
# Discovery is name-based, so it approves whatever it happens to match and is
# silent about what it does not. Renaming the full manifest to a name outside
# the pattern — llm-api.v2.yaml, api.yaml, lama.yml — leaves the root file
# pointing at a document this check never reads, while the remaining files
# still match and the run still reports success. Control 1 cannot catch that:
# the set is not empty, it is merely wrong.
#
# The root file names its manifest. Resolving that pointer and asserting it is
# in the checked set closes the gap and needs no second list to maintain.
for root in "${manifests[@]}"; do
    [[ "$(basename "$root")" == "lama.yaml" ]] || continue
    if [[ -n "$rev" ]]; then
        root_body="$(git show "$rev:$root" 2>/dev/null || true)"
    else
        root_body="$(cat "$root" 2>/dev/null || true)"
    fi
    # `manifest: path/to/file.yaml`, quoted or bare, relative to the repo root.
    #
    # Anchored at column 0 because that is where the root file writes the key,
    # and an unanchored match would let a nested `manifest:` under some other
    # mapping shadow the real pointer.
    #
    # The trailing comment and trailing whitespace have to come off before the
    # comparison. A perfectly valid `manifest: x.yaml  # the full one` would
    # otherwise fail to match any discovered path, and the failure would tell
    # the author their manifest had been renamed out of the discovery pattern —
    # sending them to fix something that is not wrong. A guard that cries wolf
    # gets disabled, so a false refusal is not a cheap kind of error to make.
    pointer="$(printf '%s\n' "$root_body" \
        | sed -n 's/^manifest:[[:space:]]*//p' \
        | sed -e 's/[[:space:]]*#.*$//' -e 's/[[:space:]]*$//' \
        | tr -d '"'"'" | head -1)"
    [[ -n "$pointer" ]] || continue
    pointer="${pointer#./}"

    # A root file that points at itself would satisfy the check while leaving
    # the full manifest unread — the control implementing itself out of a job.
    if [[ "$pointer" == "$root" ]]; then
        echo "check-lama-manifests: FAILED — $root's manifest: points at itself." >&2
        echo "  The root file is a discovery summary; the pointer must name the" >&2
        echo "  full manifest, or nothing verifies that the full manifest was read." >&2
        exit 1
    fi
    found=false
    for m in "${manifests[@]}"; do
        [[ "$m" == "$pointer" ]] && { found=true; break; }
    done
    if [[ "$found" != "true" ]]; then
        echo "check-lama-manifests: FAILED — $root points at a manifest this check did not read." >&2
        echo "  pointer:    $pointer" >&2
        echo "  discovered: ${manifests[*]}" >&2
        echo "  Discovery matches on filename, so a manifest renamed outside that" >&2
        echo "  pattern is silently skipped while the run still reports success." >&2
        echo "  Either restore the name, or widen the pattern in this script." >&2
        exit 1
    fi
done

# --- materialise the revision's copies, if reading a revision ----------------
workdir=''
cleanup() { [[ -n "$workdir" && -d "$workdir" ]] && rm -rf "$workdir"; }
trap cleanup EXIT

targets=()
if [[ -n "$rev" ]]; then
    workdir="$(mktemp -d)"
    for m in "${manifests[@]}"; do
        mkdir -p "$workdir/$(dirname "$m")"
        if ! git show "$rev:$m" >"$workdir/$m" 2>/dev/null; then
            echo "check-lama-manifests: FAILED — could not read $m at ${rev:0:12}." >&2
            exit 1
        fi
        targets+=("$workdir/$m")
    done
else
    targets=("${manifests[@]}")
fi

# --- run it ------------------------------------------------------------------
# LAMA_STRICT rather than the --strict flag: written one position too far left,
# `bun --strict <script>` is consumed by the runtime and never reaches the
# linter, and bun does not reject it — the command reads as correct, the exit
# code is 0, and the gate enforces nothing. An environment variable cannot be
# positionally misplaced.
output="$(LAMA_STRICT=1 bun "$linter" "${targets[@]}" 2>&1)"
status=$?

# Paths are printed as the temp copies when reading a revision; rewrite them
# back to repository-relative so the report names files a reader can open.
[[ -n "$workdir" ]] && output="${output//$workdir\//}"
echo "$output"

# --- control 3: strictness actually took effect ------------------------------
if [[ "$output" != *"[strict]"* ]]; then
    echo "check-lama-manifests: FAILED — the linter did not run in strict mode." >&2
    echo "  Without it, four of the six rules cannot move the exit code, so a" >&2
    echo "  clean result here would say nothing about them. Either the vendored" >&2
    echo "  linter no longer honours LAMA_STRICT, or it did not run at all." >&2
    exit 1
fi

if [[ $status -ne 0 ]]; then
    echo "check-lama-manifests: FAILED — ${#targets[@]} manifest(s) checked, findings above." >&2
    echo "  These manifests are held at zero findings, so a warning is a failure" >&2
    echo "  here even though the linter treats it as advisory by default." >&2
    exit 1
fi

# --- coverage ------------------------------------------------------------------
# Read from the same tree as the manifests: the working tree, or the revision
# being pushed, extracted with the coverage script and baseline it carries.
coverage='scripts/check-lama-coverage.ts'
if [[ -n "$rev" ]]; then
    if ! git cat-file -e "$rev:$coverage" 2>/dev/null; then
        # Absent at the revision: either it predates the script, or the
        # revision deletes it. Only the first may pass. A revision whose
        # history contains the script once had it.
        if [[ -n "$(git log -1 --format=%H "$rev" -- "$coverage" 2>/dev/null)" ]]; then
            echo "check-lama-manifests: FAILED — ${rev:0:12} deletes $coverage, which its history contains." >&2
            exit 1
        fi
        echo "check-lama-manifests: coverage SKIPPED for ${rev:0:12} — the revision predates $coverage."
        echo "check-lama-manifests: passed (${#targets[@]} manifest(s) at ${rev:0:12}, strict)."
        exit 0
    fi
    tree="$workdir/tree"
    mkdir -p "$tree"
    # The coverage roster is every workspace member, so extract the root
    # manifest and each member it lists at that revision.
    mapfile -t members < <(git show "$rev:Cargo.toml" \
        | awk '/^members = \[/{f=1;next} f&&/^\]/{exit} f' | grep -o '"[^"]*"' | tr -d '"')
    if [[ ${#members[@]} -eq 0 ]]; then
        echo "check-lama-manifests: FAILED — read no workspace members from ${rev:0:12}:Cargo.toml." >&2
        exit 1
    fi
    fixture_paths=()
    if git cat-file -e "$rev:scripts/fixtures/guard-sweep" 2>/dev/null; then
        fixture_paths=(scripts/fixtures/guard-sweep)
    fi
    if ! git archive "$rev" Cargo.toml "${members[@]}" docs/llm-api-manifest "$coverage" "${fixture_paths[@]}" | tar -x -C "$tree"; then
        echo "check-lama-manifests: FAILED — could not extract ${rev:0:12} for the coverage check." >&2
        exit 1
    fi
    cov_output="$(bun "$tree/$coverage" "$tree" 2>&1)"
    cov_status=$?
    cov_output="${cov_output//$tree\//}"
else
    if [[ ! -f "$coverage" ]]; then
        echo "check-lama-manifests: FAILED — $coverage is missing." >&2
        exit 1
    fi
    cov_output="$(bun "$coverage" . 2>&1)"
    cov_status=$?
fi
echo "$cov_output"
# The script prints "passed (N crates, M public items" only after scanning;
# a run that printed nothing, or crashed, must not read as coverage.
if [[ $cov_status -ne 0 || "$cov_output" != *"check-lama-coverage: passed ("* ]]; then
    echo "check-lama-manifests: FAILED — public items are missing from the manifest, or the coverage check did not complete." >&2
    echo "  Add an entry for each item named above, or for a stale baseline line" >&2
    echo "  delete it from docs/llm-api-manifest/coverage-baseline.txt." >&2
    exit 1
fi

# --- control 4: the guard sweep fails on its fixture ----------------------------
# The sweep above passes when every function it finds opens with the guard, and
# it would also pass if it found nothing it should. The fixture holds twelve
# functions the sweep must reject and seven it must not count; the rejected
# names must all appear and the ignored names must not. See
# scripts/fixtures/guard-sweep for what each one exercises.
fixture_root="${tree:-.}"
fixture="$fixture_root/scripts/fixtures/guard-sweep"
if [[ -d "$fixture" ]]; then
    fx_output="$(bun "$fixture_root/$coverage" --guard-sweep "$fixture" 12 2>&1)"
    fx_status=$?
    fx_expected='guard sweep found 12 guarded function(s), expected 12; 12 without the guard first.'
    fx_ok=true
    [[ $fx_status -eq 1 && "$fx_output" == *"$fx_expected"* ]] || fx_ok=false
    for name in derive_internal seal_internal expand_internal fixture_keygen_internal \
                after_slash_internal paren_form_internal lifetime_internal abi_internal \
                after_escaped_quote_internal spaced_bang_internal raw_ident_internal \
                raw_gen_internal; do
        [[ "$fx_output" == *" $name"* ]] || fx_ok=false
    done
    for name in commented_keygen_internal nested_phantom_internal string_phantom_internal \
                raw_phantom_internal commented_guarded_internal cstring_phantom_internal \
                craw_phantom_internal; do
        [[ "$fx_output" != *"$name"* ]] || fx_ok=false
    done
    if [[ "$fx_ok" != "true" ]]; then
        echo "$fx_output"
        echo "check-lama-manifests: FAILED — the guard sweep did not fail on its fixture as expected." >&2
        echo "  expected exit 1 and: $fx_expected" >&2
        echo "  A sweep that passes its fixture checks nothing." >&2
        exit 1
    fi
    echo "check-lama-manifests: the guard sweep fails on its fixture, as it must."
elif [[ -n "$rev" ]]; then
    # Absent at the revision: either it predates the fixture, or it deletes
    # it. Only the first may pass. A revision whose history contains the
    # fixture once had it.
    if [[ -n "$(git log -1 --format=%H "$rev" -- scripts/fixtures/guard-sweep 2>/dev/null)" ]]; then
        echo "check-lama-manifests: FAILED — ${rev:0:12} deletes scripts/fixtures/guard-sweep, which its history contains." >&2
        exit 1
    fi
    echo "check-lama-manifests: guard-sweep control SKIPPED for ${rev:0:12} — the revision predates its fixture."
else
    echo "check-lama-manifests: FAILED — $fixture is missing." >&2
    exit 1
fi

# --- the baseline only shrinks ---------------------------------------------------
# Every line of the baseline being checked must already be in the baseline at
# its merge base with the integration branch. Before the baseline exists there,
# there is nothing to compare against and the check says so.
baseline='docs/llm-api-manifest/coverage-baseline.txt'
base_ref="${LAMA_BASE_REF:-origin/main}"
if ! mb="$(git merge-base "${rev:-HEAD}" "$base_ref" 2>/dev/null)"; then
    echo "check-lama-manifests: FAILED — no merge base between ${rev:-HEAD} and $base_ref, so baseline growth" >&2
    echo "  cannot be checked. Fetch it (git fetch origin main) or set LAMA_BASE_REF." >&2
    exit 1
fi
if git cat-file -e "$mb:$baseline" 2>/dev/null; then
    if [[ -n "$rev" ]]; then
        now="$(git show "$rev:$baseline")"
    else
        now="$(cat "$baseline")"
    fi
    grown="$(comm -13 <(git show "$mb:$baseline" | grep -v '^#' | grep -v '^$' | LC_ALL=C sort -u) \
                      <(printf '%s\n' "$now" | grep -v '^#' | grep -v '^$' | LC_ALL=C sort -u))"
    if [[ -n "$grown" ]]; then
        echo "check-lama-manifests: FAILED — $baseline gained lines relative to ${mb:0:12} ($base_ref):" >&2
        printf '  %s\n' "$grown" >&2
        echo "  Document these items in the manifest instead." >&2
        exit 1
    fi
    echo "check-lama-manifests: the baseline has no line its merge base with $base_ref lacks."
else
    echo "check-lama-manifests: baseline growth not checked — $baseline is absent at the merge base ${mb:0:12} with $base_ref."
fi

echo "check-lama-manifests: passed (${#targets[@]} manifest(s)${rev:+ at ${rev:0:12}}, strict, coverage)."
