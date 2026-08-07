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
# What it does NOT check is coverage. A manifest can pass here with every rule
# clear and still omit an entire crate of the library it describes; that is a
# different question, answered by the roster invariant in AGENTS.md. A green
# result here must never be read as "the manifest is complete".
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

echo "check-lama-manifests: passed (${#targets[@]} manifest(s)${rev:+ at ${rev:0:12}}, strict)."
