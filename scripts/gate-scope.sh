#!/usr/bin/env bash
# Decide which optional gates a change needs, in one place.
#
# Prints `key=value` lines suitable for appending to $GITHUB_OUTPUT, and the
# same lines are readable by a human or by the pre-push hook:
#
#   rust=true|false      any Rust-relevant path changed
#   maxwell=true|false   anything oxicrypt-maxwell is BUILT FROM changed
#
# Why a script rather than a `paths:` filter in the workflow, or a second copy
# of the regexes in YAML:
#
#   * A required check skipped by GitHub's `paths:` filter never reports at all
#     — it sits at Pending and blocks the pull request forever. The supported
#     shape is for the job to always run and force-pass inside a step, which
#     needs a value it can test, which is what this prints.
#
#   * `scripts/git-hooks/pre-push` makes the identical decision locally. Two
#     copies of a fail-closed rule drift, and the drift is silent in the
#     dangerous direction: a widened local skip that CI does not share reads as
#     a passing push. One file, two callers.
#
# Usage:
#   scripts/gate-scope.sh <base-ref> [head-ref]
#   scripts/gate-scope.sh                # no refs: everything is in scope
#
# FAIL-CLOSED IN EVERY DIRECTION. An absent base, an unresolvable ref, a diff
# that cannot be computed, or a changed crate this file has never heard of all
# resolve to `true`. The cost of a wrong `true` is wall-clock; the cost of a
# wrong `false` is an ungated change. Those are not comparable, and the code
# below never treats them as if they were.

set -uo pipefail

base="${1:-}"
head="${2:-HEAD}"

emit() {
    echo "rust=$1"
    echo "maxwell=$2"
    [ -n "${3:-}" ] && echo "reason=$3"
    exit 0
}

# No base to compare against — a manual dispatch, a fresh clone, an orphan
# branch. Everything is in scope; say why, so a full run is never mistaken for
# a considered decision.
if [ -z "$base" ]; then
    emit true true "no base ref supplied; nothing to narrow against"
fi

if ! git rev-parse --verify --quiet "$base" >/dev/null; then
    emit true true "base ref '$base' does not resolve in this clone"
fi

merge_base="$(git merge-base "$base" "$head" 2>/dev/null || true)"
if [ -z "$merge_base" ]; then
    # Deliberately NOT falling back to `git diff <base>`, which compares against
    # the WORKING TREE and answers a different question — truthfully, which is
    # what makes it dangerous.
    emit true true "no merge base between '$base' and '$head'"
fi

changed="$(git diff --name-only "$merge_base" "$head" 2>/dev/null)"
if [ $? -ne 0 ]; then
    emit true true "could not compute the diff"
fi

# An empty diff is a real answer, not a failure: nothing changed, so no
# optional gate can observe anything.
if [ -z "$changed" ]; then
    emit false false "no files changed between the merge base and the head"
fi

# Rust-relevance. A path-prefix proxy, deliberately coarse: a `.toml` under
# crates/ can change a build output (cbindgen.toml regenerates a shipped
# header), so narrowing this to `*.rs` would open a real hole to save minutes.
rust_re='^(crates|benches|acvp-harness|esv-harness|oxi|tools|playground)/|^Cargo\.(toml|lock)$|^rust-toolchain\.toml$|^rustfmt\.toml$|^\.cargo/'

# oxicrypt-maxwell's dependency closure, from `cargo metadata` on 2026-08-04:
# itself plus module, sha, test-vectors and zeroize. Manifests, the lockfile,
# the toolchain pin and .cargo config are in it too — a codegen or toolchain
# change moves floating-point results, which is exactly what a <=1e-6 parity
# bound is sensitive to.
maxwell_closure_re='^crates/oxicrypt-(maxwell|module|sha|test-vectors|zeroize)/|^Cargo\.(toml|lock)$|^rust-toolchain\.toml$|^rustfmt\.toml$|^\.cargo/'

# The workspace inventory as it stood when this was written. A changed
# `crates/<name>/` path outside it is a crate this file has never seen, so it is
# treated as INSIDE the closure. Adding a crate therefore costs a full run until
# someone extends this list — it can never silently widen a skip.
known_crates_re='^crates/oxicrypt-(aes|aes-accel|cmac|dh|drbg|ecdh|ecdsa|eddsa|entropy|ffi|hmac|integrity|kdf|keccak-accel|lms|maxwell|ml-dsa|ml-kem|module|rsa|sha|sha-accel|slh-dsa|test-vectors|timer|tls-kdf|xmss|xof|zeroize)/'

rust=false
maxwell=false
unknown_crate=false

while IFS= read -r f; do
    [ -z "$f" ] && continue
    grep -qE "$rust_re" <<<"$f" && rust=true
    grep -qE "$maxwell_closure_re" <<<"$f" && maxwell=true
    case "$f" in
        crates/*) grep -qE "$known_crates_re" <<<"$f" || unknown_crate=true ;;
    esac
done <<<"$changed"

if [ "$unknown_crate" = true ]; then
    emit true true "a changed crates/ path is outside the known workspace inventory"
fi

emit "$rust" "$maxwell" "computed from $(wc -l <<<"$changed") changed path(s)"
