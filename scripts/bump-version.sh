#!/usr/bin/env bash
# Bump every version literal in the workspace, and the changelog heading.
#
# Three files carry the version as a literal string, and they are easy to edit
# individually and get wrong — a stale `lama.yaml` or `llm-api.yaml` version is
# invisible until an agent reads a manifest that claims to describe a release it
# does not describe. This script is the single place that number changes.
#
#   ./scripts/bump-version.sh 0.21.0
#   ./scripts/bump-version.sh 0.21.0 --date 2026-08-05   # override the date
#   ./scripts/bump-version.sh 0.21.0 --check             # report, change nothing
#
# What it touches:
#   Cargo.toml                          [workspace.package] version
#   docs/llm-api-manifest/llm-api.yaml  library.version
#   lama.yaml                           library.version
#   CHANGELOG.md                        `## [Unreleased]` -> `## [X.Y.Z] - DATE`
#
# It does NOT commit, tag, or push. Releases stay deliberate acts; see
# CONTRIBUTING.md § Releases.

set -euo pipefail

die() { echo "bump-version: $*" >&2; exit 1; }

[[ $# -ge 1 ]] || die "usage: bump-version.sh X.Y.Z [--date YYYY-MM-DD] [--check]"

new="$1"; shift
date_stamp=""
check_only=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --date)  [[ $# -ge 2 ]] || die "--date needs a value"; date_stamp="$2"; shift 2 ;;
        --check) check_only=true; shift ;;
        *)       die "unknown argument: $1" ;;
    esac
done

# Semver, no fourth component. The retired `.A` internal-build scheme was
# git-tag-only precisely because Cargo.toml cannot hold one.
[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
    || die "'$new' is not a semver X.Y.Z (optionally -prerelease)"

cd "$(git rev-parse --show-toplevel)" || die "not inside a git work tree"

CARGO=Cargo.toml
LLM=docs/llm-api-manifest/llm-api.yaml
LAMA=lama.yaml
CHANGELOG=CHANGELOG.md
for f in "$CARGO" "$LLM" "$LAMA" "$CHANGELOG"; do
    [[ -f "$f" ]] || die "missing $f — run from the oxicrypt workspace"
done

# Read the current version from the one authoritative place.
old="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$CARGO" | head -1)"
[[ -n "$old" ]] || die "could not read [workspace.package] version from $CARGO"

echo "bump-version: $old -> $new"
[[ "$old" == "$new" ]] && echo "bump-version: NOTE — already at $new; rewriting anyway to catch drifted files."

if [[ "$check_only" == "true" ]]; then
    echo "--- --check: no files written ---"
    grep -nE "version.*\"?${old//./\\.}\"?" "$CARGO" "$LLM" "$LAMA" || true
    grep -n '^## \[Unreleased\]' "$CHANGELOG" || echo "  ($CHANGELOG has no [Unreleased] heading)"
    exit 0
fi

# Each edit asserts its anchor matched EXACTLY ONCE before writing. A pattern
# that silently matches nothing leaves a stale literal behind and looks
# identical to a successful bump; a pattern that matches twice rewrites
# something it was never meant to.
bump_one() { # $1=file  $2=sed-address-pattern  $3=human name
    local file="$1" pattern="$2" what="$3" hits
    hits="$(grep -cE "$pattern" "$file" || true)"
    [[ "$hits" -eq 1 ]] || die "$what: pattern matched $hits times in $file (need exactly 1) — refusing to write"
    perl -i -pe "s/\Q$old\E/$new/ if /$pattern/" "$file"
    grep -qF "$new" "$file" || die "$what: rewrite did not take in $file"
    echo "  ok  $file  ($what)"
}

bump_one "$CARGO" "^version = \"${old//./\\.}\"" "[workspace.package] version"
bump_one "$LLM"   "^  version: \"${old//./\\.}\"" "llm-api manifest version"
bump_one "$LAMA"  "^  version: \"${old//./\\.}\"" "lama manifest version"

# Changelog: rename the Unreleased heading and open a fresh one above it.
if grep -q '^## \[Unreleased\]' "$CHANGELOG"; then
    stamp="${date_stamp:-$(date +%F)}"
    [[ "$stamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "--date '$stamp' is not YYYY-MM-DD"
    # Rewrite only the FIRST occurrence. A `!$done++` guard in a per-line filter
    # is self-consuming — it fires on line 1 and is false by the time the heading
    # arrives — so the flag is set inside the match, not beside it.
    python3 - "$CHANGELOG" "$new" "$stamp" <<'PY'
import sys
path, new, stamp = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
old_head = "## [Unreleased]\n"
if s.count(old_head) != 1:
    sys.exit(f"changelog: '## [Unreleased]' appears {s.count(old_head)} times (need exactly 1)")
s = s.replace(old_head, f"## [Unreleased]\n\n## [{new}] - {stamp}\n", 1)
open(path, "w").write(s)
PY
    grep -q "^## \[$new\] - $stamp\$" "$CHANGELOG" || die "changelog heading rewrite did not take"
    echo "  ok  $CHANGELOG  (## [$new] - $stamp, fresh [Unreleased] above it)"
else
    echo "  --  $CHANGELOG  (no [Unreleased] heading; left alone)"
fi

# Positive control on the whole operation: no stale literal may survive outside
# Cargo.lock, which cargo regenerates. Reporting success while a file still
# carries the old number is the failure this script exists to prevent.
echo "bump-version: checking for surviving '$old' literals..."
stale="$(git grep -nF "$old" -- ':!Cargo.lock' ':!CHANGELOG.md' || true)"
if [[ -n "$stale" ]]; then
    echo "$stale" >&2
    die "stale '$old' literals survive (listed above) — the bump is incomplete"
fi
echo "bump-version: clean. Run 'cargo update --workspace' to refresh Cargo.lock, then commit."
