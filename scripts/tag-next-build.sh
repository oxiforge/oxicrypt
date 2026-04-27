#!/usr/bin/env bash
#
# tag-next-build.sh — compute and apply the next internal-build tag.
#
# Convention (per CONTRIBUTING.md "Versioning and tagging"):
#   - Releases tag `vX.Y.Z`              (no suffix; published to crates.io)
#   - Internal builds tag `vX.Y.Z.A`     (git-tag-only; A increments per PR)
#   - A resets to 1 when X.Y.Z changes
#   - X.Y.Z is read from `[workspace.package].version` in Cargo.toml
#
# Usage:
#   bash scripts/tag-next-build.sh             # apply next tag locally; print push command
#   bash scripts/tag-next-build.sh --push      # apply + push immediately
#   bash scripts/tag-next-build.sh --dry-run   # print what the next tag would be; do not apply
#
# Run after a PR squash-merges to main and you've pulled origin/main.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Read X.Y.Z from [workspace.package].version. Fall back to top-level
# [package].version if the workspace block doesn't carry it.
read_version() {
  awk '
    /^\[workspace\.package\][[:space:]]*$/ { in_section = 1; next }
    /^\[/                                  { in_section = 0 }
    in_section && /^[[:space:]]*version[[:space:]]*=/ {
      # Strip everything except digits and dots.
      gsub(/[^0-9.]/, "", $0)
      print
      exit
    }
  ' Cargo.toml
}

read_top_level_version() {
  awk '
    /^\[package\][[:space:]]*$/ { in_section = 1; next }
    /^\[/                       { in_section = 0 }
    in_section && /^[[:space:]]*version[[:space:]]*=/ {
      gsub(/[^0-9.]/, "", $0)
      print
      exit
    }
  ' Cargo.toml
}

VERSION="$(read_version)"
if [[ -z "$VERSION" ]]; then
  VERSION="$(read_top_level_version)"
fi

if [[ -z "$VERSION" ]]; then
  echo "ERROR: could not read version from Cargo.toml" >&2
  echo "       Looked for [workspace.package].version and [package].version" >&2
  exit 1
fi

# Find highest existing .A for this X.Y.Z. Tags that are exactly
# `vX.Y.Z` (no suffix) don't count as internal builds.
LAST_A="$(
  git tag --list "v${VERSION}.*" \
    | sed -n "s/^v${VERSION//./\\.}\.\([0-9][0-9]*\)\$/\1/p" \
    | sort -n \
    | tail -1
)"

NEXT_A=$(( ${LAST_A:-0} + 1 ))
NEXT_TAG="v${VERSION}.${NEXT_A}"

# Sanity check the working state.
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "main" ]]; then
  echo "WARNING: not on main (currently on '$BRANCH')." >&2
  echo "         Internal-build tags should mark commits on main." >&2
fi

if ! git diff-index --quiet HEAD --; then
  echo "WARNING: working tree has uncommitted changes." >&2
  echo "         The tag will mark HEAD as it stands now." >&2
fi

CURRENT_SHA="$(git rev-parse HEAD)"

echo "Workspace version (Cargo.toml): $VERSION"
echo "Highest existing .A for ${VERSION}: ${LAST_A:-(none)}"
echo "Next internal-build tag:        $NEXT_TAG"
echo "Tagging commit:                 $CURRENT_SHA"
echo

case "${1:-}" in
  --dry-run)
    echo "Dry run: would create tag $NEXT_TAG. No changes made."
    exit 0
    ;;
  --push)
    git tag "$NEXT_TAG" "$CURRENT_SHA"
    git push origin "$NEXT_TAG"
    echo "Pushed: $NEXT_TAG"
    ;;
  "")
    git tag "$NEXT_TAG" "$CURRENT_SHA"
    echo "Tag applied locally. Push with:"
    echo "  git push origin $NEXT_TAG"
    ;;
  *)
    echo "ERROR: unrecognized flag '$1'" >&2
    echo "Usage: $0 [--push | --dry-run]" >&2
    exit 2
    ;;
esac
