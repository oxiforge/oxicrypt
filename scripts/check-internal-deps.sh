#!/usr/bin/env bash
# Assert that internal dependencies are declared so the workspace can be
# published (#196).
#
# A path-only dependency cannot be packaged: `cargo package` strips the path
# and records a registry requirement, which needs a version. The inverse holds
# for dev-dependencies: cargo DROPS a path-only dev-dependency when packaging,
# so giving one a version turns it into a real registry requirement that no
# first publish can satisfy — and `oxicrypt-sha` and `oxicrypt-keccak-accel`
# dev-depend on each other, so a version there is an unbreakable cycle.
#
#   normal / build dependency on a workspace member -> MUST carry a version
#   dev dependency on a workspace member            -> MUST NOT carry a version
#
# Why `cargo metadata` and not a manifest parser: TOML has many spellings of
# the same declaration -- `[dependencies.foo]` sub-tables, multi-line inline
# tables, `version="x"` without spaces, `package = "..."` renames, a trailing
# comment on a section header. A line-oriented parser silently misses whichever
# form it was not written for, and a guard that silently stops guarding is
# worse than none (the failure this repo tracks as #283). `cargo metadata` is
# the resolver itself, so every spelling arrives here already normalised, and a
# newly added crate is covered the moment it joins the workspace rather than
# when someone remembers to list it.
#
# `--offline`: this reads the workspace's own structure and never needs the
# registry, so the gate does not depend on network reachability.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Name the missing tool. Without this the script dies at 127 and the caller
# reports "internal dependencies are not publishable", which is a false
# diagnosis of a correct workspace — the reader then goes looking for a
# manifest defect that does not exist.
for tool in cargo jq; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "check-internal-deps: '$tool' is not on PATH — see CONTRIBUTING.md § Prerequisites." >&2
        echo "check-internal-deps:   This is a missing tool, NOT a finding about the workspace." >&2
        exit 2
    }
done

meta="$(cargo metadata --format-version 1 --no-deps --offline)"

members="$(jq -r '[.packages[].name] | sort | join(" ")' <<<"$meta")"
member_count="$(jq -r '.packages | length' <<<"$meta")"

# A path dependency with no version requirement resolves to `*`; one carrying a
# version resolves to a real requirement such as a caret range. `kind` is null for
# a normal dependency, "dev" or "build" otherwise.
#
# Selection is by NAME, not by the presence of a path. Filtering on `path` would
# skip a dependency on a workspace member declared registry-style
# (`oxicrypt-sha = "<version>"`) — which is exactly the "drop the path, keep the
# version" mistake, and as a dev-dependency it is the unsatisfiable requirement
# this script exists to catch. Out-of-workspace path dependencies are selected
# too, because a path dependency of any kind without a version cannot be
# packaged.
report="$(jq -r --arg members "$members" '
  ($members | split(" ")) as $m
  | .packages[] as $pkg
  | $pkg.dependencies[]
  | select((.name as $n | $m | index($n)) or .path != null)
  | [$pkg.name, .name, (.kind // "normal"), .req,
     (if (.name as $n | $m | index($n)) then "member" else "external" end)] | @tsv
' <<<"$meta")"

examined="$(grep -c . <<<"$report" || true)"

# Positive control. A jq filter that matches nothing produces an empty report,
# which is indistinguishable from "everything is fine" -- the exact failure this
# script exists to prevent elsewhere. Both numbers must be plausible before any
# clean verdict is believed.
if [[ "$member_count" -lt 2 ]]; then
    echo "check-internal-deps: cargo metadata reported $member_count package(s) — the workspace was not read" >&2
    exit 2
fi
if [[ "$examined" -eq 0 ]]; then
    echo "check-internal-deps: examined 0 internal dependencies across $member_count members — the filter matched nothing, so a clean result here would mean nothing" >&2
    exit 2
fi

bad=""
while IFS=$'\t' read -r pkg dep kind req origin; do
    [[ -n "$pkg" ]] || continue
    if [[ "$origin" == "external" ]]; then
        # A path dependency outside the workspace. It cannot be packaged
        # without a version, and no `[workspace.dependencies]` entry covers it.
        [[ "$req" != "*" ]] || bad+="  $pkg: $kind dependency $dep is a path dependency outside the workspace with no version requirement"$'\n'
    elif [[ "$kind" == "dev" ]]; then
        [[ "$req" == "*" ]] || bad+="  $pkg: dev-dependency $dep carries version requirement '$req' — must be path-only"$'\n'
    else
        [[ "$req" != "*" ]] || bad+="  $pkg: $kind dependency $dep has no version requirement — declare it '{ workspace = true }'"$'\n'
    fi
done <<<"$report"

if [[ -n "$bad" ]]; then
    echo "check-internal-deps: the workspace cannot be published as declared:" >&2
    printf '%s' "$bad" >&2
    echo "see AGENTS.md § Internal dependencies and packaging" >&2
    exit 1
fi

# A crate destined for crates.io must not depend on one that never goes there:
# every dependency of a published crate has to exist on the registry, so such an
# edge makes the depender permanently unpublishable.
#
# LIMITATION, stated rather than hidden: `[workspace.package]` currently sets
# `publish = false`, so cargo reports EVERY member as unpublishable and the two
# groups are indistinguishable here. This check therefore cannot run yet. It
# starts working by itself when the root flag flips at launch — which is also
# the moment the invariant first has teeth. Announced on every run, because a
# check that quietly does nothing is the failure this script exists to prevent.
publishable="$(jq -r '[.packages[] | select(.publish == null) | .name] | length' <<<"$meta")"
if [[ "$publishable" -eq 0 ]]; then
    echo "check-internal-deps: crates.io-roster check NOT RUN — [workspace.package] publish = false makes every member unpublishable, so the roster is not yet visible to cargo. It runs automatically once that flag flips."
else
    roster_bad="$(jq -r '
      [.packages[] | select(.publish == null) | .name] as $pub
      | .packages[]
      | select(.publish == null) as $pkg
      | $pkg.dependencies[]
      | select((.kind // "normal") != "dev")
      | select([.name] | inside($pub) | not)
      | select(.path != null)
      | "  \($pkg.name) -> \(.name) (never published)"
    ' <<<"$meta" || true)"
    if [[ -n "$roster_bad" ]]; then
        echo "check-internal-deps: these crates.io crates depend on crates that never reach crates.io:" >&2
        printf '%s\n' "$roster_bad" >&2
        exit 1
    fi
    echo "check-internal-deps: crates.io roster — $publishable publishable member(s), no edges into the never-published set."
fi

echo "check-internal-deps: ok — $examined internal dependencies across $member_count members"
