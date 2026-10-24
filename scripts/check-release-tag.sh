#!/usr/bin/env bash
# Decides whether a pushed tag may produce a release.
#
#   check-release-tag.sh <tag> <commit> <allowed-signers> [<main-ref>]
#
#   <tag>              the tag name: vX.Y.Z, or vX.Y.Z-<pre-release>
#   <commit>           the commit the run was started for; the tag must name it
#   <allowed-signers>  an ssh allowed-signers file naming who may sign releases
#   <main-ref>         the ref the commit must be reachable from (default
#                      origin/main)
#
# The tag must:
#   - be `v` and a SemVer 2.0 version without build metadata: MAJOR.MINOR.PATCH,
#     each 0 or without a leading zero, optionally `-` and dot-separated
#     pre-release identifiers, each non-empty, of [0-9A-Za-z-], and numeric
#     ones without a leading zero;
#   - name the workspace version in the Cargo.toml of the current directory:
#     when that version carries a pre-release part, the tag is `v` and exactly
#     that version; otherwise the tag's MAJOR.MINOR.PATCH equals it and any
#     pre-release part is the tag's own;
#   - be an annotated tag whose signature `git verify-tag` accepts against
#     <allowed-signers>, and whose own `tag` field, which the signature covers,
#     is <tag>, so a signed tag object cannot be pushed under another name;
#   - point at <commit>, and <commit> must be reachable from <main-ref>.
#
# The release workflow runs the copy of this script on `main`, against the
# allowed-signers file on `main`, so the tagged tree cannot change either.
#
# Exits 0 when the tag passes, 1 when it fails a check (naming it), 2 on a
# usage error.
set -euo pipefail

if [ $# -lt 3 ] || [ $# -gt 4 ]; then
    echo "usage: $0 <tag> <commit> <allowed-signers> [<main-ref>]" >&2
    exit 2
fi
TAG="$1" COMMIT="$2" SIGNERS="$3" MAIN_REF="${4:-origin/main}"
refuse() { echo "refused: $*" >&2; exit 1; }

NUM='(0|[1-9][0-9]*)'
IDENT='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER="^v${NUM}\.${NUM}\.${NUM}(-${IDENT}(\.${IDENT})*)?$"
[[ "${TAG}" =~ ${SEMVER} ]] || refuse "${TAG} is not v followed by a SemVer 2.0 version (no build metadata)"
core="${TAG#v}"
core="${core%%-*}"

version="$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')" \
    || refuse "could not read the workspace version from Cargo.toml"
case "${version}" in
    *-*) [ "${TAG}" = "v${version}" ] || refuse "${TAG} does not name the workspace version ${version}" ;;
    *) [ "${core}" = "${version}" ] || refuse "${TAG} does not name the workspace version ${version}" ;;
esac

[ -f "${SIGNERS}" ] || refuse "no allowed-signers file at ${SIGNERS}"
[ "$(git cat-file -t "refs/tags/${TAG}" 2>/dev/null)" = tag ] || refuse "${TAG} is not an annotated tag"
git -c gpg.ssh.allowedSignersFile="${SIGNERS}" verify-tag "refs/tags/${TAG}" \
    || refuse "${TAG} does not carry a valid signature from ${SIGNERS}"
named="$(git cat-file tag "refs/tags/${TAG}" | sed -n 's/^tag //p;/^$/q')" \
    || refuse "could not read the tag object ${TAG}"
[ "${named}" = "${TAG}" ] || refuse "the tag object pushed as ${TAG} was signed as ${named}"

tagged="$(git rev-parse --verify --quiet "refs/tags/${TAG}^{commit}")" || refuse "${TAG} names no commit"
[ "${tagged}" = "${COMMIT}" ] || refuse "${TAG} names ${tagged}, not ${COMMIT}"
git merge-base --is-ancestor "${COMMIT}" "${MAIN_REF}" || refuse "${COMMIT} is not on ${MAIN_REF}"
echo "accepted: ${TAG} (${COMMIT})"
