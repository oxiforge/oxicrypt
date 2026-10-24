#!/usr/bin/env bash
# Attaches release files to a DRAFT release, never to a published one.
#
#   GH_TOKEN=<token> attach-draft.sh <tag> <owner/repo> <file> [<file> ...]
#
# Finds the release for the existing tag <tag> in <owner/repo> and creates it
# as a draft when there is none. The draft is made with `--verify-tag`, so it
# attaches to the tag that was pushed and never creates one. Each file is then
# uploaded to the draft by its release ID, replacing an asset of the same name.
# Immediately before each upload the release is looked up again, and if it is
# no longer a draft nothing more is uploaded.
#
# A published release for the tag, more than one release for the tag, or a
# lookup that fails is refused before anything is uploaded. After the uploads
# the draft's assets are read back, and the script fails unless they are
# exactly the files given, each at its size, and the release is still a draft. A run that fails part way leaves
# the draft incomplete and is re-run; nothing here deletes the draft.
#
# What this cannot close is a publish between the last check and an upload;
# the repository's immutable-releases setting closes that, by refusing any
# change to a published release's assets.
#
# Releases are looked up through the releases list, which includes drafts for
# a token that can write to the repository, rather than by tag name, which
# finds published releases only.
#
# Needs `gh` on PATH. Exits 0 when the draft holds exactly the given files, 1
# otherwise, 2 on a usage error.
set -euo pipefail

[ $# -ge 3 ] || { echo "usage: $0 <tag> <owner/repo> <file> [<file> ...]" >&2; exit 2; }
TAG="$1" REPO="$2"
shift 2
for f in "$@"; do
    [ -f "${f}" ] || { echo "not a file: ${f}" >&2; exit 2; }
done
fail() { echo "attach-draft: $*" >&2; exit 1; }

# Print "<id> <draft>" for each release of the tag, one per line.
releases() {
    gh api --paginate "repos/${REPO}/releases?per_page=100" \
        --jq ".[] | select(.tag_name == \"${TAG}\") | \"\(.id) \(.draft)\""
}

found="$(releases)" || fail "could not list the releases of ${REPO}"
if [ -z "${found}" ]; then
    gh release create "${TAG}" --repo "${REPO}" --draft --verify-tag --title "${TAG}" \
        --notes "oxicrypt ${TAG}. Draft: not yet tested or published." >/dev/null \
        || fail "could not create a draft release for ${TAG}"
    found="$(releases)" || fail "could not list the releases of ${REPO}"
fi
[ -n "${found}" ] || fail "the draft release for ${TAG} is not listed after it was created"
[ "$(printf '%s\n' "${found}" | wc -l)" -eq 1 ] || fail "${REPO} has more than one release for ${TAG}: ${found//$'\n'/, }"
read -r id draft <<<"${found}"
[[ "${id}" =~ ^[0-9]+$ ]] || fail "unexpected release ID: ${id}"
[ "${draft}" = true ] || fail "${REPO} already has a published release ${TAG}; not touching it"

for f in "$@"; do
    name="$(basename "${f}")"
    now="$(releases)" || fail "could not list the releases of ${REPO}"
    [ "${now}" = "${id} true" ] || fail "${TAG} in ${REPO} is no longer one draft release; not uploading ${name}"
    old="$(gh api --paginate "repos/${REPO}/releases/${id}/assets?per_page=100" \
        --jq ".[] | select(.name == \"${name}\") | .id")" || fail "could not list the assets of release ${id}"
    if [ -n "${old}" ]; then
        gh api -X DELETE "repos/${REPO}/releases/assets/${old}" >/dev/null \
            || fail "could not replace ${name}"
    fi
    gh api -X POST -H "Content-Type: application/octet-stream" \
        "https://uploads.github.com/repos/${REPO}/releases/${id}/assets?name=${name}" \
        --input "${f}" --jq .name >/dev/null || fail "could not upload ${name}"
    echo "attached ${name}"
done

want="$(for f in "$@"; do printf '%s %s\n' "$(basename "${f}")" "$(wc -c < "${f}" | tr -d ' ')"; done | sort)"
have="$(gh api --paginate "repos/${REPO}/releases/${id}/assets?per_page=100" \
    --jq '.[] | "\(.name) \(.size)"' | sort)" || fail "could not read back the assets of release ${id}"
if [ "${have}" != "${want}" ]; then
    echo "attach-draft: the draft's assets are not exactly the files given" >&2
    diff <(echo "${want}") <(echo "${have}") >&2 || true
    exit 1
fi
now="$(releases)" || fail "could not list the releases of ${REPO}"
[ "${now}" = "${id} true" ] || fail "${TAG} in ${REPO} is no longer one draft release after the uploads"
echo "draft ${TAG} holds exactly the $# files given"
