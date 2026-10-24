#!/usr/bin/env bash
# Tests check-release-tag.sh and attach-draft.sh against fixtures.
#
#   test-release-scripts.sh
#
# check-release-tag.sh runs in scratch repositories whose tags are signed with
# ssh keys generated here: one named in the allowed-signers file, one not.
# attach-draft.sh runs against a stub `gh` that keeps the repository's
# releases as JSON and answers the calls the script makes, applying each
# `--jq` filter with jq, so the filters the script sends are the ones tested.
# The stub records the bytes, content type and path of every upload, refuses
# a second asset of the same name as GitHub does, and fails a named call on
# request.
#
# Every case asserts the exit status and a line of the output. Needs git,
# ssh-keygen, python3 and jq. Exits 0 when every case passes, 1 otherwise.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
pass=0 failed=0

# expect <name> <status> <needle> <command...>
expect() {
    local name="$1" want="$2" needle="$3" out status=0
    shift 3
    out="$("$@" 2>&1)" || status=$?
    if [ "$status" = "$want" ] && grep -qF -- "$needle" <<<"$out"; then
        pass=$((pass + 1))
    else
        failed=$((failed + 1))
        echo "FAIL $name: exit $status (want $want), output:" >&2
        printf '    %s\n' "${out//$'\n'/$'\n'    }" >&2
    fi
}

# check <name> <condition...>
check() {
    local name="$1"
    shift
    if "$@"; then pass=$((pass + 1)); else failed=$((failed + 1)); echo "FAIL $name" >&2; fi
}

# --- check-release-tag.sh -------------------------------------------------

ssh-keygen -q -t ed25519 -N '' -C allowed -f "$T/allowed-key"
ssh-keygen -q -t ed25519 -N '' -C other -f "$T/other-key"
echo "release@example.org $(cat "$T/allowed-key.pub")" > "$T/allowed-signers"

# repo <dir> <workspace version>: a repository with `main` and a side branch.
repo() {
    git init -q -b main "$1"
    printf '[workspace.package]\nversion = "%s"\n' "$2" > "$1/Cargo.toml"
    G="$1"
    g add Cargo.toml
    g commit -q -m base
    g switch -q -c side
    g commit -q --allow-empty -m side
    g switch -q main
}
g() { git -C "$G" -c user.name=Test -c user.email=tagger@example.org -c commit.gpgsign=false \
    -c tag.gpgsign=false -c gpg.format=ssh "$@"; }

# tag <name> <commit> <signed-with: allowed|other|none|lightweight>
tag() {
    g tag -d "$1" >/dev/null 2>&1 || true
    case "$3" in
        allowed) g -c user.signingkey="$T/allowed-key" tag -s -m "$1" "$1" "$2" ;;
        other) g -c user.signingkey="$T/other-key" tag -s -m "$1" "$1" "$2" ;;
        none) g tag -a -m "$1" "$1" "$2" ;;
        lightweight) g tag "$1" "$2" ;;
    esac
}
run_check() { (cd "$G" && "$HERE/check-release-tag.sh" "$1" "$2" "$T/allowed-signers" main); }

repo "$T/repo" 1.2.3
MAIN="$(g rev-parse main)"
SIDE="$(g rev-parse side)"

tag v1.2.3 "$MAIN" allowed
expect "signed release tag accepted" 0 "accepted: v1.2.3" run_check v1.2.3 "$MAIN"
tag v1.2.3-rc.1 "$MAIN" allowed
expect "signed pre-release tag accepted" 0 "accepted: v1.2.3-rc.1" run_check v1.2.3-rc.1 "$MAIN"
tag v1.2.3-rc-1.x "$MAIN" allowed
expect "hyphenated pre-release tag accepted" 0 "accepted: v1.2.3-rc-1.x" run_check v1.2.3-rc-1.x "$MAIN"
tag v1.2.4 "$MAIN" allowed
expect "other version refused" 1 "does not name the workspace version 1.2.3" run_check v1.2.4 "$MAIN"
expect "build metadata refused" 1 "is not v followed by a SemVer" run_check v1.2.3+build "$MAIN"
expect "leading zero refused" 1 "is not v followed by a SemVer" run_check v01.2.3 "$MAIN"
expect "numeric pre-release leading zero refused" 1 "is not v followed by a SemVer" run_check v1.2.3-01 "$MAIN"
expect "empty pre-release identifier refused" 1 "is not v followed by a SemVer" run_check v1.2.3-rc..1 "$MAIN"
expect "empty pre-release refused" 1 "is not v followed by a SemVer" run_check v1.2.3- "$MAIN"
tag v1.2.3 "$MAIN" lightweight
expect "lightweight tag refused" 1 "is not an annotated tag" run_check v1.2.3 "$MAIN"
tag v1.2.3 "$MAIN" none
expect "unsigned annotated tag refused" 1 "does not carry a valid signature" run_check v1.2.3 "$MAIN"
tag v1.2.3 "$MAIN" other
expect "tag signed by an unlisted key refused" 1 "does not carry a valid signature" run_check v1.2.3 "$MAIN"
tag v1.2.3 "$SIDE" allowed
expect "tag off main refused" 1 "is not on main" run_check v1.2.3 "$SIDE"
tag v1.2.3 "$MAIN" allowed
expect "tag naming another commit refused" 1 "names $MAIN, not $SIDE" run_check v1.2.3 "$SIDE"
g update-ref refs/tags/v1.2.3-renamed "$(g rev-parse refs/tags/v1.2.3)"
expect "signed tag object under another name refused" 1 "was signed as v1.2.3" run_check v1.2.3-renamed "$MAIN"
tag v1.2.3-rc.1 "$MAIN" allowed
g update-ref refs/tags/v1.2.3 "$(g rev-parse refs/tags/v1.2.3-rc.1)"
expect "signed pre-release object pushed as the release refused" 1 "was signed as v1.2.3-rc.1" run_check v1.2.3 "$MAIN"
tag v1.2.3 "$MAIN" allowed
expect "missing tag refused" 1 "is not an annotated tag" run_check v1.2.3-rc.2 "$MAIN"
expect "missing allowed-signers refused" 1 "no allowed-signers file" \
    bash -c "cd '$G' && '$HERE/check-release-tag.sh' v1.2.3 '$MAIN' '$T/absent' main"
expect "usage error" 2 "usage:" "$HERE/check-release-tag.sh" v1.2.3 "$MAIN"
g update-ref refs/remotes/origin/main "$MAIN"
expect "default main ref is origin/main" 0 "accepted: v1.2.3" \
    bash -c "cd '$G' && '$HERE/check-release-tag.sh' v1.2.3 '$MAIN' '$T/allowed-signers'"
g update-ref refs/remotes/origin/main "$(g commit-tree "$(g rev-parse "$MAIN^{tree}")" -m unrelated)"
expect "default main ref refuses a commit not on origin/main" 1 "is not on origin/main" \
    bash -c "cd '$G' && '$HERE/check-release-tag.sh' v1.2.3 '$MAIN' '$T/allowed-signers'"

repo "$T/pre" 1.3.0-rc.1
PRE="$(g rev-parse main)"
tag v1.3.0-rc.1 "$PRE" allowed
expect "pre-release workspace: its own tag accepted" 0 "accepted: v1.3.0-rc.1" run_check v1.3.0-rc.1 "$PRE"
tag v1.3.0 "$PRE" allowed
expect "pre-release workspace: release tag refused" 1 "does not name the workspace version 1.3.0-rc.1" run_check v1.3.0 "$PRE"
tag v1.3.0-rc.2 "$PRE" allowed
expect "pre-release workspace: another pre-release refused" 1 "does not name the workspace version 1.3.0-rc.1" run_check v1.3.0-rc.2 "$PRE"

repo "$T/beta" 1.4.0-beta.1
BETA="$(g rev-parse main)"
tag v1.4.0 "$BETA" allowed
expect "beta workspace: release tag refused" 1 "does not name the workspace version 1.4.0-beta.1" run_check v1.4.0 "$BETA"
tag v1.4.0-beta.1 "$BETA" allowed
expect "beta workspace: its own tag accepted" 0 "accepted: v1.4.0-beta.1" run_check v1.4.0-beta.1 "$BETA"

# --- attach-draft.sh ------------------------------------------------------

mkdir -p "$T/bin" "$T/files"
cat > "$T/bin/gh" <<'STUB'
#!/usr/bin/env bash
# Stub gh: releases live in $STUB/releases.json; calls are logged to $STUB/calls,
# uploads to $STUB/uploaded as "<name> <sha256> <content-type> <path>".
# $STUB_FAIL names one call kind to fail: create, list, assets, delete,
# list:<n> for the n-th releases list, or upload:<n> for the n-th upload.
set -euo pipefail
S="$STUB/releases.json"
echo "$*" >> "$STUB/calls"
save() { local tmp; tmp="$(mktemp)"; jq "$@" "$S" > "$tmp"; mv "$tmp" "$S"; }
failing() { [ "${STUB_FAIL:-}" = "$1" ] && { echo "HTTP 502: stub failure ($1)" >&2; exit 1; }; return 0; }
if [ "$1" = release ] && [ "$2" = create ]; then
    failing create
    save --arg t "$3" '. + [{id: 101, tag_name: $t, draft: true, assets: []}]'
    exit 0
fi
[ "$1" = api ] || { echo "stub: unhandled $*" >&2; exit 3; }
shift
method=GET filter=. ctype="" input="" path=""
while [ $# -gt 0 ]; do
    case "$1" in
        -X) method="$2"; shift 2 ;;
        -H) ctype="${2#Content-Type: }"; shift 2 ;;
        --jq) filter="$2"; shift 2 ;;
        --input) input="$2"; shift 2 ;;
        --paginate) shift ;;
        *) path="$1"; shift ;;
    esac
done
case "$method $path" in
    "GET repos/"*"/releases?per_page=100")
        failing list
        l=$(( $(cat "$STUB/lists" 2>/dev/null || echo 0) + 1 ))
        echo "$l" > "$STUB/lists"
        failing "list:$l"
        jq -r "$filter" "$S" ;;
    "GET repos/"*"/releases/"*"/assets?per_page=100")
        failing assets
        id="${path#*/releases/}"; id="${id%%/*}"
        jq -r --argjson i "$id" '.[] | select(.id == $i) | .assets' "$S" | jq -r "$filter" ;;
    "DELETE repos/"*"/releases/assets/"*)
        failing delete
        save --argjson a "${path##*/}" 'map(.assets |= map(select(.id != $a)))' ;;
    "POST https://uploads.github.com/repos/"*)
        n=$(( $(cat "$STUB/uploads" 2>/dev/null || echo 0) + 1 ))
        echo "$n" > "$STUB/uploads"
        failing "upload:$n"
        id="${path#*/releases/}"; id="${id%%/*}"
        name="${path#*name=}"
        if [ -n "$(jq -r --argjson i "$id" --arg n "$name" '.[] | select(.id == $i) | .assets[] | select(.name == $n) | .id' "$S")" ]; then
            echo "HTTP 422: already_exists" >&2; exit 1
        fi
        size="$(wc -c < "$input" | tr -d ' ')"
        echo "$name $(sha256sum < "$input" | cut -d' ' -f1) $ctype ${path%%/releases/*}" >> "$STUB/uploaded"
        save --argjson i "$id" --arg n "$name" --argjson a "$((5000 + n))" --argjson z "$size" \
            'map(if .id == $i then .assets += [{id: $a, name: $n, size: $z}] else . end)'
        if [ -n "${STUB_PUBLISH_AFTER:-}" ] && [ "$n" -ge "$STUB_PUBLISH_AFTER" ]; then
            save --argjson i "$id" 'map(if .id == $i then .draft = false else . end)'
        fi
        echo "$name" ;;
    *) echo "stub: unhandled $method $path" >&2; exit 3 ;;
esac
STUB
chmod +x "$T/bin/gh"
printf 'library tarball\n' > "$T/files/a.tar.gz"
printf 'checksum line\n' > "$T/files/a.tar.gz.sha256"

# scenario <name> <releases.json>: a fresh stub state
scenario() {
    export STUB="$T/stub-$1"
    mkdir -p "$STUB"
    printf '%s\n' "$2" > "$STUB/releases.json"
    : > "$STUB/calls"
    unset STUB_FAIL STUB_PUBLISH_AFTER
}
attach() { PATH="$T/bin:$PATH" "$HERE/attach-draft.sh" v1.2.3 owner/repo "$T/files/a.tar.gz" "$T/files/a.tar.gz.sha256"; }
assets() { jq -r '.[] | select(.tag_name == "v1.2.3") | [.assets[].name] | join(",")' "$STUB/releases.json"; }
uploads() { cat "$STUB/uploads" 2>/dev/null || echo 0; }
sha() { sha256sum < "$1" | cut -d' ' -f1; }
others='{"id": 7, "tag_name": "v1.2.30", "draft": false, "assets": []}, {"id": 8, "tag_name": "v1.2.3-rc.1", "draft": false, "assets": []}'

scenario none "[$others]"
expect "no release: draft created and filled" 0 "holds exactly the 2 files given" attach
check "no release: created with --verify-tag" grep -q -- "release create v1.2.3 --repo owner/repo --draft --verify-tag" "$STUB/calls"
check "no release: both files attached" [ "$(assets)" = "a.tar.gz,a.tar.gz.sha256" ]
check "no release: the bytes uploaded are the files given" \
    grep -qxF "a.tar.gz $(sha "$T/files/a.tar.gz") application/octet-stream https://uploads.github.com/repos/owner/repo" "$STUB/uploaded"
check "no release: the checksum file's bytes uploaded" \
    grep -qxF "a.tar.gz.sha256 $(sha "$T/files/a.tar.gz.sha256") application/octet-stream https://uploads.github.com/repos/owner/repo" "$STUB/uploaded"
check "no release: releases of other tags untouched" \
    [ "$(jq -r '[.[] | select(.tag_name != "v1.2.3") | .assets | length] | add' "$STUB/releases.json")" = 0 ]

scenario draft "[{\"id\": 9, \"tag_name\": \"v1.2.3\", \"draft\": true, \"assets\": [{\"id\": 1, \"name\": \"a.tar.gz\", \"size\": 3}]}, $others]"
expect "draft: files attached" 0 "holds exactly the 2 files given" attach
check "draft: no release created" bash -c "! grep -q 'release create' '$STUB/calls'"
check "draft: the old asset replaced, not duplicated" [ "$(assets)" = "a.tar.gz,a.tar.gz.sha256" ]
check "draft: the old asset deleted" grep -q "DELETE repos/owner/repo/releases/assets/1" "$STUB/calls"

scenario stale '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": [{"id": 1, "name": "old.tar.gz", "size": 3}]}]'
expect "draft holding a file not in the set: refused" 1 "not exactly the files given" attach

scenario published "[{\"id\": 9, \"tag_name\": \"v1.2.3\", \"draft\": false, \"assets\": []}, $others]"
expect "published: refused" 1 "already has a published release v1.2.3" attach
check "published: nothing uploaded" [ "$(uploads)" = 0 ]

scenario listfail "[$others]"
export STUB_FAIL=list
expect "list failure: refused" 1 "could not list the releases" attach
check "list failure: nothing created" bash -c "! grep -q 'release create' '$STUB/calls'"

scenario createfail "[$others]"
export STUB_FAIL=create
expect "create failure: refused" 1 "could not create a draft release" attach
check "create failure: nothing uploaded" [ "$(uploads)" = 0 ]

scenario uploadfail "[$others]"
export STUB_FAIL=upload:2
expect "upload failure: fails" 1 "could not upload a.tar.gz.sha256" attach

scenario deletefail '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": [{"id": 1, "name": "a.tar.gz", "size": 3}]}]'
export STUB_FAIL=delete
expect "delete failure: fails" 1 "could not replace a.tar.gz" attach
check "delete failure: nothing uploaded" [ "$(uploads)" = 0 ]

scenario assetsfail '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
export STUB_FAIL=assets
expect "asset list failure: fails" 1 "could not list the assets" attach
check "asset list failure: nothing uploaded" [ "$(uploads)" = 0 ]

scenario flip '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
export STUB_PUBLISH_AFTER=1
expect "published mid-run: stops" 1 "is no longer one draft release; not uploading a.tar.gz.sha256" attach
check "published mid-run: one file uploaded" [ "$(uploads)" = 1 ]

scenario lastflip '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
export STUB_PUBLISH_AFTER=2
expect "published during the last upload: fails" 1 "no longer one draft release after the uploads" attach

scenario listgap '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
export STUB_FAIL=list:3
expect "list failure between uploads: stops" 1 "could not list the releases" attach
check "list failure between uploads: one file uploaded" [ "$(uploads)" = 1 ]

scenario twice '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}, {"id": 10, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
expect "two releases for the tag: refused" 1 "more than one release for v1.2.3" attach
check "two releases for the tag: nothing uploaded" [ "$(uploads)" = 0 ]

expect "missing file: usage error" 2 "not a file" \
    env PATH="$T/bin:$PATH" "$HERE/attach-draft.sh" v1.2.3 owner/repo "$T/files/absent"

echo "release scripts: $pass passed, $failed failed"
[ "$failed" -eq 0 ] && [ "$pass" -gt 0 ]
