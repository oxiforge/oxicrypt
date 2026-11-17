#!/usr/bin/env bash
# Tests check-release-tag.sh, attach-draft.sh, release-archive-check.sh and
# android-device-check.sh against fixtures.
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
# request. release-archive-check.sh runs against archives whose bundle holds a
# stub `oxi` printing chosen lines and exiting with a chosen status, and
# against malformed bundles. Its library mode runs the README's examples
# against a stand-in library compiled here, whose oxi_init fails when
# STUB_OXI_INIT_FAILS is set and whose oxi_sha256 writes the digest of "abc"
# when it is given the three bytes "abc" and fails otherwise.
# Its examples mode runs examples/*/run.sh against stub toolchains, which
# test which examples run, which are skipped and which are required, and
# against a PATH that hides every toolchain. With OXICRYPT_TEST_EXAMPLES=1 it
# also runs them against the same stand-in with the PATH it is given, where
# each example whose toolchain is present must pass and each other must be
# reported as skipped. Those cases need the toolchains the script names (go
# and the C compiler `go env CC` names, node and npm, java and javac 22 or
# later, dotnet with a .NET SDK 10 or later) and network access for the
# packages npm and dotnet fetch.
# Its imports mode runs against a bundle holding a shared library compiled
# here that calls puts, with allow-lists written from `nm -D` independently
# of the script, and against stub objdump, llvm-readobj, nm, readelf and
# otool printing canned listings.
#
# Every case asserts the exit status and a line of the output. Needs git,
# ssh-keygen, python3, jq, sha256sum, cc, nm and readelf. Exits 0 when every
# case passes, 1 otherwise.
set -euo pipefail

# A git hook exports GIT_DIR, GIT_INDEX_FILE and their relatives to every
# process it starts, and a git command that inherits them acts on the hook's
# repository whatever directory it runs in or names with -C. The fixtures
# below create, commit to and tag scratch repositories, so the suite starts
# by dropping git's repository-local environment. The list of names comes
# from git itself and needs no repository, so the word splitting is wanted.
# shellcheck disable=SC2046
unset $(git rev-parse --local-env-vars)

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
# $STUB_LIST_LAG makes the first <n> releases lists after a create answer
# empty, as the live list does while it catches up.
set -euo pipefail
S="$STUB/releases.json"
echo "$*" >> "$STUB/calls"
save() { local tmp; tmp="$(mktemp)"; jq "$@" "$S" > "$tmp"; mv "$tmp" "$S"; }
failing() { [ "${STUB_FAIL:-}" = "$1" ] && { echo "HTTP 502: stub failure ($1)" >&2; exit 1; }; return 0; }
if [ "$1" = release ] && [ "$2" = create ]; then
    failing create
    save --arg t "$3" '. + [{id: 101, tag_name: $t, draft: true, assets: []}]'
    : > "$STUB/created"
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
        if [ -e "$STUB/created" ]; then
            p=$(( $(cat "$STUB/postlists" 2>/dev/null || echo 0) + 1 ))
            echo "$p" > "$STUB/postlists"
            [ "$p" -gt "${STUB_LIST_LAG:-0}" ] || exit 0
        fi
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
    unset STUB_FAIL STUB_PUBLISH_AFTER STUB_LIST_LAG ATTACH_LIST_ATTEMPTS ATTACH_LIST_DELAY
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

scenario lag "[$others]"
export STUB_LIST_LAG=2 ATTACH_LIST_DELAY=0
expect "a draft the list shows late: found and filled" 0 "holds exactly the 2 files given" attach
check "a draft the list shows late: created once" [ "$(grep -c 'release create' "$STUB/calls")" = 1 ]
# Three lists until the draft shows, one before each of the two uploads, one
# after them: a loop that keeps listing after the draft appears is caught.
check "a draft the list shows late: six lists after the create" [ "$(cat "$STUB/postlists")" = 6 ]

scenario lagout "[$others]"
export STUB_LIST_LAG=9 ATTACH_LIST_ATTEMPTS=3 ATTACH_LIST_DELAY=0
expect "a draft the list never shows: refused" 1 "is not listed after it was created" attach
check "a draft the list never shows: nothing uploaded" [ "$(uploads)" = 0 ]
check "a draft the list never shows: three attempts" [ "$(cat "$STUB/postlists")" = 3 ]

scenario badattempts "[$others]"
export ATTACH_LIST_ATTEMPTS=abc
expect "a non-numeric attempt count: refused" 1 "must be a positive integer" attach
check "a non-numeric attempt count: no release created" bash -c "! grep -q 'release create' '$STUB/calls'"

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

# --- release-archive-check.sh ---------------------------------------------

FP="sha256:$(printf '%064d' 0 | tr 0 a)"
PASSED="integrity: passed — this binary matches the signature recorded inside it"

# cli_archive <name> <integrity lines> <indicator> [<status> [<binary>]]: an
# archive whose bundle holds a stub <binary> (default oxi) printing
# <integrity lines> for --integrity and exiting <status> (default 0), and
# printing `self-test indicator: <indicator>` for `selftest --quiet`.
cli_archive() {
    local d="$T/archives/$1/oxicrypt-cli-test" bin="${5:-oxi}"
    mkdir -p "$d"
    {
        echo '#!/usr/bin/env bash'
        echo 'case "$*" in'
        printf -- '--integrity) printf %%s %q; exit %s ;;\n' "$2" "${4:-0}"
        printf '"selftest --quiet") echo "self-test indicator: %s" ;;\n' "$3"
        echo '*) exit 2 ;;'
        echo 'esac'
    } > "$d/$bin"
    chmod +x "$d/$bin"
    tar -czf "$T/archives/$1.tar.gz" -C "$T/archives/$1" oxicrypt-cli-test
}
archive_check() { "$HERE/release-archive-check.sh" "$@"; }

cli_archive good "$PASSED"$'\n'"  verify key: $FP"$'\n' PASS
expect "archive cli: the expected lines pass" 0 "ok: ./oxi from the extracted archive" \
    archive_check cli "$T/archives/good.tar.gz" "$FP"
cli_archive wrongkey "$PASSED"$'\n'"  verify key: ${FP%a}b"$'\n' PASS
expect "archive cli: another verify key refused" 1 "did not print \"  verify key: $FP\" exactly once" \
    archive_check cli "$T/archives/wrongkey.tar.gz" "$FP"
cli_archive twice "$PASSED"$'\n'"$PASSED"$'\n'"  verify key: $FP"$'\n' PASS
expect "archive cli: a repeated integrity line refused" 1 "did not print \"$PASSED\" exactly once" \
    archive_check cli "$T/archives/twice.tar.gz" "$FP"
cli_archive selftestfail "$PASSED"$'\n'"  verify key: $FP"$'\n' FAIL
expect "archive cli: a failed self-test refused" 1 "did not print \"self-test indicator: PASS\" exactly once" \
    archive_check cli "$T/archives/selftestfail.tar.gz" "$FP"
mkdir -p "$T/archives/nooxi/oxicrypt-cli-test"
printf 'licence\n' > "$T/archives/nooxi/oxicrypt-cli-test/LICENSE-MIT"
tar -czf "$T/archives/nooxi.tar.gz" -C "$T/archives/nooxi" oxicrypt-cli-test
expect "archive cli: a bundle without oxi refused" 1 "holds neither oxi nor oxi.exe" \
    archive_check cli "$T/archives/nooxi.tar.gz" "$FP"
cli_archive integrityexit "$PASSED"$'\n'"  verify key: $FP"$'\n' PASS 1
expect "archive cli: the right lines with exit 1 refused" 1 "FAILED: ./oxi --integrity exited 1" \
    archive_check cli "$T/archives/integrityexit.tar.gz" "$FP"
cli_archive prefixed "xx $PASSED"$'\n'"  verify key: $FP"$'\n' PASS
expect "archive cli: a prefixed integrity line refused" 1 "did not print \"$PASSED\" exactly once" \
    archive_check cli "$T/archives/prefixed.tar.gz" "$FP"
cli_archive suffixed "$PASSED xx"$'\n'"  verify key: $FP"$'\n' PASS
expect "archive cli: a suffixed integrity line refused" 1 "did not print \"$PASSED\" exactly once" \
    archive_check cli "$T/archives/suffixed.tar.gz" "$FP"
cli_archive exe "$PASSED"$'\n'"  verify key: $FP"$'\n' PASS 0 oxi.exe
expect "archive cli: a bundle holding oxi.exe passes" 0 "ok: ./oxi.exe from the extracted archive" \
    archive_check cli "$T/archives/exe.tar.gz" "$FP"
cli_archive both "$PASSED"$'\n'"  verify key: $FP"$'\n' PASS
cp "$T/archives/both/oxicrypt-cli-test/oxi" "$T/archives/both/oxicrypt-cli-test/oxi.exe"
tar -czf "$T/archives/both.tar.gz" -C "$T/archives/both" oxicrypt-cli-test
expect "archive cli: a bundle holding oxi and oxi.exe refused" 1 "holds both oxi and oxi.exe" \
    archive_check cli "$T/archives/both.tar.gz" "$FP"
cli_archive outside "$PASSED"$'\n'"  verify key: $FP"$'\n' PASS
mv "$T/archives/outside/oxicrypt-cli-test/oxi" "$T/archives/outside-oxi"
ln -s "$T/archives/outside-oxi" "$T/archives/outside/oxicrypt-cli-test/oxi"
tar -czf "$T/archives/outside.tar.gz" -C "$T/archives/outside" oxicrypt-cli-test
expect "archive cli: oxi as a link out of the bundle refused" 1 "FAILED: oxi is a symbolic link out of the bundle" \
    archive_check cli "$T/archives/outside.tar.gz" "$FP"
mkdir -p "$T/archives/twodirs/a" "$T/archives/twodirs/b"
tar -czf "$T/archives/twodirs.tar.gz" -C "$T/archives/twodirs" a b
expect "archive library: two top-level directories refused" 1 "holds 2 top-level entries, not one directory" \
    archive_check library "$T/archives/twodirs.tar.gz"
mkdir -p "$T/archives/lonefile"
printf 'oxi\n' > "$T/archives/lonefile/oxi"
tar -czf "$T/archives/lonefile.tar.gz" -C "$T/archives/lonefile" oxi
expect "archive cli: a lone top-level file refused" 1 "holds 1 top-level entries, not one directory" \
    archive_check cli "$T/archives/lonefile.tar.gz" "$FP"
expect "archive cli: a missing archive refused" 1 "FAILED: $T/archives/absent.tar.gz is not a file" \
    archive_check cli "$T/archives/absent.tar.gz" "$FP"
expect "archive cli: a wrong argument count is a usage error" 1 "usage: release-archive-check.sh cli" \
    archive_check cli "$T/archives/good.tar.gz"

# ffi_archive <name> <soname version>: $T/ffi/<name>/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz,
# whose bundle holds the stand-in library liboxicrypt_ffi.so.<version>, the
# liboxicrypt_ffi.so link to it and an oxicrypt.h declaring what the README's
# C example calls.
ffi_archive() {
    local d="$T/ffi/$1/oxicrypt-ffi-v9.9.9-linux-x86_64"
    mkdir -p "$d"
    cat > "$d/oxicrypt.h" <<'H'
#include <stdint.h>
typedef enum { OXI_RESULT_OK = 0 } OxiResult;
int oxi_init(int profile);
int oxi_sha256(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);
H
    cc -shared -fPIC -Wl,-soname,"liboxicrypt_ffi.so.$2" -I"$d" -o "$d/liboxicrypt_ffi.so.$2" "$T/ffi/stub.c"
    ln -s "liboxicrypt_ffi.so.$2" "$d/liboxicrypt_ffi.so"
    tar -czf "$T/ffi/$1/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz" -C "$T/ffi/$1" oxicrypt-ffi-v9.9.9-linux-x86_64
}
mkdir -p "$T/ffi"
{
    echo '#include <stdlib.h>'
    echo '#include <string.h>'
    echo '#include "oxicrypt.h"'
    # SHA-256("abc"), FIPS 180-4 Appendix B.1.
    printf 'static const uint8_t abc[32] = { %s };\n' \
        "$(printf '%s' ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad | sed -E 's/(..)/0x\1, /g')"
    echo 'int oxi_init(int profile) { (void)profile; return getenv("STUB_OXI_INIT_FAILS") ? 1 : 0; }'
    echo 'int oxi_sha256(const uint8_t *d, uintptr_t n, uint8_t *out) {'
    echo '    if (n != 3 || memcmp(d, "abc", 3) != 0) return 1;'
    echo '    memcpy(out, abc, 32);'
    echo '    return 0;'
    echo '}'
} > "$T/ffi/stub.c"
ffi_archive one 1
ffi_archive eight 8
expect "archive library: the README's examples pass against the stand-in" 0 \
    "ok: the README's C and Python examples run against liboxicrypt_ffi.so.1 from the extracted archive" \
    archive_check library "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
out_initfail="$(STUB_OXI_INIT_FAILS=1 archive_check library "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz" 2>&1)" \
    && status=0 || status=$?
check "archive library: a failing oxi_init exits 1" [ "$status" = 1 ]
check "archive library: a failing oxi_init fails the C example" \
    grep -qxF "FAILED: the README's C example exited 1" <<<"$out_initfail"
check "archive library: a failing oxi_init fails the Python example" \
    grep -qxF "FAILED: the README's Python example exited 1" <<<"$out_initfail"
expect "archive library: a bundle without the README's library name refused" 1 \
    "FAILED: the README's Python example loads liboxicrypt_ffi.so.1, which the bundle does not hold" \
    archive_check library "$T/ffi/eight/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
mkdir -p "$T/ffi/linked/oxicrypt-ffi-v9.9.9-linux-x86_64"
ln -s "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.1" "$T/ffi/linked/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.1"
tar -czf "$T/ffi/linked/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz" -C "$T/ffi/linked" oxicrypt-ffi-v9.9.9-linux-x86_64
expect "archive library: a versioned library that is a link out of the bundle refused" 1 \
    "FAILED: liboxicrypt_ffi.so.1 is a symbolic link out of the bundle" \
    archive_check library "$T/ffi/linked/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"

# ffi_variant <name>: a copy of the `one` bundle under $T/ffi/<name>, which
# the caller changes and packs with ffi_pack <name>.
ffi_variant() { mkdir -p "$T/ffi/$1"; cp -a "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64" "$T/ffi/$1/"; }
ffi_pack() { tar -czf "$T/ffi/$1/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz" -C "$T/ffi/$1" oxicrypt-ffi-v9.9.9-linux-x86_64; }
cp "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.1" "$T/ffi/outside.so"
ffi_variant alias
ln -sfn "$T/ffi/outside.so" "$T/ffi/alias/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so"
ffi_pack alias
expect "archive library: the unversioned alias as a link out of the bundle refused" 1 \
    "FAILED: liboxicrypt_ffi.so is a symbolic link out of the bundle" \
    archive_check library "$T/ffi/alias/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
ffi_variant dangling
ln -sfn liboxicrypt_ffi.so.7 "$T/ffi/dangling/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so"
ffi_pack dangling
expect "archive library: a dangling alias refused" 1 \
    "FAILED: liboxicrypt_ffi.so is a symbolic link out of the bundle" \
    archive_check library "$T/ffi/dangling/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
ffi_variant chain
ln -s "$T/ffi/outside.so" "$T/ffi/chain/oxicrypt-ffi-v9.9.9-linux-x86_64/hop"
ln -sfn hop "$T/ffi/chain/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so"
ffi_pack chain
expect "archive library: a two-link chain ending out of the bundle refused" 1 \
    "FAILED: liboxicrypt_ffi.so is a symbolic link out of the bundle" \
    archive_check library "$T/ffi/chain/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
ffi_variant two
cp "$T/ffi/two/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.1" "$T/ffi/two/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.2"
ffi_pack two
expect "archive library: two shared libraries refused" 1 \
    "FAILED: oxicrypt-ffi-v9.9.9-linux-x86_64 holds more than one shared library" \
    archive_check library "$T/ffi/two/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
ffi_variant header
ln -sfn oxicrypt.h "$T/ffi/header/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so"
ffi_pack header
expect "archive library: the unversioned alias linking to another file in the bundle refused" 1 \
    "FAILED: liboxicrypt_ffi.so links to oxicrypt.h, not to liboxicrypt_ffi.so.1" \
    archive_check library "$T/ffi/header/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"

# A PATH holding only what the scripts call hides every toolchain.
mkdir -p "$T/minpath"
for t in bash env dirname basename mktemp rm tar gzip find wc tr readlink grep sed awk od cat head sort cp chmod; do
    ln -s "$(command -v "$t")" "$T/minpath/$t"
done
FFI_ONE="$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
out_examples="$(PATH="$T/minpath" archive_check examples "$FFI_ONE" 2>&1)" && status=0 || status=$?
check "archive examples: no toolchain on PATH exits 1" [ "$status" = 1 ]
check "archive examples: no toolchain on PATH is named" grep -qxF "FAILED: no example toolchain on PATH" <<<"$out_examples"
for skip in "go (no go on PATH)" "node (no node on PATH)" "java (no java on PATH)" "csharp (no dotnet on PATH)"; do
    check "archive examples: skip: $skip" grep -qxF "skip: $skip" <<<"$out_examples"
done
expect "archive examples: a required language without its toolchain fails" 1 \
    "FAILED: examples/node is required here and no node on PATH" \
    env PATH="$T/minpath" OXICRYPT_EXAMPLES_REQUIRED=node "$HERE/release-archive-check.sh" examples "$FFI_ONE"

# Stub toolchains: each prints the digest the stand-in would, so these cases
# test which examples the script runs, not the examples. $STUB_GO_VERSION,
# $STUB_DOTNET_SDKS and $STUB_JAVAC_VERSION set what `go version`, `dotnet
# --list-sdks` and `javac -version` report. $STUB_EXAMPLE_FAIL=<language>
# makes that language's program exit 1 without printing the digest. The java
# and javac stubs sit in their own directory, on PATH only where a case puts
# them there.
mkdir -p "$T/toolstub" "$T/javastub" "$T/toolstub-nocc"
fail_or_digest() { printf '#!/usr/bin/env bash\n[ "${STUB_EXAMPLE_FAIL:-}" != %s ] || exit 1\necho ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n' "$1"; }
cat > "$T/toolstub/go" <<'STUB'
#!/usr/bin/env bash
case "$1" in
    version) echo "go version go${STUB_GO_VERSION:-1.24.0} linux/amd64" ;;
    env) echo stub-cc ;;
    build) cp "$(dirname "$0")/go-program" "$3" ;;
    *) exit 3 ;;
esac
STUB
fail_or_digest go > "$T/toolstub/go-program"
cat > "$T/toolstub/dotnet" <<'STUB'
#!/usr/bin/env bash
case "$1" in
    --list-sdks) printf '%s\n' "${STUB_DOTNET_SDKS:-10.0.100 [/stub/sdk]}" ;;
    build) ;;
    *) [ "${STUB_EXAMPLE_FAIL:-}" != csharp ] || exit 1
       echo ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ;;
esac
STUB
fail_or_digest node > "$T/toolstub/node"
printf '#!/usr/bin/env bash\n' > "$T/toolstub/npm"
printf '#!/usr/bin/env bash\n' > "$T/toolstub/stub-cc"
cat > "$T/javastub/javac" <<'STUB'
#!/usr/bin/env bash
[ "$1" != -version ] || echo "javac ${STUB_JAVAC_VERSION:-21}"
STUB
fail_or_digest java > "$T/javastub/java"
chmod +x "$T/toolstub/"* "$T/javastub/"*
for t in go go-program dotnet node npm; do ln -s "$T/toolstub/$t" "$T/toolstub-nocc/$t"; done
# stub_examples <go version> <dotnet sdks> <required>: examples mode on the
# stand-in with the stub toolchains on $stub_path.
stub_path="$T/toolstub:$T/minpath"
stub_examples() {
    env PATH="$stub_path" STUB_GO_VERSION="$1" STUB_DOTNET_SDKS="$2" OXICRYPT_EXAMPLES_REQUIRED="$3" \
        "$HERE/release-archive-check.sh" examples "$FFI_ONE"
}
expect "archive examples: suitable stub toolchains run" 0 "ok: the examples for csharp go node run against" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" "go node csharp"
expect "archive examples: a present required language passes" 0 "examples/node (exit 0):" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" node
expect "archive examples: a Go newer by a two-digit minor runs" 0 "examples/go (exit 0):" \
    stub_examples 1.100 "10.0.100 [/stub/sdk]" ""
expect "archive examples: a Go older than go.mod is skipped, naming both" 0 \
    "skip: go (go 1.3.9 on PATH, examples/go/go.mod needs 1.24 or later)" \
    stub_examples 1.3.9 "10.0.100 [/stub/sdk]" ""
expect "archive examples: a Go older than go.mod is skipped by patch" 0 "skip: go (go 1.23.12 on PATH" \
    stub_examples 1.23.12 "10.0.100 [/stub/sdk]" ""
expect "archive examples: only an older .NET SDK is skipped" 0 "skip: csharp (no .NET SDK 10 or later)" \
    stub_examples 1.24.0 $'8.0.404 [/stub/sdk]\n9.0.100 [/stub/sdk]' ""
expect "archive examples: a required Go too old fails" 1 \
    "FAILED: examples/go is required here and go 1.3.9 on PATH, examples/go/go.mod needs 1.24 or later" \
    stub_examples 1.3.9 "10.0.100 [/stub/sdk]" go
expect "archive examples: a required csharp with an older SDK fails" 1 \
    "FAILED: examples/csharp is required here and no .NET SDK 10 or later" \
    stub_examples 1.24.0 "9.0.100 [/stub/sdk]" "node csharp"
expect "archive examples: a required java without a JDK fails" 1 \
    "FAILED: examples/java is required here and no java on PATH" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" java
expect "archive examples: a required language with no example fails" 1 \
    "FAILED: examples/cobol is required here and has no run.sh" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" cobol
expect "archive examples: a required language after a tab or newline is still required" 1 \
    "FAILED: examples/csharp is required here and no .NET SDK 10 or later" \
    stub_examples 1.24.0 "9.0.100 [/stub/sdk]" $'node\tcsharp\ngo\n'
export STUB_EXAMPLE_FAIL=node
expect "archive examples: an example that exits 1 fails" 1 "FAILED: examples/node exited 1" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" ""
unset STUB_EXAMPLE_FAIL
stub_path="$T/javastub:$T/toolstub:$T/minpath"
export STUB_JAVAC_VERSION=21
expect "archive examples: a javac older than 22 is skipped" 0 \
    "skip: java (javac 21 on PATH, the example needs 22 or later)" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" ""
export STUB_JAVAC_VERSION=22
expect "archive examples: a javac of 22 runs the example" 0 "examples/java (exit 0):" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" java
unset STUB_JAVAC_VERSION
stub_path="$T/toolstub-nocc:$T/minpath"
expect "archive examples: go without the C compiler cgo needs is skipped" 0 \
    "skip: go (no stub-cc on PATH for cgo)" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" ""
stub_path="$T/toolstub:$T/minpath"

# example_runs <language>: the toolchain release-archive-check.sh's header
# names for examples/<language> is on PATH, at a version it accepts.
example_runs() {
    case "$1" in
        go) command -v go >/dev/null && command -v "$(go env CC)" >/dev/null \
            && awk -v have="$(go version | sed -nE 's/^go version go([0-9.]+).*/\1/p')" \
                -v need="$(sed -nE 's/^go ([0-9.]+)$/\1/p' "$HERE/../examples/go/go.mod")" 'BEGIN {
                    if (have == "" || need == "") exit 1
                    nh = split(have, h, "."); nn = split(need, w, ".")
                    for (i = 1; i <= (nh > nn ? nh : nn); i++) { if (h[i] + 0 != w[i] + 0) exit !(h[i] + 0 > w[i] + 0) }
                }' ;;
        node) command -v node >/dev/null && command -v npm >/dev/null ;;
        java) command -v java >/dev/null && command -v javac >/dev/null \
            && [ "$(javac -version 2>&1 | sed -nE 's/^javac ([0-9]+).*/\1/p')" -ge 22 ] 2>/dev/null ;;
        csharp) command -v dotnet >/dev/null \
            && dotnet --list-sdks 2>/dev/null | awk '{ split($1, v, "."); if (v[1] + 0 >= 10) ok = 1 } END { exit !ok }' ;;
        *) return 1 ;;
    esac
}
examples_ran=""
if [ "${OXICRYPT_TEST_EXAMPLES:-}" = 1 ]; then
    out_examples="$(archive_check examples "$FFI_ONE" 2>&1)" && status=0 || status=$?
    for language in go node java csharp; do
        if example_runs "$language"; then
            examples_ran="$examples_ran $language"
            check "archive examples: $language runs against the stand-in" \
                grep -qxF "examples/$language (exit 0):" <<<"$out_examples"
        else
            check "archive examples: $language is skipped without its toolchain" \
                grep -q "^skip: $language (" <<<"$out_examples"
        fi
    done
    if [ -n "$examples_ran" ]; then
        check "archive examples: every example whose toolchain is present passes" [ "$status" = 0 ]
        expect "archive examples: every present language required passes" 0 "ok: the examples for" \
            env OXICRYPT_EXAMPLES_REQUIRED="$examples_ran" "$HERE/release-archive-check.sh" examples "$FFI_ONE"
    else
        check "archive examples: no toolchain present fails" [ "$status" = 1 ]
    fi
    out_examples="$(STUB_OXI_INIT_FAILS=1 archive_check examples "$FFI_ONE" 2>&1)" && status=0 || status=$?
    check "archive examples: a failing oxi_init exits 1" [ "$status" = 1 ]
    for language in $examples_ran; do
        check "archive examples: a failing oxi_init fails $language" \
            grep -qxF "FAILED: examples/$language exited 1" <<<"$out_examples"
    done
else
    echo "examples cases: toolchains not exercised (set OXICRYPT_TEST_EXAMPLES=1)"
fi
expect "archive examples: a wrong argument count is a usage error" 1 "usage: release-archive-check.sh examples" \
    archive_check examples

IMP="$T/imports/oxicrypt-ffi-v9.9.9-linux-x86_64"
mkdir -p "$IMP" "$T/allow/exact" "$T/allow/missing" "$T/allow/extra" "$T/allow/none"
printf '#include <stdio.h>\nint f(void) { return puts("f"); }\n' | cc -shared -fPIC -o "$IMP/liboxicrypt_ffi.so.9" -x c -
tar -czf "$IMP.tar.gz" -C "$T/imports" oxicrypt-ffi-v9.9.9-linux-x86_64
{
    echo "# every import the stub library has"
    nm -D --undefined-only "$IMP/liboxicrypt_ffi.so.9" | awk '{ print $NF "  # from nm" }'
    echo "needs libc.so.6"
} > "$T/allow/exact/elf-linux-x86_64.txt"
check "archive imports: the stub library imports puts" grep -q '^puts@GLIBC_' "$T/allow/exact/elf-linux-x86_64.txt"
grep -v '^puts@' "$T/allow/exact/elf-linux-x86_64.txt" > "$T/allow/missing/elf-linux-x86_64.txt"
{ cat "$T/allow/exact/elf-linux-x86_64.txt"; echo "gone@GLIBC_2.2.5  # no longer imported"; } > "$T/allow/extra/elf-linux-x86_64.txt"
expect "archive imports: every import allowed passes" 0 "ok: liboxicrypt_ffi.so.9 imports only what $T/allow/exact/elf-linux-x86_64.txt allows" \
    archive_check imports "$IMP.tar.gz" "$T/allow/exact"
expect "archive imports: an import the allow-list lacks refused" 1 "FAILED: liboxicrypt_ffi.so.9 imports puts@GLIBC_" \
    archive_check imports "$IMP.tar.gz" "$T/allow/missing"
expect "archive imports: an allowed entry not imported is a note" 0 "note: gone@GLIBC_2.2.5 is allowed but not imported" \
    archive_check imports "$IMP.tar.gz" "$T/allow/extra"
expect "archive imports: no allow-list refused" 1 "FAILED: no allow-list $T/allow/none/elf-linux-x86_64.txt" \
    archive_check imports "$IMP.tar.gz" "$T/allow/none"
mkdir -p "$T/imports-android/oxicrypt-ffi-v9.9.9-android-x86_64"
cp "$IMP/liboxicrypt_ffi.so.9" "$T/imports-android/oxicrypt-ffi-v9.9.9-android-x86_64/liboxicrypt_ffi.so"
tar -czf "$T/imports-android/oxicrypt-ffi-v9.9.9-android-x86_64.tar.gz" -C "$T/imports-android" oxicrypt-ffi-v9.9.9-android-x86_64
cp "$T/allow/exact/elf-linux-x86_64.txt" "$T/allow/exact/elf-android-x86_64.txt"
expect "archive imports: an Android bundle's unversioned library checked against its allow-list" 0 \
    "ok: liboxicrypt_ffi.so imports only what $T/allow/exact/elf-android-x86_64.txt allows" \
    archive_check imports "$T/imports-android/oxicrypt-ffi-v9.9.9-android-x86_64.tar.gz" "$T/allow/exact"
mkdir -p "$T/allow/noneeds" "$T/allow/empty"
grep -v '^needs libc\.so\.6$' "$T/allow/exact/elf-linux-x86_64.txt" > "$T/allow/noneeds/elf-linux-x86_64.txt"
expect "archive imports: a NEEDED entry the allow-list lacks refused" 1 \
    "FAILED: liboxicrypt_ffi.so.9 imports needs libc.so.6, which the allow-list" \
    archive_check imports "$IMP.tar.gz" "$T/allow/noneeds"

# imports_listed <archive> <PATH>: the imports the mode finds in <archive>
# with <PATH>, read from what it refuses against an empty allow-list.
imports_listed() {
    local name
    name="$(basename "$1" .tar.gz)"
    printf '# nothing allowed\n' > "$T/allow/empty/$(case "$name" in
        *-windows-*) echo pe ;; *-macos-*) echo macho ;; *) echo elf ;; esac)-${name##*-v9.9.9-}.txt"
    env PATH="$2" "$HERE/release-archive-check.sh" imports "$1" "$T/allow/empty" 2>&1 \
        | sed -nE 's/^FAILED: [^ ]+ imports (.*), which the allow-list .*/\1/p' | LC_ALL=C sort
}
# fake_bundle <dir> <file> <hex magic>: an archive <dir>.tar.gz whose bundle
# holds <file>, starting with the bytes <hex magic>.
fake_bundle() {
    mkdir -p "$1"
    printf '%b' "$(printf '%s' "$3" | sed -E 's/(..)/\\x\1/g')" > "$1/$2"
    head -c 64 /dev/zero >> "$1/$2"
    tar -czf "$1.tar.gz" -C "$(dirname "$1")" "$(basename "$1")"
}
mkdir -p "$T/pestub" "$T/readobjstub" "$T/machostub" "$T/nonm" "$T/noreadelf"
fake_bundle "$T/fake/oxicrypt-ffi-v9.9.9-windows-x86_64" oxicrypt_ffi.dll 4d5a9000
fake_bundle "$T/fake/oxicrypt-ffi-v9.9.9-macos-aarch64" liboxicrypt_ffi.1.dylib cffaedfe
fake_bundle "$T/fake/oxicrypt-ffi-v9.9.9-linux-aarch64" liboxicrypt_ffi.so.9 68656c6c
cp "$IMP.tar.gz" "$T/fake/oxicrypt-ffi-v9.9.9-freebsd-x86_64.tar.gz"
# GNU objdump 2.46, with an Ordinal column, and an older one without it.
cat > "$T/pestub/objdump" <<'STUB'
#!/usr/bin/env bash
printf 'The Import Tables (interpreted .idata section contents)\n'
printf '\tDLL Name: KERNEL32.dll\n'
printf '\tvma:     Ordinal  Hint  Member-Name  Bound-To\n'
printf '\t00022500      5  <none> <none>\n'
printf '\t00022508  <none>  0006  CreateFileW\n'
printf '\n'
printf '\tDLL Name: WS2_32.dll\n'
printf '\tvma:  Hint/Ord Member-Name Bound-To\n'
printf '\t2a0c\t  123  WSAStartup\n'
printf '\t2a14\t    7  <none>\n'
printf '\n'
STUB
cat > "$T/readobjstub/llvm-readobj" <<'STUB'
#!/usr/bin/env bash
printf 'File: %s\nFormat: COFF-x86-64\nArch: x86_64\nAddressSize: 64bit\n' "${@: -1}"
printf 'Import {\n  Name: KERNEL32.dll\n  ImportLookupTableRVA: 0x22000\n  ImportAddressTableRVA: 0x22500\n'
printf '  Symbol: CreateFileW (6)\n  Symbol:  (5)\n}\n'
STUB
cat > "$T/machostub/nm" <<'STUB'
#!/usr/bin/env bash
[ "$1 $2 $3" = "-u -arch arm64" ] || exit 3
printf '_free\n_malloc\n'
STUB
cat > "$T/machostub/otool" <<'STUB'
#!/usr/bin/env bash
printf '%s:\n' "$2"
case "$1" in
    -D) printf '@rpath/liboxicrypt_ffi.1.dylib\n' ;;
    -L) printf '\t@rpath/liboxicrypt_ffi.1.dylib (compatibility version 1.0.0, current version 1.0.0)\n'
        printf '\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)\n' ;;
esac
STUB
printf '#!/usr/bin/env bash\n' > "$T/nonm/nm"
printf '#!/usr/bin/env bash\n' > "$T/noreadelf/readelf"
chmod +x "$T/pestub/"* "$T/readobjstub/"* "$T/machostub/"* "$T/nonm/"* "$T/noreadelf/"*
check "archive imports: objdump's listing normalised, ordinals included" [ "$(imports_listed "$T/fake/oxicrypt-ffi-v9.9.9-windows-x86_64.tar.gz" "$T/pestub:$PATH")" = \
    "$(printf '%s\n' kernel32.dll!CreateFileW kernel32.dll!ordinal-5 'needs kernel32.dll' 'needs ws2_32.dll' ws2_32.dll!WSAStartup ws2_32.dll!ordinal-7)" ]
check "archive imports: llvm-readobj's listing normalised, ordinals included" [ "$(imports_listed "$T/fake/oxicrypt-ffi-v9.9.9-windows-x86_64.tar.gz" "$T/readobjstub:$T/minpath")" = \
    "$(printf '%s\n' kernel32.dll!CreateFileW kernel32.dll!ordinal-5 'needs kernel32.dll')" ]
check "archive imports: nm -u and otool listings normalised" [ "$(imports_listed "$T/fake/oxicrypt-ffi-v9.9.9-macos-aarch64.tar.gz" "$T/machostub:$PATH")" = \
    "$(printf '%s\n' _free _malloc 'needs /usr/lib/libSystem.B.dylib')" ]
expect "archive imports: an unknown format refused" 1 "FAILED: liboxicrypt_ffi.so.9 starts with 68656c6c, which is not ELF, PE or Mach-O" \
    archive_check imports "$T/fake/oxicrypt-ffi-v9.9.9-linux-aarch64.tar.gz" "$T/allow/exact"
expect "archive imports: a platform the name does not give refused" 1 \
    "FAILED: oxicrypt-ffi-v9.9.9-freebsd-x86_64.tar.gz does not end in <os>-<arch>.tar.gz" \
    archive_check imports "$T/fake/oxicrypt-ffi-v9.9.9-freebsd-x86_64.tar.gz" "$T/allow/exact"
expect "archive imports: a listing with no symbols refused" 1 "FAILED: found no symbols in liboxicrypt_ffi.so.9" \
    env PATH="$T/nonm:$PATH" "$HERE/release-archive-check.sh" imports "$IMP.tar.gz" "$T/allow/exact"
expect "archive imports: a listing with no libraries refused" 1 "FAILED: found no libraries in liboxicrypt_ffi.so.9" \
    env PATH="$T/noreadelf:$PATH" "$HERE/release-archive-check.sh" imports "$IMP.tar.gz" "$T/allow/exact"

# --- android-device-check.sh ----------------------------------------------
# Runs against a bundle holding a stand-in library: an ELF header, a slot of
# non-zero bytes between the two magics at 0x10000, and filler. The NDK's
# clang and llvm-readelf are stubs; the stub clang records its arguments and
# writes a placeholder harness, and the stub llvm-readelf reports the machine
# $STUB_READELF_MACHINE (default AArch64). The stub signer reports that slot
# and two hashed ranges for --show, and for --verify accepts the signed
# library, refuses the unsigned template copy as version 0 and anything else
# as SignatureInvalid; $STUB_SIGN_ACCEPT_ALL makes it accept everything and
# $STUB_SIGN_NO_DIAGNOSIS refuse the unsigned copy as SignatureInvalid. The
# stub `adb` keeps every pushed file and answers a harness run by the bytes
# of the library it names, as the module would: the signed library
# operational, its unsigned template copy refused with status 3, anything
# else refused with status 2. $ADB_LIE makes it report the signed library
# refused, the tampered one operational, the unsigned one operational, or the
# unsigned one refused with status 10. One case runs on a PATH without
# `timeout`, which both scripts use only where it is installed.

mkdir -p "$T/android/bundle/oxicrypt-ffi-v9.9.9-android-aarch64" "$T/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
python3 - "$T/android" <<'PY'
import sys
d = sys.argv[1]
lib = bytearray(bytes(range(256)) * (0x30000 // 256))
lib[:64] = b"\x7fELF\x02\x01\x01" + bytes(57)
body = bytes([0x5A]) * (65536 - 32)
lib[0x10000:0x20000] = b"\xfcOXICRYPT_FIPS_H" + body + b"\xfdOXICRYPT_FIPS_F"
open(f"{d}/bundle/oxicrypt-ffi-v9.9.9-android-aarch64/liboxicrypt_ffi.so.0", "wb").write(lib)
lib[0x10010:0x1fff0] = bytes(65536 - 32)
open(f"{d}/template.so", "wb").write(lib)
PY
ln -s liboxicrypt_ffi.so.0 "$T/android/bundle/oxicrypt-ffi-v9.9.9-android-aarch64/liboxicrypt_ffi.so"
tar -czf "$T/android/oxicrypt-ffi-v9.9.9-android-aarch64.tar.gz" -C "$T/android/bundle" oxicrypt-ffi-v9.9.9-android-aarch64
mkdir -p "$T/android/x86/oxicrypt-ffi-v9.9.9-android-x86_64"
cp "$T/android/bundle/oxicrypt-ffi-v9.9.9-android-aarch64/liboxicrypt_ffi.so.0" "$T/android/x86/oxicrypt-ffi-v9.9.9-android-x86_64/"
tar -czf "$T/android/oxicrypt-ffi-v9.9.9-android-x86_64.tar.gz" -C "$T/android/x86" oxicrypt-ffi-v9.9.9-android-x86_64
# The same library with its footer magic overwritten.
mkdir -p "$T/android/nofooter/oxicrypt-ffi-v9.9.9-android-aarch64"
python3 - "$T/android" <<'PY2'
import sys
d = sys.argv[1]
lib = bytearray(open(f"{d}/bundle/oxicrypt-ffi-v9.9.9-android-aarch64/liboxicrypt_ffi.so.0", "rb").read())
lib[0x1fff0:0x20000] = bytes(16)
open(f"{d}/nofooter/oxicrypt-ffi-v9.9.9-android-aarch64/liboxicrypt_ffi.so.0", "wb").write(lib)
PY2
tar -czf "$T/android/nofooter/oxicrypt-ffi-v9.9.9-android-aarch64.tar.gz" -C "$T/android/nofooter" oxicrypt-ffi-v9.9.9-android-aarch64
export ADB_SIGNED_SHA ADB_UNSIGNED_SHA
ADB_SIGNED_SHA="$(sha "$T/android/bundle/oxicrypt-ffi-v9.9.9-android-aarch64/liboxicrypt_ffi.so.0")"
ADB_UNSIGNED_SHA="$(sha "$T/android/template.so")"

cat > "$T/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$ADB_STUB/clang"
while [ $# -gt 0 ]; do
    if [ "$1" = -o ]; then printf 'harness\n' > "$2"; fi
    shift
done
STUB
cat > "$T/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf" <<'STUB'
#!/usr/bin/env bash
echo "  Machine:                           ${STUB_READELF_MACHINE:-AArch64}"
STUB
cat > "$T/bin/stub-sign" <<'STUB'
#!/usr/bin/env bash
sha="$(sha256sum < "$2" | cut -d' ' -f1)"
case "$1" in
    --show)
        echo "  slot at file offset ${STUB_SHOW_OFFSET:-0x10000}, RVA 0x10000"
        echo "    [0] Plain rva 0x00000000 file 0x00000000 len 65536 hole 0"
        echo "    [1] Plain rva 0x00020000 file 0x00020000 len 65536 hole 0" ;;
    --verify)
        [ -n "${STUB_SIGN_ACCEPT_ALL:-}" ] && { echo "verify ok: $2"; exit 0; }
        [ "$sha" = "$ADB_SIGNED_SHA" ] && { echo "verify ok: $2"; exit 0; }
        [ "$sha" = "$ADB_UNSIGNED_SHA" ] && [ -z "${STUB_SIGN_NO_DIAGNOSIS:-}" ] && { echo "$2: slot invalid: slot version 0: the slot holds no signature"; exit 2; }
        echo "$2: SignatureInvalid: the file does not match its signature"; exit 2 ;;
esac
STUB
cat > "$T/bin/adb" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$ADB_STUB/calls"
case "$1" in
    wait-for-device) exit 0 ;;
    push) mkdir -p "$ADB_STUB/dev"; cp "$2" "$ADB_STUB/dev/$(basename "$3")"; exit ;;
    shell) shift ;;
    *) exit 3 ;;
esac
case "$*" in
    "getprop ro.product.cpu.abi") echo "${ADB_ABI:-arm64-v8a}" ;;
    "getprop ro.build.version.release") [ -n "${ADB_EMPTY_RELEASE:-}" ] || echo 14 ;;
    "getprop ro.build.version.sdk") echo 34 ;;
    "getconf PAGESIZE") echo 16384 ;;
    true) exit 0 ;;
    false) exit 1 ;;
    "rm -rf "* | "chmod 755 "*) exit 0 ;;
    */harness" "*)
        sha="$(sha256sum < "$ADB_STUB/dev/$(basename "$2")" | cut -d' ' -f1)"
        if { [ "$sha" = "$ADB_SIGNED_SHA" ] && [ "${ADB_LIE:-}" != signed-refused ]; } \
            || { [ "$sha" != "$ADB_SIGNED_SHA" ] && [ "$sha" != "$ADB_UNSIGNED_SHA" ] && [ "${ADB_LIE:-}" = tampered-operational ]; } \
            || { [ "$sha" = "$ADB_UNSIGNED_SHA" ] && [ "${ADB_LIE:-}" = unsigned-operational ]; }; then
            echo "oxi_init=0 oxi_is_operational=1 oxi_integrity_status=1"
            echo "library: operational"
            exit 0
        fi
        if [ "$sha" = "$ADB_UNSIGNED_SHA" ]; then status=3; else status=2; fi
        [ "$sha" != "$ADB_UNSIGNED_SHA" ] || [ "${ADB_LIE:-}" != unsigned-status-10 ] || status=10
        echo "oxi_init=-1 oxi_is_operational=0 oxi_integrity_status=$status"
        echo "library: refused by the module's power-up tests"
        exit 1 ;;
    *) echo "stub adb: unhandled shell $*" >&2; exit 3 ;;
esac
STUB
chmod +x "$T/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/"* "$T/bin/stub-sign" "$T/bin/adb"

# device_check <name> [<archive>]: runs the check on <archive> (default the
# aarch64 bundle) with a fresh stub state in $T/adb-<name>.
device_check() {
    export ADB_STUB="$T/adb-$1"
    mkdir -p "$ADB_STUB"
    : > "$ADB_STUB/calls"
    env PATH="$T/bin:${device_path:-$PATH}" ANDROID_SERIAL=stub-device ANDROID_NDK_HOME="$T/ndk" \
        "$HERE/android-device-check.sh" "${2:-$T/android/oxicrypt-ffi-v9.9.9-android-aarch64.tar.gz}" "$T/bin/stub-sign"
}

unset ADB_ABI ADB_LIE
expect "device check: all three verdicts hold" 0 "verdict ok: the tampered control is refused as not matching its signature" \
    device_check good
out_good="$(device_check good 2>&1)" || true
check "device check: the unsigned verdict printed" grep -qxF "verdict ok: the unsigned control is refused as unsigned" <<<"$out_good"
check "device check: the signed verdict printed" grep -qxF "verdict ok: the signed library reaches operational" <<<"$out_good"
check "device check: the page size printed" grep -qxF "  page size: 16384" <<<"$out_good"
check "device check: the unsigned control pushed is the template" [ "$(sha "$T/adb-good/dev/unsigned.so")" = "$ADB_UNSIGNED_SHA" ]
check "device check: the signed library pushed as shipped" [ "$(sha "$T/adb-good/dev/signed.so")" = "$ADB_SIGNED_SHA" ]
check "device check: the harness linked for 16 KiB pages" \
    grep -qE -- "-Wl,-z,max-page-size=16384 -o .* .*/\.github/probes/ffi-operational\.c -ldl$" "$T/adb-good/clang"
# A PATH holding what the device check and its stubs call, without timeout.
mkdir -p "$T/notimeout"
for t in bash env dirname basename mktemp rm tar gzip find wc tr grep sed awk od cat head cp chmod mkdir cut cmp tee sha256sum python3; do
    ln -s "$(command -v "$t")" "$T/notimeout/$t"
done
check "device check: the PATH without timeout lacks it" bash -c "! PATH='$T/notimeout' command -v timeout"
device_path="$T/notimeout"
expect "device check: no timeout on PATH waits for the device without it" 0 \
    "verdict ok: the tampered control is refused as not matching its signature" device_check notimeout
unset device_path
check "device check: no timeout on PATH still waits for the device" \
    [ "$(grep -cx 'wait-for-device' "$T/adb-notimeout/calls")" = 2 ]

export ADB_LIE=signed-refused
expect "device check: the signed library refused fails" 1 "verdict FAILED: the signed library reaches operational" \
    device_check signedrefused

export ADB_LIE=tampered-operational
expect "device check: the tampered library operational fails" 1 \
    "verdict FAILED: the tampered control is refused as not matching its signature" device_check tamperedok

unset ADB_LIE
export ADB_ABI=x86_64
expect "device check: another ABI refused" 1 "the device's ABI is x86_64; oxicrypt-ffi-v9.9.9-android-aarch64.tar.gz is for arm64-v8a" \
    device_check abi
check "device check: another ABI: nothing pushed" bash -c "! grep -q '^push' '$T/adb-abi/calls'"
unset ADB_ABI

export ADB_LIE=unsigned-operational
expect "device check: the unsigned control operational fails" 1 \
    "verdict FAILED: the unsigned control is refused as unsigned" device_check unsignedok
export ADB_LIE=unsigned-status-10
expect "device check: the unsigned control refused as damage fails" 1 \
    "verdict FAILED: the unsigned control is refused as unsigned" device_check unsigned10
unset ADB_LIE

export STUB_SIGN_ACCEPT_ALL=1
expect "device check: a signer accepting the unsigned control fails" 1 \
    "FAILED: $T/bin/stub-sign --verify accepts the unsigned control" device_check acceptall
unset STUB_SIGN_ACCEPT_ALL
export STUB_SIGN_NO_DIAGNOSIS=1
expect "device check: a signer refusing the unsigned control for another reason fails" 1 \
    "--verify refuses the unsigned control without saying it holds no signature" device_check nodiagnosis
unset STUB_SIGN_NO_DIAGNOSIS
expect "device check: a library without the footer magic fails" 1 "no slot magics at 0x10000" \
    device_check nofooter "$T/android/nofooter/oxicrypt-ffi-v9.9.9-android-aarch64.tar.gz"

export STUB_SHOW_OFFSET=0xfff0
expect "device check: a slot offset 16 bytes early refused" 1 "no slot magics at 0xfff0" device_check early
unset STUB_SHOW_OFFSET
mkdir -p "$T/android/template/oxicrypt-ffi-v9.9.9-android-aarch64"
cp "$T/android/template.so" "$T/android/template/oxicrypt-ffi-v9.9.9-android-aarch64/liboxicrypt_ffi.so.0"
tar -czf "$T/android/template/oxicrypt-ffi-v9.9.9-android-aarch64.tar.gz" -C "$T/android/template" oxicrypt-ffi-v9.9.9-android-aarch64
expect "device check: a shipped library already unsigned refused" 1 \
    "the unsigned control differs from the signed library outside the slot body, or not at all (0 0)" \
    device_check template "$T/android/template/oxicrypt-ffi-v9.9.9-android-aarch64.tar.gz"
export ADB_EMPTY_RELEASE=1
expect "device check: an empty ro.build.version.release refused" 1 \
    "FAILED: device properties: release '', sdk '34', page size '16384'" device_check norelease
unset ADB_EMPTY_RELEASE

export STUB_READELF_MACHINE="Advanced Micro Devices X86-64"
expect "device check: a harness for another machine refused" 1 "the harness is not an ELF for AArch64" \
    device_check machine
cp "$T/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang" \
    "$T/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android24-clang"
export ADB_ABI=x86_64
expect "device check: an x86_64 bundle passes" 0 "verdict ok: the tampered control is refused as not matching its signature" \
    device_check x86 "$T/android/oxicrypt-ffi-v9.9.9-android-x86_64.tar.gz"
unset ADB_ABI STUB_READELF_MACHINE

# --- an inherited GIT_DIR ----------------------------------------------------
# Runs this suite once more the way a git hook would start it, with GIT_DIR
# naming a sentinel repository, and requires the sentinel's refs and
# configuration to be byte-identical afterwards. The inner run skips this
# section and the toolchain cases, which the outer run has already run.

if [ -z "${RELEASE_SCRIPTS_INNER:-}" ]; then
    git init -q -b main "$T/sentinel"
    git -C "$T/sentinel" -c user.name=Test -c user.email=tagger@example.org -c commit.gpgsign=false \
        commit -q --allow-empty -m sentinel
    sentinel() { git -C "$T/sentinel" for-each-ref; git -C "$T/sentinel" config --list --local; }
    before="$(sentinel)"
    check "inherited GIT_DIR: the sentinel has a ref" grep -q refs/heads/main <<<"$before"
    expect "inherited GIT_DIR: the suite still passes" 0 ", 0 failed" \
        env -u OXICRYPT_TEST_EXAMPLES GIT_DIR="$T/sentinel/.git" RELEASE_SCRIPTS_INNER=1 "$HERE/test-release-scripts.sh"
    check "inherited GIT_DIR: the sentinel is unchanged" [ "$(sentinel)" = "$before" ]
fi

echo "release scripts: $pass passed, $failed failed; examples run with their toolchains:${examples_ran:- none}"
[ "$failed" -eq 0 ] && [ "$pass" -gt 0 ]
