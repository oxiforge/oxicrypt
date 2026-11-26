#!/usr/bin/env bash
# Tests check-release-tag.sh, attach-draft.sh, release-archive-check.sh,
# android-device-check.sh, list-caller-entropy-sites.sh and
# check-example-inputs.sh against fixtures.
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
# Its examples mode runs examples/*/run.sh against stub toolchains printing
# the nine expected lines, which test which examples run, which are skipped
# and which are required and how a line that differs from examples/README.md
# is reported, and against a PATH that hides every toolchain. With
# OXICRYPT_TEST_EXAMPLES=1 it also runs them with the PATH it is given
# against a second stand-in, built from the shipped oxicrypt.h, whose ML-DSA
# and ML-KEM functions keep their contracts (a signature verifies only
# unchanged, a ciphertext decapsulates to its secret only unchanged) without
# being either algorithm, and whose oxi_drbg_instantiate fails when
# STUB_DRBG_INSTANTIATE_FAILS is set. There each example whose toolchain is
# present must pass and each other must be reported as skipped, and each
# program with its expected digest altered must exit 1 printing both values.
# Those cases need the toolchains the script names (cc, python3 or python,
# go and the C compiler `go env CC` names, node and npm, java and javac 22 or
# later, dotnet with a .NET SDK 10 or later) and network access for the
# packages npm and dotnet fetch. When OXICRYPT_TEST_BUNDLE and
# OXICRYPT_TEST_FAULT_BUNDLE also name library archives, a signed library and
# a signed library built with the fault-injection feature, and
# OXICRYPT_TEST_SIGNER names the oxicrypt-integrity-sign that signed them,
# the examples also run against the real libraries: every one must pass
# against the signed library, exit 1 printing integrity status 2 against a
# copy with one signed byte flipped as release-load-check.sh flips it, and
# exit 1 printing code 33 from oxi_drbg_instantiate against the
# fault-injection library with OXI_FAULT=poison-entropy. When
# OXICRYPT_TEST_CLI also names a CLI archive signed the same way, the
# crosscheck mode must pass against it, and must fail for every example when
# the archive's `oxi` flips byte 0 of the signature before verifying it.
# With OXICRYPT_TEST_REQUIRE_BUILT=1 the suite fails unless those cases ran
# and every one of the six languages ran.
# check-example-inputs.sh runs against copies of examples/ whose six how-tos
# are replaced by stand-ins stating only the fixed inputs, as
# examples/README.md states them, and against the repository's own files.
# The crosscheck mode runs against the stub toolchains and a stub `oxi`
# whose answers can be made to disagree with the examples'.
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
# <integrity lines> for --integrity and exiting <status> (default 0),
# printing `self-test indicator: <indicator>` for `selftest --quiet`, and
# answering the ML-DSA-87 and ML-KEM-1024 round trips: verify exits
# $STUB_VERIFY_EXIT (default 0), and encaps prints $STUB_SS, as decaps does
# unless $STUB_DECAPS_SS names another secret.
STUB_SS="$(printf '%064d' 0 | tr 0 5)"
cli_archive() {
    local d="$T/archives/$1/oxicrypt-cli-test" bin="${5:-oxi}"
    mkdir -p "$d"
    {
        echo '#!/usr/bin/env bash'
        echo 'case "$*" in'
        printf -- '--integrity) printf %%s %q; exit %s ;;\n' "$2" "${4:-0}"
        printf '"selftest --quiet") echo "self-test indicator: %s" ;;\n' "$3"
        echo '"ml-dsa keygen 87 "*) : > pk.bin && : > sk.bin ;;'
        echo '"ml-dsa sign 87 "*) : > sig.bin ;;'
        echo '"ml-dsa verify 87 "*) exit "${STUB_VERIFY_EXIT:-0}" ;;'
        echo '"ml-kem keygen 1024 "*) : > ek.bin && : > dk.bin ;;'
        printf '"ml-kem encaps 1024 "*) : > ct.bin && echo %s ;;\n' "$STUB_SS"
        printf '"ml-kem decaps 1024 "*) echo "${STUB_DECAPS_SS:-%s}" ;;\n' "$STUB_SS"
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
expect "cli: pq round trips pass" 0 \
    "ok: ./oxi from the extracted archive passes its integrity test, its self-tests and the ML-DSA-87 and ML-KEM-1024 round trips" \
    archive_check cli "$T/archives/good.tar.gz" "$FP"
expect "cli: a verify that exits 5 fails the check" 1 \
    "FAILED: oxi ml-dsa verify 87 --pk pk.bin --sig sig.bin message.txt exited 5" \
    env STUB_VERIFY_EXIT=5 "$HERE/release-archive-check.sh" cli "$T/archives/good.tar.gz" "$FP"
expect "cli: secrets that differ fail the check" 1 \
    "FAILED: oxi ml-kem decaps 1024 exited 0 printing \"$(printf '%064d' 0 | tr 0 6)\", not the secret encaps printed" \
    env STUB_DECAPS_SS="$(printf '%064d' 0 | tr 0 6)" "$HERE/release-archive-check.sh" cli "$T/archives/good.tar.gz" "$FP"
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
# The stand-in carries the ABI number the README names, read from the source
# that defines it, so a version bump moves this fixture with it.
ABI="$(sed -nE 's/.*OXI_ABI_VERSION: i32 = ([0-9]+);.*/\1/p' "$HERE/../crates/oxicrypt-ffi/src/abi_version.rs")"
[ -n "$ABI" ] || { echo "test-release-scripts: cannot read OXI_ABI_VERSION" >&2; exit 2; }
ffi_archive one "$ABI"
ffi_archive eight 8
expect "archive library: the README's examples pass against the stand-in" 0 \
    "ok: the README's C and Python examples run against liboxicrypt_ffi.so.$ABI from the extracted archive" \
    archive_check library "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
out_initfail="$(STUB_OXI_INIT_FAILS=1 archive_check library "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz" 2>&1)" \
    && status=0 || status=$?
check "archive library: a failing oxi_init exits 1" [ "$status" = 1 ]
check "archive library: a failing oxi_init fails the C example" \
    grep -qxF "FAILED: the README's C example exited 1" <<<"$out_initfail"
check "archive library: a failing oxi_init fails the Python example" \
    grep -qxF "FAILED: the README's Python example exited 1" <<<"$out_initfail"
expect "archive library: a bundle without the README's library name refused" 1 \
    "FAILED: the README's Python example loads liboxicrypt_ffi.so.$ABI, which the bundle does not hold" \
    archive_check library "$T/ffi/eight/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
mkdir -p "$T/ffi/linked/oxicrypt-ffi-v9.9.9-linux-x86_64"
ln -s "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.$ABI" "$T/ffi/linked/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.$ABI"
tar -czf "$T/ffi/linked/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz" -C "$T/ffi/linked" oxicrypt-ffi-v9.9.9-linux-x86_64
expect "archive library: a versioned library that is a link out of the bundle refused" 1 \
    "FAILED: liboxicrypt_ffi.so.$ABI is a symbolic link out of the bundle" \
    archive_check library "$T/ffi/linked/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"

# ffi_variant <name>: a copy of the `one` bundle under $T/ffi/<name>, which
# the caller changes and packs with ffi_pack <name>.
ffi_variant() { mkdir -p "$T/ffi/$1"; cp -a "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64" "$T/ffi/$1/"; }
ffi_pack() { tar -czf "$T/ffi/$1/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz" -C "$T/ffi/$1" oxicrypt-ffi-v9.9.9-linux-x86_64; }
cp "$T/ffi/one/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.$ABI" "$T/ffi/outside.so"
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
cp "$T/ffi/two/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.$ABI" "$T/ffi/two/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so.$((ABI + 1))"
ffi_pack two
expect "archive library: two shared libraries refused" 1 \
    "FAILED: oxicrypt-ffi-v9.9.9-linux-x86_64 holds more than one shared library" \
    archive_check library "$T/ffi/two/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
ffi_variant header
ln -sfn oxicrypt.h "$T/ffi/header/oxicrypt-ffi-v9.9.9-linux-x86_64/liboxicrypt_ffi.so"
ffi_pack header
expect "archive library: the unversioned alias linking to another file in the bundle refused" 1 \
    "FAILED: liboxicrypt_ffi.so links to oxicrypt.h, not to liboxicrypt_ffi.so.$ABI" \
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
for skip in "c (no cc or gcc on PATH)" "python (no python3 or python on PATH)" "go (no go on PATH)" \
    "node (no node on PATH)" "java (no java on PATH)" "csharp (no dotnet on PATH)"; do
    check "archive examples: skip: $skip" grep -qxF "skip: $skip" <<<"$out_examples"
done
expect "archive examples: a required language without its toolchain fails" 1 \
    "FAILED: examples/node is required here and no node on PATH" \
    env PATH="$T/minpath" OXICRYPT_EXAMPLES_REQUIRED=node "$HERE/release-archive-check.sh" examples "$FFI_ONE"

# Stub toolchains: each program prints the nine lines examples/README.md
# expects, so these cases test which examples the script runs and how it
# compares their output, not the examples. $STUB_GO_VERSION,
# $STUB_DOTNET_SDKS and $STUB_JAVAC_VERSION set what `go version`, `dotnet
# --list-sdks` and `javac -version` report. $STUB_EXAMPLE_FAIL=<language>
# makes that language's program exit 1 without printing. The java and javac
# stubs sit in their own directory, on PATH only where a case puts them
# there.
mkdir -p "$T/toolstub" "$T/javastub" "$T/toolstub-nocc"
NINE_LINES="$(printf '%s\n' \
    "sha256 abc ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" \
    "drbg instantiated" "ml-dsa-87 keygen ok" "ml-dsa-87 verify ok" "ml-dsa-87 verify-tampered rejected 22" \
    "ml-kem-1024 keygen ok" "ml-kem-1024 decaps match" "ml-kem-1024 decaps-tampered differs" \
    "ml-kem-1024 ss $(printf '%064d' 0 | tr 0 7)")"
# A program run in its decaps mode prints `ml-kem-1024 ss $STUB_REVERSE_SS`,
# by default the secret the stub `oxi` of the crosscheck cases encapsulates.
fail_or_lines() {
    printf '#!/usr/bin/env bash\n[ "${STUB_EXAMPLE_FAIL:-}" != %s ] || exit 1\n' "$1"
    printf 'for a in "$@"; do [ "$a" != decaps ] || { echo "ml-kem-1024 ss ${STUB_REVERSE_SS:-%s}"; exit 0; }; done\n' "$STUB_SS"
    printf 'printf %%s\\\\n %q\n' "$NINE_LINES"
}
cat > "$T/toolstub/go" <<'STUB'
#!/usr/bin/env bash
case "$1" in
    version) echo "go version go${STUB_GO_VERSION:-1.24.0} linux/amd64" ;;
    env) echo stub-cc ;;
    build) cp "$(dirname "$0")/go-program" "$3" ;;
    *) exit 3 ;;
esac
STUB
fail_or_lines go >"$T/toolstub/go-program"
cat > "$T/toolstub/dotnet" <<'STUB'
#!/usr/bin/env bash
case "$1" in
    --list-sdks) printf '%s\n' "${STUB_DOTNET_SDKS:-10.0.100 [/stub/sdk]}" ;;
    build) ;;
    *) exec "$(dirname "$0")/dotnet-program" "$@" ;;
esac
STUB
fail_or_lines csharp > "$T/toolstub/dotnet-program"
fail_or_lines node >"$T/toolstub/node"
printf '#!/usr/bin/env bash\n' > "$T/toolstub/npm"
printf '#!/usr/bin/env bash\n' > "$T/toolstub/stub-cc"
cat > "$T/javastub/javac" <<'STUB'
#!/usr/bin/env bash
[ "$1" != -version ] || echo "javac ${STUB_JAVAC_VERSION:-21}"
STUB
fail_or_lines java >"$T/javastub/java"
chmod +x "$T/toolstub/"* "$T/javastub/"*
for t in go go-program dotnet dotnet-program node npm; do ln -s "$T/toolstub/$t" "$T/toolstub-nocc/$t"; done
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

# examples_tree <name>: a copy of release-archive-check.sh and examples/
# under $T/trees/<name>, for the cases that change a file the script or an
# example reads.
examples_tree() {
    mkdir -p "$T/trees/$1/scripts"
    cp "$HERE/release-archive-check.sh" "$T/trees/$1/scripts/"
    cp -R "$HERE/../examples" "$T/trees/$1/examples"
}
examples_tree altered-line
sed -i.orig 's/^ml-dsa-87 verify ok$/ml-dsa-87 verify okay/' "$T/trees/altered-line/examples/README.md"
check "examples: one expected line altered: the copy differs in one line" \
    [ "$(diff "$T/trees/altered-line/examples/README.md.orig" "$T/trees/altered-line/examples/README.md" | grep -c '^>')" = 1 ]
out_examples="$(env PATH="$stub_path" OXICRYPT_EXAMPLES_REQUIRED="go node csharp" \
    "$T/trees/altered-line/scripts/release-archive-check.sh" examples "$FFI_ONE" 2>&1)" && status=0 || status=$?
check "examples: one expected line altered fails" [ "$status" = 1 ]
for language in csharp go node; do
    check "examples: one expected line altered fails examples/$language" grep -qxF \
        "FAILED: examples/$language printed \"ml-dsa-87 verify ok\" as line 4, not \"ml-dsa-87 verify okay\"" <<<"$out_examples"
done
examples_tree no-ss-line
sed -i.orig '/^ml-kem-1024 ss </d' "$T/trees/no-ss-line/examples/README.md"
expect "archive examples: a README block without the ss line fails" 1 \
    "FAILED: examples/README.md has no \`\`\`text block of eight fixed lines and the ml-kem-1024 ss line" \
    env PATH="$stub_path" "$T/trees/no-ss-line/scripts/release-archive-check.sh" examples "$FFI_ONE"
printf '#!/usr/bin/env bash\nprintf %%s\\\\n %q extra\n' "$NINE_LINES" > "$T/toolstub/node"
expect "archive examples: a tenth line fails" 1 "FAILED: examples/node printed more than 9 lines" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" ""
printf '#!/usr/bin/env bash\nprintf %%s\\\\n %q\n' "${NINE_LINES%?}" > "$T/toolstub/node"
expect "archive examples: a shared secret one digit short fails" 1 \
    "FAILED: examples/node printed \"ml-kem-1024 ss $(printf '%063d' 0 | tr 0 7)\" as line 9, not ml-kem-1024 ss and 64 hex digits" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" ""
for secret in "$(printf '%063d' 0 | tr 0 7)g" "$(printf '%064d' 0 | tr 0 A)"; do
    printf '#!/usr/bin/env bash\nprintf %%s\\\\n %q\n' "${NINE_LINES%"ml-kem-1024 ss "*}ml-kem-1024 ss $secret" > "$T/toolstub/node"
    expect "archive examples: a shared secret $secret fails" 1 \
        "FAILED: examples/node printed \"ml-kem-1024 ss $secret\" as line 9, not ml-kem-1024 ss and 64 hex digits" \
        stub_examples 1.24.0 "10.0.100 [/stub/sdk]" ""
done
printf '#!/usr/bin/env bash\nprintf %%s\\\\n %q\n' "${NINE_LINES%$'\n'*}" > "$T/toolstub/node"
expect "archive examples: eight lines fail" 1 "FAILED: examples/node printed 8 lines, not 9" \
    stub_examples 1.24.0 "10.0.100 [/stub/sdk]" ""
fail_or_lines node > "$T/toolstub/node"

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
        c) command -v cc >/dev/null || command -v gcc >/dev/null ;;
        python) command -v python3 >/dev/null || command -v python >/dev/null ;;
        *) return 1 ;;
    esac
}

# section <language>: the lines release-archive-check.sh printed for
# examples/<language>, read from standard input: its `(exit N):` heading and
# the program's output after it.
section() {
    awk -v head="examples/$1 (exit " '
        index($0, head) == 1 { on = 1; print; next }
        /^examples\/[a-z]+ \(exit [0-9]+\):$/ { on = 0 }
        on
    '
}

# each_prints <case> <output> <line...>: for every language in $examples_ran,
# <output> reports `FAILED: examples/<language> exited 1`, and its section
# for that language holds each <line> as a whole line.
each_prints() {
    local name="$1" output="$2" language line
    shift 2
    for language in $examples_ran; do
        check "$name: examples/$language exited 1" grep -qxF "FAILED: examples/$language exited 1" <<<"$output"
        for line in "$@"; do
            check "$name: examples/$language prints \"$line\"" grep -qxF -- "$line" <<<"$(section "$language" <<<"$output")"
        done
    done
}

examples_ran=""
built_library="not run (set OXICRYPT_TEST_EXAMPLES=1, OXICRYPT_TEST_BUNDLE, OXICRYPT_TEST_FAULT_BUNDLE and OXICRYPT_TEST_SIGNER, and OXICRYPT_TEST_CLI for crosscheck)"
if [ "${OXICRYPT_TEST_EXAMPLES:-}" = 1 ]; then
    # The examples' stand-in: the shipped header, and functions with the
    # ML-DSA and ML-KEM contracts the examples check, over an FNV-1a digest
    # and a splitmix64 stream rather than the algorithms.
    EX="$T/ffi/examples/oxicrypt-ffi-v9.9.9-linux-x86_64"
    mkdir -p "$EX"
    cp "$HERE/../crates/oxicrypt-ffi/include/oxicrypt.h" "$EX/"
    {
        printf 'static const unsigned char abc_digest[32] = { %s };\n' \
            "$(printf '%s' ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad | sed -E 's/(..)/0x\1, /g')"
        cat <<'C'
#include <stdlib.h>
#include <string.h>
#include "oxicrypt.h"
struct OxiDrbg { uint64_t state; };
static int init_failed;
static uint64_t next(uint64_t *s) {
    uint64_t z = (*s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
static void stream(uint64_t seed, uint8_t *out, size_t n) { while (n--) *out++ = (uint8_t)next(&seed); }
static uint64_t fnv(uint64_t h, const uint8_t *p, size_t n) { while (n--) h = (h ^ *p++) * 0x100000001b3ULL; return h; }
int oxi_init(int profile) { (void)profile; init_failed = getenv("STUB_OXI_INIT_FAILS") != NULL; return init_failed ? 2 : 0; }
int oxi_integrity_status(void) { return init_failed ? 2 : 1; }
int oxi_integrity_key_fingerprint(uint8_t *out, uintptr_t n) { if (n < 32) return 11; memset(out, 0xaa, 32); return 0; }
int oxi_sha256(const uint8_t *d, uintptr_t n, uint8_t *out) {
    if (n != 3 || memcmp(d, "abc", 3) != 0) return 1;
    memcpy(out, abc_digest, 32);
    return 0;
}
int oxi_hmac_drbg_sha256_new_rbg(OxiDrbg **out) { *out = calloc(1, sizeof **out); return *out ? 0 : 255; }
int oxi_drbg_instantiate(OxiDrbg *h, const uint8_t *p, uintptr_t n) {
    if (getenv("STUB_DRBG_INSTANTIATE_FAILS")) return 33;
    h->state = fnv(0xcbf29ce484222325ULL, p, n);
    return 0;
}
void oxi_drbg_free(OxiDrbg *h) { free(h); }
int oxi_ml_dsa_87_keygen_rbg(OxiDrbg *rbg, uint8_t *pk, uint8_t *sk, uint8_t *seed) {
    (void)seed;
    stream(next(&rbg->state), pk, 2592);
    memcpy(sk, pk, 2592);
    stream(next(&rbg->state), sk + 2592, 4896 - 2592);
    return 0;
}
int oxi_ml_dsa_87_sign(const uint8_t *sk, const uint8_t *m, uintptr_t m_len, const uint8_t *ctx, uintptr_t ctx_len, uint8_t *sig) {
    (void)ctx; (void)ctx_len;
    stream(fnv(fnv(1, sk, 2592), m, m_len), sig, 4627);
    return 0;
}
int oxi_ml_dsa_87_verify(const uint8_t *pk, const uint8_t *m, uintptr_t m_len, const uint8_t *ctx, uintptr_t ctx_len, const uint8_t *sig) {
    uint8_t want[4627];
    (void)ctx; (void)ctx_len;
    stream(fnv(fnv(1, pk, 2592), m, m_len), want, sizeof want);
    return memcmp(want, sig, sizeof want) == 0 ? 0 : 22;
}
int oxi_ml_kem_1024_keygen_rbg(OxiDrbg *rbg, uint8_t *ek, uint8_t *dk, uint8_t *seed) {
    (void)seed;
    stream(next(&rbg->state), ek, 1568);
    memcpy(dk, ek, 1568);
    stream(next(&rbg->state), dk + 1568, 3168 - 1568);
    return 0;
}
int oxi_ml_kem_1024_encapsulate_rbg(const uint8_t *ek, OxiDrbg *rbg, uint8_t *ss, uint8_t *ct) {
    stream(fnv(next(&rbg->state), ek, 1568), ct, 1568);
    stream(fnv(fnv(2, ek, 1568), ct, 1568), ss, 32);
    return 0;
}
int oxi_ml_kem_1024_decapsulate(const uint8_t *dk, const uint8_t *ct, uint8_t *ss) {
    stream(fnv(fnv(2, dk, 1568), ct, 1568), ss, 32);
    return 0;
}
C
    } > "$T/ffi/examples-stub.c"
    cc -Wall -Wextra -Werror -shared -fPIC -Wl,-soname,"liboxicrypt_ffi.so.$ABI" -I"$EX" \
        -o "$EX/liboxicrypt_ffi.so.$ABI" "$T/ffi/examples-stub.c"
    ln -s "liboxicrypt_ffi.so.$ABI" "$EX/liboxicrypt_ffi.so"
    EX_STAND="$T/ffi/examples/oxicrypt-ffi-v9.9.9-linux-x86_64.tar.gz"
    tar -czf "$EX_STAND" -C "$T/ffi/examples" oxicrypt-ffi-v9.9.9-linux-x86_64

    out_examples="$(archive_check examples "$EX_STAND" 2>&1)" && status=0 || status=$?
    for language in c python go node java csharp; do
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
            env OXICRYPT_EXAMPLES_REQUIRED="$examples_ran" "$HERE/release-archive-check.sh" examples "$EX_STAND"
    else
        check "archive examples: no toolchain present fails" [ "$status" = 1 ]
    fi
    out_examples="$(STUB_OXI_INIT_FAILS=1 archive_check examples "$EX_STAND" 2>&1)" && status=0 || status=$?
    check "archive examples: a failing oxi_init exits 1" [ "$status" = 1 ]
    each_prints "archive examples: a failing oxi_init" "$out_examples" \
        "oxi_init returned 2: the module refused to start" "integrity status 2"
    out_examples="$(STUB_DRBG_INSTANTIATE_FAILS=1 archive_check examples "$EX_STAND" 2>&1)" && status=0 || status=$?
    check "archive examples: a failing oxi_drbg_instantiate exits 1" [ "$status" = 1 ]
    each_prints "archive examples: a failing oxi_drbg_instantiate" "$out_examples" "oxi_drbg_instantiate returned 33"

    # Each program's expected digest, and only that, is altered in a copy.
    examples_tree altered-value
    altered=0
    for program in c/example.c python/example.py go/main.go node/example.js java/Example.java csharp/Program.cs; do
        f="$T/trees/altered-value/examples/$program"
        [ "$(grep -c ba7816bf "$f")" = 1 ] && sed -i.orig 's/ba7816bf/ca7816bf/' "$f" \
            && [ "$(grep -c ca7816bf "$f")" = 1 ] && altered=$((altered + 1))
    done
    check "examples: altered expected value: each of the six programs altered once" [ "$altered" = 6 ]
    out_examples="$("$T/trees/altered-value/scripts/release-archive-check.sh" examples "$EX_STAND" 2>&1)" && status=0 || status=$?
    check "examples: altered expected value exits 1" [ "$status" = 1 ]
    each_prints "examples: altered expected value exits 1" "$out_examples" \
        "expected: sha256 abc ca7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" \
        "     got: sha256 abc ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    if [ -n "${OXICRYPT_TEST_BUNDLE:-}" ] && [ -n "${OXICRYPT_TEST_FAULT_BUNDLE:-}" ] && [ -n "${OXICRYPT_TEST_SIGNER:-}" ]; then
        built_library="run"
        expect "examples: every example passes against the built library" 0 "ok: the examples for" \
            env OXICRYPT_EXAMPLES_REQUIRED="$examples_ran" "$HERE/release-archive-check.sh" examples "$OXICRYPT_TEST_BUNDLE"

        # The tamper fixture: a copy of the signed library with the byte
        # release-load-check.sh flips flipped.
        mkdir -p "$T/tamper"
        tar -xzf "$OXICRYPT_TEST_BUNDLE" -C "$T/tamper"
        tdir="$(find "$T/tamper" -mindepth 1 -maxdepth 1 -type d)"
        tlib="$(find "$tdir" -maxdepth 1 -type f -name 'liboxicrypt_ffi.so.*')"
        "$OXICRYPT_TEST_SIGNER" --show "$tlib" > "$T/tamper.show"
        offset="$(python3 "$HERE/../.github/probes/extent-tamper-offset.py" "$T/tamper.show" "$tlib")"
        python3 "$HERE/../.github/probes/flip-byte.py" "$tlib" "$offset"
        check "examples: oxi_init failure exits 1: the tampered copy fails --verify" \
            bash -c '! "$1" --verify "$2" >/dev/null 2>&1' _ "$OXICRYPT_TEST_SIGNER" "$tlib"
        tar -czf "$T/tampered.tar.gz" -C "$T/tamper" "$(basename "$tdir")"
        out_examples="$(archive_check examples "$T/tampered.tar.gz" 2>&1)" && status=0 || status=$?
        check "examples: oxi_init failure exits 1" [ "$status" = 1 ]
        each_prints "examples: oxi_init failure exits 1" "$out_examples" \
            "oxi_init returned 2: the module refused to start" "integrity status 2"

        expect "examples: drbg instantiate failure exits 1: control without OXI_FAULT passes" 0 "ok: the examples for" \
            env OXICRYPT_EXAMPLES_REQUIRED="$examples_ran" "$HERE/release-archive-check.sh" examples "$OXICRYPT_TEST_FAULT_BUNDLE"
        out_examples="$(OXI_FAULT=poison-entropy archive_check examples "$OXICRYPT_TEST_FAULT_BUNDLE" 2>&1)" \
            && status=0 || status=$?
        check "examples: drbg instantiate failure exits 1" [ "$status" = 1 ]
        each_prints "examples: drbg instantiate failure exits 1" "$out_examples" "oxi_drbg_instantiate returned 33"

        if [ -n "${OXICRYPT_TEST_CLI:-}" ]; then
            expect "crosscheck: every example agrees with oxi" 0 "on every object, against" \
                env OXICRYPT_EXAMPLES_REQUIRED="$examples_ran" "$HERE/release-archive-check.sh" crosscheck \
                "$OXICRYPT_TEST_CLI" "$OXICRYPT_TEST_BUNDLE"
            # The same CLI archive, with `oxi` a wrapper that flips byte 0
            # of the signature file before the real oxi verifies it, and
            # records that byte before and after in $T/flip.log. The wrapper
            # replaces a Unix `oxi`; an archive holding `oxi.exe` is not
            # handled.
            mkdir -p "$T/flipcli"
            tar -xzf "$OXICRYPT_TEST_CLI" -C "$T/flipcli"
            cdir="$(find "$T/flipcli" -mindepth 1 -maxdepth 1 -type d)"
            if [ -f "$cdir/oxi" ]; then
                mv "$cdir/oxi" "$cdir/oxi-real"
                : > "$T/flip.log"
                {
                    echo '#!/usr/bin/env bash'
                    echo 'if [ "$1 $2" = "ml-dsa verify" ]; then'
                    printf '    before="$(od -An -tx1 -N1 sig.bin)"\n'
                    printf '    python3 %q sig.bin 0 || exit 99\n' "$HERE/../.github/probes/flip-byte.py"
                    printf '    echo "$before $(od -An -tx1 -N1 sig.bin)" >> %q\n' "$T/flip.log"
                    echo 'fi'
                    echo 'exec "$(dirname "$0")/oxi-real" "$@"'
                } > "$cdir/oxi"
                chmod +x "$cdir/oxi"
                tar -czf "$T/flipcli.tar.gz" -C "$T/flipcli" "$(basename "$cdir")"
                out_examples="$("$HERE/release-archive-check.sh" crosscheck "$T/flipcli.tar.gz" "$OXICRYPT_TEST_BUNDLE" 2>&1)" \
                    && status=0 || status=$?
                check "crosscheck: a flipped signature byte fails" [ "$status" = 1 ]
                for language in $examples_ran; do
                    check "crosscheck: a flipped signature byte fails crosscheck/$language" grep -qxF \
                        "FAILED: crosscheck/$language: oxi ml-dsa verify exited 5 on the program's signature" <<<"$out_examples"
                done
                check "crosscheck: a flipped signature byte: one flip per example" \
                    [ "$(grep -c '' "$T/flip.log")" = "$(wc -w <<<"$examples_ran" | tr -d ' ')" ]
                check "crosscheck: a flipped signature byte: byte 0 changed every time" \
                    awk 'NF != 2 || $1 == $2 { bad = 1 } END { exit bad || NR == 0 }' "$T/flip.log"
            else
                echo "crosscheck: the flipped-signature case needs a CLI archive holding oxi, not oxi.exe"
            fi
        fi
    fi
else
    echo "examples cases: toolchains not exercised (set OXICRYPT_TEST_EXAMPLES=1)"
fi
echo "examples cases against a built library: $built_library"
# OXICRYPT_TEST_REQUIRE_BUILT=1 makes cases that could not run a failure, so
# a job meant to run them cannot pass by skipping them.
if [ "${OXICRYPT_TEST_REQUIRE_BUILT:-}" = 1 ]; then
    check "required: the built-library cases ran" [ "$built_library" = run ]
    check "required: the crosscheck cases ran" [ -n "${OXICRYPT_TEST_CLI:-}" ]
    for language in c python go node java csharp; do
        check "required: examples/$language ran" grep -qw -- "$language" <<<"$examples_ran"
    done
fi
expect "archive examples: a wrong argument count is a usage error" 1 "usage: release-archive-check.sh examples" \
    archive_check examples
expect "crosscheck: a wrong argument count is a usage error" 1 "usage: release-archive-check.sh crosscheck" \
    archive_check crosscheck "$T/archives/good.tar.gz"
examples_tree no-nist
sed -i.orig '/^## A known answer from NIST$/d' "$T/trees/no-nist/examples/README.md"
expect "crosscheck: a README without the known answer fails" 1 \
    "FAILED: examples/README.md has no known-answer section holding a 64-hex-digit seed and digest" \
    "$T/trees/no-nist/scripts/release-archive-check.sh" crosscheck "$T/archives/good.tar.gz" "$FFI_ONE"

# A stub `oxi` answering the crosscheck: verify exits $STUB_VERIFY_EXIT,
# decaps prints the stub programs' secret or $STUB_DECAPS_SS, encaps prints
# $STUB_SS, and hash prints the known-answer digest or $STUB_DIGEST.
NIST_DIGEST=40298270777d3306d2fcb6b4691d7a7ab799cd1069eea88f843cf0ec26d4b01f
mkdir -p "$T/archives/xc/oxicrypt-cli-test"
{
    echo '#!/usr/bin/env bash'
    echo 'case "$1 $2" in'
    echo '    "ml-dsa verify") exit "${STUB_VERIFY_EXIT:-0}" ;;'
    printf '    "ml-kem decaps") echo "${STUB_DECAPS_SS:-%s}" ;;\n' "$(printf '%064d' 0 | tr 0 7)"
    printf '    "ml-kem encaps") echo %s ;;\n' "$STUB_SS"
    echo '    "ml-dsa keygen") exit 0 ;;'
    printf '    "hash sha256") echo "${STUB_DIGEST:-%s}  $3" ;;\n' "$NIST_DIGEST"
    echo '    *) exit 2 ;;'
    echo 'esac'
} > "$T/archives/xc/oxicrypt-cli-test/oxi"
chmod +x "$T/archives/xc/oxicrypt-cli-test/oxi"
tar -czf "$T/archives/xc.tar.gz" -C "$T/archives/xc" oxicrypt-cli-test
# xc [<NAME=value>...]: the crosscheck on the stub archives with the stub
# toolchains, node required, and the given environment.
xc() { env PATH="$stub_path" OXICRYPT_EXAMPLES_REQUIRED=node "$@" "$HERE/release-archive-check.sh" crosscheck "$T/archives/xc.tar.gz" "$FFI_ONE"; }
expect "crosscheck: the stub oxi agreeing passes" 0 "ok: the examples for csharp go node agree with oxi on every object" xc
expect "crosscheck: a verify exiting 5 fails" 1 "FAILED: crosscheck/node: oxi ml-dsa verify exited 5 on the program's signature" \
    xc STUB_VERIFY_EXIT=5
expect "crosscheck: a decaps secret that differs fails" 1 \
    "FAILED: crosscheck/node: oxi ml-kem decaps exited 0 printing \"$(printf '%064d' 0 | tr 0 6)\", not the program's secret" \
    xc STUB_DECAPS_SS="$(printf '%064d' 0 | tr 0 6)"
expect "crosscheck: a reverse-direction secret that differs fails" 1 \
    "FAILED: crosscheck/node: the program's decaps mode exited 0 printing \"ml-kem-1024 ss $(printf '%064d' 0 | tr 0 6)\", not oxi's secret $STUB_SS" \
    xc STUB_REVERSE_SS="$(printf '%064d' 0 | tr 0 6)"
expect "crosscheck: a known-answer digest that differs fails" 1 \
    "FAILED: crosscheck/node: oxi hash sha256 nist.pk exited 0 printing \"$(printf '%064d' 0)  nist.pk\", not \"$NIST_DIGEST  nist.pk\"" \
    xc STUB_DIGEST="$(printf '%064d' 0)"

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
mkdir -p "$T/pestub" "$T/readobjstub" "$T/machostub" "$T/elfstub" "$T/nonm" "$T/noreadelf"
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
# The exported names are $STUB_PE_EXPORTS, separated by spaces.
printf 'The Export Tables (interpreted .rdata section contents)\n\n'
printf 'Export Address Table -- Ordinal Base 1\n'
printf '\t          Ordinal  Address  Type\n'
printf '\t[   0] +base[   1] 00001000 Export RVA\n'
printf '\n'
printf '[Ordinal/Name Pointer] Table -- Ordinal Base 1\n'
printf '\t          Ordinal   Hint Name\n'
i=0
for name in ${STUB_PE_EXPORTS:-oxi_sha256}; do
    printf '\t[%4d] +base[%4d]  %04x %s\n' "$i" "$((i + 1))" "$i" "$name"
    i=$((i + 1))
done
printf '\n'
STUB
# The --coff-exports listing is the one llvm-readobj 21 prints for a DLL; the
# exported names are $STUB_READOBJ_EXPORTS, separated by spaces.
cat > "$T/readobjstub/llvm-readobj" <<'STUB'
#!/usr/bin/env bash
printf '\nFile: %s\nFormat: COFF-x86-64\nArch: x86_64\nAddressSize: 64bit\n' "${@: -1}"
case "$1" in
    --coff-imports)
        printf 'Import {\n  Name: KERNEL32.dll\n  ImportLookupTableRVA: 0x22000\n  ImportAddressTableRVA: 0x22500\n'
        printf '  Symbol: CreateFileW (6)\n  Symbol:  (5)\n}\n' ;;
    --coff-exports)
        i=1
        for name in ${STUB_READOBJ_EXPORTS:-oxi_sha256}; do
            printf 'Export {\n  Ordinal: %d\n  Name: %s\n  RVA: 0x%x\n}\n' "$i" "$name" "$((0x1000 + i))"
            i=$((i + 1))
        done ;;
    *) exit 3 ;;
esac
STUB
# The exports `nm -g -U` lists are $STUB_NM_EXPORTS, one per line.
cat > "$T/machostub/nm" <<'STUB'
#!/usr/bin/env bash
case "$1 $2 $3 $4" in
    "-u -arch arm64 "*) printf '_free\n_malloc\n' ;;
    "-g -U -arch arm64") printf '%b' "${STUB_NM_EXPORTS:-_oxi_sha256\n}" ;;
    *) exit 3 ;;
esac
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
# The exports `nm -D --defined-only` lists are $STUB_NM_EXPORTS, one per
# line; every other call goes to the nm at $STUB_REAL_NM.
cat > "$T/elfstub/nm" <<'STUB'
#!/usr/bin/env bash
case "$1 $2" in
    "-D --defined-only") printf '%b' "${STUB_NM_EXPORTS:-0000000000001100 T oxi_sha256\n}" ;;
    *) exec "$STUB_REAL_NM" "$@" ;;
esac
STUB
printf '#!/usr/bin/env bash\n' > "$T/nonm/nm"
printf '#!/usr/bin/env bash\n' > "$T/noreadelf/readelf"
chmod +x "$T/pestub/"* "$T/readobjstub/"* "$T/machostub/"* "$T/elfstub/"* "$T/nonm/"* "$T/noreadelf/"*
check "archive imports: objdump's listing normalised, ordinals included" [ "$(imports_listed "$T/fake/oxicrypt-ffi-v9.9.9-windows-x86_64.tar.gz" "$T/pestub:$PATH")" = \
    "$(printf '%s\n' kernel32.dll!CreateFileW kernel32.dll!ordinal-5 'needs kernel32.dll' 'needs ws2_32.dll' ws2_32.dll!WSAStartup ws2_32.dll!ordinal-7)" ]
check "archive imports: llvm-readobj's listing normalised, ordinals included" [ "$(imports_listed "$T/fake/oxicrypt-ffi-v9.9.9-windows-x86_64.tar.gz" "$T/readobjstub:$T/minpath")" = \
    "$(printf '%s\n' kernel32.dll!CreateFileW kernel32.dll!ordinal-5 'needs kernel32.dll')" ]
check "archive imports: nm -u and otool listings normalised" [ "$(imports_listed "$T/fake/oxicrypt-ffi-v9.9.9-macos-aarch64.tar.gz" "$T/machostub:$PATH")" = \
    "$(printf '%s\n' _free _malloc 'needs /usr/lib/libSystem.B.dylib')" ]
mkdir -p "$T/allow/macho"
printf '_free\n_malloc\nneeds /usr/lib/libSystem.B.dylib\n' > "$T/allow/macho/macho-macos-aarch64.txt"
expect "archive imports: a library exporting no test symbol passes" 0 \
    "ok: liboxicrypt_ffi.1.dylib imports only what $T/allow/macho/macho-macos-aarch64.txt allows (3 imports)" \
    env PATH="$T/machostub:$PATH" "$HERE/release-archive-check.sh" imports \
    "$T/fake/oxicrypt-ffi-v9.9.9-macos-aarch64.tar.gz" "$T/allow/macho"
expect "archive imports: a library exporting an oxi_test_ symbol refused" 1 \
    "FAILED: liboxicrypt_ffi.1.dylib exports the test symbol oxi_test_probe" \
    env STUB_NM_EXPORTS='_oxi_sha256\n_oxi_test_probe\n' PATH="$T/machostub:$PATH" \
    "$HERE/release-archive-check.sh" imports "$T/fake/oxicrypt-ffi-v9.9.9-macos-aarch64.tar.gz" "$T/allow/macho"
expect "archive imports: an ELF library exporting no test symbol passes" 0 \
    "ok: liboxicrypt_ffi.so.9 imports only what $T/allow/exact/elf-linux-x86_64.txt allows" \
    env STUB_REAL_NM="$(command -v nm)" PATH="$T/elfstub:$PATH" \
    "$HERE/release-archive-check.sh" imports "$IMP.tar.gz" "$T/allow/exact"
expect "archive imports: an ELF library exporting an oxi_test_ symbol refused" 1 \
    "FAILED: liboxicrypt_ffi.so.9 exports the test symbol oxi_test_probe" \
    env STUB_NM_EXPORTS='0000000000001100 T oxi_sha256\n0000000000001200 T oxi_test_probe\n' \
    STUB_REAL_NM="$(command -v nm)" PATH="$T/elfstub:$PATH" \
    "$HERE/release-archive-check.sh" imports "$IMP.tar.gz" "$T/allow/exact"
mkdir -p "$T/allow/pe"
printf '%s\n' kernel32.dll!CreateFileW kernel32.dll!ordinal-5 'needs kernel32.dll' 'needs ws2_32.dll' \
    ws2_32.dll!WSAStartup ws2_32.dll!ordinal-7 > "$T/allow/pe/pe-windows-x86_64.txt"
expect "archive imports: a PE library exporting no test symbol passes" 0 \
    "ok: oxicrypt_ffi.dll imports only what $T/allow/pe/pe-windows-x86_64.txt allows (6 imports)" \
    env PATH="$T/pestub:$PATH" "$HERE/release-archive-check.sh" imports \
    "$T/fake/oxicrypt-ffi-v9.9.9-windows-x86_64.tar.gz" "$T/allow/pe"
expect "archive imports: a PE library exporting an oxi_test_ symbol refused" 1 \
    "FAILED: oxicrypt_ffi.dll exports the test symbol oxi_test_probe" \
    env STUB_PE_EXPORTS='oxi_sha256 oxi_test_probe' PATH="$T/pestub:$PATH" \
    "$HERE/release-archive-check.sh" imports "$T/fake/oxicrypt-ffi-v9.9.9-windows-x86_64.tar.gz" "$T/allow/pe"
mkdir -p "$T/allow/readobj"
printf '%s\n' kernel32.dll!CreateFileW kernel32.dll!ordinal-5 'needs kernel32.dll' > "$T/allow/readobj/pe-windows-x86_64.txt"
expect "archive imports: a PE library exporting no test symbol passes under llvm-readobj" 0 \
    "ok: oxicrypt_ffi.dll imports only what $T/allow/readobj/pe-windows-x86_64.txt allows (3 imports)" \
    env STUB_READOBJ_EXPORTS='oxi_sha256 oxi_version' PATH="$T/readobjstub:$T/minpath" \
    "$HERE/release-archive-check.sh" imports "$T/fake/oxicrypt-ffi-v9.9.9-windows-x86_64.tar.gz" "$T/allow/readobj"
expect "archive imports: a PE library exporting an oxi_test_ symbol refused under llvm-readobj" 1 \
    "FAILED: oxicrypt_ffi.dll exports the test symbol oxi_test_probe" \
    env STUB_READOBJ_EXPORTS='oxi_sha256 oxi_test_probe' PATH="$T/readobjstub:$T/minpath" \
    "$HERE/release-archive-check.sh" imports "$T/fake/oxicrypt-ffi-v9.9.9-windows-x86_64.tar.gz" "$T/allow/readobj"
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
# unsigned one refused with status 10. A run of the example program prints
# the nine lines, or with $ADB_LIE=pq-verify-fails stops after a failed
# verification and exits 1. One case runs on a PATH without
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
    "cd "*" ./example "*)
        echo "sha256 abc ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        echo "drbg instantiated"
        echo "ml-dsa-87 keygen ok"
        if [ "${ADB_LIE:-}" = pq-verify-fails ]; then
            printf 'expected: ml-dsa-87 verify ok\n     got: ml-dsa-87 verify returned 22\n' >&2
            exit 1
        fi
        printf '%s\n' "ml-dsa-87 verify ok" "ml-dsa-87 verify-tampered rejected 22" "ml-kem-1024 keygen ok" \
            "ml-kem-1024 decaps match" "ml-kem-1024 decaps-tampered differs" "ml-kem-1024 ss $(printf '%064d' 0 | tr 0 3)" ;;
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
check "device check: the pq round trip verdict printed" grep -qxF "verdict ok: pq round trip" <<<"$out_good"
check "device check: the round trip runs the signed library as shipped" \
    [ "$(sha "$T/adb-good/dev/liboxicrypt_ffi.so")" = "$ADB_SIGNED_SHA" ]
check "device check: the round trip builds examples/c/example.c for 16 KiB pages" \
    grep -q -- "-Wl,-z,max-page-size=16384 .*examples/c/example.c" "$T/adb-good/clang"
check "device check: the round trip runs with no seed argument" \
    grep -qE '^shell cd /data/local/tmp/oxicrypt-pq && LD_LIBRARY_PATH=/data/local/tmp/oxicrypt-pq \./example /data/local/tmp/oxicrypt-pq /data/local/tmp/oxicrypt-pq/out$' \
    "$T/adb-good/calls"
export ADB_LIE=pq-verify-fails
expect "android-device-check: a verify that fails is reported" 1 "verdict FAILED: pq round trip" device_check pqfail
unset ADB_LIE
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

# --- list-caller-entropy-sites.sh -------------------------------------------
# A fixture crate with one caller-entropy call outside and one inside a
# #[cfg(test)] module, whose body also holds a brace in a string literal.

SITES="$(mktemp -d -p "$T")"
mkdir -p "$SITES/fixture/src"
printf '[package]\nname = "fixture"\n' > "$SITES/fixture/Cargo.toml"
cat > "$SITES/fixture/src/lib.rs" <<'EOF'
pub fn seed(drbg: &mut Drbg) {
    drbg.instantiate(&[0; 32], &[0; 16], b"outside");
    drbg.instantiate(b"module seeded, one argument");
    drbg.reseed(b"module seeded, one argument");
}

#[cfg(test)]
mod tests {
    #[test]
    fn seeds() {
        let _ = "}";
        drbg.instantiate(&[1; 32], &[1; 16], b"inside");
    }
}
EOF
check "caller-entropy sites: lists a production call and skips a cfg(test) block" \
    [ "$("$HERE/list-caller-entropy-sites.sh" "$SITES")" \
        = 'fixture/src/lib.rs:2: drbg.instantiate(&[0; 32], &[0; 16], b"outside");' ]

# --- check-example-inputs.sh --------------------------------------------------
# A copy of examples/ whose six how-tos are stand-ins holding only the
# fixed-input rows of examples/README.md, so the agreement logic is tested
# independently of the how-tos' text.

OK_INPUTS="ok: the message, the personalization string and both flipped bytes agree across 13 files"
ROWS="$(grep -E '^\| `(MESSAGE|PERSONALIZATION|SIG_FLIP_BYTE|CT_FLIP_BYTE)` \|' "$HERE/../examples/README.md")" || true
check "example inputs: examples/README.md has the four rows" [ "$(grep -c '' <<<"$ROWS")" = 4 ]
# inputs_tree <name>: the completed copy, at $T/inputs/<name>.
inputs_tree() {
    local language
    mkdir -p "$T/inputs/$1"
    cp -R "$HERE/../examples/." "$T/inputs/$1/"
    for language in c python go node java csharp; do
        printf '# How-to\n\n| Constant | Value |\n|---|---|\n%s\n' "$ROWS" > "$T/inputs/$1/$language/README.md"
    done
}
inputs_tree agree
expect "example inputs: thirteen agreeing files pass" 0 "$OK_INPUTS" \
    "$HERE/check-example-inputs.sh" "$T/inputs/agree"
inputs_tree position
sed -i.orig -E 's/^CT_FLIP_BYTE = 0$/CT_FLIP_BYTE = 1/' "$T/inputs/position/python/example.py"
check "example inputs: the position edit took" grep -qxF "CT_FLIP_BYTE = 1" "$T/inputs/position/python/example.py"
expect "example inputs: an edited position exits 1" 1 \
    "FAILED: python/example.py states CT_FLIP_BYTE as \"1\", README.md as \"0\"" \
    "$HERE/check-example-inputs.sh" "$T/inputs/position"
inputs_tree howto-position
sed -i.orig 's/^| `SIG_FLIP_BYTE` | 0:/| `SIG_FLIP_BYTE` | 7:/' "$T/inputs/howto-position/java/README.md"
expect "example inputs: an edited position in a how-to exits 1" 1 \
    "FAILED: java/README.md states SIG_FLIP_BYTE as \"7\", README.md as \"0\"" \
    "$HERE/check-example-inputs.sh" "$T/inputs/howto-position"
inputs_tree message
sed -i.orig 's/lazy dog/lazy cat/' "$T/inputs/message/go/main.go"
expect "example inputs: an edited message exits 1" 1 \
    "FAILED: go/main.go states MESSAGE as \"The quick brown fox jumps over the lazy cat\"" \
    "$HERE/check-example-inputs.sh" "$T/inputs/message"
inputs_tree twice
printf '\nconst SIG_FLIP_BYTE_TOO = 0;\nconst SIG_FLIP_BYTE = 3;\n' >> "$T/inputs/twice/node/example.js"
expect "example inputs: a value stated twice differently exits 1" 1 \
    "FAILED: node/example.js states SIG_FLIP_BYTE more than once, with different values" \
    "$HERE/check-example-inputs.sh" "$T/inputs/twice"
expect "example inputs: the repository's examples and how-tos agree" 0 "$OK_INPUTS" "$HERE/check-example-inputs.sh"
inputs_tree missing
rm "$T/inputs/missing/c/README.md"
expect "example inputs: a missing how-to exits 1" 1 "FAILED: c/README.md is missing" \
    "$HERE/check-example-inputs.sh" "$T/inputs/missing"
inputs_tree no-root
rm "$T/inputs/no-root/README.md"
expect "example inputs: a missing examples/README.md exits 1" 1 "FAILED: README.md is missing" \
    "$HERE/check-example-inputs.sh" "$T/inputs/no-root"
inputs_tree no-row
sed -i.orig '/^| `PERSONALIZATION` |/d' "$T/inputs/no-row/csharp/README.md"
expect "example inputs: a how-to without a row exits 1" 1 "FAILED: csharp/README.md states no PERSONALIZATION" \
    "$HERE/check-example-inputs.sh" "$T/inputs/no-row"
inputs_tree perso
sed -i.orig 's/"oxicrypt example"/"oxicrypt sample"/' "$T/inputs/perso/c/example.c"
expect "example inputs: an edited personalization string exits 1" 1 \
    "FAILED: c/example.c states PERSONALIZATION as \"oxicrypt sample\", README.md as \"oxicrypt example\"" \
    "$HERE/check-example-inputs.sh" "$T/inputs/perso"
inputs_tree prose
printf '\nThe constants `MESSAGE` and `SIG_FLIP_BYTE` are fixed; `CT_FLIP_BYTE` (FIPS 203) too.\n' >> "$T/inputs/prose/go/README.md"
expect "example inputs: prose naming a constant is not read as its row" 0 "$OK_INPUTS" \
    "$HERE/check-example-inputs.sh" "$T/inputs/prose"

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
        env -u OXICRYPT_TEST_EXAMPLES -u OXICRYPT_TEST_REQUIRE_BUILT GIT_DIR="$T/sentinel/.git" RELEASE_SCRIPTS_INNER=1 "$HERE/test-release-scripts.sh"
    check "inherited GIT_DIR: the sentinel is unchanged" [ "$(sentinel)" = "$before" ]
fi

echo "release scripts: $pass passed, $failed failed; examples run with their toolchains:${examples_ran:- none}; against a built library: ${built_library%% (*}"
[ "$failed" -eq 0 ] && [ "$pass" -gt 0 ]
