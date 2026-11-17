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
# stub `oxi` printing chosen lines, and against malformed bundles; its
# library mode needs a real library and is not run here.
#
# Every case asserts the exit status and a line of the output. Needs git,
# ssh-keygen, python3 and jq. Exits 0 when every case passes, 1 otherwise.
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

# cli_archive <name> <integrity lines> <indicator>: an archive whose bundle
# holds a stub `oxi` printing <integrity lines> for --integrity and
# `self-test indicator: <indicator>` for `selftest --quiet`.
cli_archive() {
    local d="$T/archives/$1/oxicrypt-cli-test"
    mkdir -p "$d"
    {
        echo '#!/usr/bin/env bash'
        echo 'case "$1" in'
        printf -- '--integrity) printf %%s %q ;;\n' "$2"
        printf 'selftest) echo "self-test indicator: %s" ;;\n' "$3"
        echo '*) exit 2 ;;'
        echo 'esac'
    } > "$d/oxi"
    chmod +x "$d/oxi"
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
mkdir -p "$T/archives/twodirs/a" "$T/archives/twodirs/b"
tar -czf "$T/archives/twodirs.tar.gz" -C "$T/archives/twodirs" a b
expect "archive library: two top-level directories refused" 1 "holds 2 top-level entries, not one directory" \
    archive_check library "$T/archives/twodirs.tar.gz"

# --- android-device-check.sh ----------------------------------------------
# Runs against a bundle holding a stand-in library: an ELF header, a slot of
# non-zero bytes between the two magics at 0x10000, and filler. The NDK's
# clang and llvm-readelf are stubs; the stub clang records its arguments and
# writes a placeholder harness. The stub signer reports that slot and two
# hashed ranges for --show, and for --verify accepts the signed library,
# refuses the unsigned template copy as version 0 and anything else as
# SignatureInvalid. The stub `adb` keeps every pushed file and answers a
# harness run by the bytes of the library it names, as the module would:
# the signed library operational, its unsigned template copy refused with
# status 3, anything else refused with status 2. $ADB_LIE makes it report
# the signed library refused or the tampered one operational.

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
echo "  Machine:                           AArch64"
STUB
cat > "$T/bin/stub-sign" <<'STUB'
#!/usr/bin/env bash
sha="$(sha256sum < "$2" | cut -d' ' -f1)"
case "$1" in
    --show)
        echo "  slot at file offset 0x10000, RVA 0x10000"
        echo "    [0] Plain rva 0x00000000 file 0x00000000 len 65536 hole 0"
        echo "    [1] Plain rva 0x00020000 file 0x00020000 len 65536 hole 0" ;;
    --verify)
        [ "$sha" = "$ADB_SIGNED_SHA" ] && { echo "verify ok: $2"; exit 0; }
        [ "$sha" = "$ADB_UNSIGNED_SHA" ] && { echo "$2: slot invalid: slot version 0: the slot holds no signature"; exit 2; }
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
    "getprop ro.build.version.release") echo 14 ;;
    "getprop ro.build.version.sdk") echo 34 ;;
    "getconf PAGESIZE") echo 16384 ;;
    true) exit 0 ;;
    false) exit 1 ;;
    "rm -rf "* | "chmod 755 "*) exit 0 ;;
    */harness" "*)
        sha="$(sha256sum < "$ADB_STUB/dev/$(basename "$2")" | cut -d' ' -f1)"
        if { [ "$sha" = "$ADB_SIGNED_SHA" ] && [ "${ADB_LIE:-}" != signed-refused ]; } \
            || { [ "$sha" != "$ADB_SIGNED_SHA" ] && [ "$sha" != "$ADB_UNSIGNED_SHA" ] && [ "${ADB_LIE:-}" = tampered-operational ]; }; then
            echo "oxi_init=0 oxi_is_operational=1 oxi_integrity_status=1"
            echo "library: operational"
            exit 0
        fi
        if [ "$sha" = "$ADB_UNSIGNED_SHA" ]; then status=3; else status=2; fi
        echo "oxi_init=-1 oxi_is_operational=0 oxi_integrity_status=$status"
        echo "library: refused by the module's power-up tests"
        exit 1 ;;
    *) echo "stub adb: unhandled shell $*" >&2; exit 3 ;;
esac
STUB
chmod +x "$T/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/"* "$T/bin/stub-sign" "$T/bin/adb"

# device_check <name>: runs the check with a fresh stub state in $T/adb-<name>.
device_check() {
    export ADB_STUB="$T/adb-$1"
    mkdir -p "$ADB_STUB"
    : > "$ADB_STUB/calls"
    env PATH="$T/bin:$PATH" ANDROID_SERIAL=stub-device ANDROID_NDK_HOME="$T/ndk" \
        "$HERE/android-device-check.sh" "$T/android/oxicrypt-ffi-v9.9.9-android-aarch64.tar.gz" "$T/bin/stub-sign"
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

# --- an inherited GIT_DIR ----------------------------------------------------
# Runs this suite once more the way a git hook would start it, with GIT_DIR
# naming a sentinel repository, and requires the sentinel's refs and
# configuration to be byte-identical afterwards. The inner run skips this
# section.

if [ -z "${RELEASE_SCRIPTS_INNER:-}" ]; then
    git init -q -b main "$T/sentinel"
    git -C "$T/sentinel" -c user.name=Test -c user.email=tagger@example.org -c commit.gpgsign=false \
        commit -q --allow-empty -m sentinel
    sentinel() { git -C "$T/sentinel" for-each-ref; git -C "$T/sentinel" config --list --local; }
    before="$(sentinel)"
    check "inherited GIT_DIR: the sentinel has a ref" grep -q refs/heads/main <<<"$before"
    expect "inherited GIT_DIR: the suite still passes" 0 ", 0 failed" \
        env GIT_DIR="$T/sentinel/.git" RELEASE_SCRIPTS_INNER=1 "$HERE/test-release-scripts.sh"
    check "inherited GIT_DIR: the sentinel is unchanged" [ "$(sentinel)" = "$before" ]
fi

echo "release scripts: $pass passed, $failed failed"
[ "$failed" -eq 0 ] && [ "$pass" -gt 0 ]
