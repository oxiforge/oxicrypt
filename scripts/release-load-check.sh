#!/usr/bin/env bash
# Loads a release artifact the way its consumer does and requires the module
# inside it to reach operational, with the artifact as linked, before
# signing, as the control that shows the integrity test runs.
#
#   release-load-check.sh library <harness> <unsigned> <signed> <signer>
#   release-load-check.sh cli <unsigned> <signed> <signer>
#   release-load-check.sh adb-library <harness> <unsigned> <signed> <signer>
#
# library      <harness> is .github/probes/ffi-operational.c or
#              pe-ffi-operational.rs, built: it loads the library, calls
#              oxi_init and prints `oxi_init=R oxi_is_operational=O
#              oxi_integrity_status=S`. The signed library must report
#              operational (0, 1, 1); the unsigned one must be refused with
#              integrity status 3, the unsigned diagnosis.
# cli          The signed `oxi` must run `oxi hash sha256` and print the right
#              digest; the unsigned one must be refused by the module's power-up
#              tests (.github/probes/oxi-startup.sh classifies both).
# adb-library  As `library`, on the one device `adb` reaches: the files are
#              pushed to /data/local/tmp/oxicrypt-release and run there.
#
# A signed ELF or PE artifact also gets a tamper control: a copy with one byte
# flipped at the offset .github/probes/extent-tamper-offset.py picks from
# `<signer> --show`, inside the extent and read by nothing before the
# integrity test. The copy must be refused with integrity status 2
# (SignatureInvalid; for `oxi`, its diagnosis), and `<signer> --verify` must
# fail on it. A Mach-O artifact gets no tamper control here: a flipped byte
# leaves its code signature stale, and this script does not renew it with
# codesign. The integrity image probe workflow runs the Mach-O tamper controls
# on re-signed copies. The script says so when it skips the control.
#
# Each check requires the harness's exit status AND its verdict lines, each
# matched as a whole line exactly once, so neither a lost status nor a stray
# line can pass it alone. Every adb setup step is checked. Exit 0 when every
# check holds, 1 otherwise.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
mode="${1:-}"

# exactly_once <text> <line>: <line> appears in <text> as a whole line, once.
exactly_once() { [ "$(printf '%s\n' "$1" | grep -cxF -- "$2")" -eq 1 ]; }

# is_elf <file>: the file begins with the ELF magic.
is_elf() { [ "$(head -c 4 "$1" | od -An -tx1 | tr -d ' \n')" = 7f454c46 ]; }

# tamperable <file>: an ELF or PE artifact, whose tampered copy the loader
# runs without checking any platform signature.
tamperable() { is_elf "$1" || [ "$(head -c 2 "$1" | od -An -tx1 | tr -d ' \n')" = 4d5a ]; }

# native <path>: <path> as a program built for the host OS takes it (a
# Windows path under Git Bash, unchanged elsewhere).
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

# tampered_copy <signer> <signed> <out>: writes <out>, a copy of <signed> with
# one byte inside the extent flipped, and requires `<signer> --verify` to
# refuse it. Returns non-zero, naming the step, if any step fails.
tampered_copy() {
    local signer="$1" signed="$2" out="$3" py off show rc
    py="$(command -v python3 || command -v python)" || { echo "FAILED: no python for the tamper control" >&2; return 1; }
    show="$out.show.txt"
    "$signer" --show "$signed" > "$show" || { echo "FAILED: $signer --show $signed" >&2; return 1; }
    off="$("$py" "$root/.github/probes/extent-tamper-offset.py" "$show" "$signed")" \
        || { echo "FAILED: no tamper offset for $signed" >&2; return 1; }
    cp "$signed" "$out" || return 1
    "$py" "$root/.github/probes/flip-byte.py" "$out" "$off" || { echo "FAILED: flip-byte $out $off" >&2; return 1; }
    echo "tamper control: flipped the byte at file offset $off of a copy of $signed"
    "$signer" --verify "$out" > "$out.verify.txt" 2>&1
    rc=$?
    cat "$out.verify.txt"
    if [ "$rc" -ne 0 ] && grep -q SignatureInvalid "$out.verify.txt"; then
        echo "control ok: --verify refuses the tampered copy"
    else
        echo "control FAILED: --verify did not refuse the tampered copy (exit $rc)" >&2
        return 1
    fi
}

# check_tampered_library <run> <harness> <tampered>: the harness refuses the
# tampered library with integrity status 2.
check_tampered_library() {
    local run="$1" harness="$2" tampered="$3" out rc
    out="$($run "$harness" "$tampered" 2>&1 | tr -d '\r'; exit "${PIPESTATUS[0]}")"
    rc=$?
    printf 'tampered (exit %s):\n%s\n' "$rc" "$out"
    if [ "$rc" -eq 1 ] \
        && [ "$(printf '%s\n' "$out" | grep -cE '^oxi_init=-?[1-9][0-9]* oxi_is_operational=0 oxi_integrity_status=2$')" -eq 1 ] \
        && exactly_once "$out" "library: refused by the module's power-up tests"; then
        echo "control ok: the tampered library is refused as not matching its signature"
    else
        echo "control FAILED: the tampered library was not refused with integrity status 2" >&2
        return 1
    fi
}

check_library() {
    # $1 runner prefix (empty or "adb shell"), $2 harness, $3 unsigned, $4 signed.
    # The harness exits 0 for operational and 1 for refused (ffi-operational.c,
    # pe-ffi-operational.rs); the status and both printed lines must agree.
    local run="$1" harness="$2" unsigned="$3" signed="$4" out rc failed=0
    out="$($run "$harness" "$unsigned" 2>&1 | tr -d '\r'; exit "${PIPESTATUS[0]}")"
    rc=$?
    printf 'unsigned (exit %s):\n%s\n' "$rc" "$out"
    if [ "$rc" -eq 1 ] \
        && [ "$(printf '%s\n' "$out" | grep -cE '^oxi_init=-?[1-9][0-9]* oxi_is_operational=0 oxi_integrity_status=3$')" -eq 1 ] \
        && exactly_once "$out" "library: refused by the module's power-up tests"; then
        echo "control ok: the library as linked is refused as unsigned"
    else
        echo "control FAILED: the library as linked was not refused as unsigned" >&2
        failed=1
    fi
    out="$($run "$harness" "$signed" 2>&1 | tr -d '\r'; exit "${PIPESTATUS[0]}")"
    rc=$?
    printf 'signed (exit %s):\n%s\n' "$rc" "$out"
    if [ "$rc" -eq 0 ] \
        && exactly_once "$out" "oxi_init=0 oxi_is_operational=1 oxi_integrity_status=1" \
        && exactly_once "$out" "library: operational"; then
        echo "ok: the signed library reaches operational"
    else
        echo "FAILED: the signed library did not reach operational" >&2
        failed=1
    fi
    return "$failed"
}

# step <what> <command...>: runs a setup command and stops, naming it, if it fails.
step() {
    local what="$1"; shift
    "$@" || { echo "FAILED: $what (exit $?)" >&2; exit 1; }
}

case "$mode" in
    library)
        [ $# -eq 5 ] || { echo "usage: release-load-check.sh library <harness> <unsigned> <signed> <signer>" >&2; exit 1; }
        check_library "" "$2" "$3" "$4"
        rc=$?
        if tamperable "$4"; then
            tmp="$(mktemp -d)"
            trap 'rm -rf "$tmp"' EXIT
            # The copy keeps the library's extension, which a Windows loader
            # needs to load it as a DLL.
            copy="$(native "$tmp")/tampered.${4##*.}"
            if tampered_copy "$5" "$4" "$copy"; then
                check_tampered_library "" "$2" "$copy" || rc=1
            else
                rc=1
            fi
        else
            echo "no tamper control: $(basename "$4") is neither ELF nor PE"
        fi
        exit "$rc"
        ;;
    adb-library)
        [ $# -eq 5 ] || { echo "usage: release-load-check.sh adb-library <harness> <unsigned> <signed> <signer>" >&2; exit 1; }
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        step "the tamper control's copy" tampered_copy "$5" "$4" "$tmp/tampered.so"
        dev=/data/local/tmp/oxicrypt-release
        step "adb wait-for-device" timeout 300 adb wait-for-device
        # adb shell has returned the remote exit status since Android 7; the
        # emulator here runs API 34. A probe of it is the first check.
        step "adb shell exit status" adb shell true
        if adb shell false; then
            echo "FAILED: adb shell does not return the remote exit status" >&2
            exit 1
        fi
        step "adb shell mkdir" adb shell "rm -rf $dev && mkdir -p $dev"
        step "adb push harness" adb push "$2" "$dev/harness"
        step "adb push unsigned" adb push "$3" "$dev/unsigned.so"
        step "adb push signed" adb push "$4" "$dev/signed.so"
        step "adb push tampered" adb push "$tmp/tampered.so" "$dev/tampered.so"
        step "adb shell chmod" adb shell "chmod 755 $dev/harness"
        check_library "adb shell" "$dev/harness" "$dev/unsigned.so" "$dev/signed.so"
        rc=$?
        check_tampered_library "adb shell" "$dev/harness" "$dev/tampered.so" || rc=1
        adb shell "rm -rf $dev" >/dev/null 2>&1 || true
        exit "$rc"
        ;;
    cli)
        [ $# -eq 4 ] || { echo "usage: release-load-check.sh cli <unsigned> <signed> <signer>" >&2; exit 1; }
        failed=0
        out="$(bash "$root/.github/probes/oxi-startup.sh" "$2" "oxicrypt-integrity-sign --sign --key <signing key> <this binary>")"
        rc=$?
        printf '%s\n' "$out"
        if [ "$rc" -eq 1 ] && exactly_once "$out" "startup: refused by the module's power-up tests"; then
            echo "control ok: oxi as linked is refused as unsigned"
        else
            echo "control FAILED: oxi as linked was not refused as unsigned (probe status $rc)" >&2
            failed=1
        fi
        out="$(bash "$root/.github/probes/oxi-startup.sh" "$3")"
        rc=$?
        printf '%s\n' "$out"
        if [ "$rc" -eq 0 ] && exactly_once "$out" "startup: operational"; then
            echo "ok: the signed oxi reaches operational"
        else
            echo "FAILED: the signed oxi did not reach operational (probe status $rc)" >&2
            failed=1
        fi
        if tamperable "$3"; then
            tmp="$(mktemp -d)"
            trap 'rm -rf "$tmp"' EXIT
            copy="$tmp/$(basename "$3")"
            if tampered_copy "$4" "$3" "$copy"; then
                # IntegrityError::SignatureInvalid's message (status 2), and no
                # other status's.
                out="$(bash "$root/.github/probes/oxi-startup.sh" "$copy" "the module image does not match the signature recorded in it")"
                rc=$?
                printf '%s\n' "$out"
                if [ "$rc" -eq 1 ]; then
                    echo "control ok: the tampered oxi is refused as not matching its signature"
                else
                    echo "control FAILED: the tampered oxi was not refused with the SignatureInvalid diagnosis (probe status $rc)" >&2
                    failed=1
                fi
            else
                failed=1
            fi
        else
            echo "no tamper control: $(basename "$3") is neither ELF nor PE"
        fi
        exit "$failed"
        ;;
    *)
        echo "usage: release-load-check.sh library|adb-library|cli ..." >&2
        exit 1
        ;;
esac
