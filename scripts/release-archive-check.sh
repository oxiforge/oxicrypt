#!/usr/bin/env bash
# Extracts a release archive into a new empty directory and runs what it holds
# the way a user does, so the bytes that ship are the bytes that ran. Nothing
# runs from the build output directory.
#
#   release-archive-check.sh cli <archive.tar.gz> <verify-key-fingerprint>
#   release-archive-check.sh library <archive.tar.gz>
#
# Each archive must hold exactly one top-level directory, the bundle.
#
# cli      The bundle holds `oxi` or `oxi.exe`, not both. Run from inside the
#          bundle, `oxi --integrity` must exit 0 and print
#              integrity: passed — this binary matches the signature recorded inside it
#                verify key: <verify-key-fingerprint>
#          and `oxi selftest --quiet` must exit 0 and print
#              self-test indicator: PASS
# library  The README's Quick start C and Python examples run against the
#          bundle. Both are read from README.md at run time, so the check runs
#          the programs the README shows. The C example is compiled with the
#          README's `cc` command, its `$DIR` set to the bundle; the Python
#          example runs from inside the bundle, its library name rewritten to
#          the shared library the bundle holds. Each must exit 0 and print
#              ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
#          Both call oxi_init(0) before hashing, so a library that fails its
#          power-up self-tests or its integrity test prints no digest. A
#          bundle holding the import library oxicrypt_ffi.dll.lib is compiled
#          with MSVC `cl` instead of `cc`: the one on PATH, or else the
#          toolchain `vswhere` reports, set up by its vcvars64.bat. That
#          branch is exercised only by the release workflow's Windows leg.
#
# Each check requires the program's exit status AND its verdict lines, each
# matched as a whole line exactly once, so neither a lost status nor a stray
# line can pass it alone. A failed check prints `FAILED: <what>`. Exit 0 when
# every check holds, 1 otherwise.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
mode="${1:-}"
# SHA-256("abc"), FIPS 180-4 Appendix B.1.
abc_digest="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

# exactly_once <text> <line>: <line> appears in <text> as a whole line, once.
exactly_once() { [ "$(printf '%s\n' "$1" | grep -cxF -- "$2")" -eq 1 ]; }

# native <path>: <path> as a program built for the host OS takes it (a
# Windows path under Git Bash, unchanged elsewhere).
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

# bundle <archive>: extracts <archive> into a new directory under $tmp and
# prints the path of its single top-level directory.
bundle() {
    local archive="$1" x entries
    [ -f "$archive" ] || { echo "FAILED: $archive is not a file" >&2; return 1; }
    x="$(mktemp -d "$tmp/extract.XXXXXX")" || return 1
    tar -xzf "$archive" -C "$x" || { echo "FAILED: could not extract $archive" >&2; return 1; }
    entries="$(find "$x" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
    if [ "$entries" -ne 1 ] || [ "$(find "$x" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" -ne 1 ]; then
        echo "FAILED: $archive holds $entries top-level entries, not one directory" >&2
        return 1
    fi
    find "$x" -mindepth 1 -maxdepth 1 -type d
}

# run_program <what> <command...>: runs the command, prints its output, and
# leaves the output, carriage returns removed, in $out and the status in $rc.
run_program() {
    local what="$1"
    shift
    out="$("$@" 2>&1 | tr -d '\r'; exit "${PIPESTATUS[0]}")"
    rc=$?
    printf '%s (exit %s):\n%s\n' "$what" "$rc" "$out"
}

# require <what> <line...>: the program last run exited 0 and printed each
# <line> exactly once. Returns non-zero, naming each failure, otherwise.
require() {
    local what="$1" line failed=0
    shift
    if [ "$rc" -ne 0 ]; then
        echo "FAILED: $what exited $rc" >&2
        failed=1
    fi
    for line in "$@"; do
        if ! exactly_once "$out" "$line"; then
            echo "FAILED: $what did not print \"$line\" exactly once" >&2
            failed=1
        fi
    done
    return "$failed"
}

# readme_block <lang> <needle>: prints the first fenced <lang> block of the
# README that contains <needle>.
readme_block() {
    awk -v lang="$1" -v needle="$2" '
        !inside && $0 == "```" lang { inside = 1; block = ""; hit = 0; next }
        inside && $0 == "```" { if (hit) { printf "%s", block; exit } inside = 0; next }
        inside { block = block $0 "\n"; if (index($0, needle)) hit = 1 }
    ' "$root/README.md"
}

# readme_cc_line: prints the `cc` command of the first fenced bash block after
# the README's C example.
readme_cc_line() {
    awk '
        $0 == "```c" { c = 1 }
        c && $0 == "```bash" { bash = 1; next }
        bash && $0 == "```" { exit }
        bash && /^cc / { print }
    ' "$root/README.md"
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

case "$mode" in
    cli)
        [ $# -eq 3 ] || { echo "usage: release-archive-check.sh cli <archive.tar.gz> <verify-key-fingerprint>" >&2; exit 1; }
        dir="$(bundle "$2")" || exit 1
        if [ -f "$dir/oxi" ] && [ -f "$dir/oxi.exe" ]; then
            echo "FAILED: $(basename "$dir") holds both oxi and oxi.exe" >&2
            exit 1
        elif [ -f "$dir/oxi" ]; then
            bin=./oxi
        elif [ -f "$dir/oxi.exe" ]; then
            bin=./oxi.exe
        else
            echo "FAILED: $(basename "$dir") holds neither oxi nor oxi.exe" >&2
            exit 1
        fi
        cd "$dir" || exit 1
        failed=0
        run_program "$bin --integrity" "$bin" --integrity
        require "$bin --integrity" \
            "integrity: passed — this binary matches the signature recorded inside it" \
            "  verify key: $3" || failed=1
        run_program "$bin selftest --quiet" "$bin" selftest --quiet
        require "$bin selftest --quiet" "self-test indicator: PASS" || failed=1
        if [ "$failed" -eq 0 ]; then
            echo "ok: $bin from the extracted archive passes its integrity test and its self-tests"
        fi
        exit "$failed"
        ;;
    library)
        [ $# -eq 2 ] || { echo "usage: release-archive-check.sh library <archive.tar.gz>" >&2; exit 1; }
        dir="$(bundle "$2")" || exit 1
        lib=""
        for candidate in "$dir"/liboxicrypt_ffi.so.[0-9]* "$dir"/liboxicrypt_ffi.[0-9]*.dylib "$dir/oxicrypt_ffi.dll"; do
            if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
                [ -z "$lib" ] || { echo "FAILED: $(basename "$dir") holds more than one shared library" >&2; exit 1; }
                lib="$(basename "$candidate")"
            fi
        done
        [ -n "$lib" ] || { echo "FAILED: $(basename "$dir") holds no shared library" >&2; exit 1; }
        c_source="$(readme_block c 'oxi_sha256((const unsigned char *)"abc"')"
        [ -n "$c_source" ] || { echo "FAILED: no C example in README.md" >&2; exit 1; }
        py_source="$(readme_block python 'ctypes.CDLL(')"
        [ "$(printf '%s\n' "$py_source" | grep -c 'ctypes\.CDLL("[^"]*")')" -eq 1 ] \
            || { echo "FAILED: no Python example with one ctypes.CDLL(\"...\") call in README.md" >&2; exit 1; }
        failed=0

        work="$tmp/c"
        mkdir -p "$work"
        printf '%s' "$c_source" > "$work/sha256_demo.c"
        if [ -f "$dir/oxicrypt_ffi.dll.lib" ]; then
            ndir="$(native "$dir")"
            # Dashes, not slashes: Git Bash rewrites an argument that starts
            # with a slash into a Windows path before cl sees it.
            cl_args="-nologo -I\"$ndir\" sha256_demo.c -link -LIBPATH:\"$ndir\" oxicrypt_ffi.dll.lib"
            if command -v cl.exe >/dev/null 2>&1; then
                compile=(bash -c "cl.exe $cl_args")
            else
                vswhere="$(command -v vswhere.exe || printf '%s' "${PROGRAMFILES:-C:/Program Files} (x86)/Microsoft Visual Studio/Installer/vswhere.exe")"
                vs="$("$vswhere" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
                    -property installationPath 2>/dev/null | tr -d '\r' | head -n 1)"
                [ -n "$vs" ] || { echo "FAILED: no MSVC toolchain found (vswhere reported none)" >&2; exit 1; }
                compile=(cmd //c "call \"$vs\\VC\\Auxiliary\\Build\\vcvars64.bat\" >nul && cl $cl_args")
            fi
            if (cd "$work" && "${compile[@]}"); then
                # The loader finds the DLL through PATH; the program stays outside the bundle.
                run_program "the README's C example" env PATH="$dir:$PATH" "$work/sha256_demo.exe"
                require "the README's C example" "$abc_digest" || failed=1
            else
                echo "FAILED: cl could not compile the README's C example" >&2
                failed=1
            fi
        else
            cc_line="$(readme_cc_line)"
            [ "$(printf '%s\n' "$cc_line" | grep -c '^cc ')" -eq 1 ] \
                || { echo "FAILED: no single cc command after the C example in README.md" >&2; exit 1; }
            echo "compiling with the README's command, DIR=$dir: $cc_line"
            if (cd "$work" && DIR="$dir" bash -c "$cc_line"); then
                run_program "the README's C example" "$work/sha256_demo"
                require "the README's C example" "$abc_digest" || failed=1
            else
                echo "FAILED: cc could not compile the README's C example" >&2
                failed=1
            fi
        fi

        py="$(command -v python3 || command -v python)" || { echo "FAILED: no python for the README's Python example" >&2; exit 1; }
        printf '%s\n' "$py_source" | sed -E "s#ctypes\\.CDLL\\(\"[^\"]*\"\\)#ctypes.CDLL(\"./$lib\")#" > "$tmp/sha256_demo.py"
        # -I keeps the bundle directory off the module search path.
        run_program "the README's Python example" bash -c 'cd "$1" && "$2" -I "$3"' _ "$dir" "$py" "$(native "$tmp/sha256_demo.py")"
        require "the README's Python example" "$abc_digest" || failed=1
        if [ "$failed" -eq 0 ]; then
            echo "ok: the README's C and Python examples run against $lib from the extracted archive"
        fi
        exit "$failed"
        ;;
    *)
        echo "usage: release-archive-check.sh cli|library ..." >&2
        exit 1
        ;;
esac
