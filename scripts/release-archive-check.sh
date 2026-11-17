#!/usr/bin/env bash
# Extracts a release archive into a new empty directory and runs what it holds
# the way a user does, so the bytes that ship are the bytes that ran. Nothing
# runs from the build output directory.
#
#   release-archive-check.sh cli <archive.tar.gz> <verify-key-fingerprint>
#   release-archive-check.sh library <archive.tar.gz>
#   release-archive-check.sh imports <archive.tar.gz> <allow-list-dir>
#   release-archive-check.sh examples <archive.tar.gz>
#
# Each archive must hold exactly one top-level directory, the bundle.
#
# cli      The bundle holds an entry named `oxi` or one named `oxi.exe`, not
#          both, and it is not a symbolic link. Run from inside the bundle,
#          `oxi --integrity` must exit 0 and print
#              integrity: passed — this binary matches the signature recorded inside it
#                verify key: <verify-key-fingerprint>
#          and `oxi selftest --quiet` must exit 0 and print
#              self-test indicator: PASS
# library  The README's Quick start C and Python examples run against the
#          bundle. Both are read from README.md at run time, so the check runs
#          the programs the README shows. The C example is compiled with the
#          README's `cc` command, its `$DIR` set to the bundle; the Python
#          example runs from inside the bundle. On an ELF bundle the library
#          name the Python example loads must be in the bundle and is loaded
#          as written; on a Mach-O or PE bundle it is rewritten to the shared
#          library the bundle holds, and a note names both. Each must exit 0
#          and print
#              ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
#          Both call oxi_init(0) before hashing, so a library that fails its
#          power-up self-tests or its integrity test prints no digest. A
#          bundle holding the import library oxicrypt_ffi.dll.lib is compiled
#          with MSVC `cl` instead of `cc`: the one on PATH, or else the
#          toolchain `vswhere` reports, through a build.bat that calls its
#          vcvars64.bat and then `cl`. That branch is exercised only by the
#          release workflow's Windows leg.
# imports  The bundle's shared library, found as in `library`, imports only
#          what its allow-list names, so a run-time dependency nobody
#          declared fails the build. The format comes from the library's
#          magic bytes and the platform from the archive name, which picks
#          <allow-list-dir>/<format>-<platform>.txt, e.g. elf-linux-x86_64.txt.
#          One import per line:
#              ELF     symbol@VERSION (unversioned if the library asks for no
#                      version) from `nm -D --undefined-only`, and
#                      `needs <soname>` per NEEDED entry from `readelf -d`
#              PE      <dll, lower case>!<symbol> per import from
#                      `objdump -p`, and `needs <dll, lower case>` per DLL
#              Mach-O  each undefined symbol from `nm -u`, and
#                      `needs <install name>` per dylib `otool -L` lists
#                      other than the library's own
#          The llvm- tool of the same name stands in for a missing one, and
#          `llvm-readobj --coff-imports` for objdump. The Mach-O branch is
#          exercised only by the release workflow's macOS legs. The
#          allow-list holds one entry per line; `#` starts a comment, so an
#          entry may carry `  # reason`. An import the allow-list does not
#          name fails the check. An entry the library no longer imports is
#          reported as a note and does not fail it. Names a library looks
#          up at run time through dlsym or GetProcAddress are not imports
#          and are not checked.
# examples Each examples/<language>/ directory holding a run.sh runs it with
#          the bundle directory as its argument, and it must exit 0 and print
#              ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
#          An example whose toolchain is not on PATH is skipped with
#          `skip: <language> (<reason>)`: go needs `go` and the C compiler
#          `go env CC` names, node needs `node` and `npm`, java needs `java`
#          and a `javac` of 22 or later, csharp needs `dotnet`. A directory
#          with a run.sh and no toolchain listed here fails the check, and so
#          does a run in which no example ran.
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
        { sub(/\r$/, "") }
        !inside && $0 == "```" lang { inside = 1; block = ""; hit = 0; next }
        inside && $0 == "```" { if (hit) { printf "%s", block; exit } inside = 0; next }
        inside { block = block $0 "\n"; if (index($0, needle)) hit = 1 }
    ' "$root/README.md"
}

# readme_cc_line: prints the `cc` command of the first fenced bash block after
# the README's C example.
readme_cc_line() {
    awk '
        { sub(/\r$/, "") }
        $0 == "```c" { c = 1 }
        c && $0 == "```bash" { bash = 1; next }
        bash && $0 == "```" { exit }
        bash && /^cc / { print }
    ' "$root/README.md"
}

# shared_library <dir>: prints the name of the one shared library <dir> holds,
# not counting a symbolic link to a file beside it. A link whose target names
# a directory, which can lead out of the bundle, fails.
shared_library() {
    local dir="$1" candidate lib=""
    for candidate in "$dir"/liboxicrypt_ffi.so.[0-9]* "$dir"/liboxicrypt_ffi.[0-9]*.dylib "$dir/oxicrypt_ffi.dll"; do
        if [ -L "$candidate" ]; then
            case "$(readlink "$candidate")" in
                "" | */*) echo "FAILED: $(basename "$candidate") is a symbolic link, not a file in the bundle" >&2; return 1 ;;
            esac
        elif [ -f "$candidate" ]; then
            [ -z "$lib" ] || { echo "FAILED: $(basename "$dir") holds more than one shared library" >&2; return 1; }
            lib="$(basename "$candidate")"
        fi
    done
    [ -n "$lib" ] || { echo "FAILED: $(basename "$dir") holds no shared library" >&2; return 1; }
    printf '%s' "$lib"
}

# tool <name>: prints <name>, or llvm-<name> when only that is on PATH.
tool() {
    if command -v "$1" >/dev/null 2>&1; then
        printf '%s' "$1"
    elif command -v "llvm-$1" >/dev/null 2>&1; then
        printf 'llvm-%s' "$1"
    else
        echo "FAILED: neither $1 nor llvm-$1 is on PATH" >&2
        return 1
    fi
}

# list_imports <elf|pe|macho> <library> <mach-o arch>: prints the library's
# imports, one per line, in the forms the header lists. Returns non-zero,
# naming the tool, when a tool fails to read the library.
list_imports() {
    local format="$1" lib="$2" arch="$3" nm readelf otool listing id
    case "$format" in
        elf)
            nm="$(tool nm)" && readelf="$(tool readelf)" || return 1
            listing="$("$nm" -D --undefined-only "$lib")" || { echo "FAILED: $nm could not read $lib" >&2; return 1; }
            printf '%s\n' "$listing" | awk 'NF { print $NF }'
            listing="$("$readelf" -d "$lib")" || { echo "FAILED: $readelf could not read $lib" >&2; return 1; }
            printf '%s\n' "$listing" | sed -n 's/.*(NEEDED).*\[\(.*\)\].*/needs \1/p'
            ;;
        pe)
            if command -v objdump >/dev/null 2>&1; then
                listing="$(objdump -p "$lib")" || { echo "FAILED: objdump could not read $lib" >&2; return 1; }
                # Each `DLL Name:` line is followed by a column header and one
                # row per import. Newer binutils add an Ordinal column before
                # the hint; a row without a name is an import by ordinal.
                printf '%s\n' "$listing" | tr -d '\r' | awk '
                    /^\tDLL Name: / { dll = tolower($3); print "needs " dll; col = 0; next }
                    dll != "" && /^\tvma:/ { col = ($0 ~ /Ordinal/) ? 4 : 3; next }
                    dll != "" && col && NF == 0 { dll = ""; col = 0; next }
                    dll != "" && col { if (NF >= col) print dll "!" $col; else print dll "!ordinal-" $2 }
                '
            elif command -v llvm-readobj >/dev/null 2>&1; then
                listing="$(llvm-readobj --coff-imports "$lib")" || { echo "FAILED: llvm-readobj could not read $lib" >&2; return 1; }
                printf '%s\n' "$listing" | tr -d '\r' | awk '
                    /^Import \{/ { inside = 1; next }
                    /^\}/ { inside = 0; dll = ""; next }
                    inside && /^  Name: / { dll = tolower($2); print "needs " dll; next }
                    inside && dll != "" && /^  Symbol: / { print dll "!" $2 }
                '
            else
                echo "FAILED: neither objdump nor llvm-readobj is on PATH" >&2
                return 1
            fi
            ;;
        macho)
            nm="$(tool nm)" && otool="$(tool otool)" || return 1
            listing="$("$nm" -u -arch "$arch" "$lib")" || { echo "FAILED: $nm could not read $lib" >&2; return 1; }
            printf '%s\n' "$listing" | awk 'NF && !/:$/ { print $NF }'
            # `otool -L` lists the library's own install name with the dylibs
            # it loads; `otool -D` prints that name after a header line.
            id="$("$otool" -D "$lib" | tail -n +2)" || { echo "FAILED: $otool could not read $lib" >&2; return 1; }
            listing="$("$otool" -L "$lib")" || { echo "FAILED: $otool could not read $lib" >&2; return 1; }
            printf '%s\n' "$listing" | tail -n +2 | sed -E 's/^[[:space:]]+//; s/ \(compatibility version.*$//' \
                | awk -v id="$id" 'NF && $0 != id { print "needs " $0 }'
            ;;
    esac
    return 0
}

tmp="$(mktemp -d)"
# The mode may still be inside the extract directory.
trap 'cd / && rm -rf "$tmp"' EXIT

case "$mode" in
    cli)
        [ $# -eq 3 ] || { echo "usage: release-archive-check.sh cli <archive.tar.gz> <verify-key-fingerprint>" >&2; exit 1; }
        dir="$(bundle "$2")" || exit 1
        # By entry name: under Git Bash `test -f oxi` also finds oxi.exe.
        names="$(find "$dir" -mindepth 1 -maxdepth 1 \( -name oxi -o -name oxi.exe \) -exec basename {} \;)"
        case "$(printf '%s' "$names" | grep -c .)" in
            0) echo "FAILED: $(basename "$dir") holds neither oxi nor oxi.exe" >&2; exit 1 ;;
            1) ;;
            *) echo "FAILED: $(basename "$dir") holds both oxi and oxi.exe" >&2; exit 1 ;;
        esac
        if [ -L "$dir/$names" ]; then
            echo "FAILED: $names is a symbolic link, not a file in the bundle" >&2
            exit 1
        fi
        bin="./$names"
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
        lib="$(shared_library "$dir")" || exit 1
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
                printf 'call "%s\\VC\\Auxiliary\\Build\\vcvars64.bat" >nul\r\ncl %s\r\n' "$vs" "$cl_args" > "$work/build.bat"
                compile=(cmd //c "$(native "$work/build.bat")")
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
        py_name="$(printf '%s\n' "$py_source" | sed -nE 's/.*ctypes\.CDLL\("([^"]*)"\).*/\1/p')"
        py_name="${py_name#./}"
        py_ok=1
        if [ "$(od -An -tx1 -N4 "$dir/$lib" | tr -d ' \n')" = 7f454c46 ]; then
            # The README names the ELF library, so the name must ship.
            case "$py_name" in
                "" | */*) py_ok=0 ;;
                *) [ -e "$dir/$py_name" ] || py_ok=0 ;;
            esac
            if [ "$py_ok" -eq 1 ]; then
                printf '%s\n' "$py_source" > "$tmp/sha256_demo.py"
            else
                echo "FAILED: the README's Python example loads $py_name, which the bundle does not hold" >&2
                failed=1
            fi
        else
            printf '%s\n' "$py_source" | sed -E "s#ctypes\\.CDLL\\(\"[^\"]*\"\\)#ctypes.CDLL(\"./$lib\")#" > "$tmp/sha256_demo.py"
            echo "note: Python example loads $lib here; the README names $py_name"
        fi
        if [ "$py_ok" -eq 1 ]; then
            # -I keeps the bundle directory off the module search path.
            run_program "the README's Python example" bash -c 'cd "$1" && "$2" -I "$3"' _ "$dir" "$py" "$(native "$tmp/sha256_demo.py")"
            require "the README's Python example" "$abc_digest" || failed=1
        fi
        if [ "$failed" -eq 0 ]; then
            echo "ok: the README's C and Python examples run against $lib from the extracted archive"
        fi
        exit "$failed"
        ;;
    imports)
        [ $# -eq 3 ] || { echo "usage: release-archive-check.sh imports <archive.tar.gz> <allow-list-dir>" >&2; exit 1; }
        dir="$(bundle "$2")" || exit 1
        lib="$(shared_library "$dir")" || exit 1
        platform="$(basename "$2" | sed -nE 's/.*-((linux|windows|macos)-(x86_64|aarch64))\.tar\.gz$/\1/p')"
        [ -n "$platform" ] || { echo "FAILED: $(basename "$2") does not end in <os>-<arch>.tar.gz" >&2; exit 1; }
        magic="$(od -An -tx1 -N4 "$dir/$lib" | tr -d ' \n')"
        case "$magic" in
            7f454c46) format=elf ;;
            4d5a*) format=pe ;;
            cffaedfe | cafebabe) format=macho ;;
            *) echo "FAILED: $lib starts with $magic, which is not ELF, PE or Mach-O" >&2; exit 1 ;;
        esac
        list="$3/$format-$platform.txt"
        [ -f "$list" ] || { echo "FAILED: no allow-list $list" >&2; exit 1; }
        arch="${platform#*-}"
        [ "$arch" != aarch64 ] || arch=arm64
        found="$(list_imports "$format" "$(native "$dir/$lib")" "$arch")" || exit 1
        found="$(printf '%s\n' "$found" | tr -d '\r' | awk 'NF' | LC_ALL=C sort -u)"
        n="$(printf '%s\n' "$found" | grep -c . || true)"
        # A tool that prints nothing must not read as a library that imports nothing.
        [ "$n" -gt 0 ] || { echo "FAILED: found no imports in $lib" >&2; exit 1; }
        allowed="$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^[[:space:]]*//' "$list" | awk 'NF' | LC_ALL=C sort -u)"
        failed=0
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            echo "FAILED: $lib imports $entry, which the allow-list $list does not name" >&2
            failed=1
        done < <(LC_ALL=C comm -23 <(printf '%s\n' "$found") <(printf '%s\n' "$allowed"))
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            echo "note: $entry is allowed but not imported"
        done < <(LC_ALL=C comm -13 <(printf '%s\n' "$found") <(printf '%s\n' "$allowed"))
        if [ "$failed" -eq 0 ]; then
            echo "ok: $lib imports only what $list allows ($n imports)"
        fi
        exit "$failed"
        ;;
    examples)
        [ $# -eq 2 ] || { echo "usage: release-archive-check.sh examples <archive.tar.gz>" >&2; exit 1; }
        dir="$(bundle "$2")" || exit 1
        lib="$(shared_library "$dir")" || exit 1
        failed=0
        ran=""
        for example in "$root"/examples/*/; do
            [ -f "$example/run.sh" ] || continue
            language="$(basename "$example")"
            case "$language" in
                go) tools="go" ;;
                node) tools="node npm" ;;
                java) tools="java javac" ;;
                csharp) tools="dotnet" ;;
                *) echo "FAILED: examples/$language has a run.sh and no toolchain this check knows" >&2; failed=1; continue ;;
            esac
            skip=""
            for t in $tools; do
                command -v "$t" >/dev/null 2>&1 || { skip="no $t on PATH"; break; }
            done
            if [ -z "$skip" ] && [ "$language" = go ]; then
                # cgo compiles the example with this compiler.
                go_cc="$(go env CC)"
                command -v "$go_cc" >/dev/null 2>&1 || skip="no $go_cc on PATH for cgo"
            fi
            if [ -z "$skip" ] && [ "$language" = java ]; then
                # The Foreign Function & Memory API the example uses is final from Java 22.
                javac_major="$(javac -version 2>&1 | tr -d '\r' | sed -nE 's/^javac ([0-9]+).*/\1/p')"
                if [ -z "$javac_major" ] || [ "$javac_major" -lt 22 ]; then
                    skip="javac ${javac_major:-of unknown version} on PATH, the example needs 22 or later"
                fi
            fi
            if [ -n "$skip" ]; then
                echo "skip: $language ($skip)"
                continue
            fi
            ran="$ran $language"
            run_program "examples/$language" bash "$example/run.sh" "$dir"
            require "examples/$language" "$abc_digest" || failed=1
        done
        [ -n "$ran" ] || { echo "FAILED: no example toolchain on PATH" >&2; exit 1; }
        if [ "$failed" -eq 0 ]; then
            echo "ok: the examples for${ran} run against $lib from the extracted archive"
        fi
        exit "$failed"
        ;;
    *)
        echo "usage: release-archive-check.sh cli|library|imports|examples ..." >&2
        exit 1
        ;;
esac
