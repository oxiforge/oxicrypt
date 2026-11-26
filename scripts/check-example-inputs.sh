#!/usr/bin/env bash
# Checks that the example programs, their how-tos and examples/README.md state
# the same fixed inputs: the message, the personalization string, the
# signature byte flipped and the ciphertext byte flipped.
#
#   check-example-inputs.sh [<examples-dir>]
#
# <examples-dir> defaults to the repository's examples/. It must hold
# README.md and, for each of c, python, go, node, java and csharp, the
# program and a README.md, the language's how-to: thirteen files.
#
# From a program the values are read from the declarations of the constants
# MESSAGE and PERSONALIZATION (the first quoted string after `<name> =`,
# `<name>[] =` or `<name> :=`), SIG_FLIP_BYTE and CT_FLIP_BYTE (the integer
# after `<name> =` or `<name> :=`). From a Markdown file they are read from
# the table rows that begin `| \`<name>\` |`: the first backtick span of the
# second cell for MESSAGE and PERSONALIZATION, and the first integer of the
# second cell for SIG_FLIP_BYTE and CT_FLIP_BYTE. A file that is missing,
# that states a value nowhere, or that states it twice with two values,
# fails as `FAILED: <file> <reason>`, and so does a value that differs from
# examples/README.md's. Exit 0 when all thirteen files state the same four
# values, 1 otherwise.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="${1:-$here/../examples}"
[ $# -le 1 ] || { echo "usage: check-example-inputs.sh [<examples-dir>]" >&2; exit 1; }
[ -d "$dir" ] || { echo "FAILED: $dir is not a directory" >&2; exit 1; }
dir="$(cd "$dir" && pwd)"

files=(README.md
    c/example.c c/README.md
    python/example.py python/README.md
    go/main.go go/README.md
    node/example.js node/README.md
    java/Example.java java/README.md
    csharp/Program.cs csharp/README.md)

# value <file> <name>: prints the one value <file> states for <name>, or
# fails naming the file.
value() {
    local file="$1" name="$2" found
    case "$file:$name" in
        *.md:MESSAGE | *.md:PERSONALIZATION)
            found="$(sed -nE "s/^\\| \`${name}\` \\| [^\`|]*\`([^\`]*)\`.*/\\1/p" "$dir/$file")"
            ;;
        *.md:*)
            found="$(sed -nE "s/^\\| \`${name}\` \\| [^0-9|]*([0-9]+).*/\\1/p" "$dir/$file")"
            ;;
        *)
            if [ "$name" = MESSAGE ] || [ "$name" = PERSONALIZATION ]; then
                found="$(sed -nE "s/(^|.*[^A-Za-z0-9_])${name}(\\[\\])?[[:space:]]*:?=[^\"'=]*[\"']([^\"']*)[\"'].*/\\3/p" "$dir/$file")"
            else
                found="$(sed -nE "s/(^|.*[^A-Za-z0-9_])${name}[[:space:]]*:?=[[:space:]]*([0-9]+)([^0-9A-Za-z_]|\$).*/\\2/p" "$dir/$file")"
            fi
            ;;
    esac
    found="$(printf '%s\n' "$found" | tr -d '\r' | awk 'NF' | LC_ALL=C sort -u)"
    case "$(printf '%s' "$found" | grep -c '')" in
        0) echo "FAILED: $file states no $name" >&2; return 1 ;;
        1) printf '%s' "$found" ;;
        *) echo "FAILED: $file states $name more than once, with different values" >&2; return 1 ;;
    esac
}

failed=0
missing=0
for file in "${files[@]}"; do
    if [ ! -f "$dir/$file" ]; then
        echo "FAILED: $file is missing" >&2
        failed=1
        missing=1
    fi
done
[ -f "$dir/README.md" ] || exit 1

for name in MESSAGE PERSONALIZATION SIG_FLIP_BYTE CT_FLIP_BYTE; do
    want="$(value README.md "$name")" || { failed=1; continue; }
    for file in "${files[@]:1}"; do
        [ -f "$dir/$file" ] || continue
        got="$(value "$file" "$name")" || { failed=1; continue; }
        if [ "$got" != "$want" ]; then
            echo "FAILED: $file states $name as \"$got\", README.md as \"$want\"" >&2
            failed=1
        fi
    done
done
if [ "$failed" -eq 0 ]; then
    echo "ok: the message, the personalization string and both flipped bytes agree across ${#files[@]} files"
elif [ "$missing" -eq 1 ]; then
    echo "FAILED: not every file the check reads exists" >&2
fi
exit "$failed"
