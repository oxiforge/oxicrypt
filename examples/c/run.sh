#!/usr/bin/env bash
# run.sh <bundle-dir> [out-dir]: builds the example against the extracted
# bundle and runs it, writing its output files to <out-dir>, or to a
# temporary directory removed afterwards.
set -euo pipefail
[ $# -eq 1 ] || [ $# -eq 2 ] || { echo "usage: run.sh <bundle-dir> [out-dir]" >&2; exit 2; }
dir="$(cd "$1" && pwd)"
build="$(mktemp -d)"
if [ $# -eq 2 ]; then
    out="$(cd "$2" && pwd)"
    trap 'rm -rf "$build"' EXIT
else
    out="$(mktemp -d)"
    trap 'rm -rf "$build" "$out"' EXIT
fi
cd "$(dirname "$0")"
if command -v cygpath >/dev/null 2>&1; then
    # MinGW links the DLL itself; the loader finds it through PATH.
    w="$(cygpath -m "$dir")"
    cc -O2 -Wall -Wextra -I"$w" -o "$build/example.exe" example.c "$w/oxicrypt_ffi.dll"
    PATH="$dir:$PATH" "$build/example.exe" "$(cygpath -w "$dir")" "$(cygpath -w "$out")"
else
    cc -O2 -Wall -Wextra -I"$dir" -o "$build/example" example.c -L"$dir" -loxicrypt_ffi -Wl,-rpath,"$dir"
    "$build/example" "$dir" "$out"
fi
