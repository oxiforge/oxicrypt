#!/usr/bin/env bash
# run.sh <bundle-dir> [out-dir]: runs the example against the extracted
# bundle, writing its output files to <out-dir>, or to a temporary directory
# removed afterwards.
set -euo pipefail
[ $# -eq 1 ] || [ $# -eq 2 ] || { echo "usage: run.sh <bundle-dir> [out-dir]" >&2; exit 2; }
dir="$(cd "$1" && pwd)"
if [ $# -eq 2 ]; then
    out="$(cd "$2" && pwd)"
else
    out="$(mktemp -d)"
    trap 'rm -rf "$out"' EXIT
fi
native_out="$out"
if command -v cygpath >/dev/null 2>&1; then
    dir="$(cygpath -w "$dir")"
    native_out="$(cygpath -w "$out")"
fi
cd "$(dirname "$0")"
py="$(command -v python3 || command -v python)"
"$py" -I example.py "$dir" "$native_out"
