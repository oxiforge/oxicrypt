#!/usr/bin/env bash
# run.sh <bundle-dir> [out-dir]: compiles the example and runs it against the
# extracted bundle, writing its output files to <out-dir>, or to a temporary
# directory removed afterwards.
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
classes="$build"
native_out="$out"
if command -v cygpath >/dev/null 2>&1; then
    dir="$(cygpath -w "$dir")"
    native_out="$(cygpath -w "$out")"
    classes="$(cygpath -w "$build")"
fi
cd "$(dirname "$0")"
javac -d "$classes" Example.java
java --enable-native-access=ALL-UNNAMED -cp "$classes" Example "$dir" "$native_out"
