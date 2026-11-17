#!/usr/bin/env bash
# run.sh <bundle-dir>: compiles the example and runs it against the extracted
# bundle.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: run.sh <bundle-dir>" >&2; exit 2; }
dir="$(cd "$1" && pwd)"
if command -v cygpath >/dev/null 2>&1; then dir="$(cygpath -w "$dir")"; fi
cd "$(dirname "$0")"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
javac -d "$out" Sha256.java
java --enable-native-access=ALL-UNNAMED -cp "$out" Sha256 "$dir"
