#!/usr/bin/env bash
# run.sh <bundle-dir> [out-dir]: builds the example and runs it against the
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
bin="$build"
native_out="$out"
if command -v cygpath >/dev/null 2>&1; then
    dir="$(cygpath -w "$dir")"
    native_out="$(cygpath -w "$out")"
    bin="$(cygpath -w "$build")"
fi
cd "$(dirname "$0")"
export DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
dotnet build --nologo -v quiet -clp:NoSummary -o "$bin" >&2
dotnet "$bin/Example.dll" "$dir" "$native_out"
