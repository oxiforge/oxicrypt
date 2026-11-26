#!/usr/bin/env bash
# run.sh <bundle-dir> [out-dir]: builds the example and runs it against the
# extracted bundle, writing its output files to <out-dir>, or to a temporary
# directory removed afterwards.
# run.sh <bundle-dir> decaps <dk-file> <ct-file>: builds it and runs its
# decaps mode.
set -euo pipefail
usage() { printf 'usage: run.sh <bundle-dir> [out-dir]\n       run.sh <bundle-dir> decaps <dk-file> <ct-file>\n' >&2; exit 2; }
case $# in
    1 | 2) ;;
    4) [ "$2" = decaps ] || usage ;;
    *) usage ;;
esac
abs() {
    local d
    d="$(cd "$(dirname "$1")" && pwd)" || { echo "run.sh: no directory $(dirname "$1")" >&2; exit 2; }
    printf '%s/%s' "$d" "$(basename "$1")"
}
dir="$(cd "$1" && pwd)"
build="$(mktemp -d)"
out=""
trap 'rm -rf "$build" ${out:+"$out"}' EXIT
if [ $# -eq 4 ]; then
    dk="$(abs "$3")"
    ct="$(abs "$4")"
    args=(decaps "$dk" "$ct")
elif [ $# -eq 2 ]; then
    args=("$(cd "$2" && pwd)")
else
    out="$(mktemp -d)"
    args=("$out")
fi
bin="$build"
if command -v cygpath >/dev/null 2>&1; then
    dir="$(cygpath -w "$dir")"
    bin="$(cygpath -w "$build")"
    for i in "${!args[@]}"; do [ "${args[$i]}" = decaps ] || args[i]="$(cygpath -w "${args[$i]}")"; done
fi
cd "$(dirname "$0")"
export DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
dotnet build --nologo -v quiet -clp:NoSummary -o "$bin" >&2
dotnet "$bin/Example.dll" "$dir" "${args[@]}"
