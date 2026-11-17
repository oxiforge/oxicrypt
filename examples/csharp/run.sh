#!/usr/bin/env bash
# run.sh <bundle-dir>: builds the example and runs it against the extracted
# bundle.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: run.sh <bundle-dir>" >&2; exit 2; }
dir="$(cd "$1" && pwd)"
if command -v cygpath >/dev/null 2>&1; then dir="$(cygpath -w "$dir")"; fi
cd "$(dirname "$0")"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
export DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
dotnet build --nologo -v quiet -clp:NoSummary -o "$out" >&2
dotnet "$out/Sha256.dll" "$dir"
