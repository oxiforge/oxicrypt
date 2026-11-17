#!/usr/bin/env bash
# run.sh <bundle-dir>: installs the example's locked dependency and runs it
# against the extracted bundle.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: run.sh <bundle-dir>" >&2; exit 2; }
dir="$(cd "$1" && pwd)"
if command -v cygpath >/dev/null 2>&1; then dir="$(cygpath -w "$dir")"; fi
cd "$(dirname "$0")"
npm ci --no-audit --no-fund --silent >&2
node sha256.js "$dir"
