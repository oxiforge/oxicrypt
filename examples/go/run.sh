#!/usr/bin/env bash
# run.sh <bundle-dir>: builds the example against the extracted bundle and
# runs it.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: run.sh <bundle-dir>" >&2; exit 2; }
dir="$(cd "$1" && pwd)"
cd "$(dirname "$0")"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
export CGO_ENABLED=1
if command -v cygpath >/dev/null 2>&1; then
    # MinGW links the DLL itself; the loader finds it through PATH.
    w="$(cygpath -m "$dir")"
    export CGO_CFLAGS="-I$w" CGO_LDFLAGS="$w/oxicrypt_ffi.dll" PATH="$dir:$PATH"
    exe=.exe
else
    export CGO_CFLAGS="-I$dir" CGO_LDFLAGS="-L$dir -loxicrypt_ffi -Wl,-rpath,$dir"
    exe=
fi
go build -o "$out/sha256$exe" .
"$out/sha256$exe"
