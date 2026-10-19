#!/usr/bin/env bash
# Prints the file name a built C library is delivered under, which is the name
# a program linked against it asks the loader for:
#
#   library-file-name.sh <artifact>
#
#   ELF     the SONAME (liboxicrypt_ffi.so.<ABI>); $READELF names the tool
#           (default readelf)
#   Mach-O  the last component of the install name
#           (liboxicrypt_ffi.<ABI>.dylib); needs otool
#   PE      the artifact's own name (oxicrypt_ffi.dll), which Windows loads by
#
# An ELF library without a SONAME, a Mach-O library without an install name,
# or a tool that cannot read the file is an error: the script never guesses a
# name. Cargo
# writes the library under its plain name; a delivery copies it to this name
# and keeps the plain name as a link to it, which is what a linker searches for.
set -euo pipefail

artifact="${1:?usage: library-file-name.sh <artifact>}"
magic="$(od -An -tx1 -N4 "$artifact" | tr -d ' \n')"
case "$magic" in
    7f454c46)
        dynamic="$("${READELF:-readelf}" -d "$artifact")" \
            || { echo "library-file-name.sh: ${READELF:-readelf} cannot read $artifact" >&2; exit 1; }
        name="$(sed -n 's/.*Library soname: \[\(.*\)\]/\1/p' <<<"$dynamic")"
        ;;
    cffaedfe | cefaedfe)
        ids="$(otool -D "$artifact")" \
            || { echo "library-file-name.sh: otool cannot read $artifact" >&2; exit 1; }
        name="$(sed -n '2p' <<<"$ids")"
        name="${name##*/}"
        ;;
    4d5a*)
        name="$(basename "$artifact")"
        ;;
    *)
        echo "library-file-name.sh: unrecognised format (magic $magic): $artifact" >&2
        exit 1
        ;;
esac
if [ -z "$name" ]; then
    echo "library-file-name.sh: $artifact records no SONAME or install name" >&2
    exit 1
fi
printf '%s\n' "$name"
