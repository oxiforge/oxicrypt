#!/usr/bin/env bash
# Requires every PT_LOAD of an ELF file to be aligned for a given page size.
#
#   elf-page-align.sh <elf> <page-bytes> [readelf]
#
# A library aligned for 4 KiB pages loads on a 16 KiB-page Android device only
# through anonymous mappings that name no file, which the file route cannot
# follow. Every PT_LOAD's p_align must be at least the page size and its
# p_offset and p_vaddr must agree modulo it. Exit 0 when they do, 1 when any
# segment does not, 2 when no PT_LOAD was read.
set -euo pipefail

elf="${1:?usage: elf-page-align.sh <elf> <page-bytes> [readelf]}"
page="${2:?usage: elf-page-align.sh <elf> <page-bytes> [readelf]}"
readelf="${3:-readelf}"

loads="$("$readelf" -lW "$elf" | awk '$1 == "LOAD" {print $2, $3, $NF}')"
[ -n "$loads" ] || { echo "no PT_LOAD read from $elf" >&2; exit 2; }
bad=0
while read -r off vaddr align; do
    if [ $((align)) -lt "$page" ] || [ $(((off - vaddr) % page)) -ne 0 ]; then
        echo "misaligned: offset=$off vaddr=$vaddr align=$align (need $page)"
        bad=1
    fi
done <<<"$loads"
n="$(wc -l <<<"$loads")"
if [ "$bad" -eq 0 ]; then
    echo "ok: $n PT_LOAD segments aligned for $page-byte pages"
fi
exit "$bad"
