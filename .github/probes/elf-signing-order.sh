#!/usr/bin/env bash
# The ELF signing order, step by step, with what each step may change.
#
#   elf-signing-order.sh <library> <signer> <outdir> [objcopy] [strip]
#
# 1. The file-backed module statics row is read from the linked library, while
#    it still has its symbol table. An empty or non-empty row is a
#    measurement; a row that could not be taken is a failed control.
# 2. The debug information is split off and the library stripped of
#    `.debug_*`, `.symtab` and `.strtab`, then given a debuglink to the split
#    file. Integrity signing comes after this, so nothing it covers is
#    rewritten later.
# 3. The integrity signer runs. Between the debuglinked file and the signed
#    file only the slot may change, and the ELF header [0, 64) must not.
# 4. CONTROL: a byte flipped outside the slot of the signed copy must make the
#    step-3 comparison exit 1 and report a range containing that byte. A
#    statics row that could not be taken (status 2 or 3) also fails.
#
# Writes linked.so, stripped.so, signed.so, linked.debug and statics.txt to
# <outdir>. Exit 0 when step 3 holds and the control fires.
set -euo pipefail
# The library must have been built with OXICRYPT_INTEGRITY_VERIFY_KEY, and
# INTEGRITY_SIGNING_KEY names the matching signing key from --keygen.
: "${INTEGRITY_SIGNING_KEY:?set it to the signing key from --keygen}"

lib="${1:?usage: elf-signing-order.sh <library> <signer> <outdir> [objcopy] [strip]}"
signer="${2:?usage: elf-signing-order.sh <library> <signer> <outdir> [objcopy] [strip]}"
out="${3:?usage: elf-signing-order.sh <library> <signer> <outdir> [objcopy] [strip]}"
objcopy="${4:-objcopy}"
strip="${5:-strip}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

cp "$lib" "$out/linked.so"
set +e
python3 "$here/file-backed-statics.py" "$out/linked.so" > "$out/statics.txt"
statics_rc=$?
set -e
sed 's/^/measurement: /' "$out/statics.txt"
echo "measurement: file-backed module statics row status $statics_rc (0 empty, 1 non-empty)"

"$objcopy" --only-keep-debug "$out/linked.so" "$out/linked.debug"
cp "$out/linked.so" "$out/stripped.so"
"$strip" --strip-all "$out/stripped.so"
(cd "$out" && "$objcopy" --add-gnu-debuglink=linked.debug stripped.so)
cp "$out/stripped.so" "$out/signed.so"
"$signer" --sign --key "$INTEGRITY_SIGNING_KEY" "$out/signed.so"
"$signer" --verify "$out/signed.so"
python3 "$here/reservation.py" slot-only "$out/stripped.so" "$out/signed.so"

# CONTROL: the comparison must be able to fail, and must find the very byte.
# Offset 100 lies in the program headers, outside the slot and the ELF header.
# shellcheck source=signing-order-lib.sh
. "$here/signing-order-lib.sh"
cp "$out/signed.so" "$out/control.so"
flip "$out/control.so" 100
control_flip "a byte flipped outside the slot" 0 100 \
    "$py" "$here/reservation.py" slot-only "$out/stripped.so" "$out/control.so"
rm -f "$out/control.so"
if [ "$statics_rc" -ge 2 ]; then
    echo "control FAILED: the file-backed module statics row could not be taken (status $statics_rc)"
    controls_failed=1
fi
exit "$controls_failed"
