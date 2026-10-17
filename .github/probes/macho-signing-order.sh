#!/usr/bin/env bash
# The Mach-O signing order, measured: what each step writes into the dylib.
#
#   macho-signing-order.sh <dylib> <signer> <outdir> [identity]
#
# identity defaults to `-` (ad hoc); the release identity takes its place in a
# release run. Steps, each a copy in <outdir>:
#
#   A  codesign of the linked dylib, with the final identity and options
#   B  codesign of A, the same again
#   C  oxicrypt-integrity-sign --sign --reserved-against A of B: the signer
#      types as holes exactly the locator fields A and B differ in
#   D  codesign of C, the same identity and options
#
# Measured, and printed as `measurement:` lines:
#   A vs B   only the four envelope locator fields may differ in the header,
#            and nothing before the signature blob; the fields that did differ
#            are the derived holes
#   B vs C   only the integrity slot
#   C vs D   only the derived holes, before C's signature blob
#   B and D  the same code-signing identity and flags
#   D        `codesign --verify` and `oxicrypt-integrity-sign --verify`
#
# Controls, each of which must fire or the script exits 1. A flip control runs
# only when its baseline comparison passed, and must exit 1 with a reported
# range containing the flipped byte (signing-order-lib.sh):
#   D' = D with one byte of __TEXT flipped: the C vs D comparison must fail
#   D2 = C code-signed with different options: the identity check must fail
#   the A vs B comparison must fail on B with one header byte flipped outside
#   the four fields
# B vs C (slot only), codesign --verify D and the integrity verify of D must
# pass, or the script exits 1.
# If the integrity signer refuses B, the C and D controls are reported
# `control NOT RUN` and the script exits 1.
set -euo pipefail
# INTEGRITY_SIGNING_KEY names the signing key matching the verifying key the
# dylib was built with (oxicrypt-integrity-sign --keygen).
: "${INTEGRITY_SIGNING_KEY:?set it to the signing key from --keygen}"

dylib="${1:?usage: macho-signing-order.sh <dylib> <signer> <outdir> [identity]}"
signer="${2:?usage: macho-signing-order.sh <dylib> <signer> <outdir> [identity]}"
out="${3:?usage: macho-signing-order.sh <dylib> <signer> <outdir> [identity]}"
identity="${4:--}"
here="$(cd "$(dirname "$0")" && pwd)"
res="$here/reservation.py"
mkdir -p "$out"
cd "$out"

# One explicit identifier for every signature: an ad-hoc signature otherwise
# derives it from the file name (A.dylib, B.dylib, D.dylib), and the identity
# check between B and D would compare file names.
signing_id=oxicrypt-signing-order
csign() { codesign --force --sign "$identity" --identifier "$signing_id" --timestamp=none "$@"; }
# The identity and flags of a code signature, without sizes and hashes.
ident() {
    codesign -dv --verbose=2 "$1" 2>&1 |
        sed -n -e 's/^\(Identifier=.*\)$/\1/p' -e 's/^\(Format=.*\)$/\1/p' \
            -e 's/^\(Signature=.*\)$/\1/p' -e 's/^\(Authority=.*\)$/\1/p' \
            -e 's/^\(TeamIdentifier=.*\)$/\1/p' -e 's/^\(Runtime Version=.*\)$/\1/p' \
            -e 's/^CodeDirectory .*\(flags=[^ ]*\).*$/CodeDirectory \1/p'
}
# shellcheck source=signing-order-lib.sh
. "$here/signing-order-lib.sh"

cp "$dylib" A.dylib
# The dSYM beside the input, if any, serves C: the signer reads the module's
# statics from it, matched by LC_UUID, which code signing leaves unchanged.
if [ -d "$dylib.dSYM" ]; then
    rm -rf C.dylib.dSYM
    cp -R "$dylib.dSYM" C.dylib.dSYM
fi
csign A.dylib
cp A.dylib B.dylib
csign B.dylib
measure a-vs-b "$py" "$res" macho-whitelist A.dylib B.dylib
ab_rc=$last_rc
holes="$(sed -n 's/^derived-holes: //p' a-vs-b.txt)"

cp B.dylib B-control.dylib
flip B-control.dylib 8 # cpusubtype: a header byte outside the four fields
control_flip "a header byte outside the envelope fields" "$ab_rc" 8 \
    "$py" "$res" macho-whitelist A.dylib B-control.dylib

cp B.dylib C.dylib
measure sign "$signer" --sign --key "$INTEGRITY_SIGNING_KEY" --reserved-against A.dylib C.dylib
if [ "$last_rc" -ne 0 ]; then
    not_run "a __TEXT byte flipped after the final codesign" "the integrity signer refused B (exit $last_rc)"
    not_run "a different signing configuration at D" "the integrity signer refused B (exit $last_rc)"
    exit 1
fi
measure b-vs-c "$py" "$res" slot-only B.dylib C.dylib
require_ok "B vs C (only the slot may change, and it must)"
cp C.dylib D.dylib
csign D.dylib
measure c-vs-d "$py" "$res" macho-final C.dylib D.dylib --allow "${holes:-none}"
cd_rc=$last_rc
ident B.dylib > ident-B.txt
ident D.dylib > ident-D.txt
measure identity-b-vs-d diff ident-B.txt ident-D.txt
id_rc=$last_rc
measure codesign-verify-d codesign --verify D.dylib
require_ok "codesign --verify D"
measure integrity-verify-d "$signer" --verify D.dylib
require_ok "the integrity signer's --verify of D"

# CONTROL: a __TEXT byte flipped in D must break C vs D.
text_mid="$(otool -l D.dylib | awk '/segname __TEXT/{f=1} f && /^ *filesize /{print int($2/2); exit}')"
cp D.dylib D-control.dylib
flip D-control.dylib "$text_mid"
control_flip "a __TEXT byte flipped after the final codesign" "$cd_rc" "$text_mid" \
    "$py" "$res" macho-final C.dylib D-control.dylib --allow "${holes:-none}"

# CONTROL: different signing options at D must break the identity check.
if [ "$id_rc" -ne 0 ]; then
    not_run "a different signing configuration at D" "B and D already differ in identity"
else
    cp C.dylib D2.dylib
    codesign --force --sign "$identity" --identifier "$signing_id" --timestamp=none --options runtime D2.dylib
    ident D2.dylib > ident-D2.txt
    if [ -s ident-B.txt ] && ! diff -q ident-B.txt ident-D2.txt >/dev/null; then
        echo "control ok: a different signing configuration at D changes the identity"
    else
        echo "control FAILED: a different signing configuration at D left the identity unchanged"
        controls_failed=1
    fi
fi
exit "$controls_failed"
