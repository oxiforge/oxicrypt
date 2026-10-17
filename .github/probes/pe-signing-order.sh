#!/usr/bin/env bash
# The PE signing order, measured: what each Authenticode step writes.
#
#   pe-signing-order.sh <dll> <signer> <outdir> <signtool> <thumbprint> <other-thumbprint> [<pdb>]
#
# Both thumbprints name code-signing certificates in the current user's store;
# the second is used only by the identity control. <pdb> is the program
# database the DLL's CodeView record names; it is copied beside the copies,
# where the integrity signer reads the module statics from it. Steps, each a
# copy:
#
#   A  signtool sign of the linked DLL, with the final certificate and options
#   B  signtool sign of A, the same again
#   C  oxicrypt-integrity-sign --sign --reserved-against <the linked DLL> of B
#   D  signtool sign of C
#
# Measured, and printed as `measurement:` lines:
#   A vs B   within the headers only CheckSum and the Security directory entry
#            may differ; every byte from the headers to the certificate table
#            must be identical; the fields that did differ are the derived holes
#   B vs C   only the integrity slot
#   C vs D   only the derived holes, before the certificate table
#   B and D  the same signing certificate
#   D        `oxicrypt-integrity-sign --verify`
#
# Controls, each of which must fire or the script exits 1; each runs only on a
# baseline that passed, and a control that cannot run is `control NOT RUN`
# (signing-order-lib.sh). If the integrity signer refuses B, the script exits 1:
#   D' = D with one byte of .text flipped: the C vs D comparison must fail
#   D2 = C signed with the other certificate: the identity check must fail
#   B with one header byte flipped outside the two fields: A vs B must fail
# B vs C (slot only) and the integrity verify of D must pass, or the script
# exits 1.
set -euo pipefail
# INTEGRITY_SIGNING_KEY names the signing key matching the verifying key the
# DLL was built with (oxicrypt-integrity-sign --keygen).
: "${INTEGRITY_SIGNING_KEY:?set it to the signing key from --keygen}"

dll="${1:?usage: pe-signing-order.sh <dll> <signer> <outdir> <signtool> <thumbprint> <other-thumbprint>}"
signer="${2:?missing signer}"
out="${3:?missing outdir}"
signtool="${4:?missing signtool}"
thumb="${5:?missing thumbprint}"
other="${6:?missing other thumbprint}"
pdb="${7:-}"
here="$(cd "$(dirname "$0")" && pwd)"
res="$here/reservation.py"
mkdir -p "$out"
if [ -n "$pdb" ]; then
    cp "$pdb" "$out/"
fi
cd "$out"

# Git Bash rewrites arguments that start with `/` into Windows paths, which
# turns `/fd SHA256` into a path and leaves signtool with no digest
# algorithm. MSYS_NO_PATHCONV keeps signtool's switches as written.
asign() { MSYS_NO_PATHCONV=1 "$signtool" sign /fd SHA256 /sha1 "$2" "$1" >/dev/null; }
# The signing certificate of a file's Authenticode signature.
cert_of() { pwsh -NoProfile -Command "(Get-AuthenticodeSignature -FilePath '$1').SignerCertificate.Thumbprint" | tr -d '\r'; }
text_mid() {
    "$py" - "$1" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
pe, = struct.unpack_from("<I", d, 0x3C)
n, = struct.unpack_from("<H", d, pe + 6)
opt, = struct.unpack_from("<H", d, pe + 20)
for i in range(n):
    e = pe + 24 + opt + i * 40
    if d[e:e + 8].rstrip(b"\0") == b".text":
        vsize, _va, raw, ptr = struct.unpack_from("<IIII", d, e + 8)
        print(ptr + min(vsize, raw) // 2)
        break
PY
}
# shellcheck source=signing-order-lib.sh
. "$here/signing-order-lib.sh"

cp "$dll" linked.dll
cp "$dll" A.dll
asign A.dll "$thumb"
cp A.dll B.dll
asign B.dll "$thumb"
# The holes are every field signtool writes. Two signs of the same bytes
# leave CheckSum alone, since it is a checksum of the file; signtool's write
# to it shows only against the unsigned image. So the holes are the fields
# that differed from the linked DLL to A, or from A to B.
measure linked-vs-a "$py" "$res" pe-whitelist linked.dll A.dll
measure a-vs-b "$py" "$res" pe-whitelist A.dll B.dll
ab_rc=$last_rc
holes="$( { sed -n 's/^derived-holes: //p' linked-vs-a.txt; sed -n 's/^derived-holes: //p' a-vs-b.txt; } |
    tr -d '\r' | tr ',' '\n' | grep -v '^none$' | sort -u | paste -sd, - )"
echo "measurement: derived holes ${holes:-none}"

# CONTROL: a header byte outside CheckSum and the Security directory entry
# (0x40, in the DOS stub) must break A vs B.
cp B.dll B-control.dll
flip B-control.dll 0x40
control_flip "a header byte outside the Authenticode fields" "$ab_rc" 0x40 \
    "$py" "$res" pe-whitelist A.dll B-control.dll

cp B.dll C.dll
# The integrity signer's own reservation: against the DLL as linked, since
# two signtool runs of the same bytes write the same CheckSum.
set +e
"$signer" --show --reserved-against linked.dll B.dll > show-b.txt 2>&1
echo "measurement: show-b exit $?"
set -e
sed -n -E '/envelope holes|module statics|extent after|slot table|file_len/p' show-b.txt
measure sign "$signer" --sign --key "$INTEGRITY_SIGNING_KEY" --reserved-against linked.dll C.dll
if [ "$last_rc" -ne 0 ]; then
    not_run "a .text byte flipped after the final signtool run" "the integrity signer refused B (exit $last_rc)"
    not_run "a different certificate at D" "the integrity signer refused B (exit $last_rc)"
    exit 1
fi
measure b-vs-c "$py" "$res" slot-only B.dll C.dll
require_ok "B vs C (only the slot may change, and it must)"
cp C.dll D.dll
asign D.dll "$thumb"
measure c-vs-d "$py" "$res" pe-final C.dll D.dll --allow "${holes:-none}"
cd_rc=$last_rc
measure integrity-verify-d "$signer" --verify D.dll
require_ok "the integrity signer's --verify of D"
cert_b="$(cert_of B.dll)"
cert_d="$(cert_of D.dll)"
echo "measurement: signing certificate B=$cert_b D=$cert_d"

off="$(text_mid D.dll)"
cp D.dll D-control.dll
flip D-control.dll "$off"
control_flip "a .text byte flipped after the final signtool run" "$cd_rc" "$off" \
    "$py" "$res" pe-final C.dll D-control.dll --allow "${holes:-none}"

if [ -z "$cert_b" ] || [ "$cert_b" != "$cert_d" ]; then
    not_run "a different certificate at D" "B and D do not already carry the same certificate ($cert_b / $cert_d)"
else
    cp C.dll D2.dll
    asign D2.dll "$other"
    cert_d2="$(cert_of D2.dll)"
    if [ -n "$cert_d2" ] && [ "$cert_b" != "$cert_d2" ]; then
        echo "control ok: a different certificate at D changes the identity"
    else
        echo "control FAILED: a different certificate at D left the identity unchanged ($cert_b / $cert_d2)"
        controls_failed=1
    fi
fi
exit "$controls_failed"
