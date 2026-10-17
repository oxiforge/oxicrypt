#!/usr/bin/env bash
# Signs a Mach-O in the order docs/integrity-signing.md gives, in place:
#
#   macho-sign.sh <signer> <artifact> [identity]
#
# codesign (A, kept as <artifact>.reference), codesign again (B), the
# integrity signer with --reserved-against A, then the final codesign (D);
# then codesign --verify and the integrity signer's --verify. identity
# defaults to `-` (ad hoc). INTEGRITY_SIGNING_KEY names the signing key.
# Exits non-zero, naming the step, when any step fails.
set -euo pipefail
: "${INTEGRITY_SIGNING_KEY:?set it to the signing key from --keygen}"
signer="${1:?usage: macho-sign.sh <signer> <artifact> [identity]}"
artifact="${2:?usage: macho-sign.sh <signer> <artifact> [identity]}"
identity="${3:--}"
csign() { codesign --force --sign "$identity" --timestamp=none "$1"; }
csign "$artifact" || { echo "FAILED: codesign A" >&2; exit 1; }
cp "$artifact" "$artifact.reference"
csign "$artifact" || { echo "FAILED: codesign B" >&2; exit 1; }
"$signer" --sign --key "$INTEGRITY_SIGNING_KEY" --reserved-against "$artifact.reference" "$artifact" \
    || { echo "FAILED: the integrity signer refused the artifact" >&2; exit 1; }
csign "$artifact" || { echo "FAILED: codesign D" >&2; exit 1; }
codesign --verify "$artifact" || { echo "FAILED: codesign --verify" >&2; exit 1; }
"$signer" --verify "$artifact" || { echo "FAILED: the integrity signer's --verify" >&2; exit 1; }
echo "signed in order: $artifact"
