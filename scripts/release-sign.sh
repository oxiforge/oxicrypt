#!/usr/bin/env bash
# Signs one linked release artifact in its format's order, in place, and
# checks the result offline.
#
#   release-sign.sh <signer> <artifact> <record>
#
# The format is read from the file's magic number:
#
#   ELF     The debug information is split into <artifact>.debug, the artifact
#           stripped and given a debuglink to it, then integrity signed. The
#           signer reads the module statics from the debug file. $OBJCOPY and
#           $STRIP name the tools (default objcopy and strip).
#   Mach-O  codesign (A, kept as the reference), codesign again (B), the
#           integrity signer with --reserved-against A, the final codesign
#           (D), then `codesign --verify`. $APPLE_CODESIGN_IDENTITY names the
#           identity (default `-`, ad hoc). <artifact>.dSYM must be beside the
#           artifact.
#   PE      With $SIGNTOOL and $AUTHENTICODE_THUMBPRINT set: signtool sign of
#           the linked image, the integrity signer with --reserved-against the
#           linked image, then the final signtool sign. Without them, the
#           integrity signer alone. The program database the image names must
#           be beside it.
#
# Then `<signer> --verify` runs on the artifact as it finally sits. The
# signer's output is appended to <record>, and the signature and the verify
# key's fingerprint are printed as `provenance:` lines. Exactly one signature
# and one fingerprint must be reported, and when $INTEGRITY_KEY_FINGERPRINT is
# set the signing and the verification must both report it.
#
# Requires $INTEGRITY_SIGNING_KEY. Exits non-zero, naming the step, when any
# step fails.
set -euo pipefail
: "${INTEGRITY_SIGNING_KEY:?set it to the signing key (scripts/release-signing-key.sh)}"

signer="${1:?usage: release-sign.sh <signer> <artifact> <record>}"
artifact="${2:?usage: release-sign.sh <signer> <artifact> <record>}"
record="${3:?usage: release-sign.sh <signer> <artifact> <record>}"
name="$(basename "$artifact")"
dir="$(cd "$(dirname "$artifact")" && pwd)"
artifact="$dir/$name"
log="$(mktemp)"
trap 'rm -f "$log" "$log.verify"' EXIT

fail() { echo "FAILED: $name: $*" >&2; exit 1; }

# Checked before anything is signed: the value is compared, never converted.
if [ -n "${INTEGRITY_KEY_FINGERPRINT:-}" ]; then
    printf '%s\n' "$INTEGRITY_KEY_FINGERPRINT" | grep -qxE 'sha256:[0-9a-f]{64}' \
        || fail "the expected fingerprint is malformed: $INTEGRITY_KEY_FINGERPRINT"
fi

magic="$(od -An -tx1 -N4 "$artifact" | tr -d ' \n')"
case "$magic" in
    7f454c46) format=elf ;;
    cffaedfe | cefaedfe) format=macho ;;
    4d5a*) format=pe ;;
    *) fail "unrecognised format (magic $magic)" ;;
esac
echo "$name: $format"

# A path handed to a native Windows program (the signer, signtool) is
# converted to its Windows form: Git Bash's `/d/...` reaches such a program
# unconverted when MSYS path conversion is off, and signtool then reads it as
# an option. Elsewhere the path is unchanged.
native() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi
}
target="$(native "$artifact")"
key="$(native "$INTEGRITY_SIGNING_KEY")"

sign() { "$signer" --sign --key "$key" "$@" | tee -a "$log"; }

case "$format" in
    elf)
        objcopy="${OBJCOPY:-objcopy}"
        strip="${STRIP:-strip}"
        rm -f "$artifact.debug"
        "$objcopy" --only-keep-debug "$artifact" "$artifact.debug" || fail "objcopy --only-keep-debug"
        "$strip" --strip-all "$artifact" || fail "strip"
        (cd "$dir" && "$objcopy" --add-gnu-debuglink="$name.debug" "$name") || fail "objcopy --add-gnu-debuglink"
        sign "$target" || fail "the integrity signer refused the stripped artifact"
        ;;
    macho)
        identity="${APPLE_CODESIGN_IDENTITY:--}"
        csign() { codesign --force --sign "$identity" --timestamp=none "$artifact"; }
        csign || fail "codesign A"
        cp "$artifact" "$artifact.reference"
        csign || fail "codesign B"
        sign --reserved-against "$(native "$artifact.reference")" "$target" \
            || fail "the integrity signer refused the artifact"
        rm -f "$artifact.reference"
        csign || fail "codesign D"
        codesign --verify "$artifact" || fail "codesign --verify"
        ;;
    pe)
        if [ -n "${SIGNTOOL:-}" ] && [ -n "${AUTHENTICODE_THUMBPRINT:-}" ]; then
            # Git Bash rewrites arguments that start with `/` into paths;
            # MSYS_NO_PATHCONV keeps signtool's switches as written.
            asign() { MSYS_NO_PATHCONV=1 "$SIGNTOOL" sign /fd SHA256 /sha1 "$AUTHENTICODE_THUMBPRINT" "$target" >/dev/null; }
            cp "$artifact" "$artifact.linked"
            asign || fail "signtool sign before the integrity signer"
            sign --reserved-against "$(native "$artifact.linked")" "$target" \
                || fail "the integrity signer refused the artifact"
            rm -f "$artifact.linked"
            asign || fail "signtool sign after the integrity signer"
            echo "$name: Authenticode signed with $AUTHENTICODE_THUMBPRINT"
        else
            sign "$target" || fail "the integrity signer refused the artifact"
            echo "$name: no Authenticode certificate configured; integrity signed only"
        fi
        ;;
esac

# A separate run of --verify, on the file as it finally sits. `--sign` also
# prints a `verify ok:` line, for the temporary file it checks before
# replacing the artifact; that one is not this check.
verify_log="$log.verify"
"$signer" --verify "$target" > "$verify_log" || { cat "$verify_log"; rm -f "$verify_log"; fail "--verify on the signed artifact"; }
cat "$verify_log"
cat "$log" "$verify_log" >> "$record"

signature="$(sed -n 's/^signed .* -> signature \(sha256:[0-9a-f]\{64\}\)$/\1/p' "$log")"
signed_key="$(sed -n 's/^  verify key: \(sha256:[0-9a-f]*\)$/\1/p' "$log")"
verified_key="$(sed -n 's/^verify ok: .* (verify key \(sha256:[0-9a-f]*\))$/\1/p' "$verify_log")"
rm -f "$verify_log"
[ "$(printf '%s\n' "$signature" | grep -c .)" -eq 1 ] || fail "expected one signature line, got: $signature"
[ "$(printf '%s\n' "$signed_key" | grep -c .)" -eq 1 ] || fail "expected one verify-key line, got: $signed_key"
[ "$(printf '%s\n' "$verified_key" | grep -c .)" -eq 1 ] || fail "expected one verify-ok line, got: $verified_key"
[ "$signed_key" = "$verified_key" ] || fail "signed with $signed_key but verifies with $verified_key"
if [ -n "${INTEGRITY_KEY_FINGERPRINT:-}" ] && [ "$signed_key" != "$INTEGRITY_KEY_FINGERPRINT" ]; then
    fail "signed with $signed_key, expected $INTEGRITY_KEY_FINGERPRINT"
fi
echo "provenance: $name signature $signature"
echo "provenance: $name verify key $signed_key"
