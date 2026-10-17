#!/usr/bin/env bash
# The one place a release build gets its integrity key.
#
#   release-signing-key.sh public  <source> <key-dir> <signer>
#   release-signing-key.sh private <source> <key-dir>
#   release-signing-key.sh --erase <key-dir>
#
# `public` writes two lines, NAME=value, to "$GITHUB_ENV" when that is set
# and to stdout otherwise. Neither is secret:
#
#   OXICRYPT_INTEGRITY_VERIFY_KEY   the public key every artifact embeds
#   INTEGRITY_KEY_FINGERPRINT       sha256:<hex> of that public key, which
#                                   every signed artifact must report
#
# `private` prints the path `oxicrypt-integrity-sign --sign --key` is given,
# and nothing else, on stdout. The caller keeps it in a shell variable for the
# one step that signs, and erases it with `--erase` when that step ends; it is
# never written to "$GITHUB_ENV", where later steps and actions would see it.
#
# <source> is one of:
#
#   test            A test key pair: the one already in <key-dir>, or one
#                   generated there with `<signer> --keygen` by `public`. The
#                   release workflow generates one per run and gives it to every
#                   job, so all of a run's artifacts carry one fingerprint. It
#                   identifies the run, not the project. Dry runs use it.
#   ci-secret       The project's release key. `private` decodes the 32-byte
#                   ML-DSA-87 key-generation seed from
#                   OXICRYPT_RELEASE_SIGNING_KEY (base64) into
#                   <key-dir>/integrity-signing.key, mode 0600 (on Windows the
#                   mode has no effect on NTFS; what protects the file there is
#                   the runner's ephemeral disk and the erasure when the signing
#                   step ends). The public half
#                   is keys/release-integrity-verify.pub in the repository, so
#                   the key every release trusts is a reviewed file, and
#                   changing it is a commit.
#   hardware-token  Not implemented. The private key stays on a PKCS#11 token
#                   and signing runs where the token is attached.
#   kms             Not implemented. The private key stays in a cloud key
#                   management service and the signer calls it.
#
# `--erase` overwrites the private key file and removes it, and removes it even
# when the overwrite fails. Both unimplemented sources exit 3 naming what they
# need. Exit 0 on success, 1 on a usage error, 2 when the key material is
# absent or malformed.
set -euo pipefail

usage() {
    echo "usage: release-signing-key.sh public <test|ci-secret|hardware-token|kms> <key-dir> <signer>" >&2
    echo "       release-signing-key.sh private <test|ci-secret|hardware-token|kms> <key-dir>" >&2
    echo "       release-signing-key.sh --erase <key-dir>" >&2
    exit 1
}

# Overwrite in place, then remove. The removal is attempted whatever the
# overwrite did. `conv=notrunc` writes over the file's own blocks rather than
# truncating it and allocating new ones. On a copy-on-write or journalling file
# system the old blocks may survive; the runner's disk is discarded with the
# runner, which is the stronger guarantee. Fails when the size cannot be read,
# the overwrite fails or the file is still there afterwards.
erase_file() {
    local f="$1" len ok=0
    [ -e "$f" ] || return 0
    if ! len="$(wc -c < "$f" | tr -d ' ')" || ! [ "$len" -ge 0 ] 2>/dev/null; then
        echo "erase: cannot read the size of $f, so it was not overwritten" >&2
        ok=1
    elif [ "$len" -gt 0 ] && ! dd if=/dev/zero of="$f" bs="$len" count=1 conv=notrunc 2>/dev/null; then
        echo "erase: could not overwrite $f" >&2
        ok=1
    fi
    rm -f "$f"
    if [ -e "$f" ]; then
        echo "erase: could not remove $f" >&2
        ok=1
    fi
    return "$ok"
}

unimplemented() {
    case "$1" in
        hardware-token)
            echo "hardware-token: not implemented. It needs PKCS#11 support in oxicrypt-integrity-sign," >&2
            echo "which reads only a key file and refuses a pkcs11: URI, and a runner the token is attached to." >&2
            ;;
        kms)
            echo "kms: not implemented. It needs a key-management-service route in oxicrypt-integrity-sign," >&2
            echo "which reads only a key file, and credentials for the service in the release job." >&2
            ;;
    esac
    exit 3
}

# Paths are read by native programs (the build script, the signer). Under Git
# Bash on Windows a path built with `pwd` is `/d/...`, which only the shell
# understands.
native() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi
}

bytes_of() { wc -c < "$1" | tr -d ' '; }

# The digest of a file, read from stdin: given a file name containing a
# backslash (a Windows path), sha256sum escapes it and prefixes its output
# line with `\`.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum < "$1" | cut -d' ' -f1
    else
        shasum -a 256 < "$1" | cut -d' ' -f1
    fi
}

mode="${1:-}"
case "$mode" in
    --erase)
        [ $# -eq 2 ] || usage
        key="$2/integrity-signing.key"
        if [ -e "$key" ]; then
            erase_file "$key" || { echo "FAILED: $key was not erased" >&2; exit 2; }
            echo "erased $key"
        else
            echo "no signing key at $key"
        fi
        exit 0
        ;;
    public)
        [ $# -eq 4 ] || usage
        source="$2" dir="$3" signer="$4"
        here="$(cd "$(dirname "$0")" && pwd)"
        case "$source" in
            test)
                public="$dir/integrity-verify.pub"
                if [ ! -f "$dir/integrity-signing.key" ] || [ ! -f "$public" ]; then
                    "$signer" --keygen "$dir" >/dev/null
                fi
                ;;
            ci-secret)
                public="$here/../keys/release-integrity-verify.pub"
                if [ ! -f "$public" ]; then
                    echo "ci-secret: keys/release-integrity-verify.pub is not in the repository; commit the release key's public half there" >&2
                    exit 2
                fi
                ;;
            hardware-token | kms) unimplemented "$source" ;;
            *) usage ;;
        esac
        public_size="$(bytes_of "$public")" || {
            echo "$source: cannot read the size of $public" >&2
            exit 2
        }
        if [ "$public_size" -ne 2592 ]; then
            echo "$source: $public is $public_size bytes, not a 2592-byte ML-DSA-87 public key" >&2
            exit 2
        fi
        fingerprint="sha256:$(sha256_of "$public")"
        if ! printf '%s\n' "$fingerprint" | grep -qxE 'sha256:[0-9a-f]{64}'; then
            echo "$source: the fingerprint of $public is malformed: $fingerprint" >&2
            exit 2
        fi
        {
            echo "OXICRYPT_INTEGRITY_VERIFY_KEY=$(native "$public")"
            echo "INTEGRITY_KEY_FINGERPRINT=$fingerprint"
        } >> "${GITHUB_ENV:-/dev/stdout}"
        echo "key source: $source, verify key $fingerprint" >&2
        ;;
    private)
        [ $# -eq 3 ] || usage
        source="$2" dir="$3"
        private="$dir/integrity-signing.key"
        case "$source" in
            test)
                if [ ! -f "$private" ]; then
                    echo "test: no test key at $private; run \`public test\` first" >&2
                    exit 2
                fi
                ;;
            ci-secret)
                if [ -z "${OXICRYPT_RELEASE_SIGNING_KEY:-}" ]; then
                    echo "ci-secret: OXICRYPT_RELEASE_SIGNING_KEY is empty; the secret is not configured, or this job cannot read it" >&2
                    exit 2
                fi
                mkdir -p "$dir"
                # From the moment private material exists until it is handed
                # over, any exit erases it, and a signal erases it and exits.
                trap 'erase_file "$private" || true' EXIT
                trap 'erase_file "$private" || true; exit 2' HUP INT TERM
                # GNU and current macOS take -d; older macOS takes -D. The
                # flag is chosen once, so a decode failure reports its own
                # cause rather than the fallback's.
                if printf '' | base64 -d > /dev/null 2>&1; then
                    decode=-d
                else
                    decode=-D
                fi
                # The file is opened first, on its own descriptor, so a failure
                # to create it is reported as that and not as a decode error.
                # The umask sets the mode of a new file only; chmod sets it on
                # one a reused directory already holds.
                if ! ( umask 077 && : > "$private" ) || ! chmod 600 "$private"; then
                    echo "ci-secret: cannot create $private with mode 600" >&2
                    exit 2
                fi
                if ! command exec 3>> "$private"; then
                    echo "ci-secret: cannot open $private" >&2
                    exit 2
                fi
                if ! decode_error="$(
                    printf '%s' "$OXICRYPT_RELEASE_SIGNING_KEY" | base64 "$decode" 2>&1 >&3
                )"; then
                    exec 3>&-
                    echo "ci-secret: OXICRYPT_RELEASE_SIGNING_KEY did not decode as base64: $decode_error" >&2
                    exit 2
                fi
                exec 3>&-
                private_size="$(bytes_of "$private")" || {
                    echo "ci-secret: cannot read the size of $private" >&2
                    exit 2
                }
                if [ "$private_size" -ne 32 ]; then
                    echo "ci-secret: OXICRYPT_RELEASE_SIGNING_KEY decodes to $private_size bytes, not a 32-byte ML-DSA-87 key-generation seed" >&2
                    exit 2
                fi
                ;;
            hardware-token | kms) unimplemented "$source" ;;
            *) usage ;;
        esac
        native "$private"
        # Handed over: the caller now owns the file and its erasure.
        trap - EXIT HUP INT TERM
        ;;
    *)
        usage
        ;;
esac
