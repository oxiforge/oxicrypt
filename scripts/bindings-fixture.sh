#!/usr/bin/env bash
# Builds and signs the shared library the tests of the `oxicrypt` crate link
# against, with key pairs generated for this fixture alone.
#
#   bindings-fixture.sh <dir>
#
# <dir> must be empty or absent. On success it holds:
#
#   keys/            the fixture's key pair (integrity-verify.pub, integrity-signing.key)
#   signed/          the library built with keys/ and signed by scripts/release-sign.sh,
#                    under its delivered name (liboxicrypt_ffi.so.<ABI>, from
#                    scripts/library-file-name.sh), with liboxicrypt_ffi.so a
#                    link to it for linking
#   unsigned/        the same library as linked, never signed, laid out the same way
#   archive/         the static archive liboxicrypt_ffi.a from the same build
#   second-key/      a library built with a second key pair (keys2/) and signed with it
#   bin/             the oxicrypt-integrity-sign binary used to sign
#   env.sh           the variables a test run sets, in `export NAME=value` form
#
# and the script prints the same variables. The private keys stay in <dir>;
# delete the directory when the run is over.
#
# The build uses $CARGO_TARGET_DIR when it is set, else `target/` in the
# repository. $OXICRYPT_INTEGRITY_SIGN names an already built signer to use
# instead of building one. Only ELF targets (Linux) are handled.
set -euo pipefail

dir="${1:?usage: bindings-fixture.sh <dir>}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$repo/target}"

fail() { echo "FAILED: $*" >&2; exit 1; }

mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
[ -z "$(ls -A "$dir")" ] || fail "$dir is not empty"
mkdir -p "$dir/signed" "$dir/unsigned" "$dir/archive" "$dir/second-key" "$dir/bin"

cd "$repo"
if [ -n "${OXICRYPT_INTEGRITY_SIGN:-}" ]; then
    cp "$OXICRYPT_INTEGRITY_SIGN" "$dir/bin/oxicrypt-integrity-sign"
else
    cargo build --release -p oxicrypt-integrity-sign
    cp "$target_dir/release/oxicrypt-integrity-sign" "$dir/bin/"
fi
signer="$dir/bin/oxicrypt-integrity-sign"

build_ffi() {
    OXICRYPT_INTEGRITY_VERIFY_KEY="$1/integrity-verify.pub" cargo build --release -p oxicrypt-ffi
}

# Copies a built library into a directory under its delivered name, links the
# plain name to it, and prints the delivered file's path.
deliver() {
    local name
    name="$("$repo/scripts/library-file-name.sh" "$1")"
    cp "$1" "$2/$name"
    if [ "$name" != "liboxicrypt_ffi.so" ]; then
        ln -s "$name" "$2/liboxicrypt_ffi.so"
    fi
    printf '%s\n' "$2/$name"
}

fingerprint_of() {
    "$signer" --show "$1" | sed -n 's/^  verify key: \(sha256:[0-9a-f]\{64\}\)$/\1/p'
}

# The second key first, so that the last build left in the target directory
# is the one the tests pin.
"$signer" --keygen "$dir/keys2" > /dev/null || fail "--keygen keys2"
build_ffi "$dir/keys2"
second_lib="$(deliver "$target_dir/release/liboxicrypt_ffi.so" "$dir/second-key")"
INTEGRITY_SIGNING_KEY="$dir/keys2/integrity-signing.key" \
    "$repo/scripts/release-sign.sh" "$signer" "$second_lib" "$dir/second-key/record.txt"

"$signer" --keygen "$dir/keys" > /dev/null || fail "--keygen keys"
build_ffi "$dir/keys"
deliver "$target_dir/release/liboxicrypt_ffi.so" "$dir/unsigned" > /dev/null
signed_lib="$(deliver "$target_dir/release/liboxicrypt_ffi.so" "$dir/signed")"
cp "$target_dir/release/liboxicrypt_ffi.a" "$dir/archive/"
INTEGRITY_SIGNING_KEY="$dir/keys/integrity-signing.key" \
    "$repo/scripts/release-sign.sh" "$signer" "$signed_lib" "$dir/signed/record.txt"

fingerprint="$(fingerprint_of "$signed_lib")"
second="$(fingerprint_of "$second_lib")"
printf '%s\n' "$fingerprint" | grep -qxE 'sha256:[0-9a-f]{64}' || fail "no fingerprint for signed/: $fingerprint"
printf '%s\n' "$second" | grep -qxE 'sha256:[0-9a-f]{64}' || fail "no fingerprint for second-key/: $second"
[ "$fingerprint" != "$second" ] || fail "the two keys report one fingerprint"

{
    echo "export OXICRYPT_LIB_DIR=$dir/signed"
    echo "export OXICRYPT_LIB_FINGERPRINT=$fingerprint"
    echo "export OXICRYPT_BINDINGS_FIXTURE=$dir"
} > "$dir/env.sh"
cat "$dir/env.sh"
