#!/usr/bin/env bash
# Loads the library from a release's Android bundle on the one device `adb`
# reaches and requires the signed library to reach operational, an unsigned
# copy to be refused as unsigned, and a tampered copy to be refused as not
# matching its signature.
#
#   android-device-check.sh <oxicrypt-ffi-<tag>-android-<arch>.tar.gz> <signer>
#
# <arch> is aarch64, for an arm64-v8a device, or x86_64, for an x86_64
# emulator; the device's ro.product.cpu.abi must be that ABI, checked before
# anything is pushed. <signer> is a host build of oxicrypt-integrity-sign.
#
# Environment:
#   ANDROID_SERIAL    the device, as `adb devices` lists it
#   ANDROID_NDK_HOME  the Android NDK root
# Needs adb on PATH and python3. `timeout` bounds the wait for the device
# where it is installed.
#
# Steps:
#   1. Extracts the bundle into a new, empty directory. It must hold exactly
#      one top-level directory, and that directory one regular file named
#      liboxicrypt_ffi.so*, the signed library.
#   2. Builds .github/probes/ffi-operational.c with the NDK's clang for
#      <arch>-linux-android, API 24, linked for 16 KiB pages, and requires
#      the NDK's llvm-readelf to report the result's machine as the bundle's.
#   3. Writes the unsigned control: a copy of the signed library whose slot
#      holds the unsigned template the build emits, the header and footer
#      magics with zeros between them. `<signer> --show` gives the slot's
#      file offset; the slot is SLOT_SIZE (65536) bytes and both magics must
#      be in place before the bytes between them are zeroed. The module
#      reports such a slot as SlotDefect::Unsigned
#      (crates/oxicrypt-integrity/src/verify.rs:336), integrity status 3
#      (crates/oxicrypt-integrity/src/lib.rs:694). A slot zeroed whole would
#      lose its header magic and be reported as damage, status 10. The copy
#      differs from the signed library only inside the slot, and
#      `<signer> --verify` must refuse it, saying the slot holds no signature.
#   4. Prints the device's ro.build.version.release, ro.build.version.sdk,
#      ro.product.cpu.abi and page size. The first two must be non-empty and
#      the page size a number.
#   5. Runs `release-load-check.sh adb-library` with the harness, the
#      unsigned control and the signed library. It derives the tampered
#      control from the signed library with <signer>, pushes the four files
#      and runs each case on the device.
#   6. Prints one verdict line per case.
#
# Exit 0 when every check and all three verdicts hold, 1 when any fails, 2
# for a usage or environment error.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

usage() { echo "usage: android-device-check.sh <oxicrypt-ffi-<tag>-android-<arch>.tar.gz> <signer>" >&2; exit 2; }
fail() { echo "FAILED: $*" >&2; exit 1; }

[ $# -eq 2 ] || usage
archive="$1" signer="$2"
[ -f "$archive" ] || { echo "$archive is not a file" >&2; exit 2; }
[ -x "$signer" ] || { echo "$signer is not an executable" >&2; exit 2; }
[ -n "${ANDROID_SERIAL:-}" ] || { echo "set ANDROID_SERIAL to the device's serial" >&2; exit 2; }
[ -n "${ANDROID_NDK_HOME:-}" ] || { echo "set ANDROID_NDK_HOME to the NDK root" >&2; exit 2; }
command -v adb >/dev/null 2>&1 || { echo "no adb on PATH" >&2; exit 2; }
py="$(command -v python3 || command -v python)" || { echo "no python3 on PATH" >&2; exit 2; }

name="$(basename "$archive")"
arch="$(printf '%s' "$name" | sed -nE 's/^oxicrypt-ffi-.+-android-(aarch64|x86_64)\.tar\.gz$/\1/p')"
case "$arch" in
    aarch64) abi=arm64-v8a machine=AArch64 ;;
    x86_64) abi=x86_64 machine="Advanced Micro Devices X86-64" ;;
    *) echo "$name is not named oxicrypt-ffi-<tag>-android-aarch64.tar.gz or ...-android-x86_64.tar.gz" >&2; exit 2 ;;
esac

bin=""
for host in linux-x86_64 darwin-x86_64 linux-aarch64; do
    if [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host/bin" ]; then
        bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host/bin"
        break
    fi
done
[ -n "$bin" ] || { echo "no prebuilt toolchain under $ANDROID_NDK_HOME" >&2; exit 2; }
clang="$bin/${arch}-linux-android24-clang"
readelf="$bin/llvm-readelf"
[ -x "$clang" ] || { echo "no $clang" >&2; exit 2; }
[ -x "$readelf" ] || { echo "no $readelf" >&2; exit 2; }

# getprop <key>: the device property, carriage returns removed.
getprop() { adb shell getprop "$1" | tr -d '\r'; }

if command -v timeout >/dev/null 2>&1; then
    timeout 300 adb wait-for-device
else
    adb wait-for-device
fi || fail "adb wait-for-device"
device_abi="$(getprop ro.product.cpu.abi)" || fail "adb shell getprop ro.product.cpu.abi"
[ "$device_abi" = "$abi" ] || fail "the device's ABI is $device_abi; $name is for $abi"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

x="$tmp/extract"
mkdir "$x"
tar -xzf "$archive" -C "$x" || fail "could not extract $archive"
entries="$(find "$x" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
if [ "$entries" -ne 1 ] || [ "$(find "$x" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" -ne 1 ]; then
    fail "$archive holds $entries top-level entries, not one directory"
fi
dir="$(find "$x" -mindepth 1 -maxdepth 1 -type d)"
libs="$(find "$dir" -maxdepth 1 -type f -name 'liboxicrypt_ffi.so*')"
[ "$(printf '%s\n' "$libs" | grep -c .)" -eq 1 ] || fail "$name does not hold exactly one liboxicrypt_ffi.so* file"
signed="$libs"
echo "signed library: ${signed#"$x"/}"

harness="$tmp/harness"
"$clang" -O1 -Wall -Wextra -Wl,-z,max-page-size=16384 -o "$harness" "$root/.github/probes/ffi-operational.c" -ldl \
    || fail "building the harness with $clang"
# Captured first: under pipefail, grep -q closing the pipe early can fail it.
header="$("$readelf" -h "$harness" 2>&1)" || fail "$readelf -h $harness: $header"
grep -qE "^ *Machine: +$machine\$" <<<"$header" \
    || fail "the harness is not an ELF for $machine: $(grep Machine <<<"$header")"
echo "harness: built for $machine with $(basename "$clang")"

unsigned="$tmp/unsigned.so"
"$signer" --show "$signed" > "$tmp/show.txt" || fail "$signer --show $signed"
slot="$(sed -nE 's/^  slot at file offset (0x[0-9a-fA-F]+),.*/\1/p' "$tmp/show.txt")"
[ "$(printf '%s\n' "$slot" | grep -c .)" -eq 1 ] || fail "$signer --show did not report one slot offset"
cp "$signed" "$unsigned" || fail "copying $signed"
# The magics are SLOT_HEADER_MAGIC and SLOT_FOOTER_MAGIC
# (crates/oxicrypt-integrity/src/lib.rs).
"$py" -I - "$unsigned" "$slot" <<'PY' || fail "writing the unsigned template over the slot at $slot"
import sys
SIZE = 65536
HEADER = b"\xfcOXICRYPT_FIPS_H"
FOOTER = b"\xfdOXICRYPT_FIPS_F"
path, off = sys.argv[1], int(sys.argv[2], 16)
with open(path, "r+b") as f:
    f.seek(off)
    slot = f.read(SIZE)
    if len(slot) != SIZE or slot[:16] != HEADER or slot[-16:] != FOOTER:
        sys.exit(f"no slot magics at {off:#x}")
    f.seek(off + 16)
    f.write(bytes(SIZE - 32))
PY
# cmp -l prints 1-based offsets: every differing byte must lie in the slot
# body, and some must differ.
diffs="$(cmp -l "$signed" "$unsigned" | awk -v lo="$((slot + 17))" -v hi="$((slot + 65520))" \
    '{n++} $1 < lo || $1 > hi {out++} END {print n + 0, out + 0}')"
[ "${diffs#* }" = 0 ] && [ "${diffs% *}" -gt 0 ] \
    || fail "the unsigned control differs from the signed library outside the slot body, or not at all ($diffs)"
if "$signer" --verify "$unsigned" > "$tmp/unsigned-verify.txt" 2>&1; then
    fail "$signer --verify accepts the unsigned control"
fi
grep -qF "holds no signature" "$tmp/unsigned-verify.txt" \
    || fail "$signer --verify refuses the unsigned control without saying it holds no signature: $(cat "$tmp/unsigned-verify.txt")"
echo "unsigned control: slot at $slot reset to the unsigned template (${diffs% *} bytes changed); --verify refuses it: $(cat "$tmp/unsigned-verify.txt")"

release="$(getprop ro.build.version.release)"
sdk="$(getprop ro.build.version.sdk)"
page="$(adb shell getconf PAGESIZE | tr -d '\r')"
[ -n "$release" ] && [ -n "$sdk" ] && [[ "$page" =~ ^[0-9]+$ ]] \
    || fail "device properties: release '$release', sdk '$sdk', page size '$page'"
echo "device: $ANDROID_SERIAL"
echo "  ro.build.version.release: $release"
echo "  ro.build.version.sdk: $sdk"
echo "  ro.product.cpu.abi: $device_abi"
echo "  page size: $page"

bash "$here/release-load-check.sh" adb-library "$harness" "$unsigned" "$signed" "$signer" 2>&1 | tee "$tmp/load.txt"
rc="${PIPESTATUS[0]}"

failed=0
[ "$rc" -eq 0 ] || { echo "FAILED: release-load-check.sh adb-library exited $rc" >&2; failed=1; }
# verdict <line from release-load-check.sh> <case>
verdict() {
    if [ "$(grep -cxF -- "$1" "$tmp/load.txt")" -eq 1 ]; then
        echo "verdict ok: $2"
    else
        echo "verdict FAILED: $2" >&2
        failed=1
    fi
}
verdict "control ok: the library as linked is refused as unsigned" "the unsigned control is refused as unsigned"
verdict "ok: the signed library reaches operational" "the signed library reaches operational"
verdict "control ok: the tampered library is refused as not matching its signature" \
    "the tampered control is refused as not matching its signature"
exit "$failed"
