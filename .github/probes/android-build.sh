#!/usr/bin/env bash
# Builds the artifact directory the Android measurements run from.
#
#   android-build.sh <rust-target> <ndk-dir> <outdir> [api]
#
# <rust-target> is aarch64-linux-android or x86_64-linux-android; api defaults
# to 24. Into <outdir> it writes:
#
#   subject.so          liboxicrypt_ffi.so for the target, linked for 16 KiB
#                       pages, then signed by the host's oxicrypt-integrity-sign
#   subject-unsigned.so the same library before signing (keeps .symtab)
#   statics.txt         the file-backed module statics row, from the unsigned
#                       library's symbol table
#   extent-v2-probe     the typed probe, 16 KiB-aligned
#   probe               the stability probe, 16 KiB-aligned
#   decoy.so            the NDK's libc++_shared.so for the target, which
#                       carries no integrity slot
#
# Every library and probe is checked for 16 KiB alignment, and a probe linked
# explicitly for 4 KiB pages (its p_align checked to be 0x1000 first) must fail
# that check, or the check is not checking. The signed library is verified and
# compared with the unsigned one: only the slot may change, and it must.
# Requires rustup with the target installed (it is added if missing), cargo,
# python3 and the NDK's llvm-readelf.
set -euo pipefail
# The library embeds the verifying key named by OXICRYPT_INTEGRITY_VERIFY_KEY
# when it is built, and is signed with INTEGRITY_SIGNING_KEY, its private
# half; both come from `oxicrypt-integrity-sign --keygen`.
: "${OXICRYPT_INTEGRITY_VERIFY_KEY:?set it to the public key from --keygen}"
: "${INTEGRITY_SIGNING_KEY:?set it to the signing key from --keygen}"

target="${1:?usage: android-build.sh <rust-target> <ndk-dir> <outdir> [api]}"
ndk="${2:?usage: android-build.sh <rust-target> <ndk-dir> <outdir> [api]}"
out="${3:?usage: android-build.sh <rust-target> <ndk-dir> <outdir> [api]}"
api="${4:-24}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

bin=""
for host in linux-x86_64 darwin-x86_64 linux-aarch64; do
    if [ -d "$ndk/toolchains/llvm/prebuilt/$host/bin" ]; then
        bin="$ndk/toolchains/llvm/prebuilt/$host/bin"
        break
    fi
done
[ -n "$bin" ] || { echo "no prebuilt toolchain under $ndk" >&2; exit 1; }
clang="$bin/${target}${api}-clang"
[ -x "$clang" ] || { echo "no $clang" >&2; exit 1; }
readelf="$bin/llvm-readelf"
page=16384
mkdir -p "$out"

# From the repository root, so the pinned toolchain is the one asked.
(cd "$root" && rustup target list --installed) | grep -qx "$target" || (cd "$root" && rustup target add "$target")
upper="$(echo "$target" | tr 'a-z-' 'A-Z_')"
lower="$(echo "$target" | tr '-' '_')"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
(
    cd "$root"
    env "CC_${lower}=$clang" "AR_${lower}=$bin/llvm-ar" "CARGO_TARGET_${upper}_LINKER=$clang" \
        "CARGO_TARGET_${upper}_RUSTFLAGS=-C link-arg=-Wl,-z,max-page-size=$page" \
        cargo build --release -p oxicrypt-ffi --target "$target"
    cargo build --release -p oxicrypt-integrity-sign
)
cp "$target_dir/$target/release/liboxicrypt_ffi.so" "$out/subject-unsigned.so"
set +e
python3 "$here/file-backed-statics.py" "$out/subject-unsigned.so" > "$out/statics.txt"
statics_rc=$?
set -e
cat "$out/statics.txt"
echo "measurement: file-backed module statics row status $statics_rc (0 empty, 1 non-empty)" | tee -a "$out/statics.txt"
if [ "$statics_rc" -ge 2 ]; then
    echo "control FAILED: the statics row could not be taken (status $statics_rc)" >&2
    exit 1
fi
cp "$out/subject-unsigned.so" "$out/subject.so"
"$target_dir/release/oxicrypt-integrity-sign" --sign --key "$INTEGRITY_SIGNING_KEY" "$out/subject.so"
"$target_dir/release/oxicrypt-integrity-sign" --verify "$out/subject.so"
python3 "$here/reservation.py" slot-only "$out/subject-unsigned.so" "$out/subject.so"

"$clang" -O1 -Wall -Wextra -Wl,-z,max-page-size=$page -o "$out/extent-v2-probe" "$here/extent-v2-probe.c" -ldl
"$clang" -O1 -Wall -Wextra -Wl,-z,max-page-size=$page -o "$out/probe" "$here/image-stability-probe.c" -ldl
# The control artifact is linked for 4 KiB pages explicitly: an NDK whose
# default is 16 KiB would otherwise hand the check an aligned control.
"$clang" -O1 -Wall -Wextra -Wl,-z,max-page-size=4096 -o "$out/probe-4k" "$here/image-stability-probe.c" -ldl
if "$readelf" -lW "$out/probe-4k" | awk '$1 == "LOAD" && $NF != "0x1000" {bad = 1} END {exit bad}'; then
    echo "control artifact: every PT_LOAD of probe-4k has p_align 0x1000"
else
    echo "control NOT RUN: probe-4k is not 4 KiB-aligned, so it cannot test the 16 KiB check" >&2
    "$readelf" -lW "$out/probe-4k" | grep LOAD >&2
    exit 1
fi

triple="$target"
cp "$bin/../sysroot/usr/lib/$triple/libc++_shared.so" "$out/decoy.so"

for f in subject.so extent-v2-probe probe; do
    bash "$here/elf-page-align.sh" "$out/$f" "$page" "$readelf"
done
# CONTROL: the alignment check must reject the 4 KiB probe as misaligned,
# which is exit 1; exit 2 (no PT_LOAD read) is not a rejection.
set +e
bash "$here/elf-page-align.sh" "$out/probe-4k" "$page" "$readelf" >/dev/null
align_rc=$?
set -e
if [ "$align_rc" -ne 1 ]; then
    echo "control FAILED: the 16 KiB check on a 4 KiB-aligned probe exited $align_rc, not 1" >&2
    exit 1
fi
rm -f "$out/probe-4k"
echo "control ok: a 4 KiB-aligned probe fails the 16 KiB check (exit 1)"
