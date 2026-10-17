#!/usr/bin/env bash
# The commas in the compiler arrays are linker-flag syntax, not separators.
# shellcheck disable=SC2054
# Builds the fixtures the probe self-tests run against, from elf-fixture.c.
#
#   build-fixtures.sh <outdir>
#
# ELF fixtures are built with $CC (default cc). On macOS the Mach-O fixtures are
# built with the same compiler. Elsewhere, with CROSS_CLANG naming a clang that
# ships lld (the Android NDK's does), the Mach-O and PE fixtures are
# cross-built; without it they are skipped and the self-test says so.
#
# Every fixture has a positive twin: `-filebacked` places the zero-initialised
# module static in initialised data, which the statics report must name.
set -euo pipefail
# Runs under macOS's bash 3.2: an empty array is expanded as
# ${arr[@]+"${arr[@]}"}, which `set -u` accepts there.

out="${1:?usage: build-fixtures.sh <outdir>}"
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/elf-fixture.c"
mkdir -p "$out"
cc="${CC:-cc}"

if [ "$(uname -s)" != Darwin ]; then
    for v in "" -filebacked; do
        def=()
        [ -n "$v" ] && def=(-DFILE_BACKED_STATIC)
        "$cc" -shared -fPIC -O1 ${def[@]+"${def[@]}"} -Wl,-z,now -Wl,-z,relro -o "$out/fixture$v.so" "$src"
        python3 "$here/slot-stamp.py" "$out/fixture$v.so"
    done
    # RELR packing, so the probe's RELR decoder and the Relative checks run.
    "$cc" -shared -fPIC -O1 -Wl,-z,now -Wl,-z,relro -Wl,-z,pack-relative-relocs \
        -o "$out/fixture-relr.so" "$src"
    python3 "$here/slot-stamp.py" "$out/fixture-relr.so"
    cp "$out/fixture.so" "$out/fixture-stripped.so"
    strip "$out/fixture-stripped.so"
    echo "built ELF fixtures"
fi

macho=()
pe=()
if [ "$(uname -s)" = Darwin ]; then
    macho=("$cc" -shared -O1)
elif [ -n "${CROSS_CLANG:-}" ]; then
    # A text stub of libSystem, so the one import binds through a real
    # library ordinal rather than the flat namespace.
    cat > "$out/libSystem.tbd" <<'EOF'
--- !tapi-tbd
tbd-version: 4
targets: [ x86_64-macos, arm64-macos ]
install-name: '/usr/lib/libSystem.B.dylib'
exports:
  - targets: [ x86_64-macos, arm64-macos ]
    symbols: [ _strlen, dyld_stub_binder ]
...
EOF
    macho=("$CROSS_CLANG" --target=arm64-apple-macos12 -fuse-ld=lld -nostdlib -shared -O1
        "$out/libSystem.tbd")
    pe=("$CROSS_CLANG" --target=x86_64-pc-windows-msvc -fuse-ld=lld -nostdlib -shared -O1 -Wl,-noentry)
fi

if [ ${#macho[@]} -gt 0 ]; then
    for v in "" -filebacked; do
        def=()
        [ -n "$v" ] && def=(-DFILE_BACKED_STATIC)
        "${macho[@]}" -Wl,-fixup_chains ${def[@]+"${def[@]}"} -o "$out/fixture$v.dylib" "$src"
    done
    # The same library with opcode-encoded fixups, for the parser's other form.
    "${macho[@]}" -Wl,-no_fixup_chains -o "$out/fixture-opcodes.dylib" "$src"
    echo "built Mach-O fixtures"
fi
if [ ${#pe[@]} -gt 0 ]; then
    # An import library for the one kernel32 import, so the IAT exists.
    printf 'LIBRARY kernel32.dll\nEXPORTS\nGetTickCount\n' > "$out/kernel32.def"
    "$(dirname "$CROSS_CLANG")/llvm-dlltool" -m i386:x86-64 -d "$out/kernel32.def" -l "$out/kernel32.lib"
    pe+=("$out/kernel32.lib")
    for v in "" -filebacked -initialised; do
        def=()
        [ "$v" = -filebacked ] && def=(-DFILE_BACKED_STATIC)
        [ "$v" = -initialised ] && def=(-DSTATE_INITIALISED)
        "${pe[@]}" ${def[@]+"${def[@]}"} "-Wl,-map:$out/fixture$v.map" -o "$out/fixture$v.dll" "$src"
    done
    echo "built PE fixtures"
fi
