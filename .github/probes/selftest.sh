#!/usr/bin/env bash
# Runs every probe self-test that needs no artifact of the module: each tool
# against fixtures and synthetic inputs that must pass, and against mutations
# and malformed inputs that must fail in the stated way. Linux host.
#
#   selftest.sh <workdir>
#
# Requires CROSS_CLANG, a clang that ships lld (the Android NDK's): the Mach-O
# and PE fixtures are built with it, and the llvm-objdump and llvm-readobj
# beside it (or in LLVM_BIN) give the independent fixup parses for them. The
# Windows half of the PE probe is type-checked for x86_64-pc-windows-gnu, so
# that Rust target must be installed. Nothing is skipped: a missing tool fails
# the run. Exit 1 if any case fails.
set -euo pipefail

work="${1:?usage: selftest.sh <workdir>}"
here="$(cd "$(dirname "$0")" && pwd)"
: "${CROSS_CLANG:?CROSS_CLANG must name a clang that ships lld}"
llvm_bin="${LLVM_BIN:-$(dirname "$CROSS_CLANG")}"
mkdir -p "$work"
cd "$work"
failed=0
step() { # name command...
    local name="$1"
    shift
    echo "== $name"
    if "$@"; then echo "-- ok: $name"; else echo "-- FAILED: $name"; failed=1; fi
}
# expect_rc NAME WANT COMMAND...: COMMAND must exit with exactly WANT.
expect_rc() {
    local name="$1" want="$2" rc
    shift 2
    set +e
    "$@" > expect.txt 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq "$want" ]; then
        echo "-- ok: $name (exit $rc)"
    else
        sed 's/^/   /' expect.txt | tail -8
        echo "-- FAILED: $name (exit $rc, expected $want)"
        failed=1
    fi
}

# The readelf whose output the ELF cross-check parses, for the record.
readelf --version | head -1
step "fixtures" bash "$here/build-fixtures.sh" fixtures
step "analyse.py" python3 "$here/analyse.py" --selftest
step "reservation.py" python3 "$here/reservation.py" --selftest
step "pe-tamper.py" python3 "$here/pe-tamper.py" --selftest
step "fixup-crosscheck.py" python3 "$here/fixup-crosscheck.py" --selftest
step "file-backed-statics.py" python3 "$here/file-backed-statics.py" --selftest fixtures

# ---- the typed probes compile cleanly --------------------------------------
step "ELF typed probe compiles" cc -O1 -Wall -Wextra -Werror -o extent-v2-probe "$here/extent-v2-probe.c" -ldl
step "Mach-O typed probe compiles (host core)" cc -O1 -Wall -Wextra -Werror -o macho-typed-probe "$here/macho-typed-probe.c"
step "Mach-O typed probe's dyld declarations type-check" \
    cc -Wall -Wextra -Werror -DDARWIN_DECLARATIONS_CHECK -fsyntax-only "$here/macho-typed-probe.c"
step "PE typed probe compiles (host core)" rustc -O -o pe-typed-probe "$here/pe-typed-probe.rs"
step "PE typed probe's Windows half type-checks" \
    rustc --target x86_64-pc-windows-gnu --emit=metadata -o pe-typed-probe.rmeta "$here/pe-typed-probe.rs"
step "PE library harness compiles (host: the listing parser)" \
    rustc -O -o pe-ffi-operational "$here/pe-ffi-operational.rs"
step "PE library harness's Windows half type-checks" \
    rustc --target x86_64-pc-windows-gnu --emit=metadata -o pe-ffi-operational.rmeta "$here/pe-ffi-operational.rs"
# The bind report reads the signer's listing: each Bind entry's words, with
# the record its line names.
printf '%s\n' '    [3] Bind rva 0x00001000 file 0x00000400 len 16 hole 0 record 1' \
    '    record [0] A.dll f addend 0 strong' '    record [1] B.dll #7 addend 0 strong' > listing.txt
expect_rc "PE harness listing, two words" 0 ./pe-ffi-operational --parse listing.txt
step "PE harness listing names record 1 at the second word" grep -qx '0x1008 B.dll #7' expect.txt
printf '%s\n' '    record [0] A.dll f addend 0 strong' > listing-empty.txt
expect_rc "PE harness listing with no bound word" 1 ./pe-ffi-operational --parse listing-empty.txt

# ---- every result bit of each typed probe fires, alone ----------------------
step "ELF probe mutations, fixture" \
    bash "$here/extent-v2-mutations.sh" --require-all ./extent-v2-probe "$PWD/fixtures/fixture.so"
step "ELF probe mutations, RELR fixture" \
    bash "$here/extent-v2-mutations.sh" --require-all ./extent-v2-probe "$PWD/fixtures/fixture-relr.so"
step "Mach-O probe mutations, simulated load" \
    bash "$here/extent-v2-mutations.sh" --require-all --generic ./macho-typed-probe "$PWD/fixtures/fixture.dylib" --simulate 0x40000
step "PE probe mutations, simulated load" \
    bash "$here/extent-v2-mutations.sh" --require-all --generic ./pe-typed-probe "$PWD/fixtures/fixture.dll" --simulate 0x10000
step "PE probe mutations, simulated load with ImageBase rewritten as Windows does" \
    bash "$here/extent-v2-mutations.sh" --require-all --generic ./pe-typed-probe "$PWD/fixtures/fixture.dll" \
    --simulate 0x10000 --imagebase-rewritten
# CONTROL: with no slide, the Mach-O and PE probes' own controls must fire.
expect_rc "Mach-O probe, slide 0, control bit" 32 ./macho-typed-probe --simulate 0 fixtures/fixture.dylib
expect_rc "PE probe, delta 0, control bit" 32 ./pe-typed-probe --simulate 0 fixtures/fixture.dll

# ---- malformed and truncated inputs end in a RESULT failure, never a crash ---
# Each input runs through the probe as built for CI and through a build with
# AddressSanitizer and UndefinedBehaviorSanitizer (the C probes) or with Rust's
# debug assertions and overflow checks (the PE probe): a sanitizer report, a
# Rust panic, a signal, a hang, a missing RESULT, a RESULT that differs from
# the exit status, or a pass all fail the case.
SAN=(-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all -g -O1)
step "ELF probe, sanitized build" cc "${SAN[@]}" -o extent-v2-probe-san "$here/extent-v2-probe.c" -ldl
step "Mach-O probe, sanitized build" cc "${SAN[@]}" -o macho-typed-probe-san "$here/macho-typed-probe.c"
step "PE probe, overflow-checked build" \
    rustc -C debug-assertions -C overflow-checks -o pe-typed-probe-checked "$here/pe-typed-probe.rs"
malformed_ran=0
malformed() { # file command...
    local f="$1" out rc status
    shift
    set +e
    out="$(ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 timeout 60 "$@" 2>&1 < /dev/null)"
    rc=$?
    set -e
    malformed_ran=$((malformed_ran + 1))
    status="$(sed -n 's/^RESULT status=\([0-9]*\).*/\1/p' <<<"$out" | tail -1)"
    if grep -qE 'ERROR: AddressSanitizer|runtime error:|panicked' <<<"$out"; then
        grep -E 'ERROR: AddressSanitizer|runtime error:|panicked' <<<"$out" | head -3 | sed 's/^/   /'
        echo "-- FAILED: $(basename "$f") under $(basename "$1"): sanitizer report or panic"
        failed=1
    elif [ -n "$status" ] && [ "$status" -ne 0 ] && [ "$rc" -eq "$status" ]; then
        echo "-- ok: $(basename "$f") under $(basename "$1"): RESULT status=$status"
    else
        echo "-- FAILED: $(basename "$f") under $(basename "$1"): exit $rc, RESULT '${status:-none}' (a crash, a hang or a pass)"
        failed=1
    fi
}
# cases KIND FIXTURE WANT: writes the malformed copies of FIXTURE, which must
# number WANT, to cases.txt; malformed.py failing, or a fixture lacking a
# structure, fails here. (Run in this shell, never in $(...), so `failed`
# survives.)
cases() {
    local list n
    if ! list="$(python3 "$here/malformed.py" "$1" "$2" "malformed/$(basename "$2")")"; then
        echo "-- FAILED: malformed.py $1 $2 exited non-zero" >&2
        failed=1
        return 0
    fi
    n="$(grep -c . <<<"$list" || true)"
    if [ "$n" -ne "$3" ]; then
        echo "-- FAILED: malformed.py wrote $n cases for $2, expected $3" >&2
        failed=1
    fi
    printf '%s\n' "$list" > cases.txt
}
echo "== malformed inputs"
for fx in fixture.so:11 fixture-relr.so:13; do
    cases elf "fixtures/${fx%%:*}" "${fx##*:}"
    while read -r f; do
        malformed "$f" ./extent-v2-probe --file "$f" "$PWD/fixtures/${fx%%:*}"
        malformed "$f" ./extent-v2-probe-san --file "$f" "$PWD/fixtures/${fx%%:*}"
    done < cases.txt
done
for fx in fixture.dylib:16 fixture-opcodes.dylib:17; do
    cases macho "fixtures/${fx%%:*}" "${fx##*:}"
    while read -r f; do
        malformed "$f" ./macho-typed-probe --simulate 0x40000 "$f"
        malformed "$f" ./macho-typed-probe-san --simulate 0x40000 "$f"
    done < cases.txt
done
cases pe fixtures/fixture.dll 19
while read -r f; do
    malformed "$f" ./pe-typed-probe --simulate 0x10000 "$f"
    malformed "$f" ./pe-typed-probe-checked --simulate 0x10000 "$f"
done < cases.txt
# 11 + 13 + 16 + 17 + 19 inputs, each through two builds
if [ "$malformed_ran" -ne 152 ]; then
    echo "-- FAILED: $malformed_ran malformed runs, expected 152"
    failed=1
else
    echo "-- ok: $malformed_ran malformed runs, half of them sanitized or overflow-checked"
fi

# ---- the fixup cross-check, and its controls --------------------------------
for so in fixture fixture-relr; do
    readelf -rW "fixtures/$so.so" > "$so.readelf-r"
    readelf -dW "fixtures/$so.so" > "$so.readelf-d"
    step "ELF fixup cross-check, $so" python3 "$here/fixup-crosscheck.py" elf "fixtures/$so.so" \
        --readelf-r "$so.readelf-r" --readelf-d "$so.readelf-d"
done
# Both RELR layouts readelf has printed must parse: the newer one this host's
# readelf may print, and the older one (binutils 2.42 and earlier: a count line,
# then one address per line), rebuilt here from the same addresses.
python3 - fixture-relr.readelf-r fixture-relr.readelf-r.old <<'PY2'
import re, sys
out, relr, addrs = [], False, []
for line in open(sys.argv[1]).read().splitlines():
    if line.startswith("Relocation section"):
        relr = ".relr" in line
        out.append(line)
        if relr:
            out.append("<<ADDRESSES>>")
        continue
    if relr:
        m = re.match(r"^\d+:\s+[0-9a-f]+\s+([0-9a-f]{16})", line) or re.match(r"^\s+([0-9a-f]{16})", line) \
            or re.match(r"^([0-9a-f]{16})\s*$", line)
        if m:
            addrs.append(m.group(1))
        continue
    out.append(line)
text = "\n".join(out).replace("<<ADDRESSES>>", f"  {len(addrs)} offsets\n" + "\n".join(addrs))
open(sys.argv[2], "w").write(text + "\n")
sys.exit(0 if addrs else 1)
PY2
step "ELF fixup cross-check, RELR in the older readelf layout" python3 "$here/fixup-crosscheck.py" elf \
    fixtures/fixture-relr.so --readelf-r fixture-relr.readelf-r.old
# CONTROL: one RELR address missing from that layout is the measured verdict.
last_relr="$(grep -nE '^[0-9a-f]{16}$' fixture-relr.readelf-r.old | tail -1 | cut -d: -f1)"
sed "${last_relr}d" fixture-relr.readelf-r.old > fixture-relr.readelf-r.old-dropped
expect_rc "a RELR address dropped from the older layout" 1 \
    python3 "$here/fixup-crosscheck.py" elf fixtures/fixture-relr.so --readelf-r fixture-relr.readelf-r.old-dropped
# CONTROL: a relocation missing from the tool's side is the measured verdict.
first="$(grep -n -m1 -E '_RELATIVE|_GLOB_DAT' fixture.readelf-r | cut -d: -f1)"
sed "${first}d" fixture.readelf-r > fixture.readelf-r.dropped
expect_rc "a relocation dropped from readelf's side" 1 \
    python3 "$here/fixup-crosscheck.py" elf fixtures/fixture.so --readelf-r fixture.readelf-r.dropped
# CONTROL: a tool output that prints its first record twice cannot show a
# dropped line, so the tool-side control must report itself dead (exit 2).
lowest="$(grep -E '^[0-9a-f]{16} ' fixture.readelf-r | sort | head -1 | cut -c1-16)"
awk -v k="$lowest" '{print} index($0, k) == 1 && !done {print; done = 1}' fixture.readelf-r > fixture.readelf-r.doubled
expect_rc "the tool-side control on a record printed twice" 2 \
    python3 "$here/fixup-crosscheck.py" elf fixtures/fixture.so --readelf-r fixture.readelf-r.doubled
expect_rc "a malformed input to the cross-check" 3 \
    python3 "$here/fixup-crosscheck.py" elf malformed/elf-truncated-headers --readelf-r fixture.readelf-r

"$llvm_bin/llvm-objdump" --macho --dyld-info fixtures/fixture.dylib > fixture.dyld-info
step "Mach-O fixup cross-check (chained)" python3 "$here/fixup-crosscheck.py" macho fixtures/fixture.dylib \
    --tool fixture.dyld-info
"$llvm_bin/llvm-objdump" --macho --private-headers fixtures/fixture.dylib > fixture.load-commands
step "chained-fixup assertion" python3 "$here/macho-chained.py" assert fixture.load-commands --minos 12.0
# The count reads the signer's `slot budget:` line and re-derives nothing, so
# its parsing is checked against stand-in signers printing each outcome.
for fits in yes no; do
    printf '#!/bin/sh\necho "  slot budget: stored 101 string-table 40 capacity 3797 fits %s"\n' "$fits" > "signer-$fits"
    chmod +x "signer-$fits"
done
printf '#!/bin/sh\necho "no budget here"\n' > signer-none
chmod +x signer-none
expect_rc "Mach-O entry count, an extent that fits" 0 \
    python3 "$here/macho-chained.py" count fixtures/fixture.dylib --signer ./signer-yes
expect_rc "Mach-O entry count, an extent that does not fit" 1 \
    python3 "$here/macho-chained.py" count fixtures/fixture.dylib --signer ./signer-no
expect_rc "Mach-O entry count, a signer that prints no budget" 2 \
    python3 "$here/macho-chained.py" count fixtures/fixture.dylib --signer ./signer-none
# CONTROL: the same deployment target with opcode-encoded fixups must fail on
# the encoding, not on the deployment target.
"$CROSS_CLANG" --target=arm64-apple-macos12 -fuse-ld=lld -nostdlib -shared -O1 \
    -Wl,-no_fixup_chains -o opcodes.dylib "$here/elf-fixture.c" fixtures/libSystem.tbd
"$llvm_bin/llvm-objdump" --macho --private-headers opcodes.dylib > opcodes.load-commands
expect_rc "the chained-fixup assertion on an opcode-encoded dylib" 1 \
    python3 "$here/macho-chained.py" assert opcodes.load-commands --minos 12.0
if grep -q 'FAILED: LC_DYLD_INFO' expect.txt && ! grep -q 'FAILED: minos' expect.txt; then
    echo "-- ok: it failed on LC_DYLD_INFO and not on the deployment target"
else
    echo "-- FAILED: the opcode control did not fail on LC_DYLD_INFO alone"
    failed=1
fi
"$llvm_bin/llvm-objdump" --macho --rebase --bind --lazy-bind --weak-bind opcodes.dylib > opcodes.fixups
step "Mach-O fixup cross-check (opcodes)" python3 "$here/fixup-crosscheck.py" macho opcodes.dylib --tool opcodes.fixups
"$llvm_bin/llvm-readobj" --coff-basereloc fixtures/fixture.dll > fixture.basereloc
step "PE fixup cross-check" python3 "$here/fixup-crosscheck.py" pe fixtures/fixture.dll --tool fixture.basereloc

step "shellcheck" shellcheck -x -P SCRIPTDIR "$here"/*.sh
if [ "$failed" -ne 0 ]; then
    echo "FAILED: at least one self-test failed" >&2
    exit 1
fi
echo "all self-tests passed"
