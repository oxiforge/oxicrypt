#!/usr/bin/env bash
# Runs the typed probe once untouched and once per mutation, and requires each
# mutation to set exactly the bit it names.
#
# A probe whose bits have never been seen to fire cannot be told apart from a
# probe that does not look: every bit therefore has a mutation, and this script
# fails if any of them leaves the result unchanged or sets another bit as well.
# Three further controls come from outside the probe's own mutation list: the
# other loader's expectation must set the typing bit, a library that does not
# exist must set the setup bit, and a non-dumpable process must still pass
# through process_vm_readv while one that also has process_vm_readv denied by
# seccomp must report `route=unreadable`.
#
# Usage:
#   extent-v2-mutations.sh [--require-all] [--na-ok NAME]... [--generic] <probe> <lib> [probe options...]
#
# The same script drives the Mach-O and PE typed probes: --generic keeps the
# baseline, every listed mutation and the missing-library control, and drops
# the controls that only the ELF probe has (the other loader's expectation and
# the two memory-route controls).
#
# With PROBE_RUN set (for example PROBE_RUN='adb shell'), each probe command is
# passed to it as one string, which is how a device or emulator runs it. The
# result is read from the probe's `RESULT status=N` line, never from the exit
# status of the transport.
#
# --require-all fails when a mutation does not apply to the image. --na-ok NAME
# (repeatable) exempts one named mutation, for a property of the image rather
# than of the probe: an image with no bytes after its DT_NULL entry cannot
# exercise that comparison, which the fixture, run with no exemption, does.
# Without --require-all an inapplicable mutation is reported as n/a.
set -euo pipefail
# Runs under macOS's bash 3.2: the options array may be empty, so it is
# expanded as ${opts[@]+"${opts[@]}"}, which `set -u` accepts there.

require_all=0
generic=0
na_ok=" "
while :; do
    case "${1:-}" in
        --require-all) require_all=1; shift ;;
        --generic) generic=1; shift ;;
        --na-ok) na_ok="$na_ok${2:?--na-ok needs a mutation name} "; shift 2 ;;
        *) break ;;
    esac
done
probe="${1:?usage: extent-v2-mutations.sh [--require-all] <probe> <lib> [probe options...]}"
lib="${2:?usage: extent-v2-mutations.sh [--require-all] <probe> <lib> [probe options...]}"
shift 2
opts=("$@")

loader=glibc
for ((i = 0; i < ${#opts[@]}; i++)); do
    if [ "${opts[$i]}" = "--loader" ] && [ $((i + 1)) -lt ${#opts[@]} ]; then
        loader="${opts[$((i + 1))]}"
    fi
done
other_loader=bionic
[ "$loader" = bionic ] && other_loader=glibc

# The probe's own status is read from its RESULT line, so a non-zero exit here
# is expected and must not stop the script. stdin is closed: `adb shell`
# reads it, and would swallow the rest of the mutation list being looped over.
run() {
    if [ -n "${PROBE_RUN:-}" ]; then
        # shellcheck disable=SC2086 # PROBE_RUN is a command prefix by design
        { $PROBE_RUN "$*" 2>&1 < /dev/null || true; } | tr -d '\r'
    else
        "$@" 2>&1 < /dev/null || true
    fi
}

status_of() { sed -n 's/^RESULT status=\([0-9]*\).*/\1/p' <<<"$1" | tail -1; }

failures=0
report() { # name expected got verdict
    printf '%-18s expected=%-4s got=%-4s %s\n' "$1" "$2" "$3" "$4"
    case "$4" in ok | n/a | "n/a (allowed)") ;; *) failures=$((failures + 1)) ;; esac
}

out="$(run "$probe" ${opts[@]+"${opts[@]}"} "$lib")"
got="$(status_of "$out")"
if [ "$got" != 0 ]; then
    printf '%s\n' "$out"
    report baseline 0 "${got:-none}" FAILED
    echo "the untouched image must pass before a mutation can mean anything" >&2
    exit 1
fi
report baseline 0 0 ok

list="$(run "$probe" --list-mutations)"
count=0
while read -r name bit; do
    [ -n "$name" ] || continue
    count=$((count + 1))
    out="$(run "$probe" ${opts[@]+"${opts[@]}"} --mutate "$name" "$lib")"
    got="$(status_of "$out")"
    if grep -q "MUTATE $name not applicable" <<<"$out"; then
        case "$na_ok" in
            *" $name "*) report "$name" "$bit" "${got:-none}" "n/a (allowed)" ;;
            *) if [ "$require_all" = 1 ]; then report "$name" "$bit" "${got:-none}" "NOT APPLICABLE"; else report "$name" "$bit" "${got:-none}" n/a; fi ;;
        esac
    elif [ "$got" = "$bit" ]; then
        report "$name" "$bit" "$got" ok
    else
        printf '%s\n' "$out" | grep -E '^(MUTATE|FAIL|RESULT)' || true
        report "$name" "$bit" "${got:-none}" MISMATCH
    fi
done <<<"$list"
# A list that came back empty would make every line above vacuous.
# Each probe's own mutation count, so a list that lost entries fails here.
case "$(basename "$probe")" in
    extent-v2-probe*) floor=18 ;;
    macho-typed-probe*) floor=11 ;;
    pe-typed-probe*) floor=10 ;;
    *) echo "control FAILED: no mutation floor for probe $(basename "$probe")" >&2; exit 1 ;;
esac
[ "$count" -ge "$floor" ] || { echo "control FAILED: the probe listed $count mutations, at least $floor required" >&2; exit 1; }

out="$(run "$probe" ${opts[@]+"${opts[@]}"} "$lib.absent")"
got="$(status_of "$out")"
if [ "$got" = 64 ]; then report missing-library 64 "$got" ok; else report missing-library 64 "${got:-none}" MISMATCH; fi

if [ "$generic" = 1 ]; then
    if [ "$failures" -ne 0 ]; then
        echo "FAILED: $failures control(s) did not behave as required" >&2
        exit 1
    fi
    echo "all controls fired as required"
    exit 0
fi

# The probe takes the last --loader it is given.
out="$(run "$probe" ${opts[@]+"${opts[@]}"} --loader "$other_loader" "$lib")"
got="$(status_of "$out")"
if [ -n "$got" ] && [ $((got & 1)) = 1 ]; then report "loader=$other_loader" 1 "$got" ok; else report "loader=$other_loader" 1 "${got:-none}" MISMATCH; fi

out="$(run "$probe" ${opts[@]+"${opts[@]}"} --non-dumpable "$lib")"
got="$(status_of "$out")"
route="$(sed -n 's/^PROC route=//p' <<<"$out")"
if [ "$got" = 0 ] && [ "$route" = process_vm_readv ]; then
    report non-dumpable "0/pvr" "$got/$route" ok
else
    report non-dumpable "0/pvr" "${got:-none}/${route:-none}" MISMATCH
fi

out="$(run "$probe" ${opts[@]+"${opts[@]}"} --seccomp-deny-pvr "$lib")"
got="$(status_of "$out")"
route="$(sed -n 's/^PROC route=//p' <<<"$out")"
if [ "$got" = 64 ] && [ "$route" = unreadable ]; then
    report seccomp-deny-pvr "64/unread" "$got/$route" ok
else
    report seccomp-deny-pvr "64/unread" "${got:-none}/${route:-none}" MISMATCH
fi

if [ "$failures" -ne 0 ]; then
    echo "FAILED: $failures control(s) did not behave as required" >&2
    exit 1
fi
echo "all controls fired as required"
