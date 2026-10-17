# shellcheck shell=bash
# shellcheck disable=SC2034 # controls_failed and last_rc are read by the caller
# Shared by macho-signing-order.sh and pe-signing-order.sh; sourced, not run.
#
# A measurement records its command's exit status and never stops the script.
# A control runs only on a baseline that passed: a comparison that already
# fails, or does not parse, cannot show that it also catches a flipped byte.
# A control that cannot run says `control NOT RUN` and counts as failed, so a
# script whose controls did not all fire never exits 0.
# Written for bash 3.2 (macOS): no arrays, no bash-4 expansions.

py="${PYTHON:-$(command -v python3 || command -v python)}"
controls_failed=0
last_rc=0

# measure LABEL COMMAND...: runs COMMAND into LABEL.txt; its status is in last_rc.
measure() {
    local label="$1"
    shift
    set +e
    "$@" > "$label.txt" 2>&1
    last_rc=$?
    set -e
    sed "s/^/  /" "$label.txt"
    echo "measurement: $label exit $last_rc"
}

# flip FILE OFFSET: inverts one bit of the byte at OFFSET.
flip() {
    "$py" - "$1" "$2" <<'PY'
import sys
p, o = sys.argv[1], int(sys.argv[2], 0)
d = bytearray(open(p, "rb").read())
d[o] ^= 1
open(p, "wb").write(d)
PY
}

# require_ok LABEL: the last measured command must have exited 0; a step the
# order depends on (the slot-only comparison, a verify) is not a measurement.
require_ok() {
    if [ "$last_rc" -ne 0 ]; then
        echo "control FAILED: $1 exited $last_rc"
        controls_failed=1
    fi
}

not_run() { # description reason
    echo "control NOT RUN: $1: $2"
    controls_failed=1
}

# control_flip DESCRIPTION BASELINE_RC OFFSET COMMAND...: COMMAND compares a
# copy with one byte flipped at OFFSET. It must exit 1 and print a
# `RANGE start end` line that contains OFFSET.
control_flip() {
    local what="$1" base="$2" off="$3" rc
    shift 3
    if [ "$base" -ne 0 ]; then
        not_run "$what" "its baseline comparison exited $base"
        return 0
    fi
    set +e
    "$@" > control.txt 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 1 ] && "$py" - "$off" control.txt <<'PY'
import sys
off = int(sys.argv[1], 0)
rows = [l.split() for l in open(sys.argv[2]) if l.startswith("RANGE 0x")]
sys.exit(0 if any(int(a, 16) <= off < int(b, 16) for _r, a, b in rows) else 1)
PY
    then
        echo "control ok: $what (exit 1, reported range contains $off)"
    else
        sed "s/^/  /" control.txt
        echo "control FAILED: $what (exit $rc, or no reported range contains $off)"
        controls_failed=1
    fi
}
