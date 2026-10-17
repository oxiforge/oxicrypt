#!/usr/bin/env bash
# Runs the Android loaded-image measurements on a device or emulator over adb.
#
#   android-device-measure.sh [--abi ABI] <artifact-dir> [runs]        stability
#   android-device-measure.sh [--abi ABI] facts
#   android-device-measure.sh [--abi ABI] typed <artifact-dir> [runs]
#   android-device-measure.sh [--abi ABI] apk   <artifact-dir> [runs]
#
# stability  `image-stability-probe` (artifact `probe`) on `subject.so`, runs
#            times, analysed by analyse.py: the untyped stability measurement.
# facts      the device's release, API level, ABI and page size.
# typed      `extent-v2-probe` (artifact `extent-v2-probe`) on `subject.so`
#            with bionic typing, runs times, analysed by `analyse.py --typed`,
#            then every mutation and route control of extent-v2-mutations.sh.
# apk        the same library stored page-aligned inside an APK-shaped
#            archive with a decoy library (artifact `decoy.so`, which must not
#            carry the integrity slot magic) stored before it. The decoy is
#            dlopen()ed first, so the archive is mapped twice and the probe's
#            image-base arithmetic has a wrong answer to find. Then three
#            controls: every run finds the image base at the subject entry;
#            without a decoy every mapping of the archive is the subject's;
#            and with --also naming the subject itself the probe reports that
#            no decoy was mapped.
#
# Exit status: 0 everything held; 1 only the measured verdict failed; 2 a
# control failed or could not run, or the setup was wrong (no device, the
# wrong ABI, a missing artifact).
#
# `subject.so` must have been signed by oxicrypt-integrity-sign: the typed
# probe anchors on the slot's version and slot_rva, which an unsigned slot does
# not carry yet.
#
# The ABI expected of the device is arm64-v8a unless --abi says otherwise (the
# emulator in CI is x86_64). An unexpected ABI stops the run: measuring the
# wrong architecture would silently repeat another measurement.
#
# Prerequisites: `adb` on PATH, one device visible to it, `python3` on the
# host. Files are copied to /data/local/tmp/oxicrypt-extent and removed at the
# end. Each mode writes its record to the current directory.
set -Eeuo pipefail
# Exit 1 means one thing here, a failed measured verdict, and only verdict()
# and the stability analysis produce it. Any other command that fails, an adb
# push or a crashed helper, ends the run as a failed setup (2), so it can
# never be read as a measurement.
trap 'echo "control FAILED: a command failed at line $LINENO" >&2; exit 2' ERR

here="$(cd "$(dirname "$0")" && pwd)"
want_abi=arm64-v8a
if [ "${1:-}" = --abi ]; then
    want_abi="${2:?--abi needs a value}"
    shift 2
fi
mode=stability
case "${1:-}" in
    facts | typed | apk) mode="$1"; shift ;;
esac
dev=/data/local/tmp/oxicrypt-extent

# A run with no device attached would push nothing, measure nothing, and hand
# the analyser an empty file, which reads exactly like a clean result.
adb wait-for-device
devices="$(adb devices | awk 'NR>1 && $2=="device" {print $1}')"
[ -n "$devices" ] || { echo "control FAILED: no adb device is connected" >&2; exit 2; }
abi="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
[ "$abi" = "$want_abi" ] || { echo "control FAILED: expected a $want_abi device, got '$abi'" >&2; exit 2; }

facts() {
    local release sdk page
    release="$(adb shell getprop ro.build.version.release | tr -d '\r')"
    sdk="$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
    page="$(adb shell getconf PAGESIZE | tr -d '\r')"
    echo "device: release=$release sdk=$sdk abi=$abi pagesize=$page" | tee device-facts.txt
}

push() { # files...
    adb shell "rm -rf $dev && mkdir -p $dev"
    adb push "$@" "$dev/" >/dev/null
    adb shell "chmod 755 $dev/*probe* 2>/dev/null; true"
}

cleanup() { adb shell "rm -rf $dev" >/dev/null 2>&1 || true; }

need() { # dir files...
    local d="$1" f
    shift
    for f in "$@"; do [ -f "$d/$f" ] || { echo "missing $d/$f" >&2; exit 2; }; done
}

# A mode exits 0 when everything held, 1 when only the measured verdict
# (analyse.py) failed, and 2 when any control failed or could not run: a
# failed control voids the verdict, so it takes precedence.
mode_verdict=0
mode_controls=0
control_failed() { echo "control FAILED: $1" | tee -a controls.txt; mode_controls=1; }
verdict() { # analyse.py's exit status
    case "$1" in
        0) ;;
        1) mode_verdict=1; echo "measurement: the typed verdict failed" ;;
        *) control_failed "analyse.py exited $1 (a dead control or an unreadable record)" ;;
    esac
}
finish_mode() {
    if [ "$mode_controls" -ne 0 ]; then exit 2; fi
    exit "$mode_verdict"
}

runs_of() { # count outfile command...
    local count="$1" out="$2" i
    shift 2
    : > "$out"
    for i in $(seq 1 "$count"); do
        # The probe's verdict is in its output; adb passes on its exit status,
        # which must not end the loop.
        { adb shell "$*" || true; } | tr -d '\r' | sed "s/^/run${i} /" >> "$out"
    done
}

case "$mode" in
facts)
    facts
    ;;

stability)
    dir="${1:?usage: android-device-measure.sh [--abi ABI] <artifact-dir> [runs]}"
    count="${2:-20}"
    need "$dir" probe subject.so
    facts
    push "$dir/probe" "$dir/subject.so"
    runs_of "$count" runs.txt "cd $dev && ./probe ./subject.so"
    cleanup
    recorded="$(grep -c LOADBASE runs.txt || true)"
    echo "recorded ${recorded} runs of ${count}"
    [ "$recorded" -eq "$count" ] || { echo "control FAILED: expected ${count} runs" >&2; exit 2; }
    rc=0
    python3 "$here/analyse.py" < runs.txt | tee android-device-analysis.txt || rc=${PIPESTATUS[0]}
    exit "$rc"
    ;;

typed)
    dir="${1:?usage: android-device-measure.sh [--abi ABI] typed <artifact-dir> [runs]}"
    count="${2:-20}"
    need "$dir" extent-v2-probe subject.so
    facts
    push "$dir/extent-v2-probe" "$dir/subject.so"
    runs_of "$count" typed-runs.txt "$dev/extent-v2-probe --loader bionic $dev/subject.so"
    rc=0
    python3 "$here/analyse.py" --typed "$count" < typed-runs.txt | tee typed-analysis.txt || rc=${PIPESTATUS[0]}
    verdict "$rc"
    # No bytes follow DT_NULL in a lld-linked library; the fixture proves that
    # comparison with no exemption.
    rc=0
    PROBE_RUN="adb shell" bash "$here/extent-v2-mutations.sh" --require-all --na-ok dyn-postnull \
        "$dev/extent-v2-probe" "$dev/subject.so" --loader bionic | tee typed-mutations.txt || rc=${PIPESTATUS[0]}
    [ "$rc" -eq 0 ] || control_failed "the typed probe's mutations and route controls (exit $rc)"
    cleanup
    finish_mode
    ;;

apk)
    dir="${1:?usage: android-device-measure.sh [--abi ABI] apk <artifact-dir> [runs]}"
    count="${2:-20}"
    need "$dir" extent-v2-probe subject.so decoy.so
    facts
    python3 -I "$here/apk_fixture.py" fixture.apk "$abi" "$dir/subject.so" "$dir/decoy.so" | tee apk-fixture.txt
    grep -q 'arithmetic_ok=True' apk-fixture.txt || { control_failed "the archive's own arithmetic"; finish_mode; }
    push "$dir/extent-v2-probe" fixture.apk
    subject="$dev/fixture.apk!/lib/$abi/subject.so"
    decoy="$dev/fixture.apk!/lib/$abi/decoy.so"
    runs_of "$count" apk-runs.txt "$dev/extent-v2-probe --loader bionic --also '$decoy' '$subject'"
    rc=0
    python3 "$here/analyse.py" --typed "$count" < apk-runs.txt | tee apk-analysis.txt || rc=${PIPESTATUS[0]}
    verdict "$rc"
    # CONTROL: the image base every run found must be the subject entry's data
    # offset in the archive, which apk_fixture.py computed independently.
    want_base="$(sed -n 's/.* apk_base=\(0x[0-9a-f]*\) .*/\1/p' apk-fixture.txt)"
    bases="$(sed -n 's/.*IMAGE apk_base=\(0x[0-9a-f]*\) .*/\1/p' apk-runs.txt | sort -u)"
    if [ -n "$want_base" ] && [ "$bases" = "$want_base" ]; then
        echo "control ok: every run found the image base at the subject entry, $want_base" | tee -a apk-analysis.txt
    else
        control_failed "image bases [$bases], expected ${want_base:-none}"
    fi
    # CONTROL: with no decoy dlopen()ed, the run passes and every mapping of
    # the archive belongs to the subject (image_mappings=k/k); with --also
    # naming the subject, the decoy check must fire.
    # adb shell passes on the probe's exit status, which must agree with its
    # RESULT line in both runs.
    no_decoy_rc=0
    adb shell "$dev/extent-v2-probe --loader bionic '$subject'" > apk-no-decoy.raw || no_decoy_rc=$?
    tr -d '\r' < apk-no-decoy.raw > apk-no-decoy.txt
    grep -E '^(IMAGE|RESULT)' apk-no-decoy.txt | tee -a apk-analysis.txt || true
    if [ "$no_decoy_rc" -eq 0 ] && grep -q '^RESULT status=0' apk-no-decoy.txt &&
        grep -qE '^IMAGE .* image_mappings=([0-9]+)/\1 ' apk-no-decoy.txt; then
        echo "control ok: without a decoy every mapping of the archive is the subject's" | tee -a apk-analysis.txt
    else
        control_failed "without a decoy the run did not pass with image_mappings=k/k (exit $no_decoy_rc)"
    fi
    self_rc=0
    adb shell "$dev/extent-v2-probe --loader bionic --also '$subject' '$subject'" > apk-self-decoy.raw || self_rc=$?
    tr -d '\r' < apk-self-decoy.raw > apk-self-decoy.txt
    if [ "$self_rc" -eq 64 ] && grep -q '^RESULT status=64' apk-self-decoy.txt &&
        grep -q 'decoy was not mapped' apk-self-decoy.txt; then
        echo "control ok: --also naming the subject reports that no decoy was mapped" | tee -a apk-analysis.txt
    else
        control_failed "the decoy check did not fire (exit $self_rc)"
    fi
    cleanup
    finish_mode
    ;;
esac
