#!/usr/bin/env bash
# Runs the loaded-image stability measurement on a PHYSICAL Android device.
#
# CI cannot do this for arm64: hosted arm64 Linux runners carry no Android NDK,
# and an arm64 emulator needs an arm64 host to reach hardware virtualisation. A
# real device is also better evidence than an emulator would have been.
#
# Prerequisites: `adb` on PATH, and one device visible to it — USB with
# developer options and USB debugging enabled, or `adb connect <host>:<port>`
# for wireless debugging. Nothing is installed on the device; two files are
# copied to /data/local/tmp and removed at the end.
#
# Usage:  android-device-measure.sh <dir-with-probe-and-subject.so> [runs]
set -euo pipefail

dir="${1:?usage: android-device-measure.sh <artifact-dir> [runs]}"
count="${2:-20}"

for f in probe subject.so; do
    [ -f "$dir/$f" ] || { echo "missing $dir/$f" >&2; exit 1; }
done

# A run with no device attached would push nothing, measure nothing, and hand
# the analyser an empty file — which reads exactly like a clean result.
devices="$(adb devices | awk 'NR>1 && $2=="device" {print $1}')"
[ -n "$devices" ] || { echo "control FAILED: no adb device is connected" >&2; exit 1; }
echo "device(s): $devices"

abi="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
echo "device ABI: $abi"
# Measuring an x86_64 device would silently repeat what CI already did.
case "$abi" in
    arm64*) ;;
    *) echo "control FAILED: expected an arm64 device, got '$abi'" >&2; exit 1 ;;
esac

adb push "$dir/probe" "$dir/subject.so" /data/local/tmp/ >/dev/null
adb shell chmod 755 /data/local/tmp/probe

: > runs.txt
for i in $(seq 1 "$count"); do
    adb shell "cd /data/local/tmp && ./probe ./subject.so" \
        | tr -d '\r' | sed "s/^/run${i} /" >> runs.txt
done

recorded="$(grep -c LOADBASE runs.txt || true)"
echo "recorded ${recorded} runs of ${count}"
[ "$recorded" -eq "$count" ] || { echo "control FAILED: expected ${count} runs" >&2; exit 1; }

adb shell rm -f /data/local/tmp/probe /data/local/tmp/subject.so

python3 "$(dirname "$0")/analyse.py" < runs.txt | tee android-device-analysis.txt
exit "${PIPESTATUS[0]}"
