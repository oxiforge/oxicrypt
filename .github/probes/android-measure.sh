#!/usr/bin/env bash
# Drives the stability probe on a booted Android emulator.
#
# This lives in a file rather than inline in the workflow because
# `reactivecircus/android-emulator-runner` executes its `script:` input one
# LINE AT A TIME, each in a separate `/usr/bin/sh -c`. A multi-line loop is
# therefore split across shells and dies with a syntax error, and `sh` there is
# dash, which has no `pipefail`. One file invoked as one command avoids both.
set -euo pipefail

runs="${1:?usage: android-measure.sh <output-file> <count>}"
count="${2:?usage: android-measure.sh <output-file> <count>}"

adb wait-for-device
adb push probe subject.so /data/local/tmp/
adb shell chmod 755 /data/local/tmp/probe

: > "$runs"
for i in $(seq 1 "$count"); do
    # `tr -d '\r'` because adb shell hands back CRLF line endings, which the
    # analyser would otherwise carry into every field it parses.
    adb shell "cd /data/local/tmp && ./probe ./subject.so" \
        | tr -d '\r' | sed "s/^/run${i} /" >> "$runs"
done

echo "probe runs recorded: $(grep -c LOADBASE "$runs" || true)"
