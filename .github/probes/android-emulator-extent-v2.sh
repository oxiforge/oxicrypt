#!/usr/bin/env bash
# The extent v2 Android measurements on a booted emulator, as one command.
#
#   android-emulator-extent-v2.sh <abi> <artifact-dir> [runs]
#
# One file because `reactivecircus/android-emulator-runner` runs its `script:`
# input a line at a time in separate `sh -c` shells. Runs the `facts`, `typed`
# and `apk` modes of android-device-measure.sh. A mode that failed only its
# measured verdict is reported as a `measurement:` line; a mode whose control
# failed or could not run (status 2 or more) makes this script exit 1, so the
# job fails. The records are uploaded either way by the workflow.
set -uo pipefail

abi="${1:?usage: android-emulator-extent-v2.sh <abi> <artifact-dir> [runs]}"
dir="${2:?usage: android-emulator-extent-v2.sh <abi> <artifact-dir> [runs]}"
count="${3:-20}"
here="$(cd "$(dirname "$0")" && pwd)"
failed=0

for mode in facts typed apk; do
    if [ "$mode" = facts ]; then
        bash "$here/android-device-measure.sh" --abi "$abi" facts
    else
        bash "$here/android-device-measure.sh" --abi "$abi" "$mode" "$dir" "$count"
    fi
    rc=$?
    case "$rc" in
        0) echo "ok: $mode" ;;
        1) echo "measurement: $mode verdict failed (exit 1)" ;;
        *) echo "control FAILED: $mode exited $rc"; failed=1 ;;
    esac
done
exit "$failed"
