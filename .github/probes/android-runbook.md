# Android device and emulator runbook

How to take the extent v2 Android measurements on a physical arm64 device, and the same on an x86_64 emulator. CI runs the emulator half (`extent-v2-android` in `integrity-image-probe.yml`); arm64 has no emulator CI can reach, so the device half is run by hand with these scripts.

## What this measures, and what it does not

The probes are loader-behaviour and file-route instruments. They establish how bionic maps and relocates the library, which words it writes, whether the typed comparison of memory against the file holds, whether the image base inside an APK is found by the verifier's arithmetic, and which memory routes the process has. They are not the integrity oracle: a tampered byte is refused only by the signed module itself at initialisation, which `ffi-operational.c` reads. A green runbook qualifies the loader model, not the Android integrity claim.

## 1. Build the artifacts

On a Linux x86_64 host with the Android NDK and the repository's pinned Rust toolchain:

```sh
bash .github/probes/android-build.sh aarch64-linux-android "$ANDROID_NDK_HOME" artifacts-arm64
```

This writes `subject.so` (the library linked for 16 KiB pages and integrity-signed), `subject-unsigned.so`, `statics.txt` (the file-backed module statics row), `extent-v2-probe`, `probe` and `decoy.so` (the NDK's `libc++_shared.so`, which carries no integrity slot). It fails if any of them is not aligned for 16 KiB pages, and if a probe linked without the flag passes that check.

## 2. Device prerequisites

`adb` on the host and one arm64 device visible to it: USB with developer options and USB debugging enabled, or `adb connect <host>:<port>` for wireless debugging. Nothing is installed; files go to `/data/local/tmp/oxicrypt-extent` and are removed at the end of each mode. Every mode refuses to run against a device of another ABI.

## 3. Measurements

Run from an empty directory, with `P` set to the repository's `.github/probes` directory; each mode writes its records there.

| Mode | Command | Records | Pass |
|---|---|---|---|
| Device facts | `bash $P/android-device-measure.sh facts` | `device-facts.txt` | release, API level, ABI, page size recorded |
| Typed probe, native process | `bash $P/android-device-measure.sh typed artifacts-arm64 20` | `typed-runs.txt`, `typed-analysis.txt`, `typed-mutations.txt` | `typed ok` with 20 distinct biases; every mutation `ok` |
| Library inside an APK, decoy mapped first | `bash $P/android-device-measure.sh apk artifacts-arm64 20` | `apk-fixture.txt`, `apk-runs.txt`, `apk-analysis.txt` | `typed ok`; every run's image base is the subject entry's data offset; the decoy control fires |
| Stability (untyped) | `bash $P/android-device-measure.sh artifacts-arm64 20` | `runs.txt`, `android-device-analysis.txt` | both controls hold |

Each mode exits 0 when everything held, 1 when only the measured verdict (`analyse.py`) failed, and 2 when a control failed or could not run; a failed control voids the verdict. The typed mode runs every mutation with `--require-all`, exempting only `dyn-postnull`, because a library linked by lld has no bytes after its DT_NULL entry; the self-tests prove that comparison on a fixture that does.

What the typed records show, per run: `PROC` (dumpable, seccomp, SELinux context, which memory route), `SLOT`, `IMAGE` (image base, bias, mappings of the file), `DYNAMIC … aps2=absent bind_now=yes`, `DYNAMIC_SUMMARY … relative_ok=0` (bionic adjusts no `.dynamic` entry), `RELRO_SUMMARY … plain_differing=0`, `GOT unchanged=yes`, `FILEONLY …`, `RESULT status=0 PASS`.

The mutation table includes the route controls: a non-dumpable process must still pass through `process_vm_readv`, and one that also has `process_vm_readv` denied by seccomp must report `route=unreadable`. A mismatch there on a device is a finding about that device's kernel, not a failure of the build; record it.

## 4. App process (not automated)

Shell-process evidence does not qualify an app process. An app runs under the app seccomp filter and the `untrusted_app` SELinux domain, which decide whether `process_vm_readv` is allowed, whether `/proc/self/mem` opens, and whether `base.apk` can be opened for the file route. These are measured by a NativeActivity harness that loads the library from inside its own APK and reports the probe's `PROC` and `RESULT` lines; until that harness exists, Android app configurations are not claimed.

## 5. Emulator

The same scripts run against an x86_64 emulator with `--abi x86_64` before the mode, using artifacts built for `x86_64-linux-android`. `android-emulator-extent-v2.sh` runs the facts, typed and APK modes as one command, which is the form CI uses.

## 6. Records to keep

`device-facts.txt`, `typed-runs.txt`, `typed-analysis.txt`, `typed-mutations.txt`, `apk-fixture.txt`, `apk-runs.txt`, `apk-analysis.txt`, `apk-no-decoy.txt`, `apk-self-decoy.txt`, and `statics.txt` from the build.
