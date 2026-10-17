#!/usr/bin/env bash
# Runs an `oxi` binary once and classifies how it started.
#
#   oxi-startup.sh <binary> [<expected-diagnosis>]
#
# Exit status:
#   0  operational: the process exited 0 AND printed the SHA-256 of "abc".
#      The digest is evidence that `oxi` dispatched the command, which it only
#      does after the module's power-up tests have passed.
#   1  refused by the module's power-up tests: the process exited non-zero AND
#      said "module initialization failed". When <expected-diagnosis> is given,
#      the output must also contain it, so a control can require one specific
#      integrity outcome rather than any power-up failure.
#   2  anything else: no output, a signal, an unexpected message. A binary the
#      operating system kills at launch lands here, so it can satisfy neither
#      of the outcomes above.
#   3  refused by the power-up tests, but without <expected-diagnosis>: some
#      other test failed, or the integrity test failed for another reason.
#
# The classification lives in one file because integrity-image-probe.yml and
# release-artifacts.yml both assert on it, and each assertion is only as good
# as the predicate under it.
set -uo pipefail

bin="${1:?usage: oxi-startup.sh <binary> [<expected-diagnosis>]}"
want="${2:-}"
# SHA-256("abc"), FIPS 180-4 Appendix B.1.
expected="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

out="$(printf 'abc' | "$bin" hash sha256 2>&1)"
rc=$?
printf '%s\n' "$out"
echo "exit status: $rc"

if [ "$rc" -eq 0 ]; then
  case "$out" in
    *"$expected"*) echo "startup: operational"; exit 0 ;;
  esac
else
  case "$out" in
    *"module initialization failed"*)
      case "$out" in
        *"$want"*) echo "startup: refused by the module's power-up tests"; exit 1 ;;
      esac
      echo "startup: refused by the power-up tests, but without the expected diagnosis: $want"
      exit 3 ;;
  esac
fi
echo "startup: neither operational nor refused by the module (killed, crashed, or unexpected output)"
exit 2
