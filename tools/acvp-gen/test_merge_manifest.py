#!/usr/bin/env python3
"""Tests for generate.py's merge_manifest, which keeps the MANIFEST.toml rows
the generator does not write.

Run: python3 tools/acvp-gen/test_merge_manifest.py
"""
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("generate", HERE / "generate.py")
generate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate)

EXISTING = """\
# old header

[gen]
X = { sha256 = "old-x" }
# why Y is pinned
Y = { sha256 = "old-y" }
# a hand-written row
Z = [
  1,
  2,
]
# trailing note

[hand]
# kept whole
A = { file = "a.json" }
B = [
  "b",
]
"""

GENERATED = [
    "# new header",
    "",
    "[gen]",
    'X = { sha256 = "new-x" }',
    'Y = { sha256 = "new-y" }',
    "",
]

EXPECTED = """\
# new header

[gen]
X = { sha256 = "new-x" }
# why Y is pinned
Y = { sha256 = "new-y" }
# a hand-written row
Z = [
  1,
  2,
]
# trailing note

[hand]
# kept whole
A = { file = "a.json" }
B = [
  "b",
]"""


def rows(lines):
    out = set()
    for name, body in generate._manifest_sections(lines):
        for key, entry in generate._entries(body):
            if key is not None:
                out.add((name, tuple(entry)))
    return out


class MergeManifest(unittest.TestCase):
    def test_keeps_comments_multiline_values_and_hand_sections(self):
        merged = generate.merge_manifest(GENERATED, EXISTING)
        self.assertEqual("\n".join(merged), EXPECTED)

    def test_is_stable_on_a_second_run(self):
        once = generate.merge_manifest(GENERATED, EXISTING)
        twice = generate.merge_manifest(GENERATED, "\n".join(once) + "\n")
        self.assertEqual(once, twice)

    def test_the_vendored_manifest_survives_a_regeneration(self):
        """Regenerating without the sections and rows the generator does not
        write loses none of them."""
        text = (HERE.parents[1] / "vendor" / "nist" / "MANIFEST.toml").read_text()
        hand = {"[acvp_ml_dsa_spec]", "[acvp_server.pbkdf]", "[acvp_server.pqc]"}
        generated = []
        for name, body in generate._manifest_sections(text.splitlines()):
            if name in hand:
                continue
            if name is not None:
                generated.append(name)
            generated.extend(l for l in body if not l.startswith("HKDF_SHA3_512 "))
        self.assertLess(len(rows(generated)), len(rows(text.splitlines())))
        merged = generate.merge_manifest(generated, text)
        self.assertEqual(rows(merged), rows(text.splitlines()))


if __name__ == "__main__":
    unittest.main()
