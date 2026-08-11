#!/usr/bin/env python3
"""Integrity check for docs/validation/acvp-demo-evidence.json.

What this checks, stated precisely because the file it guards is a document about checkability:

  1. INTERNAL CONSISTENCY. Every figure in `summary`, and the published `algorithms` list, is
     re-derived from the `sessions` rows and must match. This catches drift between a headline and
     the evidence under it. It does NOT and cannot attest that the rows themselves are true — rows
     and summary can agree while both are wrong. Only NIST can confirm a grading.

  2. LEAKAGE. No credential-shaped or identity-shaped string may appear, checked against BOTH the
     raw bytes AND every decoded string in the parsed document. The raw form alone is not enough:
     `\\/home\\/rick` and `\\u0065\\u0079\\u004a` are legal JSON that many writers emit by default and
     that a raw-bytes regex never sees.

  3. HONESTY. The demonstration-server caveat and the no-certificate statement must be present and
     must not have been inverted.

Every regex alternation is exercised against a planted string on each run. A guard that has
silently stopped matching reads exactly like a clean file.

Exit 0 = pass, 1 = failure.
"""
import json
import os
import re
import sys

EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docs', 'validation',
                        'acvp-demo-evidence.json')

# Each entry is (name, pattern, must-match example). The example is the per-alternation positive
# control: if any of these stops matching, the guard has rotted and the run fails.
LEAK_PATTERNS = [
    ('jwt',          r'eyJ[A-Za-z0-9_-]{10,}',                       'eyJabcdefghijklmnop'),
    ('token-word',   r'access[_-]?token|api[_-]?key|client[_-]?secret|password\s*[=:]'
                     r'|Authorization\s*:|Bearer\s+[A-Za-z0-9._-]{8,}',
                                                                     'Authorization: Bearer abcdefgh12345'),
    ('pem',          r'-----BEGIN',                                  '-----BEGIN PRIVATE KEY-----'),
    ('email',        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', 'someone@example.com'),
    ('posix-path',   r'/home/|/Users/',                              'in /home/someone/x'),
    ('windows-path', r'[A-Za-z]:\\\\?Users\\\\?',                    r'C:\Users\someone'),
]
COMPILED = [(n, re.compile(p, re.I), ex) for n, p, ex in LEAK_PATTERNS]

REQUIRED_ROW_KEYS = ('test_session_id', 'vector_set_id', 'algorithm', 'revision', 'disposition',
                     'graded_on')
DERIVED_SUMMARY_KEYS = {
    'vector_sets_graded', 'vector_sets_without_recorded_verdict', 'vector_sets_passed',
    'vector_sets_failed', 'distinct_test_sessions',
    'distinct_algorithms', 'algorithms_with_reproducible_case_count',
    'vector_sets_with_reproducible_case_count', 'vector_sets_passed_with_reproducible_case_count',
    'passing_test_cases_reproducible_from_this_file', 'earliest_grading', 'latest_grading',
}
# Sentences that must survive verbatim. A substring test on "no CAVP" inverts trivially
# ("no CAVP obstacle: oxicrypt IS CAVP validated"), so the whole clause is pinned.
REQUIRED_PHRASES = [
    ('_what_this_is_not', 'oxicrypt holds no CAVP or CMVP certificate'),
    ('_what_this_is_not', 'DEMONSTRATION server'),
]
BANNED_PHRASES = [r'is\s+CAVP\s+validated', r'CAVP[- ]certified', r'FIPS\s*140-3\s*(validated|certified)',
                  r'holds\s+a\s+(CAVP|CMVP)']

failures = []


def fail(msg):
    failures.append(msg)


def walk_strings(node, path='$'):
    """Yield (path, string) for every string in the parsed document, keys included."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield f'{path}.{k}', str(k)
            yield from walk_strings(v, f'{path}.{k}')
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk_strings(v, f'{path}[{i}]')
    elif isinstance(node, str):
        yield path, node


def is_plain_int(v):
    """bools are ints in Python; a `true` case count must not sum as 1."""
    return isinstance(v, int) and not isinstance(v, bool)


def main():
    # --- per-alternation positive controls ---
    for name, rx, example in COMPILED:
        if not rx.search(example):
            print(f'FAIL: leak pattern {name!r} did not match its own control {example!r}. '
                  'The guard is broken, and a broken guard reads exactly like a clean file.',
                  file=sys.stderr)
            return 1

    if not os.path.exists(EVIDENCE):
        print(f'FAIL: {EVIDENCE} not found', file=sys.stderr)
        return 1

    raw = open(EVIDENCE, encoding='utf-8').read()
    try:
        doc = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        print(f'FAIL: evidence file is not valid JSON: {exc}', file=sys.stderr)
        return 1

    # --- leakage: raw bytes AND decoded strings ---
    for name, rx, _ in COMPILED:
        n_raw = len(rx.findall(raw))
        if n_raw:
            fail(f'leak pattern {name!r} matched raw content in {n_raw} place(s). '
                 'The match is deliberately not printed: this runs in CI on a public repository '
                 'and would publish the very thing it detected.')
        for path, val in walk_strings(doc):
            m = rx.search(val)
            if m:
                fail(f'leak pattern {name!r} matched a decoded string at {path} '
                     f'(offset {m.start()}, length {len(m.group(0))}); match not printed.')

    sessions = doc.get('sessions')
    summary = doc.get('summary')
    if not isinstance(sessions, list) or not sessions:
        fail('sessions array is missing or empty')
    if not isinstance(summary, dict):
        fail('summary object is missing')
    if failures:
        return report()

    # --- rows well-formed ---
    for i, row in enumerate(sessions):
        if not isinstance(row, dict):
            fail(f'sessions[{i}] is {type(row).__name__}, expected object')
            continue
        for k in REQUIRED_ROW_KEYS:
            if not row.get(k):
                fail(f'sessions[{i}] (vsId {row.get("vector_set_id")}) missing {k}')
        if row.get('disposition') not in ('passed', 'failed'):
            fail(f'sessions[{i}] disposition is {row.get("disposition")!r}; must be passed or '
                 'failed. Both are published so the denominator is visible.')
        if 'test_cases_recounted' in row and not is_plain_int(row['test_cases_recounted']):
            fail(f'sessions[{i}] test_cases_recounted is {row["test_cases_recounted"]!r}; '
                 'must be a plain integer (bools and strings are rejected)')
    if failures:
        return report()

    # --- summary must be re-derivable, including the dates ---
    ids = [str(r.get('vector_set_id')) for r in sessions]
    dates = sorted(str(r['graded_on']) for r in sessions if r.get('graded_on'))
    ok = [r for r in sessions if r.get('disposition') == 'passed']
    rec = [r for r in sessions if 'test_cases_recounted' in r]
    rec_ok = [r for r in rec if r.get('disposition') == 'passed']
    derived = {
        'vector_sets_graded': len(sessions),
        'vector_sets_passed': len(ok),
        'vector_sets_failed': len(sessions) - len(ok),
        'distinct_test_sessions': len({str(r.get('test_session_id')) for r in sessions}),
        'distinct_algorithms': len({r.get('algorithm') for r in sessions}),
        'algorithms_with_reproducible_case_count': len({r.get('algorithm') for r in rec_ok}),
        'vector_sets_with_reproducible_case_count': len(rec),
        'vector_sets_passed_with_reproducible_case_count': len(rec_ok),
        'passing_test_cases_reproducible_from_this_file':
            sum(r.get('test_cases_recounted', 0) for r in rec_ok),
        'earliest_grading': dates[0] if dates else None,
        'latest_grading': dates[-1] if dates else None,
    }
    for key, want in derived.items():
        got = summary.get(key)
        if got != want:
            fail(f'summary.{key} is {got!r} but the rows give {want!r}')

    # vector_sets_without_recorded_verdict counts rows this file deliberately does NOT list,
    # so it cannot be re-derived from the rows; it is allow-listed but not recomputed.
    extra = set(summary) - DERIVED_SUMMARY_KEYS
    if extra:
        fail(f'summary carries underived keys {sorted(extra)}; every published figure must be '
             'derivable from the rows')

    # --- ids unique, compared as strings so 3821745 and "3821745" collide ---
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        fail(f'duplicate vector_set_id values would double-count: {dupes[:5]}')

    # --- the published algorithm list must match the rows exactly ---
    listed = doc.get('algorithms')
    if not isinstance(listed, list):
        fail('top-level algorithms list is missing')
    else:
        from_rows = {r.get('algorithm') for r in sessions}
        if set(listed) != from_rows:
            only_listed = sorted(set(listed) - from_rows)
            only_rows = sorted(from_rows - set(listed))
            fail(f'algorithms list disagrees with the rows; listed-but-ungraded={only_listed[:5]}, '
                 f'graded-but-unlisted={only_rows[:5]}')
        if len(listed) != len(set(listed)):
            fail('algorithms list contains duplicates')

    # --- honesty statements present, non-trivial, and not inverted ---
    for key in ('_what_this_is_not', 'method', 'generated_from'):
        val = doc.get(key)
        if not val or (isinstance(val, str) and len(val) < 80):
            fail(f'top-level {key!r} is missing or has been gutted; it carries the '
                 'demonstration-server caveat and the counting method, and is not optional')
    for key, phrase in REQUIRED_PHRASES:
        if phrase.lower() not in str(doc.get(key, '')).lower():
            fail(f'{key} no longer contains the required statement {phrase!r}')
    whole = json.dumps(doc)
    for banned in BANNED_PHRASES:
        m = re.search(banned, whole, re.I)
        if m:
            fail(f'file asserts a certification it does not hold: {m.group(0)!r}')

    # --- the PUBLISHED markdown gets the same leak and honesty checks as the JSON ---
    # It is authored by the generator, it is what humans actually read, and until 2026-08-11 it was
    # scanned by nothing at all: a generator emitting an affirmative certification claim plus a
    # token passed cleanly.
    md_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docs', 'validation',
                           'ACVP-EVIDENCE.md')
    if not os.path.exists(md_path):
        fail('docs/validation/ACVP-EVIDENCE.md is missing')
    else:
        md = open(md_path, encoding='utf-8').read()
        for name, rx, _ in COMPILED:
            m = rx.search(md)
            if m:
                fail(f'leak pattern {name!r} matched the published page at offset {m.start()}; '
                     'match not printed.')
        for banned in BANNED_PHRASES:
            m = re.search(banned, md, re.I)
            if m:
                fail(f'the published page asserts a certification not held: {m.group(0)!r}')
        if 'holds no CAVP' not in md:
            fail('the published page no longer states that no CAVP certificate is held')

    # --- the human-readable rendering must be in sync with this file ---
    import subprocess
    gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gen-acvp-evidence-md.py')
    if not os.path.exists(gen):
        fail('scripts/gen-acvp-evidence-md.py is missing; the published markdown cannot be verified')
    else:
        r = subprocess.run([sys.executable, gen, '--check'], capture_output=True, text=True)
        if r.returncode != 0:
            fail(f'ACVP-EVIDENCE.md is out of sync with the JSON: {r.stderr.strip() or r.stdout.strip()}')

    return report()


def report():
    if failures:
        print('check-acvp-evidence: FAILED', file=sys.stderr)
        for f in failures:
            print(f'  - {f}', file=sys.stderr)
        return 1
    print(f'check-acvp-evidence: OK ({len(COMPILED)} leak patterns verified against controls; '
          'summary and algorithm list re-derived from rows)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
