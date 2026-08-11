#!/usr/bin/env python3
"""Rebuild docs/validation/acvp-demo-evidence.json from raw ACVTS session transcripts.

    scripts/extract-acvp-evidence.py <transcripts-dir>

Run this after a graded ACVP session, then scripts/gen-acvp-evidence-md.py to re-render the readable
page. scripts/check-acvp-evidence.py validates the result in CI.

The transcript directory is NOT in this repository and must not be added to it: every session
registration embeds an account access token whose payload carries personal identifying data in
cleartext. This script is the scrub — it reads those transcripts and emits only NIST-issued
identifiers, verdicts and counts.

Two method rules are load-bearing, both learned from real miscounts:
  * Build the vector-set -> verdict map GLOBALLY across all transcripts before joining to prompts. A
    session that failed to submit and was banked later has its verdict in a different file from its
    prompt; a per-file join silently loses those grades.
  * Count entries carrying an explicit per-case `result` in the verdict body. NEVER count tcId
    occurrences: each appears twice per transcript (prompt and response), a 2x overcount.
  * Prompt-bearing events key their payload on `data`, not `detail`. A parser written against
    `detail` alone silently resolves zero algorithms.
"""
import json, glob, os, re, sys, datetime, collections

if len(sys.argv) < 2:
    sys.exit(__doc__)
SRC = sys.argv[1]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docs', 'validation',
                   'acvp-demo-evidence.json')
files = sorted(glob.glob(os.path.join(SRC, '*.json')))
if not files:
    sys.exit(f'no transcripts found under {SRC}')

verdicts, prompts, stats = {}, {}, collections.Counter()

VERDICT_RE = re.compile(r'/acvp/v1/testSessions/(\d+)/vectorSets/(\d+)\s*:\s*(\w+)')
PATH_RE = re.compile(r'/acvp/v1/testSessions/(\d+)/vectorSets/(\d+)')

verdicts = {}      # vsId -> {tsId, disposition, cases, ts}
prompts = {}       # vsId -> {algorithm, mode, revision, groups, ts}
stats = collections.Counter()


def as_obj(detail):
    """verdict_body arrives as a JSON string or an already-parsed list."""
    if isinstance(detail, (list, dict)):
        return detail
    if isinstance(detail, str):
        try:
            return json.loads(detail)
        except Exception:
            return None
    return None


def count_passed(body):
    """Count graded test cases: entries carrying an explicit per-case result."""
    n = 0
    for chunk in (body if isinstance(body, list) else [body]):
        if not isinstance(chunk, dict):
            continue
        for t in chunk.get('tests', []) or []:
            if isinstance(t, dict) and 'result' in t:
                n += 1
    return n


def disposition_of(body):
    for chunk in (body if isinstance(body, list) else [body]):
        if isinstance(chunk, dict) and 'disposition' in chunk:
            return chunk['disposition']
    return None


for f in files:
    stats['files'] += 1
    try:
        doc = json.load(open(f, encoding='utf-8', errors='replace'))
    except Exception:
        stats['files_unparseable'] += 1
        continue
    for e in doc.get('transcript', []) or []:
        ev, ts = e.get('event'), e.get('timestamp')
        det = e.get('data') if e.get('data') is not None else e.get('detail')

        if ev == 'verdict' and isinstance(det, str):
            m = VERDICT_RE.search(det)
            if m:
                ts_id, vs_id, disp = m.group(1), int(m.group(2)), m.group(3)
                r = verdicts.setdefault(vs_id, {})
                r.update(test_session_id=ts_id, disposition=disp)
                r.setdefault('graded_at', ts)
                stats['verdict_events'] += 1

        elif ev == 'verdict_body':
            body = as_obj(det)
            if body is None:
                stats['verdict_body_unparsed'] += 1
                continue
            vs = None
            for chunk in (body if isinstance(body, list) else [body]):
                if isinstance(chunk, dict) and 'vsId' in chunk:
                    vs = chunk['vsId']
                    break
            if vs is None:
                continue
            r = verdicts.setdefault(int(vs), {})
            r['test_cases'] = count_passed(body)
            d = disposition_of(body)
            if d:
                r['disposition'] = d
            r.setdefault('graded_at', ts)
            stats['verdict_bodies'] += 1

        elif ev in ('vector_set_prompt', 'registration_response', 'vector_set_response'):
            body = as_obj(det)
            if body is None:
                continue
            for chunk in (body if isinstance(body, list) else [body]):
                if not isinstance(chunk, dict) or 'vsId' not in chunk:
                    continue
                p = prompts.setdefault(int(chunk['vsId']), {})
                for k_src, k_dst in (('algorithm', 'algorithm'), ('mode', 'mode'), ('revision', 'revision')):
                    if chunk.get(k_src) and not p.get(k_dst):
                        p[k_dst] = chunk[k_src]
                if isinstance(chunk.get('testGroups'), list) and not p.get('test_groups'):
                    p['test_groups'] = len(chunk['testGroups'])
                p.setdefault('seen_at', ts)

        elif ev in ('submit_ok', 'resubmit_post', 'fetch_vectors') and isinstance(det, str):
            m = PATH_RE.search(det)
            if m:
                verdicts.setdefault(int(m.group(2)), {}).setdefault('test_session_id', m.group(1))


records = []
for vs_id, v in sorted(verdicts.items()):
    p = prompts.get(vs_id, {})
    records.append({'vector_set_id': vs_id, 'test_session_id': v.get('test_session_id'),
                    'algorithm': p.get('algorithm'), 'mode': p.get('mode'),
                    'revision': p.get('revision'), 'test_groups': p.get('test_groups'),
                    'test_cases': v.get('test_cases'), 'disposition': v.get('disposition'),
                    'graded_at': v.get('graded_at')})
recs = records

# Each entry is (name, pattern, a string that MUST match it). One control per pattern: a single
# combined control string is worthless here, because the leftmost alternation matches first and
# masks every other branch — all twelve could rot to nothing while the control still fired.
LEAK_PATTERNS = [
    ('jwt',            r'eyJ[A-Za-z0-9_-]{10,}',                'eyJabcdefghijklmnop'),
    ('token-word',     r'access[_-]?token|api[_-]?key|client[_-]?secret'
                       r'|password\s*[=:]|Authorization\s*:|Bearer\s+[A-Za-z0-9._-]{8,}',
                                                                'accessToken'),
    ('token-word-2',   r'Authorization\s*:|Bearer\s+[A-Za-z0-9._-]{8,}',
                                                                'Authorization: Bearer abcdefgh12'),
    ('pem',            r'-----BEGIN',                           '-----BEGIN PRIVATE KEY-----'),
    ('email',          r'[^\s@]+@[^\s@]+\.[^\s@]{2,}',          'someone@example.com'),
    ('posix-path',     r'/home/|/Users/',                       'in /home/someone/x'),
    ('posix-path-2',   r'/Users/',                              'in /Users/someone/x'),
    ('windows-path',   r'[A-Za-z]:\\\\?Users',                  r'C:\Users'),
    ('operator-name',  r'leckinger|riseup\.net',                'r.leckinger'),
    ('operator-org',   r'vyoman|code ?siren|secrecy ?labs',     'VyomanLLC'),
    ('fleet-host',     r'\b(orinoco|danube|yamuna|volga)\b|\.ts\.net',  'on orinoco'),
    ('private-project',r'carakastan|daemonseed',                'under carakastan'),
    ('harness-internal',r'resubmit-session|transcripts-raw|acvts-demo',  'acvts-demo/x'),
]
COMPILED = [(n, re.compile(p, re.I), ex) for n, p, ex in LEAK_PATTERNS]


def leak_hits(doc_obj, blob):
    """Scan the serialised blob AND every decoded string. Non-ASCII PII (e.g. an accented name)
    escapes to \\uXXXX in the blob and is invisible to a raw scan; the decoded walk sees it."""
    out = []

    def walk(node, path='$'):
        if isinstance(node, dict):
            for k, v in node.items():
                yield f'{path}.{k}', str(k)
                yield from walk(v, f'{path}.{k}')
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from walk(v, f'{path}[{i}]')
        elif isinstance(node, str):
            yield path, node

    for name, rx, _ in COMPILED:
        if rx.search(blob):
            out.append(f'{name} (raw blob)')
        for path, val in walk(doc_obj):
            if rx.search(val):
                out.append(f'{name} at {path}')
    return out


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%d') if ts else None


graded = [r for r in recs if r.get('disposition') in ('passed', 'failed')]
graded.sort(key=lambda r: (r.get('graded_at') or 0, r['vector_set_id']))

# The only free-text fields that reach the output are algorithm, mode and revision, and they are
# ACVP catalog identifiers with a known shape. Validate them POSITIVELY rather than trying to deny
# every form PII could take: a denylist is defeated by one accent (Leckinger vs Leckinger with an
# acute e), and no enumerable list of forbidden strings can cover what it does not anticipate. An
# allow-list on the only free-text path is structural instead of adversarial.
CATALOG_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 /_.+-]*$')


def check_catalog_field(value, field, vs_id):
    if value is None:
        return
    if not isinstance(value, str) or not CATALOG_ID.match(value) or not value.isascii():
        sys.exit(f'REFUSING TO WRITE - vector set {vs_id} has a {field} that is not a plain ASCII '
                 'ACVP catalog identifier. Value not printed. This field is copied verbatim from '
                 'the transcript into a public file, so anything unexpected in it stops the run.')


sessions = []
for r in graded:
    for _f in ('algorithm', 'mode', 'revision'):
        check_catalog_field(r.get(_f), _f, r.get('vector_set_id'))
    row = {
        'test_session_id': r['test_session_id'],
        'vector_set_id': r['vector_set_id'],
        'algorithm': r['algorithm'],
        'revision': r['revision'],
        'disposition': r['disposition'],
        'graded_on': iso(r.get('graded_at')),
    }
    if r.get('mode') is not None:
        row['mode'] = r['mode']
    if r.get('test_groups') is not None:
        row['test_groups'] = r['test_groups']
    if r.get('test_cases') is not None:
        row['test_cases_recounted'] = r['test_cases']
    sessions.append(row)

passed = [s for s in sessions if s['disposition'] == 'passed']
recounted = [s for s in sessions if 'test_cases_recounted' in s]
recounted_pass = [s for s in recounted if s['disposition'] == 'passed']
algs_all = {s['algorithm'] for s in sessions}
algs_recounted = {s['algorithm'] for s in recounted if s['disposition'] == 'passed'}

doc = {
    "_what_this_is": (
        "The record of oxicrypt's algorithm testing against NIST's ACVP demonstration server. Each "
        "row is one vector set submitted for grading, identified by the test session and vector set "
        "IDs NIST itself issued, with the verdict NIST returned. Both passing and failing gradings "
        "are listed, so the denominator is visible rather than implied. Vector sets that were "
        "submitted but for which no pass/fail verdict was recorded are counted in "
        "vector_sets_without_recorded_verdict and are not listed here."
    ),
    "_what_this_is_not": (
        "NOT a CAVP certificate and NOT a FIPS 140-3 validation. These results come from NIST's "
        "DEMONSTRATION server, which runs the same protocol and the same test-vector generators as "
        "the certification path, but issues no certificate and confers no validation status. "
        "oxicrypt holds no CAVP or CMVP certificate."
    ),
    "generated_from": (
        "The session transcripts produced by the test harness at grading time. The raw transcripts "
        "are not published: every session registration embeds an account access token whose payload "
        "carries personal identifying data in cleartext. This file is the derived, scrubbed record."
    ),
    "method": {
        "verdict_map": (
            "The vector-set-to-verdict map is built globally across all transcripts before joining "
            "to prompts. A session that failed to submit and was banked later has its verdict in a "
            "different transcript from its prompt; a per-file join silently loses those grades."
        ),
        "case_counting": (
            "test_cases_recounted counts entries carrying an explicit per-case result in the "
            "verdict body. It deliberately does NOT count tcId occurrences, which appear twice per "
            "transcript (prompt and response) and produce a 2x overcount."
        ),
        "coverage_limit": (
            f"A per-case count is reproducible for {len(recounted)} of {len(sessions)} graded vector "
            f"sets, because the full verdict body was retained only for those. Cut by algorithm the "
            f"limit is sharper and is stated plainly here rather than left to be discovered: only "
            f"{len(algs_recounted)} of {len(algs_all)} algorithms carry any reproducible count at "
            "all, and the ones that do not include the high-volume symmetric and hash families. The "
            "project's overall test-case total is therefore NOT reconstructible from this file, and "
            "this file does not assert it."
        ),
        "counting_unit": (
            "The algorithm count here is distinct ACVP algorithm registrations, which is a finer "
            "unit than the algorithm-family count the project quotes elsewhere. The two are "
            "different units, not competing figures."
        ),
        "verification": (
            "These rows are attestable, not re-queryable by a third party, and the difference is "
            "worth stating exactly. ACVP test sessions expire 30 days after creation, and most of "
            "these are long past that; session URLs are also scoped to the account that created "
            "them, so another party's demonstration-server credentials reach their own sessions and "
            "not these. What the identifiers give a reader is the ability to put a specific, "
            "falsifiable question to NIST or to a testing laboratory about a specific session, and "
            "the ability to hold this record against any future certification submission."
        ),
    },
    "summary": {
        "vector_sets_graded": len(sessions),
        "vector_sets_without_recorded_verdict":
            len([r for r in recs if r.get('disposition') not in ('passed', 'failed')]),
        "vector_sets_passed": len(passed),
        "vector_sets_failed": len(sessions) - len(passed),
        "distinct_test_sessions": len({s['test_session_id'] for s in sessions}),
        "distinct_algorithms": len(algs_all),
        "algorithms_with_reproducible_case_count": len(algs_recounted),
        "vector_sets_with_reproducible_case_count": len(recounted),
        "vector_sets_passed_with_reproducible_case_count": len(recounted_pass),
        "passing_test_cases_reproducible_from_this_file":
            sum(s['test_cases_recounted'] for s in recounted_pass),
        "earliest_grading": min(s['graded_on'] for s in sessions if s['graded_on']),
        "latest_grading": max(s['graded_on'] for s in sessions if s['graded_on']),
    },
    "algorithms": sorted(algs_all),
    "sessions": sessions,
}

blob = json.dumps(doc, indent=2)
for name, rx, example in COMPILED:
    if not rx.search(example):
        sys.exit(f'REFUSING TO WRITE - leak pattern {name!r} did not match its own control. '
                 'A guard that has stopped matching reads exactly like a clean file.')
hits = leak_hits(doc, blob)
if hits:
    sys.exit('REFUSING TO WRITE - forbidden content in output: ' + '; '.join(sorted(set(hits)))
             + '. The matches are deliberately not printed.')
open(OUT, 'w').write(blob + "\n")
print(f'wrote {OUT}')
for k, v in doc['summary'].items():
    print(f'  {k:<48} {v}')
print(f'  scrubbed {stats["files"]} transcripts; scrubber control FIRED (ok)')
# A silently-shrinking record is the broken-probe failure: report every drop, loudly.
_dropped = len([r for r in recs if r.get('disposition') not in ('passed', 'failed')])
for _label, _n in (('transcripts that failed to parse', stats['files_unparseable']),
                   ('verdict bodies that failed to parse', stats['verdict_body_unparsed']),
                   ('vector sets with no pass/fail verdict (not published)', _dropped)):
    if _n:
        print(f'  NOTE: {_n} {_label}')
if stats['files_unparseable'] or stats['verdict_body_unparsed']:
    print('  ^ the record is INCOMPLETE relative to the transcripts on disk; investigate before '
          'publishing.')
