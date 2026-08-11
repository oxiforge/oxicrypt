#!/usr/bin/env python3
"""Render docs/validation/ACVP-EVIDENCE.md from acvp-demo-evidence.json.

The JSON is the source of truth; the markdown is a rendering of it for humans. CI regenerates and
diffs, so the two cannot drift apart.

Usage:
  gen-acvp-evidence-md.py            # write the markdown
  gen-acvp-evidence-md.py --check    # exit 1 if the file on disk differs from what we would write
"""
import json
import os
import sys
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
JSON = os.path.join(HERE, '..', 'docs', 'validation', 'acvp-demo-evidence.json')
MD = os.path.join(HERE, '..', 'docs', 'validation', 'ACVP-EVIDENCE.md')

# Family grouping follows the project's stated merge rule: sub-modes a reader would name as one
# thing are merged (SP 800-185 XOFs; the three DRBGs; the two KAS variants).
def family(alg):
    a = alg.upper()
    if a.startswith('ACVP-AES'):
        return 'AES'
    if a == 'CMAC-AES':
        return 'CMAC'
    if 'DRBG' in a:
        return 'DRBG'
    if a.startswith('HMAC'):
        return 'HMAC'
    if any(a.startswith(x) for x in ('SHAKE', 'CSHAKE', 'KMAC', 'TUPLEHASH', 'PARALLELHASH')):
        return 'SP 800-185 (XOF)'
    if a.startswith('SHA3'):
        return 'SHA-3'
    if a.startswith('SHA'):
        return 'SHA-1 / SHA-2'
    if a.startswith('TLS') or a == 'KDF-COMPONENTS':
        return 'TLS KDFs'
    if a == 'KDA':
        return 'KDA-HKDF'
    if a == 'KDF':
        return 'KBKDF'
    if a.startswith('KAS'):
        return 'KAS'
    if a.startswith('KTS'):
        return 'KTS-IFC (OAEP)'
    return {'ECDSA': 'ECDSA', 'EDDSA': 'EdDSA', 'RSA': 'RSA', 'PBKDF': 'PBKDF',
            'ML-KEM': 'ML-KEM', 'ML-DSA': 'ML-DSA', 'SLH-DSA': 'SLH-DSA', 'LMS': 'LMS'}.get(a, alg)


def render(doc):
    s = doc['summary']
    rows = doc['sessions']
    ok = [r for r in rows if r['disposition'] == 'passed']

    services = sorted({(r['algorithm'], r.get('mode'), r['revision']) for r in ok})
    by_fam = collections.defaultdict(list)
    for svc in services:
        by_fam[family(svc[0])].append(svc)

    vsets_by_svc = collections.Counter(
        (r['algorithm'], r.get('mode'), r['revision']) for r in ok)
    cases_by_svc = collections.Counter()
    for r in ok:
        if 'test_cases_recounted' in r:
            cases_by_svc[(r['algorithm'], r.get('mode'), r['revision'])] += r['test_cases_recounted']

    L = []
    w = L.append
    w('# Algorithm testing evidence')
    w('')
    w('<!-- Generated from acvp-demo-evidence.json by scripts/gen-acvp-evidence-md.py.')
    w('     Do not edit by hand; CI regenerates this file and fails if it differs. -->')
    w('')
    w('Every algorithm oxicrypt has submitted to NIST for grading, and the verdict NIST returned.')
    w('')
    w('This is the submission record, not an inventory of the codebase: an algorithm implemented here')
    w('but never submitted does not appear. **XMSS is the notable absence** — it is implemented, but')
    w("NIST's demonstration server does not advertise it, so it cannot be submitted for grading at all.")
    w('')
    w('> **Not a certificate.** These gradings come from NIST\'s ACVP *demonstration* server. It runs')
    w('> the same protocol and the same test-vector generators as the certification path, but issues no')
    w("> certificate. **oxicrypt holds no CAVP or FIPS 140-3 certificate** and has not been submitted to")
    w('> a testing laboratory.')
    w('')
    w('| | |')
    w('|---|--:|')
    w(f"| Algorithm families | **{len(by_fam)}** |")
    w(f"| ACVP services graded | **{len(services)}** |")
    w(f"| Vector sets graded | **{s['vector_sets_graded']}** — {s['vector_sets_passed']} passed, "
      f"{s['vector_sets_failed']} failed |")
    w(f"| NIST test sessions | {s['distinct_test_sessions']} |")
    w(f"| Period | {s['earliest_grading']} to {s['latest_grading']} |")
    w('')
    w('## What was graded')
    w('')
    w('One row per ACVP service — the (algorithm, mode, revision) tuple NIST registers and grades.')
    w('')
    for fam in sorted(by_fam):
        svcs = by_fam[fam]
        w(f'**{fam}** — {len(svcs)} service{"s" if len(svcs) != 1 else ""}')
        w('')
        w('| Algorithm | Mode | Revision | Vector sets | Cases |')
        w('|---|---|---|--:|--:|')
        for svc in svcs:
            alg, mode, rev = svc
            cases = cases_by_svc.get(svc)
            w(f"| `{alg}` | {mode or '—'} | {rev} | {vsets_by_svc[svc]} "
              f"| {cases if cases else '—'} |")
        w('')
    w('<details>')
    w(f"<summary>Full session record — all {s['vector_sets_graded']} graded vector sets, with the "
      'NIST identifiers</summary>')
    w('')
    w('| Graded | Session | Vector set | Algorithm | Mode | Revision | Verdict | Cases |')
    w('|---|--:|--:|---|---|---|---|--:|')
    for r in rows:
        verdict = 'passed' if r['disposition'] == 'passed' else '**failed**'
        w(f"| {r['graded_on']} | {r['test_session_id']} | {r['vector_set_id']} | `{r['algorithm']}` "
          f"| {r.get('mode') or '—'} | {r['revision']} | {verdict} "
          f"| {r.get('test_cases_recounted', '—')} |")
    w('')
    w('</details>')
    w('')
    w('## Notes')
    w('')
    # Derive the harness-maturity cutover from the data rather than asserting it.
    # Derived, over ALL graded rows. Find the last date on which EVERY grading lacked a count —
    # that is the retention changeover — then report anything after it explicitly rather than
    # rounding it away.
    by_date = collections.defaultdict(lambda: [0, 0])
    for r in rows:
        by_date[r['graded_on']][0] += 1
        if 'test_cases_recounted' in r:
            by_date[r['graded_on']][1] += 1
    all_missing = sorted(d for d, (t, c) in by_date.items() if c == 0)
    missing = [r for r in rows if 'test_cases_recounted' not in r]
    if all_missing and missing:
        cutover = all_missing[-1]
        after = [r for r in missing if r['graded_on'] > cutover]
        w('**Why some case counts are blank.** The test harness did not retain the full verdict body')
        w('in its earliest sessions, so those gradings kept the verdict but not the per-case detail.')
        w(f'**Every grading up to and including {cutover} lacks a count** '
          f'({len(missing) - len(after)} of {len(missing)} blanks). Retention began with the next')
        w('session and has held since.')
        if after:
            dispo = collections.Counter(r['disposition'] for r in after)
            shape = ', '.join(f'{n} {k}' for k, n in sorted(dispo.items()))
            w('')
            w(f'There {"is" if len(after) == 1 else "are"} **{len(after)} exception'
              f'{"" if len(after) == 1 else "s"} after that date** ({shape}), listed in the table')
            w('above rather than smoothed over: '
              + ', '.join(f"vector set {r['vector_set_id']} on {r['graded_on']}" for r in after[:4])
              + '.')
        w('')
    w('**Failures are listed.** A failed vector set means that submission did not pass; where the')
    w('implementation was then corrected, a later passing row for the same service records it.')
    w('')
    w(f"**Case counts are partial.** A count appears only where the full verdict body was retained — "
      f"{s['vector_sets_with_reproducible_case_count']} of {s['vector_sets_graded']} sets, and "
      f"{s['algorithms_with_reproducible_case_count']} of {s['distinct_algorithms']} algorithms. It is")
    w("left blank rather than estimated elsewhere, so the project's overall test-case total cannot be")
    w('rebuilt from this page and is not claimed here.')
    w('')
    w('**Checking these rows.** ACVP sessions expire thirty days after creation and are scoped to the')
    w('account that created them, so a third party cannot re-run them. The identifiers support a')
    w('specific question to NIST or to a testing laboratory about a named session, and hold this record')
    w('against any future certification submission.')
    w('')
    w('**Source.** Generated from [`acvp-demo-evidence.json`](acvp-demo-evidence.json), the machine-')
    w('readable form of the same record. Raw session transcripts are not published: each embeds an')
    w('account access token carrying personal data in cleartext.')
    w('')
    return '\n'.join(L) + '\n'


def main():
    doc = json.load(open(JSON, encoding='utf-8'))
    out = render(doc)
    if '--check' in sys.argv:
        if not os.path.exists(MD):
            print(f'FAIL: {MD} does not exist; run scripts/gen-acvp-evidence-md.py', file=sys.stderr)
            return 1
        cur = open(MD, encoding='utf-8').read()
        if cur != out:
            print('FAIL: ACVP-EVIDENCE.md is out of sync with acvp-demo-evidence.json. '
                  'Regenerate with scripts/gen-acvp-evidence-md.py', file=sys.stderr)
            return 1
        print('gen-acvp-evidence-md: OK (markdown matches the JSON)')
        return 0
    open(MD, 'w', encoding='utf-8').write(out)
    print(f'wrote {MD} ({len(out.splitlines())} lines)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
