# Security Policy

## Reporting a vulnerability

Email **hello@oxicrypt.dev**. The same address is published at
[oxicrypt.dev/.well-known/security.txt](https://oxicrypt.dev/.well-known/security.txt).

Please include enough to reproduce: the algorithm and parameter set, the inputs,
and what you expected against what you observed. A failing test is ideal.

Expect an acknowledgement within a few days. Please allow a reasonable period for
a fix before public disclosure. There is no bug bounty.

## What is in scope

Everything inside the cryptographic module boundary — the algorithm
implementations, the module state machine, the power-up and conditional
self-tests, the integrity check, and the C ABI.

Findings of particular interest, because they are the ones this project exists to
get right:

- An algorithm producing output that disagrees with its standard.
- A service reachable in a module state or under an algorithm profile that should
  forbid it.
- A self-test that passes when it should fail, or one that never runs.
- Secret-dependent branching or memory access in a routine documented as
  constant-time.
- Key material surviving in memory past the point it is documented to be zeroed.

## Supported versions

The `0.x` series is pre-1.0 and only the most recent release is supported. A
`0.x` minor bump may break compatibility, which is the contract cargo already
applies below 1.0.

## Validation status

oxicrypt holds **no CMVP certificate and no CAVP certificate**. Its algorithm
implementations have been graded as passing on NIST's ACVP demonstration server,
which is evidence of algorithm correctness and is not a certificate. Do not
select it to satisfy a compliance obligation on the strength of that grading.
