# FUNES Test Cases — Real-First Evidence Plan

Status: provisional working plan. This document keeps the product grounded in
real executions while the QNX environment is being brought online.

## Principle

The primary demonstrations must begin with a real command, a real input, and a
real process outcome. A synthetic fixture may exercise a parser boundary or a
security invariant, but it must never be presented as real QNX evidence.

Every case should preserve this chain:

```text
source state -> exact argv -> observed process -> stdout/stderr -> artifact
-> evidence bundle -> independent verifier -> bounded claim
```

If one link is unavailable, the case is labeled `BLOCKED`, `NOT_RUN`, or
`CONTRACT_TEST_ONLY`; it is not silently promoted to `PASS`.

## Case matrix

| ID | Case | Input and execution | Expected evidence | Claim boundary | Priority |
|---|---|---|---|---|---|
| C01 | Real host build succeeds | Build the host fixture or the project itself with the installed compiler | Source state, argv, compiler output, artifact bytes, digest, verified bundle | `VERIFIED_HOST_ONLY` | Must have |
| C02 | Real build fails | Run a genuine failing compilation in a disposable copy | Non-zero exit, stderr, incomplete artifact state, verifiable bundle | Failure was observed; not a successful build | Must have |
| C03 | Real test fails | Run `qnx8-hello fail` or an equivalent real test against a captured artifact | Test argv, artifact digest, exit code `3`, stdout/stderr, verifier result | Failure was observed; evidence was not laundered | Must have |
| C04 | Real command times out | Run a real long-lived command under `--timeout-sec` | Kill signal, elapsed bound, preserved output, verified bundle | Process was terminated; no claim about its intended result | Must have |
| C05 | Real bundle is mutated | Capture a real bundle, then mutate a disposable copy | Exact `DIGEST_MISMATCH`, `SEAL_MISMATCH`, missing-blob, or symlink failure | The verifier detects this mutation; it is an adversarial reproduction, not an external incident | Must have |
| C06 | Real signer is wrong or replaced | Sign a real bundle, verify with the wrong key, then exercise forced re-signing | Signature and trust states remain distinct and explicit | Key control is shown; execution is still not proven | Must have |
| C07 | Real imported report differs from observation | Produce a real report file from a real test tool and import it against a real artifact | `IMPORTED_ONLY`, report digest, artifact association, verifier output | Imported text is not promoted to observed execution | Should have |
| C08 | Real QNX build | With licensed SDP loaded, build the fixture through `qcc` and explicit validated target flags | QNX compiler identity, target flags, artifact digest, captured command, verified bundle | `VERIFIED_REAL_QNX` only after target-specific proof; build alone does not prove execution | Critical blocker |
| C09 | Real QNX or QEMU execution | Run the captured QNX artifact in a genuinely supported target or QEMU | Runtime command, target identity, output, exit status, artifact association | Target execution only; no safety or coverage claim | After C08 |

## Required evidence per case

For each demonstrated case, record:

- the source commit and dirty/untracked state;
- the exact command vector, without reconstructing a shell string;
- the toolchain and target identity when applicable;
- stdout, stderr, exit status, signal, timeout, and truncation state;
- the artifact path, role, size, and SHA-256 digest;
- the bundle digest and independent verifier output;
- what the case proves;
- what it explicitly does not prove.

The UI should render these as a timeline or evidence card, not as one generic
green score. The minimum useful visual states are `PASS`, `WARN`, `FAIL`,
`BLOCKED`, `NOT_RUN`, and `CONTRACT_TEST_ONLY`.

## Real data policy

Use real project files, real compilers, real test commands, real reports, and
real process failures wherever the product claim depends on them. The following
are acceptable adversarial tests because they start from real evidence and
operate on disposable copies:

- flipping one artifact or log byte;
- editing a manifest without resealing;
- deleting a referenced blob;
- planting a symlink or unexpected file;
- using an incorrect trust root;
- supplying malformed or oversized reports to the parser.

The following are not acceptable as product evidence:

- a hand-written transcript presented as a run;
- a host binary labeled as a QNX binary;
- a fake `qcc` result labeled `VERIFIED_REAL_QNX`;
- a generated success report with no real test process behind it;
- a mock bundle used to demonstrate the normal happy path.

The repository's fake `qcc` harness remains useful as
`CONTRACT_TEST_ONLY`: it checks argument formation and target-claim boundaries,
but it is not evidence that the QNX SDP works.

## Demonstration order

1. C01: real host build and offline verification.
2. C03: real failing test preserved as evidence.
3. C05: mutate the real bundle and show the verifier reject it.
4. C06: show integrity, signature, trust, and execution claims separately.
5. C08: build the fixture with the real QNX SDP.
6. C09: execute it on a real target or supported QEMU environment, if available.

If the QNX environment remains unavailable, stop at C06 and present the QNX
cases as explicitly `BLOCKED` rather than filling the gap with synthetic data.

## Definition of done

The host demonstration phase is complete when every `Must have` case through
C06 has a reproducible command and a real bundle, and every unavailable claim
is visible as a bounded state. The QNX phase is complete only after C08 has
been attempted with the licensed SDP; C09 is an additional target-execution
milestone, not a prerequisite for the host evidence product. The plan does not
require a large UI: one readable case selector, an evidence timeline, and a
verifier result are enough to make the mechanism understandable.
