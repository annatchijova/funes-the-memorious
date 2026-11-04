# Limitations

A short, plain-language answer to one question: when `funes-verify` reports
`integrity_status=INTEGRITY_VALID` (optionally with `signer_trust_status=
TRUSTED_SIGNER`), what does that actually prove, and what does it not?

For the detailed, per-check engineering log, see `docs/STATUS.md`. This
document is the short version for a reader meeting the project for the
first time.

## What a verified bundle proves

- **The recorded bytes are internally consistent.** Every artifact,
  stdout/stderr blob, and test-report blob hashes to exactly the digest the
  manifest claims, and the manifest hashes to exactly what `SEAL.txt`
  commits to. If any byte anywhere in the bundle changed after sealing, the
  verifier reports a specific failure (`DIGEST_MISMATCH`, `SEAL_MISMATCH`,
  `MISSING_ARTIFACT`) naming exactly what changed, not a generic "invalid".
- **A failing build or test is preserved, not hidden.** A bundle recording
  a crashed build or a failing test still verifies as integrity-valid; the
  real exit status and signal are part of the sealed evidence.
- **With a signature and a matching `--trusted-key`** (Level 3,
  `signer_trust_status=TRUSTED_SIGNER`): the bundle's content has not
  changed since it was signed by the holder of that specific private key.
  That is all a signature proves — control of a key over these exact
  bytes, nothing about who that key's holder is or whether they are
  trustworthy. Trust is established entirely by the reviewer supplying the
  right public key; `funes-verify` invents no trust roots.
- **A declared set of expected test names was actually present** (Level 4,
  `expect-tests`/`MISSING_EXPECTED_TEST`) — by name, not by origin (see
  below).

## What it explicitly does NOT prove

- **That the software is safe, correct, or free of defects.** Passing
  tests are evidence those specific tests passed, nothing more. FUNES
  makes no safety or correctness claim of any kind, at any level.
- **That a test was genuinely executed, from the omission check alone.**
  `expect-tests` detects a *missing named record*; it does not check
  `test.<n>.origin`. A name can be satisfied by a real executed test
  (`OBSERVED`) or by an `import-test` that ran nothing at all (`IMPORTED`,
  self-asserted). The verifier reports `test_observation_status` as a
  separate, un-collapsed field specifically so this distinction is never
  hidden behind a single pass/fail — a reviewer who needs the stronger
  "this really ran" guarantee must check that field too, not just the
  omission result (Red Team Round 2, RT2-01).
- **That the host was honest.** Integrity (Level 1) is not authenticity
  (Level 3) is not proof of execution. A compromised build host could, in
  principle, still produce a bundle that verifies — it would need to
  control the recorded bytes consistently, which is a real, not free,
  constraint, but not one `funes-verify` rules out on its own.
- **Anything about QNX.** `qnx_toolchain_status` reports what the manifest
  recorded about `QNX_HOST`/`QNX_TARGET` *presence flags* — it is not a QNX
  build verification. No `VERIFIED_REAL_QNX` claim exists anywhere in this
  codebase; Level 2 (genuine QNX SDP integration) is `BLOCKED` without a
  licensed SDP, and stays `BLOCKED` rather than being approximated.
- **That the comparison between two bundles is exhaustive.** `funes
  compare` diffs the fields this project considers material (source,
  artifacts, tests, argv, QNX presence flags); timestamps and paths are
  deliberately excluded as noise, not as a completeness claim about every
  possible difference.
- **Anything about resource budgets beyond "within the stated caps".**
  Every size/count/depth limit in `docs/security/RESOURCE-LIMITS.md` is a
  stated, bounded guarantee (checked by a dedicated regression per limit),
  not a claim that no larger input could ever matter.

## The honest floor

Two facts underlie everything above and are worth stating once, plainly,
rather than leaving them implicit:

1. **A hash proves integrity, not truth.** It certifies that bytes did not
   change after being sealed. It says nothing about whether the sealed
   claim was ever accurate in the first place.
2. **A signature proves key control, not correctness.** It certifies that
   whoever holds a specific private key approved these exact bytes. It
   says nothing about whether that approval was well-founded.

Every report `funes-verify` produces carries a fixed `limitations=` line
restating this boundary, and the project's own semantics document
(`docs/spec/VERIFIER-SEMANTICS.md`, "What success does not mean") states it
in full. This document exists so a reader does not have to go find that.

## Current blockers (not limitations of the design — of the environment)

- **Level 2 (genuine QNX SDP 8.0 build integration) is `BLOCKED`**: no
  licensed QNX SDP is installed on the development host. See
  `docs/QNX-SETUP.md`. Everything downstream of it that depends on real
  QNX execution (part of Level 4, the QEMU runtime scenario) inherits that
  block and is `NOT_RUN`, not simulated or approximated.
