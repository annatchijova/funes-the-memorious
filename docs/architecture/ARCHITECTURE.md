# Technical README — Architecture

Status: Levels 0-1 implemented on the Linux host; QNX parts remain design
until Level 2. Implemented state is tracked in `docs/ROADMAP.md` and
`docs/STATUS.md`; where this document and observed status disagree, the
observed status wins.

Language of this document: English.

## System in one paragraph

Funes is two C programs for a Linux host plus a C fixture for QNX targets.
`funes` (collector) executes build/test commands under observation and seals
a versioned evidence bundle. `funes-verify` (independent verifier) checks a
bundle offline and read-only, implementing the public format itself rather
than calling the collector's verification logic. The bundle format is the
contract; the collector is replaceable, the verifier must not have to trust it.

## Components

| Component | Language | Runs on | Responsibility |
|---|---|---|---|
| `funes` collector | C11 | Linux host | Environment inspection, supervised execution, source/artifact hashing, bundle sealing, optional signing |
| `funes-verify` verifier | C11 | Linux host (any offline machine) | Independent parsing, bounds checks, hash recomputation, optional signature checks, diagnostics |
| QNX fixture | C | QNX target (built via `qcc`) | Small deterministic program whose build/test is the evidence subject |
| Bundle format spec | Markdown + golden vectors | — | Canonical bytes, hashing/signing rules, versioning policy |

## Why C

See `ADR-001-LANGUAGE-AND-TARGETS.md`. Summary of the decision
recorded there: the owner directed C; independently, C fits because (a) the
verifier should be a small, auditable binary with no language-runtime
dependency, (b) the QNX fixture and any future on-target-adjacent code share
the language and toolchain model, and (c) process supervision, hashing, and
canonical serialization are all expressible with a small dependency surface.
The costs — manual memory management and a higher burden of parser hardening
and fuzzing — are accepted explicitly and addressed in Levels 1 and 6.

## Trust boundaries

- Host operating system and its administrator: trusted to run the collector
  at all; a compromised host can fabricate observations. Funes does not claim
  to detect a dishonest host. It makes the resulting evidence checkable for
  internal consistency and later tampering.
- Collector <-> subprocess: the collector controls argv, working directory,
  timeout, and output bounds; subprocess output is data, never instructions.
- Git metadata <-> filesystem: a commit hash does not identify untracked or
  modified files; source provenance therefore uses a content digest over an
  explicit source set in addition to Git state.
- Producer <-> bundle <-> verifier: the bundle is untrusted input to the
  verifier. All paths, lengths, and nesting are validated before use.
- Signature <-> trust root: verification only authenticates against a public
  key the reviewer explicitly supplies. Unknown keys are `UNTRUSTED_SIGNER`.

## Invariants

1. Canonical serialization is single-sourced, typed, and versioned; the same
   logical manifest always produces identical bytes.
2. Hashes are SHA-256 over raw bytes with domain separation where a digest
   could otherwise be confused across roles.
3. Missing, empty, null, false, zero, and omitted are distinct states in the
   format and in diagnostics.
4. Evidence origin is labeled per record: `OBSERVED`, `IMPORTED`, `ASSERTED`,
   `INFERRED`, `VERIFIED` (only where independently justified). Labels are
   never promoted in transit.
5. The verifier fails closed on unsupported schema versions or algorithms.
6. No private key is ever stored in a bundle. No absolute private host path
   is required in a portable bundle.

## Data flow

1. Inspect: host OS/arch, compiler, `qcc` presence and identity, `QNX_HOST` /
   `QNX_TARGET`, QEMU presence. Secrets and unrelated environment values are
   never captured; only an allowlist is recorded.
2. Execute: explicit executable plus argument vector (no shell string by
   default), bounded stdout/stderr, timeout, exit status, wall-clock
   timestamps plus monotonic elapsed time.
3. Collect: source digest, artifact hashes with roles, test records linked
   to artifact digests. Failed builds and failed tests are preserved as
   evidence, not discarded.
4. Seal: canonical manifest referencing content-addressed blobs; optional
   Ed25519 signature over domain-separated canonical bytes.
5. Verify: independent re-parse, bounds checks, hash recomputation, optional
   signature verification against a caller-supplied trust root, fielded
   report (`integrity_status`, `signature_status`, `signer_trust_status`,
   `test_observation_status`, `artifact_status`, `limitations`, ...).

## Non-goals

- Certifying software safety or correctness.
- Proving the host was honest during collection.
- Reproducible builds (Funes records provenance; it does not make builds
  reproducible).
- Hosted services, dashboards that invent results, or any AI-derived verdict
  in the verification path.

## Open decisions

- Directory bundle vs. single-file archive for v1 (decided in the bundle spec,
  Level 0/1).
- Signing library selection, if Ed25519 is implemented in Level 3.
- JUnit/TAP/JSON test-report adapters (optional, Level 4).
