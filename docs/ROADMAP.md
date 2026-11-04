# Roadmap — Construction Levels

FUNES THE MEMORIOUS — Linux-hosted build/test provenance for QNX 8.0, in C.
Competition: QNX Global Hackathon 2026, Developer Tooling & Host Tools.

This roadmap is a construction program, not a wishlist. Each level states a
problem, concrete deliverables, threats addressed, tests, and entry/exit
criteria. A level is `DONE` only when its exit criteria are met and the
"Evidence" field links observed commands, logs, or artifacts. A document
existing is never, by itself, evidence that a level is done.

Live status summary:

| Level | Name | Status |
|---|---|---|
| 0 | Foundations and Invariants | DONE |
| 1 | Real Host Capture and Independent Verification | DONE (VERIFIED_HOST_ONLY) |
| 2 | Genuine QNX SDP 8.0 Build Integration | BLOCKED |
| 3 | Authenticated Provenance and Trust Policies | DONE (VERIFIED_HOST_ONLY) |
| 4 | Test Evidence and QNX Runtime | NOT_STARTED |
| 5 | Forensic Comparison and Audit UX | DONE (VERIFIED_HOST_ONLY) |
| 6 | Security, Performance, Portability and Release | NOT_STARTED |
| 7 | Hackathon Jury Experience | NOT_STARTED |

Status vocabulary: `DONE`, `PARTIAL`, `BLOCKED`, `NOT_STARTED`, plus the
execution taxonomy `VERIFIED_REAL_QNX`, `VERIFIED_HOST_ONLY`,
`CONTRACT_TEST_ONLY`, `NOT_RUN`, `FAILED` for individual exercises.

---

## Level 0 — Foundations and Invariants

**Problem.** Without fixed invariants, a provenance tool drifts into
overclaiming: hashes get described as trust, imported reports get described
as observed runs, and Linux output gets described as QNX evidence. Level 0
fixes the language, the trust model, and the repository discipline before
code exists, so later levels can be judged against them.

**Deliverables.**

- Owner skills inspection recorded in `docs/engineering/SKILLS-APPLIED.md`.
- `README.md` (English, primary) with Mermaid architecture and lifecycle
  diagrams, plus `README_ES.md` adaptation.
- This roadmap with per-level exit criteria.
- `.gitignore` covering C build outputs, evidence bundles, signing keys,
  QNX SDK material, and test/fuzz artifacts.
- MIT `LICENSE`; no proprietary QNX content in the repository.
- `docs/architecture/ADR-001-LANGUAGE-AND-TARGETS.md`: language decision
  (owner-directed C), comparison against Go/Rust/C++/TypeScript/Python,
  Go/QNX target nuance, compiler roles, risks. **Pending.**
- `docs/architecture/ARCHITECTURE.md`: components, trust boundaries,
  invariants. **Done in founding commit (design only).**
- `docs/spec/EVIDENCE-BUNDLE-v1.md`: bundle schema, canonical bytes,
  hashing rules, versioning. **Pending.**
- `docs/security/THREAT-MODEL.md`: assets, adversaries, boundaries,
  mitigations, out-of-scope guarantees. **Pending.**
- CI workflow (host-only build/lint/test placeholder that fails closed
  until Level 1 commands exist), formatting and lint configuration for C.
  **Pending.**

**Artifacts.** The files above; git history whose first commit is the README
and this roadmap.

**Threats addressed.** Evidentiary overclaiming; license contamination;
accidental commitment of keys, SDK content, or generated evidence.

**Dependencies.** None, besides Git and a text editor.

**Tests.** Documentation checks: internal links resolve; Mermaid blocks
parse; no command in the README is presented as tested unless it was run;
`git status` clean after the founding commit.

**Entry criteria.** Owner proposal received; language directed (C);
repository remote identified (`annatchijova/funes-the-memorious`).

**Exit criteria.**

- A reviewer can state exactly what will be built, in which language, under
  which trust assumptions, and how claims will be verified.
- ADR-001, bundle spec skeleton, and threat model exist and are consistent
  with the README invariants.
- CI runs on GitHub for the host-only checks that exist.

**Observable demo.** Reading the README and this file; no executable demo
is claimed at this level.

**Status: DONE.** Evidence: founding commit (`README.md`, `README_ES.md`,
roadmap, skills record, `.gitignore`, `LICENSE`) plus this level's closure —
`docs/architecture/ADR-001-LANGUAGE-AND-TARGETS.md`,
`docs/spec/EVIDENCE-BUNDLE-v1.md`, `docs/spec/VERIFIER-SEMANTICS.md`,
`docs/security/THREAT-MODEL.md`, `docs/QNX-SETUP.md`, and host-only CI in
`.github/workflows/ci.yml`. README invariants and the specs agree; CI runs
the same `make` / `make test` verified locally (see `docs/STATUS.md`).

**Non-goals.** Any collector, verifier, or QNX behavior. Any screenshot,
badge, or performance number.

---

## Level 1 — Real Host Capture and Independent Verification

**Problem.** A build/test claim needs firsthand, checkable evidence on the
machine where development actually happens, before QNX enters the picture.

**Deliverables.**

- `funes` collector in C: `doctor` (host subset), `build`/`test` supervised
  execution (explicit argv, working directory, timeout, bounded
  stdout/stderr, exit status, wall-clock + monotonic timing), source-state
  capture (Git commit, dirty state, content digest over an explicit source
  set excluding the evidence output), artifact hashing (SHA-256) with roles,
  environment allowlist with redaction, truncation flags.
- Evidence bundle v1 implementation per `docs/spec/EVIDENCE-BUNDLE-v1.md`:
  canonical manifest, content-addressed blobs, origin labels
  (`OBSERVED`/`IMPORTED`/`ASSERTED`/`INFERRED`/`VERIFIED`).
- `funes-verify` in C as a genuinely separate implementation of the format:
  own parsing, bounds checks, hash recomputation, fielded JSON + human
  diagnostics, documented exit codes. It must not link the collector's
  verification logic.
- `funes explain`-style human report (or verifier human mode) with separate
  `integrity_status`, `test_observation_status`, `artifact_status`, and
  `limitations` fields.
- Golden vectors: valid bundle, tampered bundle, internally consistent
  bundle whose test results are `IMPORTED` and must not verify as observed.

**Artifacts.** Both binaries; bundle spec; test suite; `docs/STATUS.md`
with the validation matrix filled from real runs.

**Threats addressed.** Command injection (argv-only execution), malicious
filenames, symlink/hardlink escapes, path traversal on bundle read,
hash/manifest substitution, truncated-log misrepresentation, secret leakage
via environment capture, dishonest imported reports.

**Dependencies.** Level 0 exit; host C compiler and `make`; SHA-256
implementation (small public-domain-style or OS-provided, decided in ADR).

**Tests.**

- Unit: digest, canonical serialization (including missing vs. empty vs.
  null vs. false vs. zero), exit-status handling, timeout, allowlist.
- Integration: real host compilation of a fixture, real passing test, real
  failing build, real failing test — failure evidence preserved.
- Adversarial: one flipped byte in binary/stdout/manifest, missing artifact,
  duplicate reference, path traversal (`../`, absolute, symlink escape),
  truncated blob, malformed JSON/UTF-8, oversized output, secret in
  environment, forged success output with non-zero exit.
- Independence: verifier test that does not import collector internals;
  determinism check — sealing the same capture twice yields identical
  manifest digests in fresh processes.

**Entry criteria.** Level 0 exit criteria met.

**Exit criteria.** On Linux, a real command and a real test are executed
under observation; the bundle verifies independently; a one-byte mutation
produces a non-zero, artifact-specific failure. All without any QNX SDK.

**Observable demo.** Host-only scenario, labeled `VERIFIED_HOST_ONLY`:
build fixture → test → seal → verify → mutate → verify fails. Scripted in
`docs/DEMO.md` and executed verbatim on the development host.

**Status: DONE (`VERIFIED_HOST_ONLY`).** Evidence: `make test` reports
`pass=41 fail=0` (see `docs/STATUS.md`), covering real gcc capture, observed
passing/failing tests, failing build, artifact/stdout/manifest tampering,
missing/unexpected/symlink material, resealed unsupported schema, imported
reports staying `IMPORTED_ONLY`, secret absence, truncation flags, digest
determinism, and verifier execution under an empty environment. Golden
vectors are produced by mutating a real captured bundle inside the suite
rather than shipped as static files; the `abc` SHA-256 vector anchors the
hash path. One scope note against the test list above: timeout behavior is
implemented (`--timeout-sec`, SIGKILL) but has no dedicated suite check yet;
it is carried as a Level 6 hardening item, not silently counted as covered.

**Non-goals.** QNX execution of any kind; signatures; UI.

---

## Level 2 — Genuine QNX SDP 8.0 Build Integration

**Problem.** The tool's QNX relevance must be demonstrated against the real
SDP, not against mocks or a compiler that happens to be named `qcc`.

**Deliverables.**

- `funes doctor` QNX subset: SDP discovery via `QNX_HOST`/`QNX_TARGET` and
  SDP environment scripts; `qcc`/`q++` execution with timeout and bounded
  output; identity, version, and supported-target capture; plain-English
  diagnostics for missing/misconfigured SDK.
- QNX build adapter: explicit target selection validated against the targets
  the installed `qcc` reports; preserved argument vector; toolchain and
  target metadata recorded in the bundle.
- Original fixture `examples/qnx8-hello/` (`main.c`, `Makefile`, `README.md`)
  with deterministic behavior and a deliberately failing variation.
- `docs/QNX-SETUP.md`: licensed SDP installation on a supported Linux host
  (isolated Ubuntu VM if the owner's Mint host is unsupported), exact
  validation commands, and expected outputs.

**Artifacts.** Real `qcc` logs, target binary hash, bundle containing QNX
toolchain evidence; setup guide.

**Threats addressed.** Toolchain path hijacking and `PATH` injection;
accepting an arbitrary `qcc` impostor; hard-coding an unsupported target;
presenting Linux output as a QNX binary.

**Dependencies.** Level 1 exit; user-installed, user-licensed QNX SDP 8.0.
Funes never installs the SDP or accepts its license.

**Tests.** Real SDP compilation (`VERIFIED_REAL_QNX`); absent-SDK diagnostic
path; malformed `QNX_HOST`/`QNX_TARGET`; unsupported target rejection;
`qcc` argument formation as `CONTRACT_TEST_ONLY` where the SDK is absent.

**Entry criteria.** Level 1 exit; SDP available on some host the owner
controls.

**Exit criteria.** A validated QNX target binary exists with compiler,
target, and flags provenance, captured by Funes and verified by
`funes-verify`. If the SDP remains unavailable, this level stays `BLOCKED`
indefinitely — it is never marked done from contract tests alone.

**Observable demo.** QNX build of the fixture with evidence, labeled with
the execution taxonomy; host-only path remains separately labeled.

**Status: BLOCKED.** Blocker: QNX SDP 8.0 is not installed on the founding
host (`qcc` absent; `QNX_HOST`/`QNX_TARGET` unset — observed at founding).
No QNX claim is made.

**Non-goals.** Running code on QNX hardware or QEMU (Level 4); supporting
SDP versions other than 8.0.

---

## Level 3 — Authenticated Provenance and Trust Policies

**Problem.** Integrity against a self-supplied manifest does not
authenticate origin: whoever rewrites the bundle can rewrite its hashes.

**Deliverables.**

- Optional Ed25519 signing of domain-separated, versioned canonical bytes
  (established primitives only; no custom cryptography).
- Key handling: private keys never enter bundles; unencrypted key storage
  only by explicit user decision with warning; malformed keys/signatures
  rejected.
- Verifier trust policy: signature checked only against reviewer-supplied
  trusted public keys; unknown signers reported `UNTRUSTED_SIGNER`;
  `INTEGRITY_VALID`, `AUTHENTICATED`, and `EXECUTION_VERIFIED` kept distinct.
- Trust documentation: rotation guidance, producer vs. third-party
  verification, and the statement that a valid signature proves key control,
  not that tests ran.

**Artifacts.** Signing/verification implementation; key-handling guide;
negative test corpus for trust substitution.

**Threats addressed.** Signature substitution, attacker-generated trust
roots, silent trust-root creation during verification, downgrade of missing
signatures into success.

**Dependencies.** Level 1 exit (Level 2 not required).

**Tests.** One substituted signature; one untrusted key; one modified signed
payload; key/signature malformation fuzz seeds; correctly sealed bundle
with a dishonest assertion — integrity may pass, the assertion must not be
promoted to verified execution.

**Entry criteria.** Level 1 exit; signing library choice recorded in an ADR.

**Exit criteria.** The independent verifier detects modified signatures and
untrusted keys, and its reports make no false authenticity statements.

**Observable demo.** Sign → verify authenticated; swap key → verify reports
untrusted; edit payload → signature invalid.

**Status: DONE (`VERIFIED_HOST_ONLY`).** Evidence: `make test` reports
`pass=61 fail=0` (see `docs/STATUS.md`): keygen (mode `0600`, overwrite
refused), signing, verification with and without a trust root, wrong-root
rejection (exit 9, `SIGNER_UNTRUSTED`), flipped signature byte and stale
manifest commitment (exit 8, `SIGNATURE_INVALID`), malformed seed refusal,
seed material absent from bundles, and JSON trust reporting. Design record:
`docs/architecture/ADR-002-SIGNING.md` (libsodium via runtime `dlopen`;
fixed Ed25519/`FUNES-SIGN-1` payload; no metadata-selected algorithm).
Accepted limitation carried forward: seed files are unencrypted at rest
(owner-managed, warned); key rotation is manual (new keypair, redistribute
the public half).

**Non-goals.** Transparency logs, timestamp authorities, or any hosted
trust service (externally anchored mode stays future work).

---

## Level 4 — Test Evidence and QNX Runtime

**Problem.** Build provenance alone does not show that tests ran against
the artifact in question, on the target that matters.

**Deliverables.**

- Controlled test invocation linked to a specific build and artifact digest;
  failed and incomplete runs preserved; expected-test omission detection
  where expectations are explicitly declared.
- Optional structured report adapters (JUnit XML, TAP, or JSON) with robust
  parsers and malicious-input tests, if practical; otherwise exit-code-only
  evidence labeled as such.
- Host-vs-target distinction enforced in every record; optional QEMU QNX
  runtime scenario capturing genuine target execution when available.

**Artifacts.** Test-evidence records correlated to artifact digests; parser
test corpus; QEMU run evidence where genuinely obtained.

**Threats addressed.** Laundering imported reports into observed facts;
test/artifact mismatch; forged success output; parser denial of service.

**Dependencies.** Levels 1 and 2 (QEMU parts also need a QNX image).

**Tests.** Passing/failing observed tests; missing-output handling;
malformed JUnit/TAP/JSON; report claiming tests for a different artifact
digest; QEMU run or explicit `NOT_RUN`.

**Entry criteria.** Level 2 exit for target claims; Level 1 exit for host
test-evidence claims.

**Exit criteria.** Real execution observations (where the environment
supports them) tie back to one specific QNX artifact, without implying
broader safety certification. Host-only parts exit as `VERIFIED_HOST_ONLY`.

**Observable demo.** Test run against the Level 2 fixture binary, including
one deliberately failing test whose evidence is preserved and verified.

**Status: NOT_STARTED.**

**Non-goals.** Coverage or safety guarantees from test counts; arbitrary
test-framework semantics.

---

## Level 5 — Forensic Comparison and Audit UX

**Problem.** Reviewers need to see what changed between two builds without
trusting the producer's summary of the difference.

**Deliverables.**

- Bundle comparison: source digest, toolchain, target, flags, artifacts,
  and test outcomes diffed field by field with evidence references.
- Human-readable audit narrative generated from verifier output only.
- Optional local read-only visual report consuming authoritative verifier
  JSON (with accessibility care if built).

**Artifacts.** Compare implementation; paired good/modified example bundles.

**Threats addressed.** Summary-level claim laundering; UI inventing results
the verifier did not produce.

**Dependencies.** Level 1 exit; Level 3 for signature-aware comparison.

**Tests.** Bundles differing in exactly one dimension each; narrative
fidelity checks against verifier JSON.

**Entry criteria.** Level 1 exit.

**Exit criteria.** A reviewer can reproduce and understand a material
difference between two bundles from the comparison output alone.

**Observable demo.** Compare the Level 1 good bundle against its mutated
twin; the diff names the changed artifact and digest.

**Status: DONE (`VERIFIED_HOST_ONLY`).** Evidence: `funes compare` verifies
both bundles with the sibling `funes-verify` before diffing (tampered input
exits 2 `INVALID_INPUT`), diffs material fields only (source, artifacts,
tests, argv set, QNX presence flags; timestamps/elapsed/paths ignored),
exits 0 identical / 10 different, and is covered in the 74-check suite (see
`docs/STATUS.md`). The optional visual report was not built; the human and
JSON diffs are the audit UX for this level. Hardened in the same round by
Red Team Round 1 (`docs/security/RED-TEAM-ROUND-1.md`).

**Non-goals.** Hosted dashboards; editing bundles from the UI.

---

## Level 6 — Security, Performance, Portability and Release

**Problem.** A verifier that parses untrusted bundles must survive hostile
input and be releasable with evidence, not adjectives.

**Deliverables.**

- Parser fuzzing (language-idiomatic harness; seed corpus from adversarial
  tests), resource budgets (size, depth, count limits) with
  `RESOURCE_LIMIT_EXCEEDED` behavior.
- Determinism and schema-compatibility checks across versions.
- CI on available hosts (host-only), formatting/lint gates, license and
  secret scanning, documentation smoke tests (README commands executed as
  written).
- Packaged release with checksums and a limitation matrix.

**Artifacts.** Fuzz corpus and findings log; release tarball + checksums;
`docs/STATUS.md` complete.

**Threats addressed.** Zip bombs and decompression abuse, parser DoS,
oversized metadata, invalid UTF-8/Unicode ambiguity, duplicate-entry
ambiguity, device-file and extraction escapes.

**Dependencies.** Levels 1–5 as applicable.

**Tests.** Fuzz runs with crash triage; budget-exceeded cases; clean-room
rebuild of the release; full adversarial suite green or explicitly waived
with reasons.

**Entry criteria.** Level 1 exit minimum.

**Exit criteria.** Verifiable release artifacts exist with a documented
limitation matrix; no known parser crash remains untriaged.

**Observable demo.** Fresh-clone build, test, and release verification from
the documented commands alone.

**Status: NOT_STARTED.**

**Non-goals.** Certifications; hosted release infrastructure.

---

## Level 7 — Hackathon Jury Experience

**Problem.** A judge must grasp the problem, reproduce the core workflow,
and inspect real evidence in minutes.

**Deliverables.**

- Reproducible under-three-minute demonstration (host path always available;
  QNX path only with real SDP evidence).
- Good bundle vs. modified bundle pair with a one-byte mutation script.
- README finalized with screenshots or terminal captures derived from
  actual runs only; Devpost submission text matching demonstrated behavior.
- Optional QNX codelab/tutorial, only if completed and competition-compliant.

**Artifacts.** `docs/DEMO.md` with truthful step-by-step commands; Devpost
text; final README.

**Threats addressed.** Demo-time overclaiming; synthetic material presented
as real (synthetic content, if any, stays under `examples/synthetic/` with
a SYNTHETIC banner).

**Dependencies.** Levels 1 and 6; Level 2 for any QNX demo claim.

**Tests.** A reviewer unfamiliar with the project follows `docs/DEMO.md`
unaided and reaches the mutation failure; timing observed, not asserted.

**Entry criteria.** Level 6 exit, or Level 1 exit plus explicit scoping of
the demo to host-only evidence.

**Exit criteria.** The judge path above succeeds end to end, and every QNX
statement in the submission traces to `VERIFIED_REAL_QNX` evidence or is
labeled otherwise.

**Observable demo.** The six-act story: claim → evidence → independent
verification → mutation → precise finding → stated boundary.

**Status: NOT_STARTED.**

**Non-goals.** Polished frontend, cloud infrastructure, blockchain, AI/ML
scoring, or any certification claim.
