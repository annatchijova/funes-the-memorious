# Threat Model

Status: Level 0/1 scope. Language: English. This model governs the C
implementation in `src/funes.c` and `verifier/funes_verify.c`. Guarantees
beyond this scope are explicitly listed as out of scope, not implied.

## Assets

Source identity (Git head, dirty state, source digests), build metadata
(argv, exit status, timing), produced artifacts, evidence blobs, test
outputs, signing keys (Level 3; none exist in v1), trust roots (Level 3),
verifier decisions, and user secrets reachable via the environment or home
directory.

## Adversaries

- Honest developer making mistakes (wrong artifact path, stale bundle).
- Producer falsifying reports (hand-written manifest, forged stdout).
- Attacker modifying artifacts after collection.
- Malicious bundle submitted to the verifier (parser attack).
- Compromised compiler/build tool on the host.
- Compromised host administrator.
- Attacker exploiting pathname or parsing ambiguity.
- Someone laundering an imported report into an observed fact.

## Trust boundaries

Host <-> QNX SDK; collector <-> subprocess; Git metadata <-> filesystem;
producer <-> bundle; bundle <-> independent verifier; signature <-> trust
root (Level 3); host observation <-> target execution (Level 2/4); user
interface <-> authoritative verifier result (Level 5).

## Threats and mitigations (implemented in v1 unless marked)

- **Hash/manifest substitution.** All blobs rewritten together with manifest
  and seal still verifies. Mitigation in v1: none beyond internal
  consistency, and the verifier says so (`signature_status=NOT_PRESENT`).
  Real mitigation is Level 3 (signatures with reviewer-supplied trust roots)
  or an externally stored digest. Never described as prevented in v1.
- **Build tool path hijacking / `PATH` injection.** The collector execs the
  argv the user supplied via `execvp` and records argv verbatim (hex). It
  does not construct shell strings. Residual risk: a hijacked `PATH` makes
  the user invoke the wrong tool; recording makes that visible, not
  impossible. Doctor reports `qcc` found on `PATH` as unverified identity.
- **Supply-chain poisoning of Funes itself.** Mitigated by small C surface,
  no third-party dependencies in v1 (SHA-256 is in-tree and test-vector
  checked), and reproducible `make` builds. Pinned dependency policy applies
  from the first external dependency (Level 3 crypto).
- **Symlink/hardlink escape.** Collector follows the artifact path the user
  explicitly named (that is the user's own file), but the verifier refuses
  symlink blobs (`lstat`) and constructs blob paths only from validated hex
  digests inside the bundle. Hardlinked blobs inside a bundle are
  indistinguishable from copies; content hashing makes the link irrelevant
  to integrity.
- **TOCTOU between hashing and use.** The collector hashes artifact bytes
  and copies them into the bundle as blobs; verification later hashes the
  copies, so a race on the original artifact cannot change sealed evidence —
  but an artifact swapped between build and hashing would be sealed as-is.
  That residual race is disclosed: capture promptly, ideally build to a
  fresh output path.
- **Overlong logs / resource exhaustion.** Captured stdout/stderr are capped
  (1 MiB stored per stream in v1) with truncation flags; the collector keeps
  draining the pipe so the child cannot deadlock. The verifier enforces
  manifest (1 MiB, 10000 lines, 8192/line), blob (64 MiB), and count limits
  with `RESOURCE_LIMIT_EXCEEDED`.
- **Invalid UTF-8 / Unicode ambiguity.** User-controlled strings are stored
  hex-encoded; the manifest grammar is ASCII. No normalization is ever
  applied to evidence bytes.
- **Oversized metadata / parser DoS.** Strict line grammar, unique keys,
  contiguous indices, value range checks, fail-closed unknown keys. Fuzzing
  is Level 6; v1 ships adversarial unit cases for the known classes.
- **Forged Git source identity.** Recorded as observed `git` output plus a
  content digest over an explicit source set. A forged `.git` can still lie
  about history; the content digest bounds what the bundle claims to the
  hashed files themselves.
- **Skewed/fabricated timestamps.** Wall-clock `started_unix` is labeled as
  collector-clock evidence; elapsed time uses a monotonic clock. Neither is
  presented as trusted time.
- **Attacker-generated signing keys.** Level 3 concern; v1 has no signatures
  and reports `NOT_PRESENT` so there is nothing to confuse.
- **Bad test assertions / forged success output.** A test that prints
  "PASS" and exits 1 is recorded with exit status 1. Interpretation of test
  semantics stays with the reviewer; only exit status and output are
  observed in v1.
- **Privileged execution and secret leakage.** The collector runs with the
  user's privileges and never elevates. Environment capture is an allowlist
  of presence booleans plus OS/arch; no variable values, tokens, or home
  contents are read into the bundle.
- **Evidentiary overclaiming.** Separate status fields, fixed limitation
  statements, origin labels that tools never promote, and README/roadmap
  wording reviewed against this model.

## Out of scope (explicit non-guarantees)

- Proving the collecting host was honest. A software-only collector on an
  untrusted host cannot do this; neither can v1 signatures alone (Level 3
  proves key control, not honest observation).
- Software safety, test adequacy, or build reproducibility.
- Confidentiality of bundle contents (bundles are evidence to share; keep
  private bundles private by filesystem means).
- Availability of the QNX SDP, QEMU, or any network service. Basic
  verification needs none of them.
