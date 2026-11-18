# Security Audit — FUNES (Levels 0/1/3/4-host/5/6, host-only)

## Red Team Round 4
**Date:** 2026-11-18  **Method:** Abductive Engineering (A–D–I) + Red-Team Auditing (Round 3 — invariants & emergent/architectural composition)
**Scope:** collector, independent verifier, signing/trust (host-only C code). QNX out of scope (Level 2 BLOCKED, no SDP).
**Base:** branch `qnx-hackathon-submission` @ `49264cc189bda9c580581c8b7201750d76cb5673`
**Reproducible evidence:** manual inductions below; regression checks appended to `tests/run_tests.sh`.

## Threat model
- Attacker CAN: submit a malicious bundle to the verifier/comparison, modify a bundle after sealing (if they hold write access to the bundle dir), control filenames/environment of a capture/sign invocation, read all source, export arbitrary environment variables before capture.
- Attacker CANNOT: hold a trusted private signing key they did not generate, modify the FUNES binaries or system libraries as root, compromise the kernel, produce a genuine QNX 8.0 target binary without the QNX SDP.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Module | Finding |
|----|----------|-------|--------|---------|
| RT4-01 | Medium | CONFIRMED BY INDUCTION | collector / signing | `funes sign` silently overwrites pre-existing signature material (`ed25519.sig`, `signer.txt`) with `O_TRUNC`; no check that the bundle already carries a signature from another key. Re-signing with a different key makes that key `TRUSTED_SIGNER` and invalidates the prior one without warning. |
| RT4-02 | Medium | CONFIRMED BY INDUCTION | collector | `qnx.host_present` / `qnx.target_present` are set solely from `getenv("QNX_HOST")` / `getenv("QNX_TARGET")`. With no QNX SDP installed (`qcc` absent), exporting `QNX_HOST=1 QNX_TARGET=1` yields a sealed bundle with `qnx.host_present=1`, `qnx.target_present=1`, `qnx_toolchain_status=RECORDED_PRESENT_FLAGS`, accepted by `funes-verify` exit 0 — QNX evidence fabricated without QNX. |

## Findings

### RT4-01 — Silent re-signing overwrites prior signature material
**Severity:** Medium  **Epistemic level:** CONFIRMED BY INDUCTION  **Bucket:** vulnerability (architecture / chain of custody)

- **Surprise / expectation violated:** A sealed bundle's signature material can be replaced silently; `sign` does not refuse when `signatures/` already contains material from a different key.
- **Abduction:** `cmd_sign` (`src/funes.c:641`) calls `mkdir(signatures, 0755)` (ignores `EEXIST`), then opens `ed25519.sig` and `signer.txt` with `O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW` via `openat` on the directory fd. There is no read of existing `signer.txt` fingerprint, no comparison against a prior key, no "already signed" refusal.
- **Deduction (prediction stated before the run):** Sign with key A → verify with A reports `TRUSTED_SIGNER`. Sign again with key B over the same bundle → verify with B reports `TRUSTED_SIGNER`, verify with A reports `SIGNER_UNTRUSTED` (exit 9).
- **Induction (executed):** Ran the exact sequence against the real `bin/funes` / `bin/funes-verify` built from `49264cc`. Result matched the prediction exactly: key B became `TRUSTED_SIGNER`; key A was rejected as `SIGNER_UNTRUSTED`. No warning, no exit error on the second `sign`.
- **Causal chain:** `sign` → `openat(sdirfd, "ed25519.sig", O_TRUNC)` truncates prior signature → new key material written → `signer.txt` rewritten with new fingerprint → verifier authenticates under the last-writer key. The bundle's manifest digest is unchanged (only signatures/ changed), so integrity holds but custody attribution flips to the last signer.
- **Threat-model precondition:** Attacker needs write access to the bundle directory between two `sign` invocations (or the ability to make a user re-sign). Not a remote exploit; a chain-of-custody hygiene defect.
- **Variant sweep:** Checked every other mutating command for the same "overwrite without state check" pattern:
  - `seal_bundle` (manifest + SEAL): temp+rename, no blind truncate of prior seal material — safe.
  - `store_blob_file` / `store_blob_mem`: `access(F_OK)==0` returns early if blob already exists — idempotent by content, safe.
  - `expect-tests`: `ll_has_prefix("expected_test_count=")` refuses re-declaration — safe.
  - `add-test` / `import-test`: reseal after adding records; do not touch `signatures/` — safe.
  Only `cmd_sign` truncates blindly.
- **Bypass the fix:** If the fix is "refuse `sign` when `signatures/` already exists", an attacker could `rm -rf signatures/` before re-signing — but that breaks `SEAL.txt` unless they reseal, which requires recomputing the manifest hash (they can, since they control the bundle). The stronger fix: `sign` must record that re-signing occurred, or refuse unless an explicit `--force` is given, and `verify` must report a re-signal when signature material was replaced after sealing. Out of scope for this round; recorded as a recommendation.
- **Blast radius:** Any workflow where a bundle is signed and later re-signed (key rotation, CI re-signing, multiple maintainers). For the QNX hackathon submission, this affects the `funes sign` step in the reviewer workflow (`funes keygen → sign → verify --trusted-key`).

### RT4-02 — QNX presence flags fabricable from environment alone
**Severity:** Medium  **Epistemic level:** CONFIRMED BY INDUCTION  **Bucket:** vulnerability (evidence overclaiming / architecture)

- **Surprise / expectation violated:** A bundle can assert `qnx.host_present=1` and `qnx.target_present=1` — and `funes-verify` accepts it — without any QNX SDP, without `qcc`, and without any QNX compilation or execution having occurred.
- **Abduction:** `cmd_capture` (`src/funes.c:853-854`) writes `qnx.host_present=%d` / `qnx.target_present=%d` from `getenv("QNX_HOST")` / `getenv("QNX_TARGET")`. These are mere environment-variable presence checks, not evidence of a QNX toolchain, a compiled QNX binary, or target execution. `funes doctor` separately confirms `qcc_found=false` and `qnx_toolchain_status=NOT_FOUND` on this host.
- **Deduction (prediction stated before the run):** Export `QNX_HOST=1 QNX_TARGET=1`, run `capture` with no QNX SDP → manifest contains `qnx.host_present=1`, `qnx.target_present=1` → `funes-verify` exits 0 with `qnx_toolchain_status=RECORDED_PRESENT_FLAGS`.
- **Induction (executed):** Ran the exact sequence against the real binaries built from `49264cc`. Result matched the prediction exactly: manifest shows both flags at 1, verifier exits 0 with `RECORDED_PRESENT_FLAGS`, while `doctor --json` honestly reports `qcc_found=false` and `qnx_toolchain_status=NOT_FOUND`. The bundle and the doctor disagree — the bundle claims QNX presence that the host cannot substantiate.
- **Causal chain:** env var set → `capture` writes flag=1 → manifest sealed → verifier checks key presence/value only (not provenance) → bundle accepted as "QNX present". The threat model's rule "presenting Linux output as QNX evidence" is violated at the flag level, not the binary level.
- **Threat-model precondition:** Attacker controls the environment of the `capture` invocation (or the user innocently exports QNX vars hoping to "enable" QNX mode). No QNX SDP needed.
- **Variant sweep:** Checked every other place that asserts QNX in sealed evidence:
  - `funes doctor`: reports `qnx_toolchain_status` from `getenv` + PATH search for `qcc`; does not seal anything — informative only, not evidence.
  - `cmd_add_test` / `cmd_import-test`: write `test.N.runtime=host` (the only real value today); no QNX target runtime path exists.
  Only `cmd_capture` writes `qnx.*_present` into sealed manifest.
- **Bypass the fix:** If the fix is "require `qcc` in PATH before setting `qnx.target_present=1`", an attacker could plant a fake `qcc` earlier in PATH. The robust fix: do not record `qnx.target_present=1` unless a genuine QNX target artifact hash exists in the bundle (Level 2 dependency). Until Level 2 is unblocked, `qnx.target_present` should remain `0` and `qnx.host_present` should reflect only an actual SDP discovery, not a bare env var.
- **Blast radius:** Directly affects the QNX Global Hackathon submission criteria ("genuinely builds for or runs on QNX 8.0, not merely that QNX 8.0 is named in the README"). A bundle with fabricated QNX flags would fail the "genuine QNX build/run" requirement if presented as QNX evidence.

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
|--------|--------|---------------|
| Duplicate manifest key via `--source` path | FALSIFIED | Paths are hex-encoded before manifest insertion; no newline/injection possible |
| `expect-tests` re-declaration bypass | FALSIFIED (Round 2, RT2-01 follow-up) | `ll_has_prefix("expected_test_count=")` refuses re-declaration; collector exits non-zero |
| Artifact symlink escape at capture input | FALSIFIED | `stat()` follows symlinks at input; the blob stored is the resolved target's content, not a symlink; verifier checks the in-bundle blob is a regular file |
| `store_blob_file` TOCTOU (access→fopen) | Not exploitable in single-process threat model | Requires concurrent writer to the bundle dir between check and write; out of scope |

## Recommendations (recorded, not implemented in this round)

1. **RT4-01:** Make `sign` refuse to overwrite existing signature material unless an explicit `--force` is passed; document re-signing as an explicit act that invalidates prior custody. Consider having `verify` report when signature material was replaced after sealing.
2. **RT4-02:** Until Level 2 (QNX SDP 8.0) is unblocked, keep `qnx.target_present=0` in all captured bundles and derive `qnx.host_present` from actual SDP discovery (`qcc` found + version), not from a bare `getenv`. Do not let `QNX_HOST`/`QNX_TARGET` env vars alone fabricate QNX presence in sealed evidence.
3. Add regression tests for both findings to `tests/run_tests.sh` (appended below).

## Regression checks added to `tests/run_tests.sh`

- RT4-01: sign with key A → verify A TRUSTED; sign with key B → verify B TRUSTED, verify A SIGNER_UNTRUSTED (exit 9).
- RT4-02: capture with `QNX_HOST=1 QNX_TARGET=1` → manifest flags at 1 → verify exit 0 with `RECORDED_PRESENT_FLAGS` → doctor reports `qcc_found=false`.
