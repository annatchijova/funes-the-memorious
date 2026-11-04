# Security Audit — FUNES (Levels 0/1/3/5)

## Red Team Round 1
**Date:** 2026-11-04  **Method:** Abductive Engineering (A-D-I) + Red-Team Auditing
**Scope:** collector, independent verifier, signing/trust, comparison. QNX out of scope (BLOCKED, no SDP).
**Base:** main @ 4e67987 plus uncommitted Level 5 work  **Reproducible evidence:** `tests/run_tests.sh` (RT regressions at the end of the suite); manual inductions run in `/tmp/rt` during the session.

## Threat model
- Attacker CAN: submit a malicious bundle to the verifier/comparison, modify a bundle after sealing, control filenames/environment (including `LD_LIBRARY_PATH`) of a capture/sign invocation, read all source.
- Attacker CANNOT: hold a trusted private signing key, modify the FUNES binaries or system libraries as root, compromise the kernel. Findings needing those are assumptions, not vulnerabilities.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Module | Finding |
|---|---|---|---|---|
| RT-01 | Low | CONFIRMED BY INDUCTION | verifier | Hidden dotfiles in `blobs/sha256/` evaded the unexpected-file check |
| RT-02 | Medium | CONFIRMED BY INDUCTION | verifier | A bundle made entirely of symlinks verified as valid |
| RT-03 | Medium | CONFIRMED BY INDUCTION | collector + verifier | Bare-name `dlopen("libsodium.so.23")` honored `LD_LIBRARY_PATH`; a fake library received signing key material |
| RT-04 | — | CONFIRMED (code) | verifier | Oversized blob files were fully streamed before the size check |
| RT-05 | Medium | CONFIRMED BY INDUCTION | collector | `funes sign` followed a pre-planted `signatures/ed25519.sig` symlink and overwrote its target (sibling sweep of RT-02) |
| RT-06 | Low | CONFIRMED BY INDUCTION | verifier | Unexpected files at the bundle root / in `signatures/` were ignored (sibling sweep of RT-01) |

All six were fixed in this round and re-induced: RT-01/RT-02/RT-06 now exit 2, RT-03's fake library receives nothing, RT-04 sizes come from `stat` before any streaming, RT-05 signing now refuses the symlink with the target byte-identical. Regression checks RT-01..RT-06 are in the suite. The sibling sweep behind RT-05/RT-06 also moved the `SEAL.txt` write to temp+rename like the manifest.

## Findings

### RT-01 — Hidden file in blob directory
**Severity:** Low  **Epistemic level:** CONFIRMED BY INDUCTION  **Bucket:** vulnerability
- Expectation violated: "unexpected material fails closed" did not hold for dotfiles.
- Abduction: the directory scan skipped every name starting with `.` (meant for `.`/`..`).
- Deduction: if true, adding `blobs/sha256/.hidden` still verifies with exit 0.
- Induction: observed exit 0 before the fix; exit 2 after. Prediction stated before each run.
- Fix: skip only the exact names `.` and `..`.

### RT-02 — Symlinked bundle structure
**Severity:** Medium  **Epistemic level:** CONFIRMED BY INDUCTION  **Bucket:** vulnerability
- Expectation violated: evidence must live in the bundle; only individual blobs were `lstat`-checked, while `manifest.txt`, `SEAL.txt` and the blob directories were followed.
- Induction: a bundle of three symlinks to a good bundle verified exit 0 before the fix; exit 2 after.
- Fix: `lstat` the manifest, seal, both blob directories, and `signer.txt`; symlinks and non-regular files are `BUNDLE_INVALID` / `SIGNATURE_INVALID`.

### RT-03 — Search-path libsodium receives key material
**Severity:** Medium  **Epistemic level:** CONFIRMED BY INDUCTION  **Bucket:** vulnerability (precondition: attacker influences the signing process environment)
- Expectation violated: the library that receives the seed must be the system libsodium (package `libsodium23`, verified on this host via the package owner of `/usr/lib/x86_64-linux-gnu/libsodium.so.23.3.0`).
- Causal chain: bare `dlopen` name → dynamic linker honors `LD_LIBRARY_PATH` → fake `crypto_sign_*` functions run inside the signing process → seed/secret-key bytes are written to the attacker's log.
- Induction: fake library logged 32 seed bytes and 64 secret-key bytes before the fix; received nothing after.
- Fix: try absolute system paths only (`/lib`, `/usr/lib`, `/usr/lib64`, `/usr/local/lib`); no bare-name fallback on either the key-handling or the trust-deciding path — fail closed instead.
- Residual: an attacker who can replace the system library itself is root-equivalent and out of scope. Library identity rests on the system package manager; no digest pinning (would break across distro builds).

### RT-04 — Unbounded streaming before size check
**Severity:** Low  **Epistemic level:** CONFIRMED (code fact; resource effect not separately measured)  **Bucket:** vulnerability
- The blob loop hashed the whole file and compared sizes afterwards, so an attacker-sized file was read in full. Fixed by comparing `stat` size to the recorded size before streaming.

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
|---|---|---|
| Duplicate field in `signer.txt` | FALSIFIED (safe) | The strict extractor rejects a second occurrence; verification exits 8 |
| Re-signing staleness after `add-test` | FALSIFIED (safe) | Manifest change invalidates the old signature; verifier reports `SIGNATURE_INVALID` |
| Signature replay onto a different bundle | Not exploitable as framed | The payload binds the manifest digest; a copied signature only validates for a byte-identical manifest, which is the same evidence |
| Trojanned sibling `funes-verify` next to `funes` (compare) | Threat-model assumption | Requires controlling the install directory, which already implies control of `funes` itself |
| Artifact TOCTOU between build and hashing | Accepted residual (threat model) | Disclosed in `docs/security/THREAT-MODEL.md`; sealed blobs are copies, so later mutation cannot alter evidence |

## Recommendations (recorded, not implemented in this round)
- Dedicated timeout regression in the suite (carried since Level 1; Level 6).
- Consider failing `funes sign` when the bundle already carries a signature from a different key, to make re-signing an explicit act.
