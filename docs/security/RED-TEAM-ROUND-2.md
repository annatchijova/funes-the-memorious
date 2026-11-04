# Security Audit — FUNES (Level 4 host-only additions)

## Red Team Round 2
**Date:** 2026-11-04  **Method:** Abductive Engineering (A-D-I) + Red-Team Auditing
**Scope:** `test.<n>.runtime` field and its enforcement, `test.<n>.name.hex`, `funes expect-tests`
and the `MISSING_EXPECTED_TEST` omission check, the JSON test-report adapter
(`import-test --format json`, `src/json_min.c`). Out of scope: RT-01..RT-06 and the
RT-02 follow-up (Round 1, already closed); anything QNX/QEMU-related (not implemented).
**Base:** main @ `d597a3f` (Level 4 host-only, schema v2)  **Reproducible evidence:**
manual inductions run in a scratch `/tmp/tmp.95QdVbgXno` directory during this session,
using the real `bin/funes` / `bin/funes-verify` built from this commit.

## Threat model
- Attacker CAN: submit a malicious bundle to the verifier, modify a bundle after sealing,
  control the content of an imported test-report file, control CLI arguments to the
  collector (names, report paths), read all source.
- Attacker CANNOT: hold a trusted private signing key, modify the FUNES binaries or
  system libraries as root, compromise the kernel.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary

| ID | Severity | Level | Module | Finding |
|---|---|---|---|---|
| RT2-01 | Low | CONFIRMED BY INDUCTION | verifier | `expect-tests` declarations can be satisfied entirely by self-asserted `import-test` records, with no execution ever occurring — **documented** (not code-fixed; see Findings) |
| RT2-02 | — | FALSIFIED | collector | A ~900 KB number literal, or an oversized report file, is not an exploitable JSON-parser DoS — both rejected in ~1-2 ms |
| RT2-03 | — | CONFIRMED BY INDUCTION (positive result) | verifier | A signature correctly goes `SIGNATURE_INVALID` after a Level 4 field (`add-test`) is added to an already-signed bundle |
| RT2-04 | Low | CONFIRMED BY INDUCTION | verifier | A genuinely signed, trusted bundle that fails `MISSING_EXPECTED_TEST` is reported as `signature_status=NOT_PRESENT` — misleading, but a pre-existing pattern across every early-exit check, not introduced by Level 4 — **fixed** (see Findings) |
| RT2-05 | — | FALSIFIED | verifier | Buffer truncation of long `*.name.hex` values cannot produce a name collision; the manifest line-length cap rejects the line outright first |
| RT2-06 | — | FALSIFIED | collector | A `cases[]` array with a malformed entry cannot produce a `report_case_count` that disagrees with what was actually accepted — parsing is all-or-nothing |
| RT2-07 | — | FALSIFIED | collector | Control bytes, `=`, embedded newline in an `expect-tests` name cannot inject into the manifest; hex-encoding neutralizes all of it |

## Findings

### RT2-01 — Omission detection is origin-blind
**Severity:** Low  **Epistemic level:** CONFIRMED BY INDUCTION  **Bucket:** hygiene / documentation precision (see reasoning below — not scored as a vulnerability)
- Expectation checked: does `funes expect-tests` + the verifier's `MISSING_EXPECTED_TEST`
  check provide any assurance that a declared test *genuinely ran*, or only that *some*
  record with that name exists, regardless of origin?
- Abduction: `key_allowed()`/the test-record loop in `verifier/funes_verify.c` collects
  `test.<n>.name.hex` for the omission cross-check without reading `test.<n>.origin` at
  that point — origin is tracked only for the separate `test_observation_status` field.
- Deduction: a bundle that declares two expected names and satisfies both purely via
  `import-test --name ... --report ...` (self-asserted `IMPORTED`, nothing executed)
  should verify exit 0, never trip `MISSING_EXPECTED_TEST`.
- Induction: built exactly that bundle (`capture` → `expect-tests unit_tests
  integration_tests` → two `import-test --name` calls, no `add-test` at all). Result:
  `exit=0`, `integrity_status=INTEGRITY_VALID`, `test_observation_status=IMPORTED_ONLY`,
  no `MISSING_EXPECTED_TEST`. Confirmed exactly as predicted.
- Bucket reasoning (both sides, per the mandatory-refutation discipline): the benign
  reading is that this is working as designed — the roadmap's own deliverable is
  "expected-test omission detection," i.e. detect a *missing name*, which it does
  correctly; whether that name corresponds to real execution is explicitly a *different*,
  already-separate question this project answers via `test_observation_status` /
  `test.<n>.origin`, consistent with Level 1's existing rule that an `IMPORTED` record is
  "reported, never promoted" and must never be described as verified execution. A
  reviewer who checks the full, un-collapsed report (as this project's own semantics
  insist on) sees `IMPORTED_ONLY` and is not misled about authenticity. The adversarial
  reading is that the omission-detection *feature's name* invites a stronger reading than
  it delivers: a reader who checks only "did `expect-tests` succeed" (exit code, or the
  `MISSING_EXPECTED_TEST` field alone) gets zero protection against a lying CI script that
  self-imports a success report for a test it never ran. Landing call: not a vulnerability
  (no documented guarantee is actually violated — the project's "fields never collapsed"
  design already carries the caveat), but worth a doc fix.
- **Fixed (documentation, same day):** `docs/spec/EVIDENCE-BUNDLE-v2.md` now states
  explicitly, directly under the `MISSING_EXPECTED_TEST` row, that the check matches on
  `test.<n>.name.hex` alone, independent of origin, and that a reviewer who needs the
  stronger "this actually ran" guarantee must separately check `test.<n>.origin` /
  `test_observation_status`. No code change — origin-blindness is accepted as-designed
  per the reasoning above, only the documentation gap is closed.

### RT2-02 — JSON parser number-literal length is not an exploitable DoS
**Severity:** —  **Epistemic level:** FALSIFIED  **Bucket:** hygiene (noted, not scored)
- Abduction: `jparse_number_raw` has no explicit digit-run length cap, unlike strings
  (`MAX_JSON_STRING_LEN`) and containers (`MAX_JSON_CONTAINER_ITEMS`); it is bounded only
  by the outer `MAX_TEST_REPORT_BYTES` (1 MiB) file-size cap applied before parsing.
- Deduction: a ~900 KB digit run in a type-mismatched position (`"passed": <900KB of
  1s>`) should either be slow/memory-heavy, or rejected quickly and cheaply.
- Induction: built a 921,612-byte report with a 900 KB number where a boolean was
  expected. Result: rejected in `0m0,002s` real time with `passed must be a boolean`.
  Separately, a >1 MiB report (1,048,631 bytes) is rejected pre-parse in `0m0,001s` via
  the `stat`-first size check (`report oversized.json exceeds 1048576 bytes, refusing to
  parse as JSON`). Both falsify an exploitable DoS.
- Hygiene note (not a vuln, recorded for completeness): an explicit per-number length cap
  would be more defensible on its own terms than relying on the outer file cap, the same
  way strings and containers already have their own caps. Low priority given the
  demonstrated cost is negligible.

### RT2-03 — Level 3 x Level 4 composition holds (positive result)
**Severity:** —  **Epistemic level:** CONFIRMED BY INDUCTION  **Bucket:** n/a (invariant preserved, not a finding against the system)
- Deduction: signing binds to the whole manifest digest (Level 3); adding any new field
  via a Level 4 command (`add-test`, which also writes `runtime=host`) changes the
  manifest, so the existing signature must go stale (`SIGNATURE_INVALID`), exactly like
  Level 3's pre-existing "signature over stale manifest" protection.
- Induction: `keygen` → `sign` → verify (exit 0, `signature_status=VALID`,
  `signer_trust_status=TRUSTED_SIGNER`) → `add-test` on the same bundle → verify again
  with the same trusted key. Result: `signature_status=INVALID`, `signer_trust_status=
  NOT_APPLICABLE`, `error_code=SIGNATURE_INVALID`, exit 8, detail correctly names both the
  old signed digest and the new bundle digest. Confirmed exactly as predicted — Level 4's
  new fields did not create a path around Level 3's binding.
- Recorded because the skill calls for stating confirmed invariants, not only breaks;
  this is a real (if unsurprising) result that the two levels compose correctly.

### RT2-04 — Signature fields misreport on a genuinely signed, trusted bundle that fails `MISSING_EXPECTED_TEST`
**Severity:** Low  **Epistemic level:** CONFIRMED BY INDUCTION  **Bucket:** hygiene (diagnostic precision, not a bypass)
- Expectation checked: does the verifier's report ever claim something false about a
  signature that is actually present and valid, when an earlier, unrelated check fails
  first?
- Abduction: `main()`'s signature-verification phase runs textually after the test-record
  loop and the new `MISSING_EXPECTED_TEST` check; any early exit (via `FAIL` or the
  manual `report_and_exit` in the omission check) never reaches it, so `signature_status`/
  `signer_trust_status` are left at their initialized defaults (`NOT_PRESENT`/
  `NOT_APPLICABLE`).
- Deduction: a bundle that is genuinely signed by a real key, verified against a matching
  `--trusted-key`, but also has an unsatisfied `expect-tests` declaration, should report
  `signature_status=NOT_PRESENT` even though a valid `signatures/` directory exists on
  disk.
- Induction: built exactly that bundle (`capture` → `expect-tests never_run_test` →
  `keygen` → `sign`, no test ever added). Result: `exit=10`, `error_code=
  MISSING_EXPECTED_TEST`, and indeed `signature_status=NOT_PRESENT`,
  `signer_trust_status=NOT_APPLICABLE` — despite the bundle carrying a real, valid
  signature. Confirmed.
- **Is this introduced by Level 4, or pre-existing?** Tested directly: took a separately
  signed+trusted bundle and tripped the *pre-existing* `BUNDLE_INVALID` check (planted an
  unreferenced blob file) instead of the new omission check. Result: identically
  `signature_status=NOT_PRESENT`, `signer_trust_status=NOT_APPLICABLE`, despite that
  bundle also being genuinely signed. **This falsifies "Level 4 introduced this" and
  confirms it is a pre-existing verifier-wide reporting convention**: every early-exit
  path (`BUNDLE_INVALID`, `DIGEST_MISMATCH`, `MISSING_ARTIFACT`, `SEAL_MISMATCH`,
  `UNSUPPORTED_SCHEMA`, and now `MISSING_EXPECTED_TEST`) shares this behavior, because
  none of them run the later signature phase. The new check simply inherited an
  already-present pattern rather than creating a new one.
- Precision note (per the skill's Part 7): this is not a bypass — the bundle still fails
  closed (non-zero exit, 10), and no false *positive* claim about integrity or trust is
  made. The imprecision is purely in a *negative* diagnostic field reading "not present"
  about a signature that is, in fact, present — a reviewer skimming only that one field
  without reading `error_code` could be misled into "this was never signed" rather than
  "signing was never checked because an earlier condition already failed."
- **Fixed (code, same day, verifier-wide as recommended):** `g_sig`/`g_trust` now default
  to `NOT_CHECKED` rather than `NOT_PRESENT`/`NOT_APPLICABLE`; the signature phase's own
  "neither file present" branch now sets the genuine `NOT_PRESENT`/`NOT_APPLICABLE` pair
  explicitly, only when it actually runs and finds nothing. Four new regression checks in
  `tests/run_tests.sh` ("red team round 2 follow-up" section) lock this in: a tampered
  *signed* bundle that fails `BUNDLE_INVALID` before reaching the signature phase now
  reports `NOT_CHECKED`/`NOT_CHECKED`, while a genuinely unsigned bundle still reports
  `NOT_PRESENT`. `docs/spec/VERIFIER-SEMANTICS.md` documents the new value and the
  distinction. Full suite: 101/101 (97 prior + 4 new) after the fix.

### RT2-05 — Name-truncation collision is genuinely impossible
**Severity:** —  **Epistemic level:** FALSIFIED  **Bucket:** n/a
- Abduction: `test_names` is a `char[][MAX_LINE]` (`MAX_LINE=8192`) buffer; if a value
  could reach the buffer without first being bounded to under 8192 bytes, two long names
  sharing a prefix could collide after `snprintf` truncation.
- Deduction: a 5000-byte raw name hex-encodes to a 10,000-byte value, producing an
  `expected_test.0.name.hex=...`/`test.0.name.hex=...` line over 10,000 bytes — longer
  than `MAX_LINE`.
- Induction: built exactly that bundle. Result: `error_code=RESOURCE_LIMIT_EXCEEDED`,
  `detail=manifest line too long`, exit 6 — rejected at line-parse time, before the value
  ever reaches `test_names[]` or any comparison. Confirmed genuinely impossible: the same
  generic per-line length check (`if (linelen >= MAX_LINE) FAIL(...)`) applies uniformly
  to every manifest line regardless of key, so `test.<n>.name.hex` and
  `expected_test.<n>.name.hex` are bounded by the identical mechanism, not two
  independent ones that could disagree.

### RT2-06 — `report_case_count` cannot disagree with accepted cases
**Severity:** —  **Epistemic level:** FALSIFIED  **Bucket:** n/a
- Abduction: `report_case_count` is set from `val->nitems` before each case object is
  individually validated in `json_test_report_parse`; if validation of a later case
  failed, an earlier-set count might already be committed.
- Deduction: a `cases` array with a valid 1st and 2nd entry and an invalid 3rd
  (`"passed":"not-a-bool"`) should either write `report_case_count=3` with incomplete
  data, or fail the whole import.
- Induction: ran `import-test --format json` with exactly that payload. Result:
  `malformed JSON report: case passed must be a boolean`, exit 1, and `test_count`
  unchanged (`test_count=1`, the bundle's prior state) — nothing was written. Parsing is
  all-or-nothing (`die()` aborts before `seal_bundle` is ever reached), so no partial or
  disagreeing count can exist in a sealed bundle. Falsified.

### RT2-07 — Control bytes / `=` / newline in an `expect-tests` name do not inject
**Severity:** —  **Epistemic level:** FALSIFIED  **Bucket:** n/a
- Deduction: a name containing a literal newline and `=` (`evil\nname=injected`) should
  either corrupt manifest line structure or be safely neutralized by the existing
  `hex_encode()` convention already used for every other user-controlled string in this
  format (paths, argv).
- Induction: declared that name via `expect-tests`. Result:
  `expected_test.0.name.hex=6576696c0a6e616d653d696e6a65637465647461696c` — a single
  well-formed hex line; `funes-verify` parses the manifest and correctly reports
  `MISSING_EXPECTED_TEST` for that exact name, with no stray lines or key collisions.
  Confirmed safe — consistent with the project's existing, uniform `*.hex` convention.
  (A simultaneously-embedded NUL byte was stripped by the shell before reaching argv in
  this specific test, which is a shell/exec-layer limitation of the test harness, not a
  property of Funes; it does not weaken the result for the bytes that did arrive.)

## Discarded (non-exploitable) vectors

| Vector | Result | Why it failed |
|---|---|---|
| ~900 KB JSON number literal as DoS | FALSIFIED (RT2-02) | Rejected by type check in 2 ms; bounded by the 1 MiB file cap regardless |
| Oversized (>1 MiB) JSON report as DoS | FALSIFIED (RT2-02) | `stat`-first cap rejects before any parsing, in 1 ms |
| Signature survives a Level 4 field addition | FALSIFIED (RT2-03 — tested as a potential break, confirmed as a correctly-preserved invariant instead) | Manifest digest changes, signature correctly goes stale |
| Long-name buffer truncation collision | FALSIFIED (RT2-05) | Manifest line-length cap rejects the line outright, uniformly, before any buffer is touched |
| Partial JSON case-array parse producing a wrong `report_case_count` | FALSIFIED (RT2-06) | Parsing is all-or-nothing; a late failure discards everything, including the count |
| Control-byte/newline/`=` injection via `expect-tests` name | FALSIFIED (RT2-07) | Existing `hex_encode()` convention neutralizes it, as it does for every other user string in the format |

## Recommendations (recorded, not implemented in this round)

- Document that `expect-tests`/`MISSING_EXPECTED_TEST` checks for a *named record*, not
  for `OBSERVED` origin (RT2-01) — point readers at `test.<n>.origin`/
  `test_observation_status` for the execution-authenticity question.
- Consider an explicit per-number length cap in `src/json_min.c`'s `jparse_number_raw`,
  for symmetry with the existing string/container caps, even though the outer file-size
  cap already makes it non-exploitable (RT2-02).
- Consider reporting `signature_status=NOT_CHECKED` (not `NOT_PRESENT`) and
  `signer_trust_status=NOT_CHECKED` (not `NOT_APPLICABLE`) on any early-exit path where
  the signature phase never ran, verifier-wide — this predates Level 4 (RT2-04) and
  affects every existing hard-failure exit code, not just `MISSING_EXPECTED_TEST`.
