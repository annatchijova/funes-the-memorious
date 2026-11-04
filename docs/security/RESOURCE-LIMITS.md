# Resource Budgets — Consolidated

Status: these limits were implemented piecemeal across Levels 1, 4, and 6
(each introduced where a new parsing/execution surface needed one); this
document is the first place they are all enumerated together, per the
Level 6 roadmap deliverable "resource budgets... with `RESOURCE_LIMIT_EXCEEDED`
behavior." No new limit is introduced here — this is consolidation, not new
hardening. Language: English.

## Why this matters

Every budget below exists because something in this codebase reads bytes,
a file, or a process's output before knowing whether it is well-behaved.
Without an explicit cap, "parse it and see" becomes "an attacker controls
how much work you do, or how much memory you hold, before you ever get to
say no." Each row states the cap, where it is enforced, what happens on
breach, and where that behavior is tested.

## Collector (`src/funes.c`)

| Limit | Value | Enforced where | On breach | Test coverage |
|---|---|---|---|---|
| Captured stdout/stderr per stream | `MAX_CAPTURE_BYTES` = 1 MiB | `run_capture()`, while reading the child's pipes | Truncated, flagged (`*.truncated=1`), never silently hidden — the bundle still seals and verifies | `tests/run_tests.sh` "truncation is flagged" |
| Imported JSON test-report file size | `MAX_TEST_REPORT_BYTES` = 1 MiB | `parse_json_report()`, via `stat` **before** any read (stat-first discipline, same pattern as the verifier's blob check below) | `die()`, nothing written to the bundle | `tests/run_tests.sh` Level 4 JSON section, "oversized report fixture exceeds 1 MiB cap" |
| Command wall-clock time | `DEFAULT_TIMEOUT_SEC` = 120s, overridable via `--timeout-sec` | `run_capture()`'s poll loop; sends `SIGKILL` on expiry | Child killed; exit/signal/elapsed recorded verbatim, build/test evidence preserved as a killed run, not hidden | `tests/run_tests.sh` "timeout enforcement" (closed in this pass — carried from Level 1, see below) |

**Carried-forward item now closed:** Level 1's own closure note and Red
Team Round 1's recommendations both named "dedicated timeout regression in
the suite" as an open item. It is now in the suite (`tests/run_tests.sh`,
`== timeout enforcement ==`): a real `sleep 30` under `--timeout-sec 1` is
confirmed killed within seconds (not left running), recorded as
`signaled=1`/`signal=9`, with `elapsed_ms` bounded near the timeout rather
than the full sleep duration, and the resulting bundle still verifies —
the killed build is preserved as evidence, not discarded.

## Verifier (`verifier/funes_verify.c`)

| Limit | Value | Enforced where | On breach | Test coverage |
|---|---|---|---|---|
| `manifest.txt` size | `MAX_MANIFEST_BYTES` = 1 MiB | `stat`-checked before `read_file()` reads it | `RESOURCE_LIMIT_EXCEEDED`, exit 6 | Implied by every manifest-tamper test staying under the cap; no dedicated oversized-manifest case (see Recommendations) |
| Manifest line length | `MAX_LINE` = 8192 bytes | `parse_manifest_buffer()`, per line during tokenizing | `RESOURCE_LIMIT_EXCEEDED`, exit 6 | `fuzz/corpus/manifest/line_too_long.txt`; exercised indirectly by Red Team Round 2's RT2-05 long-name induction |
| Manifest line count | `MAX_LINES` = 10000 | `parse_manifest_buffer()` | `RESOURCE_LIMIT_EXCEEDED`, exit 6 | Not directly tested (see Recommendations) |
| Blob file size | `MAX_BLOB_BYTES` = 64 MiB | `stat`-checked before the blob is hashed (RT-04's stat-first fix) | `RESOURCE_LIMIT_EXCEEDED`, exit 6 | Red Team Round 1, RT-04 |
| Artifact/test record count | 1024 each | After parsing, before iterating `artifact.<n>.*`/`test.<n>.*` | `RESOURCE_LIMIT_EXCEEDED`, exit 6 | Not directly tested (see Recommendations) |
| `build.argv_count` | 1–256 | Required-key validation | `BUNDLE_INVALID`, exit 2 (not `RESOURCE_LIMIT_EXCEEDED` — an existing classification choice, not changed here) | Not directly tested (see Recommendations) |
| `expected_test_count` | ≤ 1024 | Omission-check loop (Level 4) | `RESOURCE_LIMIT_EXCEEDED`, exit 6 | Not directly tested (see Recommendations) |

## JSON test-report parser (`src/json_min.c`, Level 4/ADR-003)

| Limit | Value | Enforced where | On breach | Test coverage |
|---|---|---|---|---|
| Nesting depth | `MAX_JSON_DEPTH` = 32 | `jparse_array`/`jparse_object`, checked immediately after each depth increment, before any further recursion | Parse fails with `"maximum nesting depth exceeded"` | Red Team Round 2 RT2-02 (hand-built 1200-deep bomb); `fuzz/corpus/json/nesting.json` |
| String length | `MAX_JSON_STRING_LEN` = 65536 bytes | `jparse_string_raw()`, checked incrementally while appending | Parse fails with `"string exceeds maximum length"` | Not directly tested with a dedicated case (see Recommendations) |
| Array/object member count | `MAX_JSON_CONTAINER_ITEMS` = 10000 | `jparse_array`/`jparse_object`, checked before appending each item | Parse fails with `"array/object has too many ..."` | `fuzz/corpus/json`'s `l4j_huge` fixture (40000-element array) in `tests/run_tests.sh` |

Note: the JSON number parser (`jparse_number_raw`) has no dedicated length
cap of its own — it is bounded only by the outer `MAX_TEST_REPORT_BYTES` file
cap above. Red Team Round 2 (RT2-02) tested this directly with a ~900 KB
digit run and found it rejected in ~2ms; recorded there as a hygiene
observation, not a vulnerability, and not changed in this pass.

## What this document does not claim

This is an inventory, not a new audit. Every limit here already existed
before this document was written (Levels 1, 4, and the Level 6 fuzzing
slice); consolidating them here does not make any of them stronger. The
"not directly tested" rows above are genuine gaps, named honestly rather
than implied to be covered by the limits that *are* tested nearby — see
Recommendations.

## Recommendations (recorded, not implemented in this pass)

- Dedicated regression tests for: oversized manifest (>1 MiB), manifest
  line count >10000, artifact/test record count >1024, `expected_test_count`
  >1024, `build.argv_count` >256, and JSON string length >64 KiB. All of
  these are currently enforced in code (see table above) but not exercised
  by a case that actually trips that specific limit in `tests/run_tests.sh`
  — the fuzzing harnesses in `fuzz/` may stumble onto some of these by
  mutation, but a deliberate, named regression test is a stronger and more
  legible guarantee than "the fuzzer might find it."
- Consider an explicit length cap on JSON number literals in
  `src/json_min.c` for symmetry with strings/containers, per Red Team Round
  2's RT2-02 hygiene note (not required — the outer file cap already makes
  it non-exploitable).
