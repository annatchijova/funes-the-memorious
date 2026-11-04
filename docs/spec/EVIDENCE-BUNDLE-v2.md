# Evidence Bundle Format v2

Status: implemented by Level 4 (host-only; `src/funes.c`,
`verifier/funes_verify.c`). Language: English.

This document supersedes `EVIDENCE-BUNDLE-v1.md` for bundles produced by the
current collector (`schema_version=2`). It states **only what changed from
v1** — three additions, all in the test-record area. Every other key name,
typing convention, canonicalization rule, blob format, `SEAL.txt` format,
and the compatibility policy from v1 applies unchanged; see
`EVIDENCE-BUNDLE-v1.md` for everything not listed here.

## Why a version bump

v1's own compatibility policy requires it: "Unknown key in a v1 manifest:
fail closed. New fields require a schema version bump; v1 verifiers never
silently ignore data." Level 4 adds required and optional test-record
fields, so `schema_version` moves from `1` to `2`. A v2 verifier rejects a
`schema_version=1` manifest cleanly (`UNSUPPORTED_SCHEMA`), the same way a
v1 verifier was required to reject v2 bundles cleanly; there is no silent
downgrade path and no dual-version support in either binary.

## 1. Host-vs-target distinction, enforced on every test record

Every `test.<n>.*` record now carries a required key:

| Key | Meaning |
|---|---|
| `test.<n>.runtime` | Exactly `host` or `target`. Never inferred or defaulted; missing or any other value is `BUNDLE_INVALID`. |

The current collector always writes `host` — there is no genuine QNX
execution path yet (Level 2 and the QEMU part of Level 4 remain `BLOCKED`),
and a flag letting a caller claim `target` without real QNX execution would
be exactly the overclaiming this project's threat model forbids. A future
QEMU/QNX integration is what will genuinely produce `target` records.

## 2. Optional test name

| Key | Meaning |
|---|---|
| `test.<n>.name.hex` | Optional. `*.hex` encoding (per v1 convention) of a caller-supplied test name. Absent when no name was given — not a placeholder/`NONE`, the key simply does not exist for that test, same convention as the argv keys being absent for imported tests. |

Written by `funes add-test --name NAME` and `funes import-test --name NAME`.
No additional verifier requirement beyond key presence — consistent with
every other variable-length `*.hex` key in this format (e.g.
`build.cwd.hex`, `artifact.<n>.name.hex`), none of which are content-decoded
by the verifier beyond being present.

## 3. Expected-test declaration and omission detection

A bundle may declare, **exactly once**, the set of test names its evidence
is expected to contain:

| Key | Meaning |
|---|---|
| `expected_test_count` | Optional. Absence means no expectations were declared — a legitimate state, not a finding. |
| `expected_test.<n>.name.hex` | `*.hex` encoding of the `n`-th expected test name, contiguous from 0. |

Written by `funes expect-tests --bundle DIR -- NAME...` (one or more names,
no duplicates within one call). The collector refuses to run this command a
second time against a bundle that already has `expected_test_count` —
re-declaring expectations after the fact to match whatever happened would
launder away a real omission, the same justification as `keygen` refusing
to overwrite an existing key.

If `expected_test_count` is present, the verifier requires every declared
name to match at least one `test.<n>.name.hex` among the bundle's test
records; the first unmatched name is a hard failure:

| Exit | Code name | Meaning |
|---|---|---|
| 10 | `MISSING_EXPECTED_TEST` | A test name declared in `expected_test.<n>` was never observed or imported. Integrity may otherwise be valid; completeness against the declared expectation is not. Reported as a hard failure, not a degraded status field — consistent with this format's fail-closed philosophy. |

**What this check does *not* prove (Red Team Round 2, RT2-01):** the match is
on `test.<n>.name.hex` alone, independent of `test.<n>.origin`. A declared
name is satisfied equally by a real `add-test` run (`OBSERVED`) or by a bare
`import-test --name` call that executed nothing (`IMPORTED`, self-asserted).
`expect-tests`/`MISSING_EXPECTED_TEST` detects a *missing named record*, not
a *missing execution* — that second, stronger question is what
`test.<n>.origin` and `test_observation_status` are for, and this project's
"fields are never collapsed into one score" rule means a reviewer who needs
the execution guarantee must check that separate field, not assume the
omission check already implies it.

## 4. Structured JSON test-report adapter (optional, additive)

`funes import-test --format json` parses the report file (capped at 1 MiB,
size checked via `stat` before any read, same stat-first discipline as the
verifier's blob-size check) as a strict JSON document and extracts three
additional optional test-record keys instead of leaving the report as an
opaque blob:

| Key | Meaning |
|---|---|
| `test.<n>.report_format` | `JSON` when `--format json` was used; absent otherwise (opaque/unparsed report, v1 behavior unchanged). |
| `test.<n>.report_passed` | `0`/`1`, from the report's required `passed` field. |
| `test.<n>.report_case_count` | Count of the report's optional `cases` array (`0` if absent). |

Accepted JSON shape (strict — see `ADR-003-TEST-REPORT-FORMAT.md` for why
JSON over JUnit XML/TAP, and `src/json_min.c` for the hardened reader):

```json
{"name": "string (optional)", "passed": true|false (required),
 "cases": [{"name": "string", "passed": true|false}, ...] (optional)}
```

Unknown or duplicate keys at any nesting level, wrong types, and trailing
data after the top-level value are all rejected — nothing is written to the
bundle on any parse failure. If the report's `name` field is present and no
CLI `--name` was separately given, the report's name becomes the test's
`test.<n>.name.hex` (CLI `--name` always wins when both are given).

## Migration note

A v1 bundle has no `test.<n>.runtime` keys and no `expected_test_count`
key. There is no silent migration: a v2 verifier reports a v1 bundle's
`schema_version=1` as `UNSUPPORTED_SCHEMA` (exit 5), exactly like any other
unsupported value. Re-running the same capture/test commands with the
current collector produces a fresh, valid v2 bundle; there is no in-place
upgrade of an existing v1 bundle, by design (the same "no silent downgrade
path" invariant v1 already stated for a hypothetical v2).
