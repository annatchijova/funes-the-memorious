# Status

Generated from observed runs on the development host. Nothing here is
copied from a plan. Language: English.

## Environment observed

- Host: Linux x86_64, kernel 6.14.0-37-generic (Linux Mint family host).
- Compiler: gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0; GNU Make 4.3.
- QNX: `funes doctor` reports `qnx_toolchain_status=NOT_FOUND`
  (`qcc` absent, `QNX_HOST`/`QNX_TARGET` unset). QNX status: `BLOCKED`.

## Commands actually run

```bash
make clean && make        # builds bin/funes and bin/funes-verify with -Werror
make test                 # sh tests/run_tests.sh
./bin/funes doctor
./bin/funes doctor --json
```

Observed test outcome: **97 PASS, 0 FAIL** (`RESULT: pass=97 fail=0`, suite
exit 0). The SHA-256 path is checked against the published `abc` vector.

## Validation matrix

| Capability | Expected observation | Evidence | State |
|---|---|---|---|
| Linux host collector | Real command captured | `funes capture` in `tests/run_tests.sh` | DONE (`VERIFIED_HOST_ONLY`) |
| Build artifact digest | Digest over actual bytes | gcc build of `examples/host-hello`, artifact blob = file hash | DONE (`VERIFIED_HOST_ONLY`) |
| Independent verifier | No collector internal imports | Separate C binary, own SHA-256/parser; runs under `env -i` in suite | DONE (`VERIFIED_HOST_ONLY`) |
| Artifact mutation | Non-zero verification failure | One appended byte -> exit 3 `DIGEST_MISMATCH` | DONE (`VERIFIED_HOST_ONLY`) |
| Log mutation | Precise failure | One appended byte to stdout blob -> exit 3 | DONE (`VERIFIED_HOST_ONLY`) |
| Missing evidence | Exact diagnostic | Deleted artifact blob -> exit 4 `MISSING_ARTIFACT` | DONE (`VERIFIED_HOST_ONLY`) |
| Manifest tampering | Seal failure | Edited field without reseal -> exit 7 `SEAL_MISMATCH` | DONE (`VERIFIED_HOST_ONLY`) |
| Unexpected/symlink material | Fail closed | Extra blob file -> exit 2; symlink blob -> exit 2 | DONE (`VERIFIED_HOST_ONLY`) |
| Unsupported schema | Fail closed | Resealed `schema_version=99` -> exit 5 `UNSUPPORTED_SCHEMA` | DONE (`VERIFIED_HOST_ONLY`) |
| Unknown signer | Not authenticated | Wrong `--trusted-key` -> exit 9 `SIGNER_UNTRUSTED`; no root -> `UNTRUSTED_SIGNER` | DONE (`VERIFIED_HOST_ONLY`) |
| Signature validity | Authenticated only under supplied root | Matching root -> `TRUSTED_SIGNER`; flipped sig byte / stale manifest -> exit 8 `SIGNATURE_INVALID`; seed never in bundle | DONE (`VERIFIED_HOST_ONLY`) |
| Failing build/test | Evidence preserved | `/bin/false` build and `fail` test recorded with real exit statuses; bundles verify | DONE (`VERIFIED_HOST_ONLY`) |
| Imported report | Never promoted | `import-test` + verifier reports `IMPORTED_ONLY` | DONE (`VERIFIED_HOST_ONLY`) |
| Secret leakage | Absent from manifest | Sentinel env value not present in manifest (suite) | DONE (`VERIFIED_HOST_ONLY`) |
| Truncation | Flagged, not hidden | 2 MB output -> `stdout_truncated=1`, bundle verifies | DONE (`VERIFIED_HOST_ONLY`) |
| Determinism | Stable digests | Fixed-epoch captures give identical source/stdout digests (suite) | DONE (`VERIFIED_HOST_ONLY`) |
| QNX `qcc` detected | Actual tool/environment | Doctor reports `NOT_FOUND` on this host | BLOCKED |
| QNX 8 target compiled | Actual compiler and binary | Not attempted without SDP | BLOCKED (`NOT_RUN`) |
| QNX QEMU runtime | Actual execution evidence | Not attempted | NOT_RUN |
| README quick start | Executed as written | `make`, `make test`, demo commands in `docs/DEMO.md` run on this host | DONE (`VERIFIED_HOST_ONLY`) |
| Security tests | Passed/failed counts | Hostile cases above are part of the 74-check suite | DONE (`VERIFIED_HOST_ONLY`) |
| Bundle comparison | Material diff with verification first | `funes compare`: identical exit 0, changed source/artifact named, tampered input exit 2 | DONE (`VERIFIED_HOST_ONLY`) |
| Red Team Round 1 | Findings fixed and re-induced | RT-01..RT-06 (+RT-02 follow-up) in suite; report in `docs/security/RED-TEAM-ROUND-1.md` | DONE (`VERIFIED_HOST_ONLY`) |
| Host-vs-target test records | Every test record carries runtime=host\|target, enforced | Required key, invalid/missing token -> exit 2 `BUNDLE_INVALID`; collector always writes `host` (no real QNX execution path yet) | DONE (`VERIFIED_HOST_ONLY`) |
| Expected-test omission detection | Declared test names absent from evidence are a hard failure | `funes expect-tests`; unsatisfied declaration -> exit 10 `MISSING_EXPECTED_TEST`; re-declaration and duplicate names refused by the collector | DONE (`VERIFIED_HOST_ONLY`) |
| Structured JSON test-report adapter | Hardened parser, strict schema, adversarial input rejected | `import-test --format json`; 1200-deep nesting bomb, duplicate key, trailing garbage, >1 MiB report all rejected cleanly, no crash (`src/json_min.c`, ADR-003) | DONE (`VERIFIED_HOST_ONLY`) |
| Evidence-format version bump | New fields require a schema bump, old schema cleanly rejected | `schema_version` 1->2 (`docs/spec/EVIDENCE-BUNDLE-v2.md`); a `schema_version=1` bundle is `UNSUPPORTED_SCHEMA` | DONE (`VERIFIED_HOST_ONLY`) |

## Test accounting

- Actually run: 97 host checks (unit-via-CLI, integration, adversarial;
  Level 3 signing/trust, Level 5 comparison, Red Team Round 1 regressions
  RT-01..RT-06 plus the RT-02 follow-up, and Level 4 host-only test-evidence
  checks included).
- Contract tests against the real QNX SDP: 0.
- Synthetic/synthetic-labeled exercises: the tamper/missing/schema bundles
  are mutations of a real captured bundle, produced by the suite at test
  time; no pre-made "QNX evidence" exists anywhere in the repo.
- Actual QNX SDK runs: 0. Actual QNX runtime runs: 0.
- Not run: fuzzing (Level 6), QEMU (Level 4 target/QNX part).
- Failures still open: none in the host suite. One defect was found and
  fixed during Level 1 (duplicate blob key when stdout and stderr are
  identical bytes; see commit message).

## Blockers

- Level 2 needs a licensed QNX SDP 8.0 on a supported host (see
  `docs/QNX-SETUP.md`). Until then it remains `BLOCKED`, by design.
