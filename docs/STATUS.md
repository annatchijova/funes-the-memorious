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

Observed test outcome: **41 PASS, 0 FAIL** (`RESULT: pass=41 fail=0`, suite
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
| Unknown signer | Not authenticated | No signatures in v1; `signature_status=NOT_PRESENT` asserted in suite | DONE (as explicit absence; signing is Level 3) |
| Failing build/test | Evidence preserved | `/bin/false` build and `fail` test recorded with real exit statuses; bundles verify | DONE (`VERIFIED_HOST_ONLY`) |
| Imported report | Never promoted | `import-test` + verifier reports `IMPORTED_ONLY` | DONE (`VERIFIED_HOST_ONLY`) |
| Secret leakage | Absent from manifest | Sentinel env value not present in manifest (suite) | DONE (`VERIFIED_HOST_ONLY`) |
| Truncation | Flagged, not hidden | 2 MB output -> `stdout_truncated=1`, bundle verifies | DONE (`VERIFIED_HOST_ONLY`) |
| Determinism | Stable digests | Fixed-epoch captures give identical source/stdout digests (suite) | DONE (`VERIFIED_HOST_ONLY`) |
| QNX `qcc` detected | Actual tool/environment | Doctor reports `NOT_FOUND` on this host | BLOCKED |
| QNX 8 target compiled | Actual compiler and binary | Not attempted without SDP | BLOCKED (`NOT_RUN`) |
| QNX QEMU runtime | Actual execution evidence | Not attempted | NOT_RUN |
| README quick start | Executed as written | `make`, `make test`, demo commands in `docs/DEMO.md` run on this host | DONE (`VERIFIED_HOST_ONLY`) |
| Security tests | Passed/failed counts | Hostile cases above are part of the 41-check suite | DONE (`VERIFIED_HOST_ONLY`) |

## Test accounting

- Actually run: 41 host checks (unit-via-CLI, integration, adversarial).
- Contract tests against the real QNX SDP: 0.
- Synthetic/synthetic-labeled exercises: the tamper/missing/schema bundles
  are mutations of a real captured bundle, produced by the suite at test
  time; no pre-made "QNX evidence" exists anywhere in the repo.
- Actual QNX SDK runs: 0. Actual QNX runtime runs: 0.
- Not run: fuzzing (Level 6), signing (Level 3), comparison (Level 5),
  QEMU (Level 4).
- Failures still open: none in the host suite. One defect was found and
  fixed during Level 1 (duplicate blob key when stdout and stderr are
  identical bytes; see commit message).

## Blockers

- Level 2 needs a licensed QNX SDP 8.0 on a supported host (see
  `docs/QNX-SETUP.md`). Until then it remains `BLOCKED`, by design.
