# Verifier Semantics

Status: implemented by Level 1 (`verifier/funes_verify.c`). Language: English.

## Independence contract

`funes-verify` is a separate C program. It shares no object code with the
collector: it has its own SHA-256 implementation and its own manifest parser.
It reads only the bundle and its command-line flags. It is read-only with
respect to the bundle, works fully offline, and never imports collector
business logic. The shared contract is `docs/spec/EVIDENCE-BUNDLE-v1.md`
alone.

## Result fields (never collapsed into one score)

Human output and `--json` output carry the same fields:

| Field | Values (v1) |
|---|---|
| `integrity_status` | `INTEGRITY_VALID`, `INTEGRITY_INVALID`, `NOT_CHECKED` |
| `signature_status` | `NOT_PRESENT` (v1; signature support is Level 3) |
| `signer_trust_status` | `NOT_APPLICABLE` (v1) |
| `test_observation_status` | `OBSERVED` if at least one `OBSERVED` test record exists and integrity is valid; `IMPORTED_ONLY` if tests exist but all are `IMPORTED`; `NO_TEST_RECORD` otherwise |
| `artifact_status` | `ALL_PRESENT`, `MISSING`, `DIGEST_MISMATCH`, `NOT_CHECKED` |
| `qnx_toolchain_status` | `RECORDED_PRESENT_FLAGS` / `RECORDED_ABSENT_FLAGS` (what the manifest records about `QNX_HOST`/`QNX_TARGET` presence; not a QNX verification) |
| `limitations` | Fixed statements: integrity is not authenticity; authenticity would not prove execution; validity does not certify software safety |

There is no universal `SAFE`, `TRUSTED`, or numeric confidence output, at any
level. A bundle that is internally consistent but contains only an imported
test report verifies as integrity-valid with
`test_observation_status=IMPORTED_ONLY`. It must never be described as
verified execution.

## Error taxonomy and exit codes

| Exit | Code name | Meaning |
|---|---|---|
| 0 | (none) | `INTEGRITY_VALID` |
| 2 | `BUNDLE_INVALID` | Structural failure: bad header, duplicate/unknown key, malformed value, unexpected blob, traversal attempt, symlink blob |
| 3 | `DIGEST_MISMATCH` | A blob or the seal hashes differently than recorded (names the digest and role) |
| 4 | `MISSING_ARTIFACT` | A referenced blob file is absent |
| 5 | `UNSUPPORTED_SCHEMA` | `schema_version` is not `1` |
| 6 | `RESOURCE_LIMIT_EXCEEDED` | Manifest/blob/count limits exceeded |
| 7 | `SEAL_MISMATCH` | `SEAL.txt` does not commit to the manifest bytes |

Exit 1 is reserved for verifier usage/internal errors (unreadable bundle
directory, out of memory) and is never used for evidence findings, so scripts
can distinguish "the evidence failed" from "the tool failed". The first
failure encountered is reported with its key/digest context; diagnostics are
stable strings suitable for test assertions.

## Checks, in order

1. Bundle directory readable; `manifest.txt` present and within limits;
   `SEAL.txt` present, well-formed, and matching (`SEAL_MISMATCH`).
2. Header and `schema_version` (`UNSUPPORTED_SCHEMA` before deeper parsing).
3. Strict line grammar, key sorting is not required of foreign bundles but
   duplicate/unknown/malformed keys are `BUNDLE_INVALID`; required keys
   present with in-range values; indexed keys contiguous.
4. Path safety: blob names are exactly 64 lowercase hex chars; every blob
   path stays inside `blobs/sha256/`; blobs are regular files, not symlinks
   (`lstat`); no manifest value is ever used as a filesystem path by the
   verifier.
5. Every referenced blob: existence (`MISSING_ARTIFACT`), size, and SHA-256
   recomputation over raw bytes (`DIGEST_MISMATCH`). Blob directory scanned
   for unreferenced files (`BUNDLE_INVALID`).
6. Cross-references: each artifact has a matching `artifact` blob; each test
   record's stdout/stderr (or imported report) blob exists; each test's
   `artifact_sha256` equals a recorded artifact digest, else
   `BUNDLE_INVALID` (mismatched association is a structural lie, reported as
   such, not as a pass).
7. Origin discipline: `build.origin` must be `OBSERVED`; test origins are
   reported, never promoted.

## What success does not mean

`INTEGRITY_VALID` means: these bytes match this manifest, and the manifest
matches its seal. It does not mean the build really happened on an honest
host, that the tests were adequate, that the software is safe, or that the
build is reproducible. Those boundaries are printed in every report.
