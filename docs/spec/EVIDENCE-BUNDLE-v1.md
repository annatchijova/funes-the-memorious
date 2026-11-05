# Evidence Bundle Format v1

Status: implemented by Level 1 (`src/funes.c`, `verifier/funes_verify.c`).
Superseded by v2 (`EVIDENCE-BUNDLE-v2.md`) for bundles produced by the
current collector/verifier (Level 4, `schema_version=2`); this document
remains the accurate historical record of what v1 was and is otherwise
unchanged below.
Language: English. An implementer needs only this document, SHA-256, and a
text parser to write an independent checker. No Funes code is required.

## Layout (directory bundle)

```text
<bundle>/
  manifest.txt
  SEAL.txt
  blobs/sha256/<64 lowercase hex chars>
```

A directory is used for v1 because it keeps blobs inspectable with standard
tools and avoids archive-extraction hazards (zip-slip, device files) in the
first implementation. Content addressing means a blob's filename is its
SHA-256 digest; the manifest never trusts a stored filename beyond that.

## manifest.txt — canonical bytes

- Encoding: UTF-8 without BOM. Line ending: LF (`\n`) only. Final line ends
  with LF. No trailing spaces. Maximum manifest size: 1 MiB. Maximum line
  length: 8192 bytes. Maximum lines: 10000.
- First line is exactly `FUNES-BUNDLE-1`.
- Every following line is `key=value`. Lines are sorted lexicographically by
  the full line bytes. Duplicate keys are invalid, except indexed keys
  (`build.argv.<n>.hex`, `source.file.<n>.*`, `artifact.<n>.*`,
  `test.<n>.*`) where each index is unique and contiguous from 0.
- Value encodings are typed by key suffix, so `1`, `"1"`, `true`, and absent
  can never collide:
  - `*.hex`: lowercase hex of the raw UTF-8 bytes of a user-controlled
    string (paths, argv, names). Empty string is `hex` of length 0, written
    as an empty value after `=`. Absence is expressed only by the explicit
    token `NONE` on digest/head keys, never by omitting a required key.
  - Counts, sizes, statuses, elapsed milliseconds: unsigned decimal, no
    sign, no leading zeros except the value `0` itself.
  - Booleans: `0` or `1`.
  - Digests: exactly 64 lowercase hex characters, or the token `NONE` where
    the schema says so.
  - Origin tokens: `OBSERVED`, `IMPORTED`, `ASSERTED`, `INFERRED`.

### Required keys (build capture)

| Key | Meaning |
|---|---|
| `schema_version` | `1`. Any other value: verifier fails `UNSUPPORTED_SCHEMA`. |
| `build.origin` | Always `OBSERVED` for a captured build. |
| `build.argv_count`, `build.argv.<n>.hex` | Exact argument vector, including argv[0] as invoked. No shell string is stored. |
| `build.cwd.hex` | Working directory as an absolute path string (collector-side record; portability note below). |
| `build.started_unix` | Wall-clock start, seconds since epoch (collector clock; may be skewed — evidence, not truth). |
| `build.elapsed_ms` | Monotonic elapsed time of the child, integer milliseconds. |
| `build.exit_status` | Child exit status when it exited; otherwise `128+signal`. Paired with `build.signaled` (`0`/`1`) and `build.signal` (signal number or `0`). A non-zero build is preserved, never rewritten as success. |
| `build.stdout_sha256`, `build.stdout_size`, `build.stdout_truncated` | Blob reference for captured stdout. `size` is the stored blob size; truncation is flagged, never presented as complete. Same trio for `stderr`. |
| `source.git_head` | 40-hex commit, or `NONE` outside a Git work tree. A commit alone never claims to identify dirty/untracked files. |
| `source.git_dirty` | `1` if `git status --porcelain` was non-empty at capture. |
| `source.file_count`, `source.file.<n>.path.hex`, `source.file.<n>.sha256` | Explicit source set hashed by the collector, sorted by path bytes. |
| `source.digest` | SHA-256 over the concatenation, in sorted order, of `<sha256><space><space><path.hex>\n` lines; `NONE` when the set is empty. |
| `artifact_count`, `artifact.<n>.name.hex`, `artifact.<n>.role`, `artifact.<n>.sha256`, `artifact.<n>.size` | Output artifacts hashed after the build. `role` is a non-empty ASCII token containing only letters, digits, `.`, `_`, and `-`, such as `target-executable`, `test-report`, or `compiler-log`. Each artifact's bytes are stored as a blob. |
| `env.host_os`, `env.host_arch` | `uname` system and machine strings (hex-encoded as `*.hex` values under keys `env.host_os.hex`, `env.host_arch.hex`). |
| `qnx.host_present`, `qnx.target_present` | `1` if `QNX_HOST`/`QNX_TARGET` were set (values are never stored), else `0`. |

Allowlisted environment only: no environment value other than the two
presence booleans above is recorded. Secrets cannot enter the bundle through
the environment because no other variable is read for the manifest.

### Optional keys (test records)

Appended by `funes add-test` (and `funes import-test` for imported reports).
Each test `n` carries: `test.<n>.origin` (`OBSERVED` or `IMPORTED`),
`test.<n>.argv_count` + argv hex lines (observed only),
`test.<n>.exit_status`, `test.<n>.signaled`, `test.<n>.signal`,
`test.<n>.elapsed_ms`, `test.<n>.started_unix`,
`test.<n>.stdout_sha256/size/truncated` (+ stderr trio),
`test.<n>.artifact_sha256` (digest of the artifact under test; must equal
some `artifact.<n>.sha256` in the same bundle, checked by the verifier),
and `test_count`. An imported report stores its file as a blob and is always
`IMPORTED`; it is never promoted to `OBSERVED` by any tool in this project.

### Blob lines

For every distinct stored digest exactly one line (identical bytes serving
two roles, such as empty stdout and stderr, share a single line whose role
is the first role recorded):
`blob.<sha256>=<size>:<role>` where role is one of `stdout`, `stderr`,
`test-stdout`, `test-stderr`, `artifact`, `imported-report`. The blob file
must exist at `blobs/sha256/<sha256>`, be a regular file (never a symlink),
have exactly `<size>` bytes, and hash to `<sha256>`. A blob file present but
unreferenced is `BUNDLE_INVALID` (unexpected material). A referenced blob
that is missing is `MISSING_ARTIFACT`; one whose bytes hash differently is
`DIGEST_MISMATCH`.

## SEAL.txt

Exactly one line: `<sha256 of manifest.txt bytes><space><space>manifest.txt\n`.
The seal commits to the manifest bytes. Integrity mode (v1) has no signature:
anyone who can rewrite blobs can rewrite manifest and seal together, so a
valid seal proves internal consistency, not origin. Verifiers report
`signature_status=NOT_PRESENT` for unsigned bundles, never authenticated.

## Signatures (Level 3, additive; format version unchanged)

Optional directory `signatures/` beside the manifest:

```text
signatures/
  ed25519.sig    64 raw signature bytes (regular file, never a symlink)
  signer.txt     algorithm / manifest_sha256 / payload_domain /
                 signer_fingerprint_sha256 / signer_pubkey_hex lines
```

Signed bytes are exactly `FUNES-SIGN-1` + LF + the 64-char hex SHA-256 of
`manifest.txt` + LF, verified with Ed25519. The algorithm is fixed by the
verifier; `signer.txt` values are claims checked against that fixed
expectation, and the fingerprint is recomputed from the public-key bytes.
Authentication exists only relative to a reviewer-supplied trusted public
key (`funes-verify --trusted-key`); see `VERIFIER-SEMANTICS.md` and
`ADR-002-SIGNING.md`. Signing never modifies the manifest, so unsigned v1
verification is unaffected.

## Canonicalization and determinism

Given identical field values, the collector emits byte-identical manifests
(lines sorted, fixed encodings). Timestamps (`started_unix`) are part of the
recorded evidence and therefore part of the sealed bytes; two captures at
different times legitimately produce different manifests. Determinism is
claimed only for the mapping from field values to bytes, and it is tested by
re-hashing identical inputs (blob digests, source digest, and re-sealing a
captured record under a fixed `--epoch` in the test suite).

## Compatibility policy

- Unknown `schema_version`: fail closed (`UNSUPPORTED_SCHEMA`, exit 5).
- Unknown key in a v1 manifest: fail closed (`BUNDLE_INVALID`). New fields
  require a schema version bump; v1 verifiers never silently ignore data.
- Unknown origin/role token: fail closed.
- A future v2 must keep a v1 verifier able to reject v2 bundles cleanly, and
  must document migration. There is no silent downgrade path.

## Portability

`build.cwd.hex` and source paths are recorded as observed on the collecting
host (absolute paths may appear inside hex values). They are evidence about
the capture, not instructions: a verifier must never open a path taken from
the manifest. Portable review should rely on digests, roles, and argv, not
on host paths. A future redaction mode may replace path prefixes; v1
discloses rather than hides this (see the threat model).
