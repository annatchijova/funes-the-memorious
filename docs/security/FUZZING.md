# Parser Fuzzing (Level 6, scoped slice)

Status: implemented — manifest tokenizer harness, JSON report parser
harness, seed corpora, bounded CI smoke job. This is a deliberately scoped
slice of Level 6 (`docs/ROADMAP.md`); the rest of that level (resource-budget
consolidation doc, broader CI lint/secret-scanning, packaged release with
checksums and a limitation matrix) is still open.

## What is fuzzed, and why these two

Two places in this codebase parse untrusted bytes from scratch, with no
upstream validation already done:

1. **The manifest tokenizer** (`parse_manifest_buffer()` in
   `verifier/funes_verify.c`): line-splitting, line-length/line-count
   limits, header check, duplicate/unknown-key rejection. This runs on the
   raw bytes of `manifest.txt` inside a bundle the verifier does not trust.
2. **The JSON test-report parser** (`json_test_report_parse()` in
   `src/json_min.c`): a hand-rolled recursive-descent reader for
   `import-test --format json` report files (Level 4, ADR-003).

Everything downstream of tokenization (the required-key checks, blob
cross-references, signature verification) operates on an already-validated
key-value store or already-typed fields, and is out of scope for these
harnesses — that is semantic validation, not parsing, and it is covered by
the ordinary test suite (`tests/run_tests.sh`) instead.

## Why the verifier needed a refactor and the JSON parser did not

`funes-verify`'s parsing, before this change, went through a `FAIL(code,
ex, ...)` macro that calls `exit()` on any malformed input — correct CLI
behavior, fatal to a fuzzer that needs to run thousands of inputs per
process. The manifest tokenizer was extracted into a pure function,
`parse_manifest_buffer(buf, len, &code, &exit, err, errsz)`, that returns
an error instead of exiting; every other `FAIL` call site in the file (the
~50 semantic-validation checks after tokenization) is untouched. `main()`
is now guarded behind `#ifndef FUNES_VERIFY_FUZZ_BUILD` so the fuzz harness
can `#include` the `.c` file directly (whitebox, no new public symbols, no
library split — the verifier's independence contract is unaffected) and
supply its own `main` via libFuzzer.

`json_test_report_parse()` needed no such refactor: it was already a pure,
non-exiting function from the day it was written (ADR-003).

This refactor is behavior-preserving: `sh tests/run_tests.sh` was diffed
byte-for-byte against the pre-refactor commit (`4c20b02`) and is identical
— same 101 pass lines, same exit codes, same `detail=`/`error_code=`
strings — not just the same pass count.

## Running it locally

```sh
sh fuzz/build.sh                       # requires clang (gcc builds the real binaries elsewhere)
./fuzz/bin/fuzz_manifest fuzz/corpus/manifest       # runs until Ctrl-C, or add -max_total_time=N
./fuzz/bin/fuzz_json_report fuzz/corpus/json
```

Both binaries are built with `-fsanitize=fuzzer,address`, so a crash, a
hang, or a leak during a real run aborts with a stack trace and a minimized
repro input written to disk — standard libFuzzer behavior.

## Findings

**A real crash, found by this harness's first real CI run.** The dev
sandbox that built this harness had no `clang`, so the harness was only
verified locally via a stub (no ASan). The first time `fuzz-smoke` ran for
real in GitHub Actions, it found a genuine heap-use-after-free in
`json_test_report_parse()`'s "unknown top-level key" branch within seconds:
`jval_free(root)` ran before a `snprintf(..., "%s", key)` that read `key`
— a pointer into `root`'s own tree, not a copy — freeing it out from under
the format string. Reproducible through the real `funes import-test
--format json` binary (not just the fuzz harness) with any report
containing an unrecognized top-level key, e.g. `{"foo":1}`; without ASan
it doesn't crash, it silently prints a corrupted key name instead of the
real one. CONFIRMED BY INDUCTION, not hypothetical — this is exactly the
scenario this harness exists to catch, and it caught a real one on its
first real run. Fixed by formatting the message before freeing, not after
(`src/json_min.c`); regression test and corpus seed
(`fuzz/corpus/json/unknown_key_uaf_regression.json`) added so neither the
fuzzer nor the ordinary suite can regress it silently.

## What the CI job actually proves — and does not

`.github/workflows/ci.yml`'s `fuzz-smoke` job runs each target for a
**bounded 30 seconds** against its small seed corpus on every push/PR. This
proves: *no crash in 30 seconds of mutation starting from this corpus, on
this commit.* It does **not** prove the parsers are exhaustively fuzzed,
free of all defects, or safe against an attacker with more than 30 CPU-
seconds. A real fuzzing campaign for either target would run continuously
(hours to days) on dedicated infrastructure — recorded here as future work,
not claimed as already done. Treat this job the same way the rest of this
project treats any boundary check: a stated, bounded guarantee, not a
blanket one.

`src/json_min.c`'s hardening limits (max nesting depth, max string length,
max container items) were already adversarially hand-tested in Red Team
Round 2 (`docs/security/RED-TEAM-ROUND-2.md`, RT2-02) with a real 900 KB
digit-run payload and a real 1200-deep nesting bomb. This harness extends
that one-shot manual testing with automated, ongoing mutation — it is a
second, independent layer of evidence over the same surface, not a
replacement for the hand-run cases (which are also in the ordinary test
suite, so they run on every `make test`, not just when `fuzz/build.sh` is
invoked).

## Seed corpus provenance

`fuzz/corpus/manifest/` is seeded from a real `funes capture`-produced
`manifest.txt` (`valid_minimal.txt`) plus five targeted variants built by
editing that real file (`duplicate_key.txt`, `unknown_key.txt`,
`line_too_long.txt`, `bad_header.txt`, `no_trailing_lf.txt`). `fuzz/corpus/
json/` mirrors the shapes already exercised in `tests/run_tests.sh`'s Level
4 section (a valid report, a duplicate top-level key, trailing garbage
after the document, a report with a `name` field, a nesting-depth probe).
Every file in both corpora was run once through its harness during
development (outside of libFuzzer, via a throwaway stub `main`, since this
development sandbox does not have `clang` installed) and confirmed not to
crash before being committed.
