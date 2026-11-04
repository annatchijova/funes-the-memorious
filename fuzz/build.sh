#!/bin/sh
# Builds the Level 6 libFuzzer targets. Requires clang (the main build uses
# gcc; this is intentionally a separate, opt-in path -- see
# docs/security/FUZZING.md). Not part of `make all` / `make test` / CI's
# `host` job.
set -eu
cd "$(dirname "$0")/.." || exit 1
mkdir -p fuzz/bin

clang -std=c11 -g -O1 -fsanitize=fuzzer,address \
    -DFUNES_VERIFY_FUZZ_BUILD \
    -o fuzz/bin/fuzz_manifest fuzz/fuzz_manifest.c verifier/sha256.c -ldl

clang -std=c11 -g -O1 -fsanitize=fuzzer,address \
    -o fuzz/bin/fuzz_json_report fuzz/fuzz_json_report.c

echo "built fuzz/bin/fuzz_manifest and fuzz/bin/fuzz_json_report"
