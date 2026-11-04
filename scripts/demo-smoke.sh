#!/bin/sh
# Documentation smoke test (Level 6): runs docs/DEMO.md's two fenced bash
# blocks verbatim (same commands, same order, transcribed by hand from the
# doc -- keep this file in sync with docs/DEMO.md if either changes) and
# asserts the specific outcomes the doc claims, not just "no shell error".
# A tampered bundle exiting non-zero is the CORRECT behavior, so this script
# checks exit codes and fields against what DEMO.md says should happen.
set -eu
cd "$(dirname "$0")/.." || exit 1
rm -rf /tmp/funes-demo /tmp/funes-demo2
FAIL=0

check() {
    if eval "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; FAIL=1; fi
}

echo "== docs/DEMO.md: three-minute host demo =="
make
./bin/funes doctor >/tmp/demosmoke-doctor.txt
mkdir -p /tmp/funes-demo
cp examples/host-hello/main.c /tmp/funes-demo/main.c
./bin/funes capture --out /tmp/funes-demo/bundle \
  --source /tmp/funes-demo/main.c \
  --artifact /tmp/funes-demo/app:target-executable \
  -- gcc -std=c11 -Wall -Wextra -Werror -O2 -o /tmp/funes-demo/app /tmp/funes-demo/main.c

ART=$(grep '^artifact.0.sha256=' /tmp/funes-demo/bundle/manifest.txt | cut -d= -f2)
./bin/funes add-test --bundle /tmp/funes-demo/bundle \
  --artifact-sha256 "$ART" -- /tmp/funes-demo/app --selftest

./bin/funes-verify /tmp/funes-demo/bundle >/tmp/demosmoke-v1.txt
check "first verify reports INTEGRITY_VALID (doc's stated expected observation)" \
    "grep -q 'integrity_status=INTEGRITY_VALID' /tmp/demosmoke-v1.txt"
check "first verify reports test_observation_status=OBSERVED (doc's stated expected observation)" \
    "grep -q 'test_observation_status=OBSERVED' /tmp/demosmoke-v1.txt"
./bin/funes-verify --json /tmp/funes-demo/bundle >/tmp/demosmoke-v1.json

BLOB=/tmp/funes-demo/bundle/blobs/sha256/$ART
printf 'X' >>"$BLOB"
set +e
./bin/funes-verify /tmp/funes-demo/bundle >/tmp/demosmoke-v2.txt
MUTATE_EXIT=$?
set -e
check "mutated bundle exits 3 (doc: 'exit 3, DIGEST_MISMATCH')" "[ $MUTATE_EXIT -eq 3 ]"
check "mutated bundle names DIGEST_MISMATCH (doc's stated expected observation)" \
    "grep -q 'error_code=DIGEST_MISMATCH' /tmp/demosmoke-v2.txt"

echo "== docs/DEMO.md: failure evidence (fresh bundle, separate from the mutated one above) =="
mkdir -p /tmp/funes-demo2
cp examples/host-hello/main.c /tmp/funes-demo2/main.c
./bin/funes capture --out /tmp/funes-demo2/bundle \
  --artifact /tmp/funes-demo2/app:target-executable \
  -- gcc -std=c11 -O2 -o /tmp/funes-demo2/app /tmp/funes-demo2/main.c
ART2=$(grep '^artifact.0.sha256=' /tmp/funes-demo2/bundle/manifest.txt | cut -d= -f2)
set +e
./bin/funes add-test --bundle /tmp/funes-demo2/bundle \
  --artifact-sha256 "$ART2" -- /tmp/funes-demo2/app fail
FAILTEST_EXIT=$?
set -e
check "failing test command exits 3 (doc: '# exits 3')" "[ $FAILTEST_EXIT -eq 3 ]"
check "failing exit status recorded verbatim in the manifest (doc's grep)" \
    "grep -q 'exit_status=3' /tmp/funes-demo2/bundle/manifest.txt"
./bin/funes-verify /tmp/funes-demo2/bundle >/tmp/demosmoke-v3.txt
check "bundle with the failing test still verifies INTEGRITY_VALID (doc: evidence preserved, not hidden)" \
    "grep -q 'integrity_status=INTEGRITY_VALID' /tmp/demosmoke-v3.txt"

echo ""
if [ "$FAIL" -eq 0 ]; then echo "RESULT: demo-smoke all checks passed"; else echo "RESULT: demo-smoke FAILED"; fi
exit "$FAIL"
