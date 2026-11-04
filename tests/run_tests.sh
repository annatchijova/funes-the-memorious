#!/bin/sh
# FUNES host test suite (VERIFIED_HOST_ONLY). Every check can fail; a check
# that has never been seen red does not count (falsifiable-testing).
set -u
cd "$(dirname "$0")/.." || exit 1
FUNES=./bin/funes
VERIFY=./bin/funes-verify
PASS=0
FAIL=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ok() {
    if [ "$1" -eq 0 ]; then PASS=$((PASS + 1)); echo "PASS: $2";
    else FAIL=$((FAIL + 1)); echo "FAIL: $2"; fi
}

expect_exit() {
    # expect_exit WANT GOT LABEL
    if [ "$1" -eq "$2" ]; then PASS=$((PASS + 1)); echo "PASS: $3 (exit $2)";
    else FAIL=$((FAIL + 1)); echo "FAIL: $3 (want exit $1, got $2)"; fi
}

echo "== doctor =="
$FUNES doctor >"$TMP/doctor.txt" 2>&1
grep -q "qnx_toolchain_status=" "$TMP/doctor.txt"; ok $? "doctor reports qnx_toolchain_status"
$FUNES doctor --json >"$TMP/doctor.json" 2>&1
grep -q '"qnx_toolchain_status"' "$TMP/doctor.json"; ok $? "doctor --json emits toolchain status"

echo "== sha256 known vector via capture =="
# sha256("abc") must appear as a blob digest for a 3-byte stdout capture.
printf 'abc' >"$TMP/abc.txt"
$FUNES capture --out "$TMP/bvec" -- /bin/cat "$TMP/abc.txt" >"$TMP/capvec.log" 2>&1
grep -q "blob.ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad=3:stdout" "$TMP/bvec/manifest.txt"
ok $? "SHA-256 matches published vector for abc"

echo "== end-to-end host build + observed test =="
mkdir -p "$TMP/work"
cp examples/host-hello/main.c "$TMP/work/main.c"
$FUNES capture --out "$TMP/b1" --source "$TMP/work/main.c" \
    --artifact "$TMP/work/app:target-executable" \
    -- gcc -std=c11 -Wall -Wextra -Werror -O2 -o "$TMP/work/app" "$TMP/work/main.c" \
    >"$TMP/cap1.log" 2>&1
expect_exit 0 $? "capture compiles host fixture"
$VERIFY "$TMP/b1" >"$TMP/v1.txt" 2>&1
expect_exit 0 $? "verifier accepts fresh bundle"
grep -q "integrity_status=INTEGRITY_VALID" "$TMP/v1.txt"; ok $? "fresh bundle INTEGRITY_VALID"
grep -q "test_observation_status=NO_TEST_RECORD" "$TMP/v1.txt"; ok $? "no test record yet"
grep -q "signature_status=NOT_PRESENT" "$TMP/v1.txt"; ok $? "no signature claimed in v1"
ART=$(grep "^artifact.0.sha256=" "$TMP/b1/manifest.txt" | cut -d= -f2)
[ -n "$ART" ]; ok $? "artifact digest recorded"
$FUNES add-test --bundle "$TMP/b1" --artifact-sha256 "$ART" -- "$TMP/work/app" --selftest >"$TMP/t1.log" 2>&1
expect_exit 0 $? "observed selftest captured"
$VERIFY "$TMP/b1" >"$TMP/v2.txt" 2>&1
expect_exit 0 $? "verifier accepts bundle with test"
grep -q "test_observation_status=OBSERVED" "$TMP/v2.txt"; ok $? "test reported OBSERVED"
$VERIFY --json "$TMP/b1" >"$TMP/v2.json" 2>&1
grep -q '"integrity_status":"INTEGRITY_VALID"' "$TMP/v2.json"; ok $? "verifier --json valid"

echo "== failing test is preserved, not laundered =="
$FUNES add-test --bundle "$TMP/b1" --artifact-sha256 "$ART" -- "$TMP/work/app" fail >"$TMP/t2.log" 2>&1
expect_exit 3 $? "collector mirrors failing test exit 3"
grep -q "test.1.exit_status=3" "$TMP/b1/manifest.txt"; ok $? "failing exit status recorded verbatim"
$VERIFY "$TMP/b1" >"$TMP/v3.txt" 2>&1
expect_exit 0 $? "bundle with failing test still integrity-valid"

echo "== failing build is preserved =="
$FUNES capture --out "$TMP/bfail" -- /bin/false >"$TMP/capfail.log" 2>&1
expect_exit 1 $? "collector mirrors failing build exit 1"
grep -q "build.exit_status=1" "$TMP/bfail/manifest.txt"; ok $? "failing build recorded"
$VERIFY "$TMP/bfail" >"$TMP/vfail.txt" 2>&1
expect_exit 0 $? "failing-build bundle verifies as evidence"

echo "== tamper: one byte in artifact blob =="
cp -r "$TMP/b1" "$TMP/b1_tamper_art"
ABlob="$TMP/b1_tamper_art/blobs/sha256/$ART"
printf 'X' >>"$ABlob"
$VERIFY "$TMP/b1_tamper_art" >"$TMP/vt1.txt" 2>&1
expect_exit 3 $? "tampered artifact blob rejected"
grep -q "DIGEST_MISMATCH" "$TMP/vt1.txt"; ok $? "artifact tamper named DIGEST_MISMATCH"

echo "== tamper: one byte in stdout blob =="
cp -r "$TMP/b1" "$TMP/b1_tamper_out"
OUTD=$(grep "^build.stdout_sha256=" "$TMP/b1/manifest.txt" | cut -d= -f2)
printf 'X' >>"$TMP/b1_tamper_out/blobs/sha256/$OUTD"
$VERIFY "$TMP/b1_tamper_out" >"$TMP/vt2.txt" 2>&1
expect_exit 3 $? "tampered stdout blob rejected"

echo "== tamper: manifest field without reseal =="
cp -r "$TMP/b1" "$TMP/b1_tamper_man"
sed -i 's/build.exit_status=0/build.exit_status=9/' "$TMP/b1_tamper_man/manifest.txt"
$VERIFY "$TMP/b1_tamper_man" >"$TMP/vt3.txt" 2>&1
expect_exit 7 $? "tampered manifest rejected as SEAL_MISMATCH"
grep -q "SEAL_MISMATCH" "$TMP/vt3.txt"; ok $? "manifest tamper named SEAL_MISMATCH"

echo "== missing blob =="
cp -r "$TMP/b1" "$TMP/b1_missing"
rm "$TMP/b1_missing/blobs/sha256/$ART"
$VERIFY "$TMP/b1_missing" >"$TMP/vt4.txt" 2>&1
expect_exit 4 $? "missing artifact rejected"
grep -q "MISSING_ARTIFACT" "$TMP/vt4.txt"; ok $? "missing named MISSING_ARTIFACT"

echo "== unexpected extra blob file =="
cp -r "$TMP/b1" "$TMP/b1_extra"
printf 'evil' >"$TMP/b1_extra/blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
$VERIFY "$TMP/b1_extra" >"$TMP/vt5.txt" 2>&1
expect_exit 2 $? "unexpected blob file rejected"

echo "== symlink blob escape =="
cp -r "$TMP/b1" "$TMP/b1_sym"
rm "$TMP/b1_sym/blobs/sha256/$ART"
ln -s /bin/true "$TMP/b1_sym/blobs/sha256/$ART"
$VERIFY "$TMP/b1_sym" >"$TMP/vt6.txt" 2>&1
expect_exit 2 $? "symlink blob rejected"

echo "== unsupported schema (correctly resealed) =="
cp -r "$TMP/b1" "$TMP/b1_schema"
sed -i 's/schema_version=1/schema_version=99/' "$TMP/b1_schema/manifest.txt"
NEWSEAL=$(sha256sum "$TMP/b1_schema/manifest.txt" | cut -d' ' -f1)
printf '%s  manifest.txt\n' "$NEWSEAL" >"$TMP/b1_schema/SEAL.txt"
$VERIFY "$TMP/b1_schema" >"$TMP/vt7.txt" 2>&1
expect_exit 5 $? "unsupported schema rejected"
grep -q "UNSUPPORTED_SCHEMA" "$TMP/vt7.txt"; ok $? "schema failure named UNSUPPORTED_SCHEMA"

echo "== imported report stays IMPORTED =="
$FUNES capture --out "$TMP/b2" --source "$TMP/work/main.c" \
    --artifact "$TMP/work/app2:target-executable" \
    -- gcc -std=c11 -O2 -o "$TMP/work/app2" "$TMP/work/main.c" >"$TMP/cap2.log" 2>&1
ART2=$(grep "^artifact.0.sha256=" "$TMP/b2/manifest.txt" | cut -d= -f2)
printf 'external report claims: all tests passed\n' >"$TMP/report.txt"
$FUNES import-test --bundle "$TMP/b2" --artifact-sha256 "$ART2" --report "$TMP/report.txt" >"$TMP/imp.log" 2>&1
expect_exit 0 $? "import-test records report"
$VERIFY "$TMP/b2" >"$TMP/vimp.txt" 2>&1
expect_exit 0 $? "imported bundle integrity-valid"
grep -q "test_observation_status=IMPORTED_ONLY" "$TMP/vimp.txt"; ok $? "imported never promoted to OBSERVED"
grep -q "test.0.origin=IMPORTED" "$TMP/b2/manifest.txt"; ok $? "origin label IMPORTED in manifest"

echo "== unknown artifact association refused =="
$FUNES add-test --bundle "$TMP/b2" \
    --artifact-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
    -- /bin/true >"$TMP/tbad.log" 2>&1
if [ $? -ne 0 ]; then PASS=$((PASS + 1)); echo "PASS: unknown artifact digest refused by collector";
else FAIL=$((FAIL + 1)); echo "FAIL: unknown artifact digest refused by collector"; fi

echo "== secret environment does not enter manifest =="
FUNES_TEST_SECRET=hunter2secret $FUNES capture --out "$TMP/bsec" -- /bin/true >"$TMP/capsec.log" 2>&1
if [ ! -f "$TMP/bsec/manifest.txt" ]; then
    FAIL=$((FAIL + 1)); echo "FAIL: secret-test bundle was created"
elif grep -q "hunter2secret" "$TMP/bsec/manifest.txt"; then
    FAIL=$((FAIL + 1)); echo "FAIL: secret absent from manifest"
else PASS=$((PASS + 1)); echo "PASS: secret absent from manifest"; fi

echo "== truncation is flagged =="
$FUNES capture --out "$TMP/btrunc" -- head -c 2000000 /dev/zero >"$TMP/captr.log" 2>&1
grep -q "build.stdout_truncated=1" "$TMP/btrunc/manifest.txt"; ok $? "oversized output flagged truncated"
$VERIFY "$TMP/btrunc" >"$TMP/vtr.txt" 2>&1
expect_exit 0 $? "truncated capture still verifies"

echo "== determinism of digests under fixed epoch =="
$FUNES capture --out "$TMP/bd1" --epoch 1700000000 --source "$TMP/work/main.c" -- /bin/cat "$TMP/work/main.c" >"$TMP/cd1.log" 2>&1
$FUNES capture --out "$TMP/bd2" --epoch 1700000000 --source "$TMP/work/main.c" -- /bin/cat "$TMP/work/main.c" >"$TMP/cd2.log" 2>&1
D1=$(grep "^source.digest=" "$TMP/bd1/manifest.txt")
D2=$(grep "^source.digest=" "$TMP/bd2/manifest.txt")
[ "$D1" = "$D2" ]; ok $? "source digest stable across captures"
O1=$(grep "^build.stdout_sha256=" "$TMP/bd1/manifest.txt")
O2=$(grep "^build.stdout_sha256=" "$TMP/bd2/manifest.txt")
[ "$O1" = "$O2" ]; ok $? "stdout digest stable across captures"

echo "== verifier independence (clean environment) =="
env -i "$VERIFY" "$TMP/b1" >"$TMP/vind.txt" 2>&1
expect_exit 0 $? "verifier runs with empty environment, no collector state"

echo ""
echo "RESULT: pass=$PASS fail=$FAIL (host-only suite)"
[ "$FAIL" -eq 0 ]
