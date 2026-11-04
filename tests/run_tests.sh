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

echo "== level 3: signing and trust roots =="
$FUNES capture --out "$TMP/bs" -- /bin/echo signed-evidence >"$TMP/caps.log" 2>&1
$FUNES keygen --out "$TMP/seed1.txt" --pub-out "$TMP/pub1.txt" >"$TMP/kg1.log" 2>&1
expect_exit 0 $? "keygen creates keypair"
[ "$(stat -c %a "$TMP/seed1.txt")" = "600" ]; ok $? "seed file mode 0600"
$FUNES keygen --out "$TMP/seed1.txt" --pub-out "$TMP/pub1b.txt" >"$TMP/kg1b.log" 2>&1
if [ $? -ne 0 ]; then PASS=$((PASS + 1)); echo "PASS: keygen refuses to overwrite existing key";
else FAIL=$((FAIL + 1)); echo "FAIL: keygen refuses to overwrite existing key"; fi
$FUNES sign --bundle "$TMP/bs" --key "$TMP/seed1.txt" >"$TMP/sign1.log" 2>&1
expect_exit 0 $? "sign produces signature material"
[ -f "$TMP/bs/signatures/ed25519.sig" ]; ok $? "signature file present"
SEEDHEX=$(tail -n 1 "$TMP/seed1.txt")
if grep -rq "$SEEDHEX" "$TMP/bs"; then
    FAIL=$((FAIL + 1)); echo "FAIL: private seed never enters bundle"
else PASS=$((PASS + 1)); echo "PASS: private seed never enters bundle"; fi
$VERIFY "$TMP/bs" >"$TMP/vs0.txt" 2>&1
expect_exit 0 $? "signed bundle verifies without trust root (integrity)"
grep -q "signature_status=VALID" "$TMP/vs0.txt"; ok $? "signature VALID under bundle key"
grep -q "signer_trust_status=UNTRUSTED_SIGNER" "$TMP/vs0.txt"; ok $? "no trust root means UNTRUSTED, never authenticated"
$VERIFY --trusted-key "$TMP/pub1.txt" "$TMP/bs" >"$TMP/vs1.txt" 2>&1
expect_exit 0 $? "signed bundle verifies with matching trusted key"
grep -q "signer_trust_status=TRUSTED_SIGNER" "$TMP/vs1.txt"; ok $? "matching key is TRUSTED_SIGNER"
grep -q "does not certify software safety" "$TMP/vs1.txt"; ok $? "trusted report still states limits (no execution proof)"
$FUNES keygen --out "$TMP/seed2.txt" --pub-out "$TMP/pub2.txt" >"$TMP/kg2.log" 2>&1
$VERIFY --trusted-key "$TMP/pub2.txt" "$TMP/bs" >"$TMP/vs2.txt" 2>&1
expect_exit 9 $? "different trusted key rejected"
grep -q "SIGNER_UNTRUSTED" "$TMP/vs2.txt"; ok $? "wrong trust root named SIGNER_UNTRUSTED"
cp -r "$TMP/bs" "$TMP/bs_badsig"
printf 'Z' | dd of="$TMP/bs_badsig/signatures/ed25519.sig" bs=1 seek=0 count=1 conv=notrunc 2>/dev/null
$VERIFY --trusted-key "$TMP/pub1.txt" "$TMP/bs_badsig" >"$TMP/vs3.txt" 2>&1
expect_exit 8 $? "flipped signature byte rejected"
grep -q "SIGNATURE_INVALID" "$TMP/vs3.txt"; ok $? "bad signature named SIGNATURE_INVALID"
cp -r "$TMP/bs" "$TMP/bs_stale"
$FUNES capture --out "$TMP/bother" -- /bin/echo other >"$TMP/capo.log" 2>&1
cp "$TMP/bother/manifest.txt" "$TMP/bs_stale/manifest.txt"
cp "$TMP/bother/SEAL.txt" "$TMP/bs_stale/SEAL.txt"
cp -r "$TMP/bother/blobs" "$TMP/bs_stale/blobs2" 2>/dev/null
rm -rf "$TMP/bs_stale/blobs"
mv "$TMP/bs_stale/blobs2" "$TMP/bs_stale/blobs"
$VERIFY --trusted-key "$TMP/pub1.txt" "$TMP/bs_stale" >"$TMP/vs4.txt" 2>&1
expect_exit 8 $? "signature over stale manifest rejected"
grep -q "SIGNATURE_INVALID" "$TMP/vs4.txt"; ok $? "stale signature named SIGNATURE_INVALID"
printf 'not-a-key\n' >"$TMP/badkey.txt"
$FUNES sign --bundle "$TMP/bs" --key "$TMP/badkey.txt" >"$TMP/signbad.log" 2>&1
if [ $? -ne 0 ]; then PASS=$((PASS + 1)); echo "PASS: malformed seed file rejected by sign";
else FAIL=$((FAIL + 1)); echo "FAIL: malformed seed file rejected by sign"; fi
$VERIFY --json --trusted-key "$TMP/pub1.txt" "$TMP/bs" >"$TMP/vs5.txt" 2>&1
grep -q '"signer_trust_status":"TRUSTED_SIGNER"' "$TMP/vs5.txt"; ok $? "json reports TRUSTED_SIGNER"

echo "== level 5: forensic comparison =="
./bin/funes compare "$TMP/b1" "$TMP/b1" >"$TMP/cmp0.txt" 2>&1
expect_exit 0 $? "compare identical bundle exits 0"
grep -q "material_differences=0" "$TMP/cmp0.txt"; ok $? "identical evidence reports zero diffs"
printf 'int main(void){return 7;}\n' >"$TMP/work/main2.c"
./bin/funes capture --out "$TMP/b3" --source "$TMP/work/main2.c" \
    --artifact "$TMP/work/app3:target-executable" \
    -- gcc -std=c11 -O2 -o "$TMP/work/app3" "$TMP/work/main2.c" >"$TMP/cap3.log" 2>&1
./bin/funes compare "$TMP/b1" "$TMP/b3" >"$TMP/cmp1.txt" 2>&1
expect_exit 10 $? "compare different builds exits 10"
grep -q "DIFF source.digest" "$TMP/cmp1.txt"; ok $? "compare names source change"
grep -q "DIFF artifact.0.sha256" "$TMP/cmp1.txt"; ok $? "compare names artifact change"
./bin/funes compare --json "$TMP/b1" "$TMP/b3" >"$TMP/cmp2.txt" 2>&1
grep -q '"compare_status":"OK"' "$TMP/cmp2.txt"; ok $? "compare json reports differences"
./bin/funes compare "$TMP/b1" "$TMP/b1_tamper_art" >"$TMP/cmp3.txt" 2>&1
expect_exit 2 $? "compare refuses tampered input"
grep -q "INVALID_INPUT" "$TMP/cmp3.txt"; ok $? "tampered compare input named INVALID_INPUT"

echo "== red team round 1 regressions =="
cp -r "$TMP/b1" "$TMP/brt1"
printf 'evil' >"$TMP/brt1/blobs/sha256/.hidden"
$VERIFY "$TMP/brt1" >"$TMP/vrt1.txt" 2>&1
expect_exit 2 $? "RT-01 hidden dotfile in blobs rejected"
mkdir -p "$TMP/brt2"
ln -s "$TMP/b1/manifest.txt" "$TMP/brt2/manifest.txt"
ln -s "$TMP/b1/SEAL.txt" "$TMP/brt2/SEAL.txt"
ln -s "$TMP/b1/blobs" "$TMP/brt2/blobs"
$VERIFY "$TMP/brt2" >"$TMP/vrt2.txt" 2>&1
expect_exit 2 $? "RT-02 fully symlinked bundle rejected"
mkdir -p "$TMP/evil"
cat >"$TMP/evil/fake.c" <<'FAKEEOF'
#include <stdint.h>
#include <stdio.h>
#include <string.h>
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed) {
    FILE *f = fopen(FAKELOG, "ab");
    if (f) { fwrite(seed, 1, 32, f); fclose(f); }
    memset(pk, 0x41, 32); memset(sk, 0x42, 64);
    return 0;
}
int crypto_sign_detached(unsigned char *sig, unsigned long long *len, const unsigned char *m, unsigned long long mlen, const unsigned char *sk) {
    (void)m; (void)mlen;
    FILE *f = fopen(FAKELOG, "ab");
    if (f) { fwrite(sk, 1, 64, f); fclose(f); }
    memset(sig, 0x43, 64); *len = 64;
    return 0;
}
FAKEEOF
# shellcheck disable=SC2086
gcc -shared -fPIC -DFAKELOG="\"$TMP/evil/leak.log\"" -o "$TMP/evil/libsodium.so.23" "$TMP/evil/fake.c" 2>"$TMP/evil/cc.log"
if [ -f "$TMP/evil/libsodium.so.23" ]; then
    rm -f "$TMP/evil/leak.log"
    LD_LIBRARY_PATH="$TMP/evil" $FUNES sign --bundle "$TMP/b2" --key "$TMP/seed1.txt" >"$TMP/signrt.log" 2>&1
    if [ -f "$TMP/evil/leak.log" ]; then
        FAIL=$((FAIL + 1)); echo "FAIL: RT-03 fake libsodium received no key material"
    else PASS=$((PASS + 1)); echo "PASS: RT-03 fake libsodium received no key material"; fi
else
    echo "SKIP: RT-03 fake libsodium build unavailable"
fi
$FUNES capture --out "$TMP/brt5" -- /bin/true >"$TMP/caprt5.log" 2>&1
mkdir -p "$TMP/brt5/signatures"
printf 'IMPORTANT-DATA' >"$TMP/victim.txt"
ln -s "$TMP/victim.txt" "$TMP/brt5/signatures/ed25519.sig"
$FUNES sign --bundle "$TMP/brt5" --key "$TMP/seed1.txt" >"$TMP/signrt5.log" 2>&1
if [ $? -ne 0 ] && [ "$(cat "$TMP/victim.txt")" = "IMPORTANT-DATA" ]; then
    PASS=$((PASS + 1)); echo "PASS: RT-05 sign refuses symlinked signature file, victim intact"
else FAIL=$((FAIL + 1)); echo "FAIL: RT-05 sign refuses symlinked signature file, victim intact"; fi
cp -r "$TMP/b1" "$TMP/brt6"
printf 'fake report' >"$TMP/brt6/extra-report.html"
$VERIFY "$TMP/brt6" >"$TMP/vrt6.txt" 2>&1
expect_exit 2 $? "RT-06 unexpected bundle-root file rejected"
mkdir -p "$TMP/brt2b/outside"
printf 'planted' >"$TMP/brt2b/outside/ed25519.sig"
cp -r "$TMP/b1" "$TMP/brt2b/bundle"
rm -rf "$TMP/brt2b/bundle/signatures" 2>/dev/null
ln -s "$TMP/brt2b/outside" "$TMP/brt2b/bundle/signatures"
$VERIFY "$TMP/brt2b/bundle" >"$TMP/vrt2b.txt" 2>&1
expect_exit 2 $? "RT-02 follow-up: symlinked signatures directory rejected"
cp -r "$TMP/b1" "$TMP/brt2c"
rm -rf "$TMP/brt2c/signatures" 2>/dev/null
printf 'not a directory' >"$TMP/brt2c/signatures"
$VERIFY "$TMP/brt2c" >"$TMP/vrt2c.txt" 2>&1
expect_exit 2 $? "RT-02 follow-up: non-directory signatures rejected"

echo ""
echo "RESULT: pass=$PASS fail=$FAIL (host-only suite)"
[ "$FAIL" -eq 0 ]
