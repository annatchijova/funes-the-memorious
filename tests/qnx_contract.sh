#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

PASS=0
FAIL=0

pass() {
    PASS=$((PASS + 1))
    echo "PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "FAIL: $1"
}

FIXTURE="$TMP/qnx8-hello"
cp -R "$ROOT/examples/qnx8-hello" "$FIXTURE"
FAKE_QCC="$TMP/qcc"
cp "$ROOT/tests/fixtures/fake-qcc.sh" "$FAKE_QCC"
chmod 755 "$FAKE_QCC"
QCC_LOG="$TMP/qcc.args"

QNX_CONTRACT_LOG="$QCC_LOG" HOST_CC="${CC:-cc}" \
    make -C "$FIXTURE" clean all QCC="$FAKE_QCC" \
    QNX_TARGET_FLAGS="-Vgcc_ntox86_64" >"$TMP/make.log" 2>&1 \
    && pass "fixture build invokes the selected qcc command" \
    || fail "fixture build invokes the selected qcc command"

grep -Fx -- '-Vgcc_ntox86_64' "$QCC_LOG" >/dev/null \
    && pass "target flag reaches qcc unchanged" \
    || fail "target flag reaches qcc unchanged"
grep -Fx -- 'main.c' "$QCC_LOG" >/dev/null \
    && pass "fixture source reaches qcc" \
    || fail "fixture source reaches qcc"

OUTPUT=$(
    QNX_CONTRACT_LOG="$QCC_LOG" PATH="$TMP:$PATH" \
        "$ROOT/bin/funes" doctor 2>&1
)
printf '%s\n' "$OUTPUT" | grep -Fx 'qcc_found=1' >/dev/null \
    && pass "doctor detects the contract qcc" \
    || fail "doctor detects the contract qcc"
printf '%s\n' "$OUTPUT" | grep -Fx 'qnx_toolchain_status=FOUND_ON_PATH_UNVERIFIED' >/dev/null \
    && pass "doctor labels contract qcc as unverified" \
    || fail "doctor labels contract qcc as unverified"

BUNDLE="$TMP/bundle"
QNX_HOST=1 QNX_TARGET=1 PATH="$TMP:$PATH" \
    "$ROOT/bin/funes" capture --out "$BUNDLE" -- \
    "$FIXTURE/qnx8-hello" --selftest >"$TMP/capture.log" 2>&1 \
    && pass "capture completes with QNX variables and contract qcc present" \
    || fail "capture completes with QNX variables and contract qcc present"
grep -Fx 'qnx.host_present=1' "$BUNDLE/manifest.txt" >/dev/null \
    && pass "manifest records discovered qcc presence" \
    || fail "manifest records discovered qcc presence"
grep -Fx 'qnx.target_present=0' "$BUNDLE/manifest.txt" >/dev/null \
    && pass "manifest does not claim a QNX target" \
    || fail "manifest does not claim a QNX target"
grep -Fx 'qnx8-hello selftest: ok value=42' "$BUNDLE/blobs/sha256/$(grep '^build.stdout_sha256=' "$BUNDLE/manifest.txt" | cut -d= -f2)" >/dev/null \
    && pass "fixture behavior is captured" \
    || fail "fixture behavior is captured"

echo "RESULT: pass=$PASS fail=$FAIL (QNX contract-only; no real QNX evidence)"
[ "$FAIL" -eq 0 ]
