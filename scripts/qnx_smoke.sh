#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

blocked() {
    echo "STATUS: BLOCKED — $1" >&2
    echo "Install/source the licensed QNX SDP 8.0 and rerun with explicit QNX_TARGET_FLAGS." >&2
    exit 2
}

QCC=${QCC:-qcc}
QCC_PATH=$(command -v "$QCC" 2>/dev/null || true)
[ -n "$QCC_PATH" ] || blocked "qcc was not found on PATH"
[ -n "${QNX_HOST:-}" ] || blocked "QNX_HOST is unset"
[ -n "${QNX_TARGET:-}" ] || blocked "QNX_TARGET is unset"
[ -d "$QNX_HOST" ] || blocked "QNX_HOST does not name a directory: $QNX_HOST"
[ -d "$QNX_TARGET" ] || blocked "QNX_TARGET does not name a directory: $QNX_TARGET"
[ -n "${QNX_TARGET_FLAGS:-}" ] || blocked "QNX_TARGET_FLAGS is unset; refusing to guess a target"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
FIXTURE="$TMP/qnx8-hello"
BUNDLE="$TMP/evidence"
cp -R "$ROOT/examples/qnx8-hello" "$FIXTURE"

echo "INFO: qcc=$QCC_PATH"
echo "INFO: QNX_HOST=$QNX_HOST"
echo "INFO: QNX_TARGET=$QNX_TARGET"
echo "INFO: QNX_TARGET_FLAGS=$QNX_TARGET_FLAGS"

if ! "$ROOT/bin/funes" capture \
    --out "$BUNDLE" \
    --source "$FIXTURE/main.c" \
    --artifact "$FIXTURE/qnx8-hello:target-executable" \
    --timeout-sec 60 \
    -- make -C "$FIXTURE" clean all QCC="$QCC_PATH" QNX_TARGET_FLAGS="$QNX_TARGET_FLAGS"; then
    echo "STATUS: FAIL — qcc build failed; captured bundle preserved at $BUNDLE" >&2
    exit 1
fi

"$ROOT/bin/funes-verify" "$BUNDLE"
grep -Fx 'qnx.host_present=1' "$BUNDLE/manifest.txt" >/dev/null
grep -Fx 'qnx.target_present=0' "$BUNDLE/manifest.txt" >/dev/null

echo "STATUS: BUILD_CAPTURED_AND_VERIFIED"
echo "LIMITATION: this proves a captured qcc build only; target execution and VERIFIED_REAL_QNX labeling remain separate evidence steps."
