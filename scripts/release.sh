#!/bin/sh
# Builds a verifiable, checksummed release artifact (Level 6). This script
# only PRODUCES a local tarball + SHA256SUMS for inspection or CI upload --
# it does not create a git tag, push anything, or publish a GitHub Release.
# Cutting an actual public release is a deliberate, visible action for a
# human to take explicitly (e.g. `git tag vX.Y.Z && git push --tags` and
# creating the GitHub Release through the UI/`gh release create`), not
# something a script should do on its own. This project also has no
# version-tag convention yet; that is a decision for the author, so the
# artifact is named by commit, not by an invented version number.
set -eu
cd "$(dirname "$0")/.." || exit 1

make clean
make

SHA=$(git rev-parse --short HEAD)
OUT="funes-$SHA"
rm -rf "/tmp/$OUT"
mkdir -p "/tmp/$OUT"

cp bin/funes bin/funes-verify README.md LICENSE docs/DEMO.md docs/LIMITATIONS.md "/tmp/$OUT/"

OUTDIR="dist"
mkdir -p "$OUTDIR"
TARBALL="$OUTDIR/$OUT.tar.gz"
tar -czf "$TARBALL" -C /tmp "$OUT"
rm -rf "/tmp/$OUT"

( cd "$OUTDIR" && sha256sum "$(basename "$TARBALL")" > "$OUT.SHA256SUMS" )

echo "release artifact: $TARBALL"
echo "checksum file:    $OUTDIR/$OUT.SHA256SUMS"
echo ""
echo "verify with:"
echo "  cd $OUTDIR && sha256sum -c $OUT.SHA256SUMS"
