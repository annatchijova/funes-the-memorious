# Demo

Every command below was executed on the Linux development host and is
labeled `VERIFIED_HOST_ONLY`. No QNX claim is made; the QNX path is in
`docs/QNX-SETUP.md` and becomes a demo only with a real SDP (Level 2/7).

## Three-minute host demo

```bash
make
./bin/funes doctor

# Act I-II: claim + evidence. Build the host fixture under observation.
mkdir -p /tmp/funes-demo
cp examples/host-hello/main.c /tmp/funes-demo/main.c
./bin/funes capture --out /tmp/funes-demo/bundle \
  --source /tmp/funes-demo/main.c \
  --artifact /tmp/funes-demo/app:target-executable \
  -- gcc -std=c11 -Wall -Wextra -Werror -O2 -o /tmp/funes-demo/app /tmp/funes-demo/main.c

ART=$(grep '^artifact.0.sha256=' /tmp/funes-demo/bundle/manifest.txt | cut -d= -f2)
./bin/funes add-test --bundle /tmp/funes-demo/bundle \
  --artifact-sha256 "$ART" -- /tmp/funes-demo/app --selftest

# Act III: independent verification, offline.
./bin/funes-verify /tmp/funes-demo/bundle
./bin/funes-verify --json /tmp/funes-demo/bundle

# Act IV-V: mutate one byte of the artifact copy inside the bundle.
BLOB=/tmp/funes-demo/bundle/blobs/sha256/$ART
printf 'X' >> "$BLOB"
./bin/funes-verify /tmp/funes-demo/bundle   # exit 3, DIGEST_MISMATCH

# Act VI: the boundary. Re-read the limitations line of any report:
# validity does not certify software safety or host honesty.
```

Expected observations: the first verify prints
`integrity_status=INTEGRITY_VALID` with
`test_observation_status=OBSERVED`; after the mutation it prints
`error_code=DIGEST_MISMATCH` naming the artifact digest and exits 3.

## Failure evidence (also real)

A fresh bundle, deliberately separate from the mutated one above, so this
section stands on its own regardless of what order a reader runs things in.

```bash
# A failing test is evidence, not an embarrassment to delete.
mkdir -p /tmp/funes-demo2
cp examples/host-hello/main.c /tmp/funes-demo2/main.c
./bin/funes capture --out /tmp/funes-demo2/bundle \
  --artifact /tmp/funes-demo2/app:target-executable \
  -- gcc -std=c11 -O2 -o /tmp/funes-demo2/app /tmp/funes-demo2/main.c
ART2=$(grep '^artifact.0.sha256=' /tmp/funes-demo2/bundle/manifest.txt | cut -d= -f2)
./bin/funes add-test --bundle /tmp/funes-demo2/bundle \
  --artifact-sha256 "$ART2" -- /tmp/funes-demo2/app fail   # exits 3
grep 'exit_status=3' /tmp/funes-demo2/bundle/manifest.txt
./bin/funes-verify /tmp/funes-demo2/bundle   # still INTEGRITY_VALID -- the failing test is preserved, not hidden
```
