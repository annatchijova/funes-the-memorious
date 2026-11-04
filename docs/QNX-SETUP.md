# QNX Setup

Status: `BLOCKED` on the founding host (no SDP installed). Language: English.
Nothing in this document claims a QNX run happened. It is the procedure to
execute when a licensed QNX SDP 8.0 is available, after which the observed
output replaces the expected output here and in `docs/STATUS.md`.

## Facts and references

- Product target: QNX SDP 8.0 / QNX Everywhere, Developer Tooling & Host
  Tools category of the QNX Global Hackathon 2026.
- Official pages: [hackathon](https://qnx.devpost.com/),
  [rules](https://qnx.devpost.com/rules),
  [QNX Everywhere get-started](https://qnx.software/en/developers/get-started/qnx-everywhere),
  [SDP 8.0 docs](https://www.qnx.com/developers/docs/8.0/index.html),
  [quickstart](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.quickstart/topic/about.html),
  [Linux host install](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.quickstart/topic/install_host.html),
  [qcc reference](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/q/qcc.html).
- Check the SDP 8.0 release notes for supported Linux host distributions
  before installing. The owner's host is Linux Mint; if Mint is not a
  supported host, run the SDP inside an isolated supported Ubuntu VM. Do not
  force-install on an unsupported host and do not record such a run as
  supported.
- Funes never installs the SDP, accepts its license, stores credentials, or
  redistributes SDK content, target binaries from the SDK, or samples.

## Procedure (to run with a licensed SDP)

1. Install the SDP per the official Linux host instructions, under your own
   license, outside this repository (never inside the repo tree).
2. Load the SDP environment in a fresh shell (the exact script name comes
   from the installed SDP; typically `qnxsdp-env.sh` under the install
   root). Confirm `QNX_HOST` and `QNX_TARGET` are set.
3. Observe — do not assume — the toolchain:

```bash
command -v qcc q++
qcc -V 2>&1 | head -n 50
ls "$QNX_TARGET"
```

4. Run the doctor and record its actual output:

```bash
make
./bin/funes doctor
./bin/funes doctor --json
```

Expected today (no SDP): `qnx_toolchain_status=NOT_FOUND`. With a real SDP,
the doctor must report the resolved `qcc` path and bounded version output,
still labeled as unauthenticated version text, not proof of authenticity.

5. Build the fixture under observation (target validated against what the
   installed `qcc` supports; never hard-code a variant first):

```bash
./bin/funes capture --out /tmp/funes-qnx-bundle \
  --source examples/qnx8-hello/main.c \
  --artifact /tmp/qnx8-hello:target-executable \
  -- qcc -o /tmp/qnx8-hello examples/qnx8-hello/main.c
./bin/funes-verify /tmp/funes-qnx-bundle
file /tmp/qnx8-hello
```

Replace the `qcc` invocation with the documented target-selection flags for
the installed SDP, and record the exact command used. Only after `file` (or
the SDP's own inspection tools) confirms a QNX target binary and the bundle
verifies may the run be labeled `VERIFIED_REAL_QNX` in `docs/STATUS.md`.

## Failure handling

- `qcc` absent or `QNX_*` unset: doctor explains the missing prerequisite;
  Level 2 stays `BLOCKED`. Contract tests for argument formation may run and
  must be labeled `CONTRACT_TEST_ONLY`.
- Unsupported target: the adapter must reject it from the `qcc`-reported
  target list rather than attempting the build.
- Any failed step: preserve output, label `FAILED` with the reason, and do
  not substitute a host-compiled binary.
