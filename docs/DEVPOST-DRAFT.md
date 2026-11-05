# Devpost Submission Draft — Funes the Memorious

**Status:** Draft only. Nothing in this file has been submitted to Devpost.

## Official-form facts to verify at submission time

- **Event:** QNX Global Hackathon 2026.
- **Category:** Developer Tooling & Host Tools.
- **Repository URL:** `https://github.com/annatchijova/funes-the-memorious`
- **License:** MIT.
- **Video URL:** TODO — public YouTube URL, under three minutes.
- **QNX execution status:** `NOT_RUN`; QNX SDP 8.0 is not installed on the
  development host. Do not add a target-runtime claim without
  `VERIFIED_REAL_QNX` evidence.

The official rules and submission form prevail if they change. Re-check them
immediately before submission.

## One-line summary

Funes the Memorious is a Linux host tool that captures build and test evidence
for QNX 8.0 work and lets an independent verifier check that evidence offline.

## The problem

In safety- and timing-sensitive QNX development, “the build passed” is often a
statement detached from the source state, toolchain, command output, and test
artifact that could substantiate it. A reviewer who was not at the terminal
cannot tell whether the binary, the logs, and the test result still match.

## The solution

Funes observes explicit build and test commands, records bounded evidence and
artifact hashes in a versioned bundle, then has a separate read-only verifier
recompute the checks offline. The central demo mutates one byte in a recorded
artifact; verification fails with `DIGEST_MISMATCH` and identifies the changed
evidence.

## What works today

- Linux-hosted collection, sealing, and independent offline verification.
- A 122-check host-only suite covering normal, failed, timeout, tamper,
  resource-limit, signature/trust, parser, and test-evidence paths.
- A reproducible host demonstration in `docs/DEMO.md`, checked by
  `scripts/demo-smoke.sh`.
- A QNX-oriented host-tool path: `funes doctor` records the QNX toolchain
  environment, and the repository includes the QNX 8 fixture and setup guide.

## Evidence boundary

This submission is a host-tool demonstration, not a claim that a QNX target
binary or runtime has been exercised. On this host, `funes doctor` reports
`qnx_toolchain_status=NOT_FOUND`; therefore QNX SDP compilation and QNX/QEMU
runtime evidence are `NOT_RUN`. A valid bundle proves consistency against its
recorded manifest, not software safety, host honesty, or a QNX execution that
did not occur.

## How to test it

```bash
make
make test
sh scripts/demo-smoke.sh
./bin/funes doctor
```

The first two commands build and run the host suite. The demo smoke test
executes the documented good-bundle → verify → one-byte mutation → precise
failure path. `doctor` reports the actual QNX environment rather than
simulating one.

## Three-minute video outline

1. **0:00–0:15 — problem.** A reviewer receives a binary and a passing claim,
   but cannot tell which evidence still matches.
2. **0:15–0:30 — mechanism.** Introduce Funes as a host tool that records the
   command, artifact, and test evidence, then lets a separate verifier inspect
   the bundle offline.
3. **0:30–1:35 — working path.** Run the host path from `docs/DEMO.md`:
   capture the host fixture, add its observed self-test, and show
   `INTEGRITY_VALID` / `OBSERVED`.
4. **1:35–2:15 — challenge the claim.** Append one byte to the artifact copy
   inside the bundle and show `DIGEST_MISMATCH` plus its non-zero exit.
5. **2:15–2:40 — why QNX.** Show `funes doctor`, the QNX setup guide, and the
   QNX fixture. Say that this is a QNX developer host tool; do not present the
   absent SDK as an executed target path.
6. **2:40–2:55 — boundary and close.** A valid bundle makes evidence
   challengeable; it does not certify safety or claim an execution not shown.

Show only commands and outputs that are recorded during the take. Do not use
stock QNX footage, third-party trademarks, or copyrighted music without
permission.

## Recording checklist

- Re-run `make test` and `sh scripts/demo-smoke.sh` immediately before capture.
- Record the terminal at readable scale and remove unrelated windows,
  credentials, and personal data.
- Use the commands in `docs/DEMO.md` in their documented order.
- Keep the final public video under three minutes and retain its source
  recording locally.
- Replace the video URL placeholder only after the public YouTube upload is
  available.
- Re-check the official rules, deadline, and form fields before pressing
  submit; this file is not a submission action.

## Submission readiness

The repository, public license, build instructions, host-only demo, and
truthful draft description are ready for review. The video URL, final form
fields, and real QNX evidence (if claimed) remain open.
