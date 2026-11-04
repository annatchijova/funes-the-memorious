# qnx8-hello fixture

Original, redistributable C fixture for FUNES QNX evidence exercises. It
prints a deterministic value, supports `--selftest`, and exits 3 when passed
`fail` so that failing-test evidence can be demonstrated honestly.

- Built with the host compiler: label the result `VERIFIED_HOST_ONLY`.
- Built with a licensed QNX SDP 8.0 `qcc` and a validated target: only then
  may a run be labeled `VERIFIED_REAL_QNX`, with the `qcc` identity, target,
  flags, and artifact digest captured by `funes capture` (see
  `../../docs/QNX-SETUP.md`).

No QNX run of this fixture has happened yet (Level 2 is `BLOCKED` without
the SDP). This README claims no QNX execution.
