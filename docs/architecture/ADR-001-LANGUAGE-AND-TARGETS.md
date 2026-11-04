# ADR-001 — Use C for the host collector, the independent verifier, and the QNX fixture

Date: 2026-11-04
Status: accepted
Reversibility: one-way-ish (cost: rewriting both binaries and the bundle
parser; the bundle format itself is language-neutral and survives a rewrite)

## Forces at the time

- The owner directed C for this project. That directive is the primary force
  and is recorded honestly as such, not retrofitted into a purely technical
  narrative.
- The product is a Linux-hosted developer tool for QNX 8.0 development
  (QNX Global Hackathon 2026, Developer Tooling & Host Tools). The host
  binaries run on Linux; they never run inside QNX.
- The verifier must be independently implementable and auditable: a small
  binary with no language-runtime dependency is easier for a reviewer to
  inspect, rebuild, and run offline.
- The QNX demonstration fixture must be built with the official QNX `qcc`
  toolchain. C is the native language of that toolchain and of the fixture.
- The founding host (Linux Mint, gcc 13.3) has no QNX SDP installed. Any
  choice requiring QNX execution of the host tool itself would be blocked
  from day one.
- Unknown at decision time: which SHA-256/Ed25519 library, if any, will be
  linked in Level 3; whether structured test-report parsers will be needed
  in Level 4.

## Decision

- Collector (`funes`), independent verifier (`funes-verify`), and the QNX
  fixture are written in C (C11), built with the host C compiler and `make`.
- The evidence bundle format is a language-neutral, canonical text format
  (see `docs/spec/EVIDENCE-BUNDLE-v1.md`) so that a verifier can be written
  in any language without porting C code.
- Compiler roles are distinct and never conflated:
  - Host compiler (`gcc`/`clang` on Linux) builds `funes` and `funes-verify`.
  - QNX `qcc` (only when the licensed SDP 8.0 is installed) builds the
    fixture for a QNX target. Its output is evidence, never a host binary.

## Alternatives rejected

- **Go (collector + verifier)** — rejected because the owner directed C, and
  because a Go verifier carries a runtime and a larger binary that a
  reviewer must trust or rebuild with a Go toolchain. Best argument for it:
  excellent standard library for process handling, hashing, and canonical
  JSON, with simpler memory safety than C. If C parser hardening becomes
  the dominant cost, this is the first alternative to reopen.
- **Rust** — rejected because the owner directed C and the QNX fixture would
  still be C, splitting the project across two toolchains for no proven
  gain at this scale. Best argument for it: memory safety without a garbage
  collector and strong fuzzing tooling. Reopen if a suitable QNX-target
  story or team preference emerges.
- **C++** — rejected because its larger surface (exceptions, RTTI, template
  diagnostics) adds audit burden to the verifier without a needed feature.
  Best argument for it: RAII and the standard library reduce manual
  resource-management errors relative to C.
- **TypeScript/Node.js** — rejected because the verifier would depend on a
  JavaScript runtime being present and identical on the reviewer's machine,
  weakening the offline, minimal-dependency guarantee. Best argument for it:
  fast CLI development and ubiquitous JSON handling.
- **Python** — rejected explicitly per the proposal (do not default to
  Python) and because a Python verifier requires an interpreter and exposes
  verification to environment differences (`PYTHONHASHSEED`, library
  versions) that must then be pinned. Best argument for it: fastest path to
  a prototype and the richest testing ecosystem. It remains acceptable for
  throwaway analysis scripts outside the shipped binaries, never for the
  collector or verifier.

### The Go/QNX distinction, stated precisely

The standard Go toolchain does not list QNX as a supported `GOOS` target.
`GOOS=qnx go build` is therefore not proposed anywhere in this project, and
no Linux-compiled binary (in any language) is ever presented as running on
QNX. Go would have been a legitimate choice for the Linux-hosted binaries
only; it was not chosen, for the reasons above. The QNX-targeted artifact in
this project is exclusively the C fixture compiled by `qcc`.

## Assumption this rests on

The team can write and fuzz C parsers carefully enough that the verifier's
attack surface (untrusted bundles) stays manageable with strict bounds,
hex-encoded user-controlled strings, and fail-closed parsing. If that
assumption fails — for example, repeated memory-safety findings in the
verifier — this decision is wrong, not merely dated, and the verifier should
be rewritten first (Go and Rust are the reopen candidates).

Consequences accepted now:

- Manual memory and error management in both binaries; every allocation and
  file operation must be checked.
- No JSON library: the bundle manifest is canonical text, and JSON is only
  ever emitted (verifier `--json`), never parsed from untrusted input.

Deferred: crypto library selection (Level 3), structured report parsers
(Level 4), release packaging (Level 6).

## Revisit trigger

Reopen this ADR if any of the following is observed: (a) two or more
memory-safety defects found in the verifier's parser after Level 1, (b) the
project needs to execute code on a QNX target beyond the C fixture, or
(c) the owner directs a language change. Review by the Level 6 audit if none
of the above has fired.

## Anchored at

- `Makefile` (builds both C binaries; carries no language alternative).
- `src/funes.c`, `verifier/funes_verify.c` (the two implementations this
  ADR governs; surprising parser bounds in those files point back here).
- `docs/spec/EVIDENCE-BUNDLE-v1.md` (the language-neutral contract that
  makes this decision reversible).
