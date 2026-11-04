# ADR-003 — JSON for the structured test-report adapter, hand-rolled and hardened

Date: 2026-11-04
Status: accepted
Reversibility: two-way (the adapter is additive: `import-test` without
`--format` keeps today's opaque-blob behavior unchanged; a future JUnit/TAP
adapter can be added beside it without touching this one)

## Forces at the time

- Level 4 wants structured test-report adapters "where practical" (Roadmap),
  so a parser is unavoidable for at least one format.
- This project's C style is minimal-dependency and hand-rolled parsers
  throughout: the evidence-bundle manifest itself is a from-scratch line
  parser (ADR-001), not an off-the-shelf format. The same posture should
  govern a new untrusted-input parser rather than reaching for a library.
- The input is untrusted by construction: a report file is attacker-
  reachable the same way a bundle itself is (threat model: "attacker CAN
  submit a malicious bundle"). Whatever parses it needs the same fail-closed
  discipline as the manifest parser, not a best-effort convenience reader.
- The verifier must stay independent (no shared object code with the
  collector) and as small as practically possible in attack surface; adding
  a new parser to the collector only, never the verifier, keeps that
  property intact.

## Decision

- The adapter accepts **JSON only** in this round: `funes import-test
  --format json`. The project already speaks JSON in three other places
  (`doctor --json`, `funes-verify --json`, `compare --json`), so this isn't
  a new format vocabulary for the project, just a new place it's parsed.
- The reader is hand-written (`src/json_min.c`/`.h`), compiled into
  `bin/funes` only — never into `bin/funes-verify`, which never needs to
  re-parse this JSON; it only validates the plain typed manifest keys the
  collector already extracted (`test.<n>.report_format/passed/case_count`),
  the same as every other field in the format.
- The parser is a generic recursive-descent reader for *any* JSON value
  (object/array/string/bool/number/null), not a "peek the expected type and
  skip everything else" shortcut — every value, wherever it appears in the
  document, is parsed through the same depth-counted, length-capped path.
  Hardening limits enforced inside the parser itself, not just at the file
  level: max nesting depth 32 (checked before each recursive descent into an
  object or array, not relying on the OS stack guard page), max string
  length 65536 bytes, max array/object member count 10000. Duplicate keys
  at any nesting level are rejected, matching the manifest format's own
  duplicate-key rule. The accepted top-level shape is a strict allowlist
  (`name` optional string, `passed` required bool, `cases` optional array of
  `{name, passed}`) — any unknown key, wrong type, or trailing data after
  the top-level value is rejected, nothing is written to the bundle.
- The report file is `stat`-checked against a 1 MiB cap *before* it is read,
  same stat-first discipline as the verifier's blob-size check (Red Team
  Round 1, RT-04) — the cap bounds total bytes; the parser's own limits
  bound the shape of the work done with those bytes.

## Alternatives rejected

- **JUnit XML** — rejected for this round. An XML reader has a much larger
  attack surface for untrusted input than JSON (entity expansion/XXE, DTDs,
  namespace handling, encoding declarations) and this project has already
  chosen, consistently, not to carry that surface for the manifest format
  itself. Best argument for it: JUnit XML is the de facto standard test
  report format across CI ecosystems, and most real-world reports already
  exist in this shape — left as explicit future work, not silently dropped.
- **TAP (Test Anything Protocol)** — rejected for this round; simpler than
  XML but still a second grammar to maintain and harden for comparatively
  little gain over JSON for a from-scratch implementation. Left as future
  work alongside JUnit.
- **A JSON library (e.g. vendored cJSON)** — rejected on the same grounds as
  ADR-002 rejected a vendored Ed25519: a third-party parser not written for
  this project's hardening requirements (explicit duplicate-key rejection,
  explicit depth/length/count caps matching this project's own posture)
  would need to be audited and likely patched anyway; a project this size
  gains little by importing code instead of writing ~350 lines reviewed
  against a fixed, small schema.
- **Generic/permissive JSON (accept any shape, extract best-effort)** —
  rejected: this project's "unknown key fails closed" rule for the manifest
  format exists for a reason, and a permissive report parser would be the
  one place that rule is quietly abandoned, inviting exactly the kind of
  silent-data-loss or confused-deputy bug the manifest format was designed
  to avoid.

## Consequences accepted now

A valid report must match the fixed shape exactly; a CI system producing
richer JSON (extra fields, nested metadata) must be adapted or wrapped to
match it, or imported without `--format` as an opaque blob (today's
behavior, unaffected). JUnit XML and TAP reports cannot be structurally
imported yet — they can still be imported as opaque blobs via `import-test`
without `--format`, exactly as before this round.

## Revisit trigger

Reopen if (a) a JUnit XML or TAP adapter is requested and a hardened reader
for one of those formats is written (add it beside this one, never replace
it — existing JSON-adapter bundles must keep verifying), or (b) the fixed
JSON schema above needs a new field (requires its own schema-version
reasoning, the same as any other manifest field addition).

## Anchored at

- `src/json_min.c` / `src/json_min.h` (the parser).
- `src/funes.c` (`parse_json_report`, `cmd_add_test`'s `--format json` path).
- `docs/spec/EVIDENCE-BUNDLE-v2.md` (`report_format`/`report_passed`/`report_case_count` keys).
