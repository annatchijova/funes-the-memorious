# Skills Applied

Record of the owner's local skills actually read during the founding session,
with observable effects on this repository. This file claims compliance only
where an effect can be pointed to. Language: English.

## Inspection method

- Listed `~/.codex/skills/` and `~/.agents/skills/`; read
  `~/.claude/CLAUDE.md` (engineering discipline guide) in full.
- Searched for an `anti-mvp` skill by filename and by content across the
  skill directories.

## Finding: no `anti-mvp` skill on disk

No file or directory named `anti-mvp` (or containing that string) exists in
`~/.codex/skills/`, `~/.agents/skills/`, or `~/.claude/` as of the founding
session. The mandatory anti-MVP requirement from the project proposal is
therefore applied as a principle, sourced from `~/.claude/CLAUDE.md` and the
skills below, and marked as a fallback rather than falsely attributed:

- No fake completion, placeholder core, or happy-path-only claims.
- README status statements must trace to observed commands or artifacts.
- A level is `DONE` only against its exit criteria (see `docs/ROADMAP.md`).

If the owner later installs an `anti-mvp` skill, this file must be updated
with its real path and its rules re-checked against the repository.

## Skills read and applied

| Skill | Path | Observable application |
|---|---|---|
| Engineering discipline (`CLAUDE.md`) | `~/.claude/CLAUDE.md` | Repo content in English; chat in Rioplatense Spanish; no emojis in the repo; no rebase/squash/force-push; verify git state before claiming it; evidence before synthesis |
| readme-architecture | `~/.codex/skills/readme-architecture/SKILL.md` | README ordered problem → mental model → observable behavior → differentiator → mechanism; `English · Español · Technical README` at the top; capability/evidence/interpretation kept distinct; exhaustive depth routed to `docs/architecture/ARCHITECTURE.md` instead of deleted; curated, annotated repo tree |
| deterministic-core | `~/.codex/skills/deterministic-core/SKILL.md` | Canonical typed versioned serialization and SHA-256 sealing as Level 1 invariants; determinism check (double-seal in fresh processes) required in Level 1 tests; no float in any sealed path |
| honest-degradation | `~/.codex/skills/honest-degradation/SKILL.md` | Execution taxonomy (`VERIFIED_REAL_QNX` / `VERIFIED_HOST_ONLY` / `CONTRACT_TEST_ONLY` / `NOT_RUN` / `FAILED`); Level 2 marked `BLOCKED`, never simulated; truncated logs must be flagged, never presented as complete |
| falsifiable-testing | `~/.codex/skills/falsifiable-testing/SKILL.md` | Roadmap requires failing builds/tests and mutation cases as first-class evidence; a test never seen red does not count |
| tamper-evident-audit-chain | `~/.codex/skills/tamper-evident-audit-chain/SKILL.md` | Verifier independence (stdlib-style, no collector logic); integrity vs. authenticity reported as distinct results; content hashes inside the sealed payload, not bare identifiers |
| claim-provenance-discipline | `~/.codex/skills/claim-provenance-discipline/SKILL.md` | Per-record origin labels (`OBSERVED`/`IMPORTED`/`ASSERTED`/`INFERRED`/`VERIFIED`) that must travel with the claim and never be promoted in transit |
| secure-by-construction | `~/.codex/skills/secure-by-construction/SKILL.md` | Threat model before file layout; argv-only subprocess execution; bundle treated as untrusted input with bounds checks; fail-closed verifier |
| git-discipline | `~/.codex/skills/git-discipline/SKILL.md` | Forward-only history; founding commit verified with `git status`/`git log` before being reported |
| language-selection | `~/.codex/skills/language-selection/SKILL.md` | Language compared on problem forces; owner directed C, and the comparison plus Go/QNX nuance are owed in ADR-001 rather than decided by habit |

## Skills consulted for the roadmap structure

`decision-record-discipline` (ADR format), `daubert-defensible-writing`
(sentence-level claim scoping in the README), and `non-overwhelming-ux`
(scanning/chunking discipline shared by README and roadmap) informed the
documents above. Their full texts were not re-read in this session; no
stronger compliance is claimed for them.

## Explicit non-compliance / gaps

- `anti-mvp` skill: not found on disk (see above). Fallback principles applied.
- At founding, ADR-001, the evidence-bundle spec, the threat model, and CI
  were still owed by Level 0. Subsequent commits closed those items; current
  status is maintained in `docs/ROADMAP.md` and `docs/STATUS.md`.

## Level 7 documentation pass

The following skills were read and applied while moving the jury-experience
level from `NOT_STARTED` to an evidence-scoped `PARTIAL` state:

| Skill | Observable application |
|---|---|
| `working-on-main` and `git-discipline` | An annotated pre-session restore tag was created on `main`; no history-rewriting operation was used; state was re-read before reporting. |
| `software-archaeology`, `audit-before-patch`, and `surgical-patcher` | Stale README claims were confirmed against live roadmap/status files; every existing-file edit used a unique anchored dry run, backup, and post-write verification. |
| `abductive-engineering`, `falsifiable-testing`, and `red-team-auditing` | The next-level hypothesis and its benign alternative were tested; the host demo's tamper failure and the 122-check suite were re-run; claims are bounded by the observed QNX absence. |
| `destination-driven-construction`, `pitch-evidence-sequencing`, `cognitive-load-in-pitch-visuals`, and `adversarial-pitch-audit` | The new Devpost draft follows problem → visible mechanism → tamper evidence → boundary, limits the video to one observable journey, and avoids unsupported QNX or safety claims. |
| `hackathon-demo-production-workflow` | The current official rules were checked before recording guidance was drafted; the document requires a public under-three-minute video and warns against unlicensed media. |
