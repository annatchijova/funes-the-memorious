# ADR-002 — Ed25519 signatures via runtime-loaded libsodium, explicit trust roots

Date: 2026-11-04
Status: accepted
Reversibility: two-way (signatures are additive files beside the bundle;
removing Level 3 leaves Level 1 integrity verification untouched)

## Forces at the time

- Level 1 integrity is self-referential: whoever rewrites blobs can rewrite
  manifest and seal. An authenticated mode is needed (Roadmap Level 3).
- The founding host has libsodium and OpenSSL runtime libraries but no
  development headers for either (`libsodium-dev`/`libssl-dev` absent), and
  installing system packages is the owner's decision, not the agent's.
- The proposal forbids custom cryptographic algorithms and requires
  maintained primitives, domain separation, and no silent trust roots.
- The guarantee a signature can provide here is narrow: control of a key
  over a manifest commitment. It cannot prove an execution occurred, and
  every output must keep saying so.

## Decision

- Signatures are Ed25519 (libsodium `crypto_sign_detached` /
  `crypto_sign_verify_detached`), loaded at runtime with `dlopen` so no dev
  package or link-time dependency is required. If libsodium is absent,
  signing is unavailable and verification reports signatures as
  `UNVERIFIED`/`UNTRUSTED_SIGNER`; integrity-only operation is unaffected.
- Exactly what is signed: the ASCII bytes `FUNES-SIGN-1\n`, the 64-char
  lowercase hex SHA-256 of `manifest.txt`, and `\n`. The manifest in turn
  binds every blob digest, so blobs are covered indirectly and exactly;
  `signatures/` itself and `SEAL.txt` are not signed (the seal is redundant
  once the manifest digest is signed, and is kept for unsigned bundles).
- The algorithm is fixed in code. Bundle metadata (`signer.txt`) is checked
  against that fixed expectation and never selects an algorithm; there is
  no `none`/weak downgrade path. `signer.txt`'s public key is self-asserted
  until compared with a reviewer-supplied `--trusted-key`; the verifier
  recomputes the fingerprint from the key bytes rather than trusting the
  fingerprint field.
- Keys: `funes keygen` draws a 32-byte seed from `getrandom(2)`, derives
  the keypair deterministically, writes the seed as hex under a
  `FUNES-ED25519-SEED-1` header with mode `0600`, `O_EXCL`, plus an explicit
  unencrypted-storage warning. Public keys are bare 64-char hex files, used
  identically by `sign` (output) and `funes-verify --trusted-key` (trust
  root). Private material never enters a bundle (suite-checked).

## Alternatives rejected

- **Link OpenSSL EVP** — rejected because no headers are installed and the
  EVP surface is larger than needed. Best argument for it: OpenSSL is
  already the platform TLS stack and offers PEM tooling.
- **Require `libsodium-dev` and link `-lsodium`** — rejected because it makes
  building depend on a system package the owner has not installed. Best
  argument for it: simpler, link-time-checked code. Reopen if the project
  standardizes on installed dev packages (then drop the `dlopen` shim).
- **Vendored public-domain Ed25519** — rejected because shipping a copied
  primitive raises audit burden versus calling the maintained library that
  is already on the host. Best argument for it: zero runtime dependency.
- **Custom signature scheme** — rejected outright; forbidden by the
  proposal and by policy.

## Assumption this rests on

Reviewers can obtain signer public keys over a channel they trust (the
fingerprint comparison is only as good as that channel). If key distribution
cannot be trusted in a deployment, `TRUSTED_SIGNER` degrades to "matches the
file supplied" — the verifier wording already scopes it to the supplied key.

Consequences accepted now: unencrypted seed files (owner-managed, warned);
no key rotation tooling yet (rotate by generating a new key and
re-distributing the public half; old bundles stay verifiable under the old
public key). Deferred: encrypted seeds, hardware keys, timestamps,
transparency anchoring.

## Revisit trigger

Reopen if (a) libsodium disappears from supported hosts, (b) a second
signature algorithm must be accepted (then add a versioned domain, never a
metadata-selected one), or (c) encrypted seed storage is required.

## Anchored at

- `src/funes.c` (`cmd_keygen`, `cmd_sign`, payload construction comment).
- `verifier/funes_verify.c` (signature phase: fixed algorithm/domain checks).
- `docs/spec/VERIFIER-SEMANTICS.md` (exit codes 8/9 and trust statuses).
