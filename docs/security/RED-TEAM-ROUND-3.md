# Security Audit — Funes the Memorious

## Red Team Round 3

**Date:** 2026-11-05
**Method:** Abductive Engineering (A–D–I) and `red-team-auditing`
**Scope:** Process supervision, signing-path containment, and manifest-schema
composition in `src/funes.c` and `verifier/funes_verify.c`.
**Base:** `main` at `9b231ce`
**Reproducible evidence:** Exact commands are recorded under each finding;
all fixtures were created in a fresh `/tmp` directory and removed after each
induction.

This round deliberately does not change production code. It records observed
failures in the audited revision so that remediation can be characterized and
verified separately.

## Threat model

- An attacker can supply a command executed by `capture` or `add-test`,
  including one that creates descendants.
- An attacker can control a bundle directory supplied to `sign`, including
  its initial `signatures` entry.
- An attacker can supply the `ROLE` portion of an artifact argument through
  an automation boundary that invokes `capture` before a trusted operator
  signs the resulting bundle.
- An attacker cannot modify the Funes executable, compromise the host kernel,
  or obtain the trusted signing private key.

## Epistemic legend

`CODE FACT` · `PLAUSIBLE HYPOTHESIS` · `CONFIRMED BY INDUCTION` · `FALSIFIED`

## Executive summary

| ID | Severity | Level | Module | Finding |
|---|---|---|---|---|
| RT3-01 | High | CONFIRMED BY INDUCTION | collector | A timeout kills only the direct child; a descendant remains alive. |
| RT3-02 | High | CONFIRMED BY INDUCTION | collector | `sign` follows an intermediate `signatures/` symlink and writes outside the bundle. |
| RT3-03 | Medium | CONFIRMED BY INDUCTION | collector + verifier | Newline injection in an artifact role creates out-of-range manifest keys that a trusted verifier accepts but ignores. |

## Findings

### RT3-01 — Timeout does not contain a subprocess tree

**Severity:** High
**Epistemic level:** CONFIRMED BY INDUCTION
**Bucket:** Software vulnerability

- **Surprise / expectation violated:** `--timeout-sec` records the direct
  command as killed, but a process started by that command can keep running
  after the collector returns.
- **Firstness:** `run_capture()` calls `kill(pid, SIGKILL)` at
  `src/funes.c:346-348`, where `pid` is the direct `fork()` result. It does
  not create a process group or signal one.
- **Secondness:** The documented timeout guarantee says the child is killed
  rather than left running. A descendant remaining alive preserves resource
  consumption beyond the recorded execution boundary.
- **Abduction:** The direct shell dies on timeout while a background `sleep`
  remains in its inherited process group. The simpler alternative was that
  killing the shell also terminates its child. The induction discriminates
  between them.
- **Deduction:** A shell that writes its background child PID and waits will
  return exit 137 after one second, while `kill -0` on that recorded PID will
  still succeed.
- **Induction:**

  ```sh
  audit_tmp=$(mktemp -d /tmp/funes-redteam-timeout.XXXXXX)
  marker="$audit_tmp/child.pid"
  ./bin/funes capture --out "$audit_tmp/bundle" --timeout-sec 1 -- \
    sh -c "sleep 30 & child=\$!; printf '%s\\n' \"\$child\" > '$marker'; wait"
  child=$(tr -d '\n' < "$marker")
  kill -0 "$child"
  ```

  Observed: `capture_exit=137`, `elapsed_ms=1001`, and
  `child_state_after_timeout=alive`. The probe then killed the child and
  removed its fixture directory.
- **Causal chain:** direct-child PID is killed → background descendant has a
  different PID → no group-wide signal is sent → descendant continues.
- **Threat-model precondition:** The executed command may create descendants.

### RT3-02 — Signing follows a symbolic-link directory component

**Severity:** High
**Epistemic level:** CONFIRMED BY INDUCTION
**Bucket:** Software vulnerability

- **Surprise / expectation violated:** The existing `O_NOFOLLOW` protection
  applies only to `ed25519.sig` and `signer.txt`; it does not protect the
  intermediate `signatures/` component.
- **Firstness:** `cmd_sign()` accepts `mkdir(sdir)` returning `EEXIST` at
  `src/funes.c:633-635`, then opens paths beneath it at lines 639-651. On
  Linux, `O_NOFOLLOW` applies to the final component, not an earlier symbolic
  link in the path.
- **Secondness:** Round 1 closed the final-file symlink write. A symbolic-link
  directory is a distinct pathname boundary and must not redirect a signing
  operation outside the requested bundle.
- **Abduction:** A pre-existing `bundle/signatures -> outside` link is
  accepted as `EEXIST`, making both output paths resolve under `outside`.
  The simpler alternative was that `O_NOFOLLOW` rejects the whole path.
- **Deduction:** `sign` will exit 0 and create both signature files under an
  external directory, not under the bundle.
- **Induction:**

  ```sh
  audit_tmp=$(mktemp -d /tmp/funes-redteam-sign.XXXXXX)
  printf 'artifact\n' > "$audit_tmp/artifact"
  ./bin/funes capture --out "$audit_tmp/bundle" \
    --artifact "$audit_tmp/artifact:fixture" -- true
  ./bin/funes keygen --out "$audit_tmp/seed" --pub-out "$audit_tmp/pub"
  mkdir "$audit_tmp/outside"
  ln -s "$audit_tmp/outside" "$audit_tmp/bundle/signatures"
  ./bin/funes sign --bundle "$audit_tmp/bundle" --key "$audit_tmp/seed"
  test -f "$audit_tmp/outside/ed25519.sig"
  test -f "$audit_tmp/outside/signer.txt"
  ```

  Observed: `sign_exit=0` and `outside_signature_material=written`.
- **Causal chain:** attacker-controlled intermediate symlink → `mkdir` accepts
  `EEXIST` → final-component-only `O_NOFOLLOW` opens external files → signing
  material is written outside the bundle.
- **Threat-model precondition:** The bundle path is attacker-writable before
  the trusted operator invokes `sign`.

### RT3-03 — Out-of-range manifest records are accepted and hidden

**Severity:** Medium
**Epistemic level:** CONFIRMED BY INDUCTION
**Bucket:** Software vulnerability

- **Surprise / expectation violated:** The format promises contiguous indexed
  keys. An artifact role can inject a newline and create `test.99.origin`,
  while `test_count=0`; the verifier accepts the signed bundle and reports no
  test record.
- **Firstness:** `cmd_capture()` writes `artifact.<n>.role` directly from the
  substring following `PATH:` at `src/funes.c:816-835`, without token
  validation or encoding. `key_allowed()` accepts syntactically indexed test
  keys, and the verifier subsequently iterates only `0..test_count-1`.
- **Secondness:** The v1 format and verifier semantics require indexed keys
  to be contiguous. A signed manifest containing an ignored test-shaped key
  violates that grammar and creates a disagreement between what is sealed and
  what the verifier summarizes.
- **Abduction:** A newline in `ROLE` becomes a second manifest line during
  sealing; `test.99.origin` is an allowed key form but is outside the declared
  count, so the verifier never validates or reports it. The simpler
  alternative was that the parser rejects the injected line or enforces the
  index range.
- **Deduction:** A trusted signed bundle carrying both `test.99.origin=OBSERVED`
  and `test_count=0` will exit 0 and report `test_observation_status=NO_TEST_RECORD`.
- **Induction:**

  ```sh
  audit_tmp=$(mktemp -d /tmp/funes-redteam-signed-orphan.XXXXXX)
  printf 'artifact\n' > "$audit_tmp/artifact"
  role=$(printf 'fixture\ntest.99.origin=OBSERVED')
  ./bin/funes capture --out "$audit_tmp/bundle" \
    --artifact "$audit_tmp/artifact:$role" -- true
  ./bin/funes keygen --out "$audit_tmp/seed" --pub-out "$audit_tmp/pub"
  ./bin/funes sign --bundle "$audit_tmp/bundle" --key "$audit_tmp/seed"
  ./bin/funes-verify --trusted-key "$audit_tmp/pub" "$audit_tmp/bundle"
  ```

  Observed: `integrity_status=INTEGRITY_VALID`, `signature_status=VALID`,
  `signer_trust_status=TRUSTED_SIGNER`, and
  `test_observation_status=NO_TEST_RECORD`.
- **Causal chain:** unvalidated `ROLE` newline → additional allowed manifest
  key → key survives sealing and signing → count-bounded verifier loop skips
  it → trusted summary omits it.
- **Threat-model precondition:** A trusted collection/signing workflow accepts
  an artifact role from an untrusted automation boundary.

## Discarded and inconclusive vectors

| Vector | Result | Why |
|---|---|---|
| AddressSanitizer and UndefinedBehaviorSanitizer full suite | INCONCLUSIVE | LeakSanitizer exits before the program runs because this environment is traced; the standard build passes all 127 checks. This is not evidence of a code defect or of sanitizer cleanliness. |
| “`O_NOFOLLOW` protects the signing path” | FALSIFIED | It protects only the final filename. RT3-02 demonstrated that an intermediate directory symlink is still followed. |
| “The timeout kills every process created by the command” | FALSIFIED | RT3-01 demonstrated that only the direct child is signaled. |
| “Allowed indexed keys are necessarily in range” | FALSIFIED | RT3-03 demonstrated that `test.99.*` remains outside `test_count=0` while verification succeeds. |

## Recommendations

1. Contain a captured command in a new process group/session and send timeout
   signals to that group; characterize descendant cleanup before changing the
   timeout record semantics.
2. Open and validate the `signatures/` directory itself with a directory file
   descriptor and `O_NOFOLLOW`, then create both files relative to that
   descriptor without following path components.
3. Define artifact roles as a strict token and reject control bytes and
   delimiters. In the verifier, reject every indexed key whose index is not
   within its corresponding declared count, and reject gaps/extra keys for
   every indexed family.

## Remediation result

The audited base remains intentionally preserved above. Remediation was applied
after the red-first regressions failed and was then re-induced successfully:

| Finding | Remediation | Evidence |
|---|---|---|
| RT3-01 | The collector creates a dedicated process group, blocks descendants from changing session or process group, and signals the group on timeout. | Ordinary-descendant and `setsid`-escape regressions pass. |
| RT3-02 | Signing opens `signatures/` with `O_DIRECTORY|O_NOFOLLOW` and writes both files with `openat`. | A symlinked `signatures/` directory is refused; no external files are created. |
| RT3-03 | Artifact roles are restricted to grammar tokens; the verifier rejects every indexed key outside its declared collection. | Control-byte role and resealed `test.99.*` regressions both fail closed. |
