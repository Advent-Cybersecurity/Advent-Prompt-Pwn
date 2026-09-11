# Version 1.0 Retrospective

Review date: 2026-09-09

This document records the 1.0 state and the improvements carried into 1.1.0rc1. The release
candidate adds adaptive minimization, calibrated semantic judging, synthetic agent tooling, RAG
fixtures, authorization windows, DNS result pinning, and three synthetic qualification
assessments. External review and live-provider evidence remain open maturity gates, so the package
metadata uses the Beta classifier.

## Where the library is useful

The strongest part of `advent-prompt-pwn` is its engagement workflow. It turns a collection of
prompt tests into a bounded, repeatable assessment with recorded scope, deterministic case
generation, checkpoints, redaction, evidence integrity, reports, and baseline comparison. It is
suited to controlled consulting work and application-security regression testing.

It does not replace practitioner judgment. An oracle success demonstrates its configured
objective, not the complete impact or severity of a vulnerability. A run without observed
successes does not prove that a target is secure.

## Improvements implemented from this review

- Repeated executions can be configured with `trials_per_variant` from 1 through 100.
- Preflight planning counts every repeated trial against the minimum request budget.
- Repeated outcomes include success rates, mixed-result detection, and Wilson 95% confidence
  intervals.
- Deterministic trial identifiers and integrity-protected base-variant metadata support reliable
  checkpoint resume.
- The `reproducers` command extracts the shortest already-observed successful variant for each
  finding from an integrity-verified report.
- Reproducer documents retain the source report digest and have a bundled version 1 JSON Schema.
- Remote manifests require a separate exact execution-time authorization and network grant.
- Checkpoints use an operator-held HMAC key and bind the complete target and execution contract.
- Endpoint evidence, bundle enumeration, structured-input ambiguity, and JUnit control characters are
  handled conservatively at their trust boundaries.

## Remaining limitations after 1.1.0rc1

- Adaptive search is bounded and heuristic. It does not establish global prompt optimality.
- Deterministic oracles can miss semantic, partial, or contextual policy violations. The semantic
  judge API requires a representative labeled calibration set and practitioner review.
- Compact reproducer selection is evidence based. It is not adaptive delta debugging and does not
  establish a globally minimal prompt.
- Agent tooling is intentionally side-effect-free and does not yet provide multi-hop trust-boundary
  graphs or human-review queues.
- Pattern-based redaction cannot identify every secret.
- Checkpoint HMACs provide shared-key authenticity but not encryption, public-key signatures, or
  non-repudiation.
- Third-party plugins execute trusted Python in the assessor process.
- DNS pins are checked before built-in requests, but production engagements should also enforce
  network egress controls against post-check routing changes.
- Live compatibility checks for provider adapters require credentials and may incur provider cost.
- External practitioner review and authorized field evidence are still required before describing
  the project as mature.

## Next evidence gates

1. Complete the CodeQL, OpenSSF Scorecard, mutation, and Python 3.10 through 3.14 Linux and Windows
   workflows for the exact release-candidate commit.
2. Run credentialed one-request smoke checks for each supported first-party provider adapter.
3. Obtain two external practitioner reviews.
4. Calibrate every semantic judge against a representative labeled evaluation set before using it
   for an engagement gate.
5. Collect authorized field evidence without placing client data in the public repository.
