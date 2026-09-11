# Version 1.0 Retrospective

Review date: 2026-09-09

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

## Remaining limitations

- Built-in strategies are structured transformations, not an adaptive attack-discovery engine.
- Deterministic oracles can miss semantic, partial, or contextual policy violations.
- Compact reproducer selection is evidence based. It is not adaptive delta debugging and does not
  establish a globally minimal prompt.
- Agent tooling and retrieval workflows do not yet provide complete sandboxed simulations or
  multi-hop trust-boundary analysis.
- Pattern-based redaction cannot identify every secret.
- Checkpoint HMACs provide shared-key authenticity but not encryption, public-key signatures, or
  non-repudiation.
- Third-party plugins execute trusted Python in the assessor process.
- Remote host authorization does not pin the operating-system DNS result.
- External practitioner review and evidence from multiple authorized field assessments are still
  required before describing the project as mature.

## Next evidence gates

1. Run the complete CI matrix on every declared Python version and both supported operating-system
   families.
2. Complete at least three documented assessments against authorized or intentionally vulnerable
   targets.
3. Obtain two external practitioner reviews.
4. Calibrate any future semantic judge against a labeled evaluation set before using it for gates.
5. Add adaptive, budget-bound delta debugging and a sandboxed agent and retrieval laboratory.
