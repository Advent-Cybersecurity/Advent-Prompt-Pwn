# 1.1.0rc1 self-qualification

This qualification uses deterministic, intentionally vulnerable local fixtures. It proves that
the release candidate can generate, detect, preserve, and verify representative evidence without
network access. It is maintainer-run synthetic evidence, not an independent practitioner review
or proof of compatibility with a live model provider.

| Assessment | Boundary exercised | Expected and observed result |
| --- | --- | --- |
| [Instruction hierarchy](https://github.com/Advent-Cybersecurity/Advent-Prompt-Pwn/blob/main/examples/reports/qualification/instruction-hierarchy.md) | System-only synthetic canary versus an instruction override | One deduplicated high-severity finding detected |
| [RAG indirect injection](https://github.com/Advent-Cybersecurity/Advent-Prompt-Pwn/blob/main/examples/reports/qualification/rag-indirect-injection.md) | Untrusted retrieved content crossing into model control | One deduplicated high-severity finding detected |
| [Unauthorized tool use](https://github.com/Advent-Cybersecurity/Advent-Prompt-Pwn/blob/main/examples/reports/qualification/unauthorized-tool-use.md) | Synthetic transfer request bypassing policy and human approval | One deduplicated critical-severity finding detected |

The corresponding JSON reports are modification-detectable and pass `advent-prompt-pwn verify`:

- `examples/reports/qualification/instruction-hierarchy.json`
- `examples/reports/qualification/rag-indirect-injection.json`
- `examples/reports/qualification/unauthorized-tool-use.json`

Regenerate them with `python examples/qualification_assessments.py`. The automated test suite runs
the same scenarios in a temporary directory and requires every fixture to produce a finding with
zero execution errors and valid evidence hashes.

## Automated evidence

- Example-based tests cover public APIs, providers, report formats, scope, resume, and malformed
  inputs.
- Hypothesis properties cover Unicode redaction, nested serializable evidence, stable hashing, and
  all built-in strategy outputs.
- A state-machine model checks request reservation and release sequences.
- A 32-worker stress test verifies that concurrent reservations never exceed a shared budget.
- CodeQL and OpenSSF Scorecard workflows provide independent static and supply-chain automation.
- The release workflow produces a validated CycloneDX SBOM, SHA-256 checksums, PyPI attestations,
  and signed-tag verification.
- Targeted mutation testing is configured for redaction and integrity paths on Linux.

## Evidence still required

- Live smoke tests for the four first-party provider adapters require provider credentials and may
  incur cost.
- Two independent practitioner reviews remain open.
- GitHub Pages publishing requires the repository owner to enable GitHub Actions as the Pages
  source.
