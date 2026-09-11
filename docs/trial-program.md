# 1.1 release-candidate trial program

Version 1.1.0rc1 is for controlled trials by authorized AI red-team practitioners. It is not a
claim of broad field maturity.

## Fifteen-minute start

1. Create an isolated Python environment and install `advent-prompt-pwn==1.1.0rc1` with `--pre`.
2. Run `advent-prompt-pwn doctor --output diagnostics.json`.
3. Run `advent-prompt-pwn engagement init engagement.yaml`.
4. Review the generated scope and run
   `advent-prompt-pwn engagement validate engagement.yaml --explain`.
5. Run the local fixture, verify its evidence bundle, then adapt a copy for an authorized target.

Do not attach diagnostic files, manifests, prompts, reports, or screenshots from a client
engagement to a public issue. Reproduce defects with synthetic data.

## Useful feedback

For each trial, record the package version, Python version, operating system, target adapter,
number of planned attempts, number of completed attempts, false-positive or false-negative oracle
decisions, and time needed to obtain a reviewable report. Report whether scope and preflight
messages were clear before the first request.

Use the repository bug form for reproducible defects and the provider-compatibility form for
synthetic adapter observations. A minimal local reproducer is more useful than a large engagement
bundle.

## Exit criteria

The final 1.1.0 release requires the release-candidate automation to stay green, credentialed
provider smoke tests to be recorded without exposing credentials, and blocking trial defects to be
resolved. External practitioner review remains independent evidence and cannot be replaced by the
maintainer's own tests.
