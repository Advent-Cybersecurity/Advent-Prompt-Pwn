# 1.1.0rc1 release checklist

## Completed locally

- [x] Version and changelog identify an opt-in release candidate.
- [x] Maturity metadata remains Beta.
- [x] Stable diagnostic codes and nonsecret doctor bundles have regression tests.
- [x] Explainable engagement validation has regression coverage.
- [x] Property, state-machine, and concurrent budget tests pass locally.
- [x] Three intentionally vulnerable offline assessments produce valid findings and evidence.
- [x] Documentation builds in strict mode.
- [x] Wheel and source archive build, metadata, and clean-install checks pass.
- [x] Dependency audit and public-file credential-pattern scan pass.

## Hosted release gates

- [ ] Python 3.10 through 3.14 tests pass on Linux and Windows for the release commit.
- [ ] Ruff, strict mypy, documentation, dependency audit, and build jobs pass.
- [ ] CodeQL reports no release-blocking finding.
- [ ] OpenSSF Scorecard workflow completes and its results are reviewed.
- [ ] Targeted mutation qualification has no unresolved surviving or untested mutant.
- [ ] The generated CycloneDX SBOM validates.
- [ ] The signed tag matches the package version and verifies against `docs/allowed-signers`.
- [ ] PyPI Trusted Publishing produces attestations for both archives.
- [ ] GitHub release contains the two archives, SBOM, and SHA-256 checksums.
- [ ] A clean environment installs the exact pre-release from PyPI and passes `doctor`.

## External evidence that does not block publishing the release candidate

- [ ] Credentialed one-request smoke checks for OpenAI, Azure OpenAI, Anthropic, and Gemini.
- [ ] Two independent practitioner reviews.
- [ ] Authorized field feedback from trial users.
- [ ] GitHub Pages enabled by the repository owner and the documentation deployment rerun.

These external items block a broad maturity claim or final 1.1.0 promotion, not an honestly labeled
release candidate.
