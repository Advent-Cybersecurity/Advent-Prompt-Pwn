# Release Checklist

## Before tagging

- [x] Finalize the public name, package name, CLI name, and import namespace.
- [x] Add final repository URLs.
- [x] Confirm Apache 2.0 with the LLC owner.
- [ ] Obtain an external practitioner review of the engagement workflow.
- [x] Update README with the local release status.
- [x] Set the changelog release date for 1.0.0.
- [x] Run `ruff check src tests`.
- [x] Run `mypy src`.
- [x] Run `pytest --cov=advent_prompt_pwn --cov-report=term-missing`.
- [x] Audit the installed third-party dependencies with `python -m pip_audit --local --skip-editable`.
- [x] Run `python -m build` and `python -m twine check dist/*`.
- [x] Install the wheel in a fresh environment.
- [x] Verify `advent-prompt-pwn doctor`, `init`, `validate`, safe and finding runs, evidence verification, comparison, and resume.
- [x] Review runtime and development dependencies.
- [x] Review GitHub Actions versions and pin them to full commit hashes.
- [x] Complete a full-repository application-security review and remediate its pre-release findings.

## Registry setup

- [ ] Reserve the PyPI project.
- [ ] Configure the GitHub `pypi` environment with required reviewer approval.
- [ ] Configure PyPI Trusted Publishing for the exact owner, repository, workflow, and environment.
- [ ] Enable GitHub private vulnerability reporting and branch protection.

## Release

- [ ] Create a signed `vX.Y.Z` tag.
- [ ] Verify the CI build artifact before approving publication.
- [ ] Verify the PyPI metadata and attestations.
- [ ] Install the published wheel on Windows and Linux.
- [ ] Publish checksums and release notes.

## After release

- [ ] Run the README quickstart from the published package.
- [ ] Publish the launch post only after install verification.
- [ ] Watch vulnerability reports, packaging failures, and documentation issues.
- [ ] Record practitioner feedback in the roadmap.
