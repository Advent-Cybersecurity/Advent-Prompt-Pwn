# Version 1.0.0 Release Artifacts

Publication date: 2026-09-11

The published distributions were built by the tag-triggered GitHub Actions release workflow from
signed tag `v1.0.0` and published through PyPI Trusted Publishing. Both artifacts passed
`twine==7.0.0` validation before publication. Local release candidates were installed with their
declared dependencies in separate new virtual environments and passed import, doctor, corpus
creation, validation, local execution, authenticated checkpoint, resume, comparison, bundle, and
evidence verification smoke tests. All 35 packaged library files were byte-identical across the
source tree, wheel, and source distribution. The wheel downloaded directly from PyPI passed clean
installation, import, metadata, and doctor checks on hosted Ubuntu and Windows runners. The Windows
verification also passed the README engagement quickstart and offline evidence-bundle verification.

| Artifact | SHA-256 |
| --- | --- |
| `advent_prompt_pwn-1.0.0-py3-none-any.whl` | `8cfb584520027baeaadcd7dd79f97888d6015b14aac33d982b89c95497f53806` |
| `advent_prompt_pwn-1.0.0.tar.gz` | `7af0c0ce7f60ab692b3a7b8df1b57c4c60e4f05900b8158063b91142fb72cbf7` |

These are the authoritative hashes for the artifacts published on PyPI and attached to the GitHub
Release. The hash record is intentionally excluded from the source archive so that the archive does
not contain a self-referential digest.

The `v1.0.0` Git tag is SSH-signed with the release key recorded in `docs/allowed-signers`.
Its ED25519 fingerprint is `SHA256:Ak8Zg23ihW/RCkdMsWjfl+ozrHK4JzBHY8P3rvzU23Q`.
Verify it from a clone with:

```bash
git config gpg.ssh.allowedSignersFile docs/allowed-signers
git verify-tag v1.0.0
```

Recompute after downloading:

```powershell
Get-FileHash -Algorithm SHA256 dist\advent_prompt_pwn-1.0.0-py3-none-any.whl,
  dist\advent_prompt_pwn-1.0.0.tar.gz
```
