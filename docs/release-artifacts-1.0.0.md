# Version 1.0.0 Release Artifacts

Build date: 2026-09-11

The distributions were rebuilt from the final remediated source with Python 3.13.15 and
`build==1.6.0`. Both artifacts pass `twine==7.0.0` validation. The wheel and source distribution
were installed with their declared dependencies in separate new virtual environments. They passed
import, doctor, corpus creation, validation, local execution, authenticated checkpoint, resume,
comparison, bundle, and evidence verification smoke tests. All 35 packaged library files are
byte-identical across the source tree, wheel, and source distribution.

| Artifact | SHA-256 |
| --- | --- |
| `advent_prompt_pwn-1.0.0-py3-none-any.whl` | `5a6db3e06a64b1b97c6516b54cf3d62916e30c8563e381aded2830f9584bbc36` |
| `advent_prompt_pwn-1.0.0.tar.gz` | `7af0c0ce7f60ab692b3a7b8df1b57c4c60e4f05900b8158063b91142fb72cbf7` |

This hash record is intentionally excluded from the source archive so that the archive does not
contain a self-referential digest.

The `v1.0.0` Git tag is SSH-signed with the release key recorded in `docs/allowed-signers`.
Its ED25519 fingerprint is `SHA256:Ak8Zg23ihW/RCkdMsWjfl+ozrHK4JzBHY8P3rvzU23Q`.
Verify it from a clone with:

```bash
git config gpg.ssh.allowedSignersFile docs/allowed-signers
git verify-tag v1.0.0
```

Recompute before signing or publishing:

```powershell
Get-FileHash -Algorithm SHA256 dist\advent_prompt_pwn-1.0.0-py3-none-any.whl,
  dist\advent_prompt_pwn-1.0.0.tar.gz
```
