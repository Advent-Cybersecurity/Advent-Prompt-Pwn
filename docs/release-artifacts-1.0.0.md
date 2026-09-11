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
| `advent_prompt_pwn-1.0.0-py3-none-any.whl` | `97e79def08f5c413e9c6d5836ed8f067e32677ce055752d92e1a8f1d6a9896eb` |
| `advent_prompt_pwn-1.0.0.tar.gz` | `8a4c014f7326a8c7a768069423051934ae058dc992820c5d4f0b4f49432de210` |

This hash record is intentionally excluded from the source archive so that the archive does not
contain a self-referential digest.

Recompute before signing or publishing:

```powershell
Get-FileHash -Algorithm SHA256 dist\advent_prompt_pwn-1.0.0-py3-none-any.whl,
  dist\advent_prompt_pwn-1.0.0.tar.gz
```
