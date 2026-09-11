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
| `advent_prompt_pwn-1.0.0-py3-none-any.whl` | `fc3b9c0a75da81de272787c9d6b8cf5fd3e0dc262b2b7cc7f85fb4d4aa095f83` |
| `advent_prompt_pwn-1.0.0.tar.gz` | `7ed3b91e94794f3dfe0ff5954b1bdb2848e4dedb8de98f5793b73ccc19aee00a` |

This hash record is intentionally excluded from the source archive so that the archive does not
contain a self-referential digest.

Recompute before signing or publishing:

```powershell
Get-FileHash -Algorithm SHA256 dist\advent_prompt_pwn-1.0.0-py3-none-any.whl,
  dist\advent_prompt_pwn-1.0.0.tar.gz
```
