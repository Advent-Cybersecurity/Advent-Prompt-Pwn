# Diagnostics

CLI failures include a stable category code before the safe, bounded error text. The message can
change to become clearer, but automation may group failures by code.

| Code | Category |
| --- | --- |
| `APPWN-E101` | Package configuration |
| `APPWN-E201` | Authorization scope |
| `APPWN-E202` | Request budget |
| `APPWN-E301` | Target adapter or transport |
| `APPWN-E401` | Corpus parsing or validation |
| `APPWN-E501` | Report or evidence bundle |
| `APPWN-E601` | Engagement manifest |
| `APPWN-E701` | Refused file replacement |
| `APPWN-E702` | Missing mapping key |
| `APPWN-E703` | Operating-system I/O |
| `APPWN-E704` | Invalid command value |

`advent-prompt-pwn doctor --output diagnostics.json` writes a support bundle containing the
package, Python, and operating-system versions plus dependency check results. It does not contain
environment values, hostnames, usernames, current directories, manifests, prompts, or reports.

When `--provider` is supplied, the bundle records the selected provider, credential environment
variable name, and a boolean indicating whether the variable is populated. Doctor never contacts
the provider.

Diagnostic files can still reveal software versions. Review them before sharing and never attach
files produced inside a client environment to a public issue unless the engagement rules permit
it.
