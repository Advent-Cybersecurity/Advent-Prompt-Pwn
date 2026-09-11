# Version 1.0.0 Security Review

Review date: 2026-09-09

The 1.0.0 release candidate received eight independent full-repository security passes as the
implementation matured. Each pass used an immutable source snapshot and complete file inventory.

| Scan | Snapshot | Files | Validated findings |
| --- | --- | ---: | ---: |
| `367b6c31-7d6f-4053-bc2f-a359fa10786d` | `63fcc9e78241de92647a03b41d67ee5832aeb939c75870776b20987b1c3ee20c` | 73 | 11 |
| `58a7a68b-12a1-403b-a35e-8e040b47bee2` | `0f33a34d914a7590b56f42e5b941f955e9128f86c56d3306c8eef7bb34e08304` | 83 | 10 |
| `daf9622f-be37-4adf-91a0-012ab0217d9d` | `55c6d40bac3075f82253b67e0f0d0ddf5edd01d73955fbe4d58c76adfb47e0af` | 83 | 7 |
| `af0e29d3-7b19-422b-b84d-2d7a8a5630b0` | `3b2fb94c0be3f7bba715196267aa2539e68a15eaf799949cea8c321f7c222c51` | 85 | 7 |
| `00c6a962-aeb5-4478-bfe0-3a731d5579ab` | `e0750838394d9fd556c1acb576cbd7fd13af710473d3f9026459c83c17060b7d` | 85 | 3 |
| `0ca407ea-24a0-420c-8d13-4c910be6d3a1` | `3a5d613f083f64f94364597ec80d0d72965398eecca9da5fde7096621d265ddd` | 85 | 4 |
| `e69c9fef-0f28-429d-acbb-c7f970a235d7` | `7d06fed9376aa9695d523e13a28b9ffa434425be153f509abc576e23c916c7d6` | 85 | 2 |
| `a16232c7-b4d1-4790-afdc-c45be6638b8b` | `d3d809b54763b6b1d64a5c900bffaedd9536187b10ea2a2c9f3d8ff665c88410` | 85 | 1 |

All validated pre-release findings were remediated in source and covered by regression tests.
The controls include independent remote network and workload grants, strict engagement schema
validation, proxy-independent HTTP clients, rejection of custom `Host` routing,
HMAC-authenticated checkpoints, independently approved checkpoint freshness, complete target,
redaction, metadata, and execution resume binding, conservative request accounting, keyed target
identity pseudonyms, HMAC-authenticated saved-report comparison, flushed checkpoint candidate
identities, consume-only legacy resume compatibility, canonical report loading, strict duplicate-key
handling, full-interval conservative resume rate enforcement, complete-run, target-contract,
execution-selection, generated-job, and per-case strategy coverage comparison,
constant-space bundle replacement checks, endpoint evidence sanitization, bounded processing,
128-bit finding identifiers, and valid XML output.

The remediated source passes 244 tests with 90.24 percent branch-aware coverage, Ruff, strict
mypy, and an installed dependency audit with no known vulnerabilities. The rebuilt wheel and
source distribution pass Twine validation and clean-environment installation testing. Artifact
hashes are recorded in `release-artifacts-1.0.0.md`.

## Residual operational risk

The framework cannot prove that a contract or ticket is legitimate or that execution occurs
inside its approved time window. Remote DNS is rejected by default. Its explicit opt-in does not
pin the address selected by the operating system, so hostname-based engagements require controlled
DNS and enforced host or network egress policy.

Custom strategies, oracles, targets, and injected clients execute as trusted Python in the
assessor process. They are not sandboxed. Pattern-based redaction cannot identify every secret,
and model behavior remains nondeterministic even with a fixed framework seed.

HMAC authentication prevents checkpoint forgery while a strong key remains secret and separate
from the evidence. Rollback resistance additionally requires the operator to retain and approve
the latest checkpoint integrity digest from trusted engagement state. These controls do not
provide encryption, public-key authorship, or non-repudiation. High-assurance evidence handling
still requires organization-approved storage, signing, retention, and access controls.
