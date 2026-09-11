# Threat Model

## Assets

- API credentials used by target adapters
- System instructions and synthetic canaries
- Assessment transcripts and results
- Authorization and target-scope records
- Integrity of attack corpora and third-party strategy plugins

## Trust boundaries

- Local process to remote model endpoint
- Core runner to target adapter
- Core runner to third-party strategy or oracle
- Assessment process to report storage
- Maintainer workstation to package registry

## Relevant threats

- Sending requests to an undeclared host
- Leaking credentials into transcripts or exceptions
- Treating an execution error as a security pass
- Treating a weak oracle match as a confirmed vulnerability
- Malicious third-party plugins performing hidden network activity
- Corpus changes making historical results irreproducible
- Interrupted runs silently repeating requests or resetting budget usage
- Oversized target responses exhausting memory or evidence storage
- Credentials embedded in endpoint URLs or custom headers
- DNS rebinding of an approved hostname toward an undeclared address
- Evidence files being modified after an engagement
- Formula or markup injection when evidence is imported into other tools
- Compromised release or dependency artifacts

## Current controls

- Local-only default scope
- Exact remote host allowlists, with DNS hostnames disabled unless explicitly opted in
- Required remote manifest port allowlists and independent execution-time scope grants
- Independent execution-time ceilings for remote request, rate, concurrency, retry, timeout, trial, variant, response, and evidence limits
- Strict engagement-v1 field, type, required-value, and unknown-field validation
- Rejection of URL credentials and credential-like query parameters, plus explicit allowlists for other query parameters
- Explicit authorization references
- Request budgets and rate limiting
- Environment-variable API keys
- Independent `--allow-env` grants for every environment variable named by a manifest
- Recursive redaction of messages, target metadata, tool calls, mapping keys, and report metadata
- Separate error accounting
- Deterministic strategy generation
- Repeated-trial limits, minimum request preflight, and statistical outcome summaries
- Monotonic HTTP deadline checks, short read and write stalls, identity-only response encoding, streaming response-size limits, and bounded concurrency
- Bounded corpus, composite-oracle, literal, regular-expression, report, evidence, and bundle processing
- Atomic randomized temporary writes with cumulative request counts
- HMAC-authenticated checkpoints with exact target, redaction, metadata, and execution resume binding
- A full configured request interval before the first dispatch after resuming prior requests
- Independently retained expected checkpoint integrity for rollback-resistant resume
- Built-in HTTP clients that ignore ambient proxy configuration and reject custom `Host` routing
- Corpus digests, complete attempt hashes, report-envelope hashes, and evidence-bundle checksums
- Manifest path confinement with explicit external-path and overwrite opt-ins
- Complete-run baseline compatibility checks covering keyed endpoint and target-contract identity,
  selected strategies, selected cases, trials per variant, framework seed, planned attempt totals,
  per-case strategy coverage, and exact generated job inputs when the corpus is unchanged
- No telemetry or endpoint discovery
- Dependency and source checks in CI

## Residual risk

The framework cannot prove that an authorization reference is legitimate or enforce a contractual test window. Custom plugins execute Python in the assessor's process and must be reviewed before installation. Pattern-based redaction cannot identify every secret. HMAC authentication depends on a strong key that remains separate from evidence. Checkpoint freshness also depends on the operator retaining the latest expected integrity digest in trusted state. These controls do not provide public-key authorship or non-repudiation. The explicit DNS opt-in does not pin operating-system resolution, so high-assurance remote work requires controlled DNS and host or network egress policy. Model behavior can vary even when the framework seed is fixed, so target model and provider metadata must be retained.
