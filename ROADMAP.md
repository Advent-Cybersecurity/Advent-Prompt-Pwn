# Roadmap

## Release 1.0: engagement-ready core

- [x] Deterministic execution model
- [x] Explicit authorization scope
- [x] Synthetic canary workflow
- [x] Local and OpenAI-compatible targets
- [x] CI-friendly reports and exit codes
- [x] Plugin discovery for strategies
- [x] Select the public product name: `advent-prompt-pwn`
- [x] Versioned engagement manifests and preflight planning
- [x] Custom HTTP JSON application target
- [x] Bounded concurrency, retries, atomic checkpoints, and resume
- [x] Severity, stable finding IDs, and deduplication
- [x] Evidence bundles with offline integrity verification
- [x] Baseline and regression comparison
- [x] Repeated-trial evidence and statistical outcome summaries
- [x] Evidence-based compact reproducer extraction
- [x] API compatibility policy
- [x] Independent full-repository application-security review
- [ ] Complete name clearance and reserve package and repository names
- [ ] Publish the repository and configure private vulnerability reporting
- [ ] Complete two external practitioner reviews

## Release 1.1: assessment workflow extensions

- Adaptive delta-debugging finding minimization
- Provider-specific adapters maintained outside the core
- Optional signed bundle integrations
- Engagement time-window enforcement
- Pluggable model-judge oracle with data-boundary warnings

## Release 1.2: agent and RAG testing

- Sandboxed tool-use simulation
- Retrieval-corpus poisoning fixtures
- Indirect injection across HTML, Markdown, email, and document fixtures
- Trust-boundary graphs for agent workflows
- Human-review queues for ambiguous oracle decisions

## Stable-release gate

- Documented API compatibility policy
- Reproducibility tests on every supported Python version
- Security review of transport, redaction, and report paths
- Signed releases and published checksums
- At least three documented assessments using authorized or intentionally vulnerable targets
