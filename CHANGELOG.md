# Changelog

All notable changes are recorded here. The project follows Semantic Versioning.

## 1.0.0 - Unreleased

### Fixed

- Restored `ContainsAllOracle` initialization compatibility on Python 3.10 through 3.12.

### Added

- Final project identity: `advent-prompt-pwn` distribution and CLI with `advent_prompt_pwn` imports
- Typed Python API for targets, cases, strategies, oracles, and evidence
- Local-only and explicitly authorized remote scope modes
- Request budgets, global rate limits, retry backoff, bounded concurrency, redaction, and response-size limits
- Fake, callback, Ollama, OpenAI-compatible, and custom HTTP JSON targets
- Direct, instruction-override, delimiter, encoding, role-confusion, indirect-content, and multi-turn strategies
- Literal-set, canary, regular-expression, JSON-key, JSON-path, composite, and tool-call oracles
- YAML and JSON corpora
- JSON, JSONL, HTML, Markdown, JUnit, and SARIF reports
- Versioned engagement manifests with case filtering and request preflight
- Stable finding IDs, severity, and deduplication across successful variants
- Repeated trials with deterministic identifiers, request-budget preflight, mixed-outcome detection, and Wilson 95% confidence intervals
- Integrity-verified extraction of the shortest already-observed successful variant for each finding
- Atomic checkpoints, integrity-verified resume, and cumulative request accounting
- Full attempt and report-envelope modification detection with exact resume binding
- Independent manifest credential grants and manifest-relative path confinement
- Streaming HTTP response limits and bounded regex, corpus, oracle, report, and bundle processing
- Monotonic HTTP deadline checks, bounded I/O stalls, identity-only response encoding, cumulative evidence limits, and streaming bounded report generation
- Explicit noncredential query allowlists and secure-by-default rejection of unpinned remote DNS names
- Crash-conservative request reservations and integrity-covered unresolved request accounting
- Runtime validation of target and oracle results, strict canonical report loading, and 128-bit finding identifiers
- HMAC-authenticated checkpoints and complete target and execution contract resume binding
- Independent execution-time approval for every remote manifest authorization and network capability
- Strict duplicate-key rejection for JSON and YAML inputs
- Sanitized HTTP error evidence, opaque endpoint-path redaction, bounded bundle enumeration, and XML-safe JUnit output
- Strict engagement-v1 schema enforcement for required, typed, and unknown manifest fields
- Proxy-independent built-in HTTP clients and rejection of manifest-controlled `Host` routing
- Independent remote workload ceilings for requests, rate, concurrency, retries, timeout, trials, variants, response bytes, and evidence bytes
- Keyed-only endpoint and target identity pseudonyms for redacted evidence
- Resume binding for redaction configuration and runner metadata
- Independently approved checkpoint integrity to reject authentic but stale resume files
- Synchronously flushed checkpoint candidate identities for interruption-safe freshness records
- Mandatory HMAC authentication of both reports in CLI baseline comparison
- Legacy unauthenticated resume restricted to consuming reviewed evidence without emitting new unkeyed identity hashes
- Cross-process resume enforcement of the authenticated request-rate interval
- Rejection of incomplete checkpoint evidence and mismatched target contracts during baseline comparison
- Full-interval first-dispatch delay after authenticated resume, including stale checkpoint recovery
- Authenticated baseline comparison of selected strategies, cases, trials, and framework seed
- Cross-report comparison of planned totals, per-case strategy coverage, and generated job inputs
- Constant-space rejection of unexpected force-mode evidence-bundle members
- Release publication gates that rerun the supported operating-system and Python matrix, quality checks, and dependency audit before build
- Inert Markdown rendering and recursive redaction of all persisted target-controlled fields
- Checksum evidence bundles and offline tamper verification
- Baseline comparison for new, persistent, and resolved findings
- CLI workflows for initialization, validation, execution, verification, comparison, diagnostics, and strategy discovery
- Tests, strict typing, coverage enforcement, and package build automation
- A documented v1 API compatibility policy and engagement workflow
