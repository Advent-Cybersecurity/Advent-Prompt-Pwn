# Architecture

The core execution path is deliberately small:

```text
Engagement -> Corpus -> AttackCase -> Strategy -> AttackVariant
     |                                                  |
     +------> Scope -> RequestGuard -> Target -> Response
                                                |
Bundle <- RunReport <- Finding <- AttemptResult <- OracleResult
```

## Target

A target converts normalized chat messages into a normalized response. It declares an endpoint before a request is sent so scope validation can occur first.

## Attack case

A case defines the base objective, optional system instruction, tags, metadata, and success oracle. It does not contain transport configuration.

## Strategy

A strategy converts one case into one or more message sequences. Strategy generation receives a seeded random generator so future stochastic mutations remain reproducible.

## Oracle

An oracle decides whether its adversarial objective was observed. Oracle success means attack success. It does not mean the target passed the security test.

## Scope

Scope is validated before strategy execution reaches the target. Local mode accepts in-memory adapters and loopback IP addresses. Remote mode requires exact hosts and an authorization reference.

## Execution

The runner expands variants with a seeded random generator before sending requests. It rejects duplicate variant IDs, enforces per-case variant limits, and checks concurrency against the declared scope. A shared request guard applies the total budget and rate limit across worker threads. Targets must explicitly declare concurrent-request support.

Retries use bounded exponential backoff. Errors remain separate from security passes. Atomic checkpoint reports contain completed variants and the cumulative request count so a resumed run cannot silently reset its budget. When prior requests are recorded, resume waits one full configured request interval before the first new dispatch so even requests issued after a stale checkpoint cannot reset the cross-process rate limit.

Repeated-trial execution assigns deterministic trial variant IDs and records the base variant in
protected metadata. Reports calculate per-variant success rates and Wilson 95% confidence
intervals. Preflight planning counts every trial against the minimum request budget.

## Findings and evidence

Each attempt stores normalized messages, a normalized response, the oracle decision, timestamps, duration, retry count, severity, tags, errors, and a SHA-256 hash over the redacted evidence. Successful variants with the same case ID are grouped into one stable finding ID.

An evidence bundle renders selected report formats and records each file's size and SHA-256 digest in a manifest. Offline verification requires one unique checksummed `report.json`, enforces per-file and cumulative size limits, binds bundle metadata to the report, and recalculates attempt and report-envelope hashes. Hashes detect changes but are not digital signatures.

Baseline comparison uses stable finding IDs to identify new, persistent, and resolved results. It accepts only complete runs and requires the same keyed target endpoint, adapter contract, selected strategies, selected cases, trials per variant, framework seed, planned attempt total, and per-case strategy coverage. It also requires identical generated job inputs unless the operator explicitly allows a corpus change.

Minimal reproducer extraction operates only on integrity-verified reports. It selects the shortest
successful message sequence already observed for each finding and does not contact the target.

## Extension boundary

Specialized strategies can be distributed as entry-point plugins. Target adapters can be implemented with the public `Target` abstract class. Plugins remain subject to the runner's scope and request budget only when they use the ordinary execution path. A plugin is ordinary Python code and is not sandboxed.
