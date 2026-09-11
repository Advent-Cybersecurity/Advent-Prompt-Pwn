# Authorized Use

This framework is intended for systems you own, intentionally vulnerable laboratories, public research benchmarks, or targets covered by explicit written authorization.

Before a remote run, record:

1. The owner of the target.
2. The exact hostnames and applications in scope.
3. The approved test period.
4. Request-rate and cost limits.
5. Prohibited data and actions.
6. The person who can stop the test.
7. The engagement or ticket reference used in the report.

Remote scope uses exact host matching. Subdomains are not included automatically. This prevents an allowlist entry for one host from silently authorizing an entire domain.

Remote engagement manifests require explicit ports. Remote HTTP requires an insecure-transport opt-in. Query parameters require an explicit allowlist, and credentials embedded in URLs or credential-like query parameters are rejected. At execution, independently supply the exact authorization reference, hosts, ports, query names, transport or DNS opt-ins, and maximum request, rate, concurrency, retry, timeout, trial, variant, response, and evidence limits. Built-in clients ignore ambient proxy settings and reject custom `Host` headers. These checks reduce configuration mistakes but do not replace a reviewed rules-of-engagement document.

Remote DNS names require `allow_unpinned_dns: true`. This opt-in does not pin the address used by
the operating system. High-assurance engagements should enforce approved destinations with host
or network egress controls and controlled DNS. IP literals remain available without this opt-in
when the target contract permits them.

Use laboratory canaries instead of real secrets. If the assessment concerns tool use, connect the model to simulated tools that cannot send messages, change production data, make purchases, or execute commands.

Generated evidence can contain model output supplied by an assessed application. Treat reports as sensitive engagement material even when secrets are redacted. A manifest may name credential environment variables only when the operator independently grants each name with `--allow-env` at execution time.

Use `execution.redact_env` for every environment variable whose value could appear in target output or exceptions. Every manifest-selected environment variable, including a redaction-only variable, requires a separate `--allow-env` grant. Credential variables used by built-in adapters are included automatically. Configure `execution.checkpoint_hmac_env` for resumable work, protect its value separately from the evidence, and verify the authentication tag before delivery. Retain each flushed checkpoint candidate identity in trusted engagement state, mark the successfully written candidate as current, and require its integrity digest on resume so an older authentic checkpoint cannot silently reset accounting. Resume waits one full configured request interval before dispatching after prior requests. Authenticate both complete reports with the same key when using the CLI comparison workflow, and compare only runs with matching execution selections and job coverage. Use organization-approved signing if authorship or non-repudiation is required.
