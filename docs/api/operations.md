# Scope and engagement

## Scope

`Scope.local_only(...)` restricts execution to memory, function, loopback, and local application
targets. `Scope.authorized(...)` requires an authorization reference and exact remote host grant.
Ports, query names, transport, DNS, request count, rate, concurrency, and time window are enforced.

`pinned_dns` maps each approved hostname to allowed IPv4 or IPv6 addresses. `not_before` and
`not_after` are timezone-aware ISO 8601 timestamps. The upper bound is exclusive.

## Runner

`Runner(target, scope=..., config=...)` expands cases and strategies, applies request bounds,
checkpoints results, evaluates oracles, redacts evidence, and returns `RunReport`.

## Engagement manifests

`load_engagement`, `plan_engagement`, and `run_engagement` implement the versioned manifest flow.
Remote execution requires independent command-time grants. `plan_engagement` validates future time
windows and DNS-pin syntax without resolving or contacting the target. Execution verifies both.

## Agent simulation

`ToolSandbox`, `SandboxTool`, and `AgentSandboxHarness` run bounded live turns using static tool
responses only.
