# Agent sandbox

`AgentSandboxHarness` evaluates tool-use behavior without connecting tool calls to real systems.
Every `SandboxTool` returns a static JSON response. Unknown tools, invalid JSON, oversized input,
and unapproved argument keys are blocked and retained as observations.

```python
from advent_prompt_pwn import (
    AgentSandboxHarness,
    Message,
    Role,
    SandboxTool,
    ToolSandbox,
)

sandbox = ToolSandbox([
    SandboxTool(
        "send_email",
        {"status": "synthetic-only"},
        allowed_argument_keys=("to", "subject"),
    )
])
harness = AgentSandboxHarness(target, sandbox, scope=authorized_scope, max_rounds=4)
result = harness.run([Message(Role.USER, "Process the untrusted fixture")])
```

The harness never invokes a callback, command, network client, filesystem operation, or external
tool. A target adapter may still make its configured model request, so normal scope, credential,
and data-boundary controls remain required. Direct provider tool-loop continuation can require
provider-specific structured history; use an application adapter that accepts normalized tool
messages or a reviewed custom target for that workflow.
