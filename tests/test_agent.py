from __future__ import annotations

from collections.abc import Sequence

import pytest

from advent_prompt_pwn import (
    AgentSandboxHarness,
    FakeTarget,
    Message,
    Role,
    SandboxTool,
    TargetResponse,
    ToolCall,
    ToolSandbox,
)
from advent_prompt_pwn.core.models import Message as ModelMessage
from advent_prompt_pwn.core.scope import Scope


def test_agent_harness_runs_live_turns_with_static_tool_responses() -> None:
    calls = 0

    def target(messages: Sequence[ModelMessage]) -> TargetResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            return TargetResponse(
                "requesting synthetic tool",
                tool_calls=(ToolCall("lookup", '{"query":"LAB_SECRET"}', "call-1"),),
            )
        assert messages[-1].role is Role.TOOL
        return TargetResponse("completed safely")

    sandbox = ToolSandbox(
        [
            SandboxTool(
                "lookup",
                {"result": "synthetic-only"},
                allowed_argument_keys=("query",),
            )
        ]
    )
    result = AgentSandboxHarness(
        FakeTarget(target),
        sandbox,
        scope=Scope.local_only(max_requests=2, requests_per_minute=1_000_000),
        redact_secrets=("LAB_SECRET",),
    ).run([Message(Role.USER, "test LAB_SECRET")])

    assert result.requests == 2
    assert result.stopped_reason == "completed"
    assert result.steps[0].observations[0].allowed
    assert result.steps[0].observations[0].arguments["query"] == "[REDACTED]"
    assert result.messages[0].content == "test [REDACTED]"
    assert result.steps[-1].response.content == "completed safely"


@pytest.mark.parametrize(
    ("call", "reason"),
    [
        (ToolCall("missing", "{}"), "allowlist"),
        (ToolCall("lookup", "not-json"), "valid JSON"),
        (ToolCall("lookup", "[]"), "JSON object"),
        (ToolCall("lookup", '{"extra":1}'), "unapproved keys"),
    ],
)
def test_tool_sandbox_blocks_unapproved_calls(call: ToolCall, reason: str) -> None:
    sandbox = ToolSandbox([SandboxTool("lookup", {}, allowed_argument_keys=("query",))])
    observation = sandbox.handle(call)
    assert not observation.allowed
    assert reason in observation.reason


def test_tool_sandbox_and_harness_validate_limits() -> None:
    with pytest.raises(ValueError, match="safe identifier"):
        SandboxTool("bad tool", {})
    with pytest.raises(ValueError, match="argument keys"):
        SandboxTool("lookup", {}, allowed_argument_keys=(1,))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unique"):
        ToolSandbox([SandboxTool("same", {}), SandboxTool("same", {})])
    with pytest.raises(ValueError, match="between"):
        ToolSandbox([], max_argument_bytes=0)
    with pytest.raises(ValueError, match="between"):
        ToolSandbox([], max_argument_bytes=True)

    sandbox = ToolSandbox([SandboxTool("lookup", {})], max_argument_bytes=2)
    assert not sandbox.handle(ToolCall("lookup", "{} ")).allowed
    assert sandbox.tool_names == ("lookup",)

    with pytest.raises(ValueError, match="max_rounds"):
        AgentSandboxHarness(FakeTarget(), ToolSandbox([]), max_rounds=0)
    with pytest.raises(ValueError, match="max_rounds"):
        AgentSandboxHarness(FakeTarget(), ToolSandbox([]), max_rounds=True)
    with pytest.raises(ValueError, match="max_tool_calls"):
        AgentSandboxHarness(FakeTarget(), ToolSandbox([]), max_tool_calls=0)
    with pytest.raises(ValueError, match="timeout"):
        AgentSandboxHarness(FakeTarget(), ToolSandbox([]), timeout_s=0)
    with pytest.raises(ValueError, match="timeout"):
        AgentSandboxHarness(FakeTarget(), ToolSandbox([]), timeout_s=float("nan"))


def test_agent_harness_stops_at_round_limit_and_bounds_calls() -> None:
    response = TargetResponse("", tool_calls=(ToolCall("lookup", "{}"),))
    sandbox = ToolSandbox([SandboxTool("lookup", {})])
    limited = AgentSandboxHarness(
        FakeTarget(lambda messages: response),
        sandbox,
        scope=Scope.local_only(max_requests=1, requests_per_minute=1_000_000),
        max_rounds=1,
    )
    result = limited.run([Message(Role.USER, "test")])
    assert result.stopped_reason == "max_rounds"
    assert "sandboxed tool requests" in result.messages[-2].content

    excessive = TargetResponse(
        "",
        tool_calls=(ToolCall("lookup", "{}"), ToolCall("lookup", "{}")),
    )
    with pytest.raises(ValueError, match="cumulative"):
        AgentSandboxHarness(
            FakeTarget(lambda messages: excessive),
            sandbox,
            scope=Scope.local_only(max_requests=1, requests_per_minute=1_000_000),
            max_rounds=1,
            max_tool_calls=1,
        ).run([Message(Role.USER, "test")])
    with pytest.raises(ValueError, match="at least one"):
        limited.run([])
