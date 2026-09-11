from __future__ import annotations

import pytest

from advent_prompt_pwn import (
    ConversationAttackHarness,
    FakeTarget,
    Message,
    Role,
    Scope,
    TargetResponse,
    ToolCall,
)


class _SensitiveFakeTarget(FakeTarget):
    @property
    def sensitive_values(self) -> tuple[str, ...]:
        return ("ENGAGEMENT_SECRET",)


def test_conversation_harness_adapts_to_previous_response_and_redacts() -> None:
    def respond(messages: list[Message]) -> str:
        return f"reply-{sum(message.role is Role.USER for message in messages)} ENGAGEMENT_SECRET"

    target = _SensitiveFakeTarget(respond)
    harness = ConversationAttackHarness(
        target,
        scope=Scope.local_only(max_requests=3, requests_per_minute=1_000_000),
        max_turns=3,
    )

    def planner(
        messages: tuple[Message, ...], previous: TargetResponse | None, index: int
    ) -> str | None:
        del messages
        if index == 0:
            return "first ENGAGEMENT_SECRET"
        if index == 1 and previous:
            return f"follow up on {previous.content}"
        return None

    result = harness.run(planner)

    assert result.requests == 2
    assert result.stopped_reason == "planner_stopped"
    assert len(result.turns) == 2
    assert "ENGAGEMENT_SECRET" not in repr(result)
    assert "[REDACTED]" in result.messages[0].content


def test_conversation_harness_stops_on_tool_call_without_execution() -> None:
    target = FakeTarget(
        TargetResponse(
            content="",
            tool_calls=(ToolCall("synthetic_tool", "{}", "call-1"),),
        )
    )
    result = ConversationAttackHarness(target, max_turns=2).run(
        lambda messages, previous, index: "request synthetic tool"
    )

    assert result.stopped_reason == "tool_call_requested"
    assert result.requests == 1
    assert len(result.messages) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_turns": True},
        {"max_turns": 0},
        {"max_prompt_characters": 0},
        {"timeout_s": float("nan")},
    ],
)
def test_conversation_harness_rejects_invalid_limits(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ConversationAttackHarness(FakeTarget(), **kwargs)  # type: ignore[arg-type]


def test_conversation_harness_rejects_invalid_planner_and_tool_history() -> None:
    harness = ConversationAttackHarness(FakeTarget())
    with pytest.raises(ValueError, match="non-empty"):
        harness.run(lambda messages, previous, index: "")
    with pytest.raises(ValueError, match="character limit"):
        ConversationAttackHarness(FakeTarget(), max_prompt_characters=2).run(
            lambda messages, previous, index: "long"
        )
    with pytest.raises(ValueError, match="tool messages"):
        harness.run(
            lambda messages, previous, index: None,
            initial_messages=(Message(Role.TOOL, "{}", name="tool"),),
        )
