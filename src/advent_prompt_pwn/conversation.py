"""Bounded live multi-turn attack conversations."""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from advent_prompt_pwn.core.models import Message, Role, TargetResponse, ToolCall
from advent_prompt_pwn.core.redaction import redact_text, redact_value
from advent_prompt_pwn.core.scope import RequestGuard, Scope
from advent_prompt_pwn.targets.base import Target

TurnPlanner = Callable[[tuple[Message, ...], TargetResponse | None, int], str | None]


@dataclass(frozen=True, slots=True)
class ConversationTurn:
    """One attacker message and target response in a live conversation."""

    index: int
    attacker_message: Message
    response: TargetResponse


@dataclass(frozen=True, slots=True)
class ConversationAttackResult:
    """Redacted transcript and turn evidence from a bounded conversation."""

    messages: tuple[Message, ...]
    turns: tuple[ConversationTurn, ...]
    requests: int
    stopped_reason: str


class ConversationAttackHarness:
    """Run a feedback-adaptive attacker planner against a scoped target."""

    def __init__(
        self,
        target: Target,
        *,
        scope: Scope | None = None,
        max_turns: int = 6,
        max_prompt_characters: int = 100_000,
        timeout_s: float = 30.0,
        redact_secrets: Sequence[str] = (),
    ) -> None:
        if (
            isinstance(max_turns, bool)
            or not isinstance(max_turns, int)
            or not 1 <= max_turns <= 64
        ):
            raise ValueError("max_turns must be between 1 and 64")
        if (
            isinstance(max_prompt_characters, bool)
            or not isinstance(max_prompt_characters, int)
            or not 1 <= max_prompt_characters <= 2_000_000
        ):
            raise ValueError("max_prompt_characters must be between 1 and 2000000")
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s)
            or not 0 < timeout_s <= 600
        ):
            raise ValueError("timeout_s must be between 0 and 600")
        self.target = target
        self.scope = scope or Scope.local_only(max_requests=max_turns)
        self.max_turns = max_turns
        self.max_prompt_characters = max_prompt_characters
        self.timeout_s = timeout_s
        self.redact_secrets = tuple(value for value in redact_secrets if value)

    def run(
        self,
        planner: TurnPlanner,
        *,
        initial_messages: Sequence[Message] = (),
    ) -> ConversationAttackResult:
        """Run until the trusted local planner stops or a safety bound is reached."""

        transcript = list(initial_messages)
        if any(message.role is Role.TOOL for message in transcript):
            raise ValueError("conversation harness does not accept tool messages")
        self.scope.assert_endpoint(self.target.endpoint)
        guard = RequestGuard(self.scope)
        raw_turns: list[ConversationTurn] = []
        previous: TargetResponse | None = None
        stopped_reason = "max_turns"

        for index in range(self.max_turns):
            prompt = planner(tuple(transcript), previous, index)
            if prompt is None:
                stopped_reason = "planner_stopped"
                break
            if not isinstance(prompt, str) or not prompt.strip():
                raise ValueError("turn planner must return a non-empty string or None")
            if len(prompt) > self.max_prompt_characters:
                raise ValueError("turn planner prompt exceeded the character limit")
            attacker_message = Message(Role.USER, prompt)
            transcript.append(attacker_message)
            self.scope.assert_endpoint(self.target.endpoint)
            guard.acquire()
            self.scope.assert_endpoint(self.target.endpoint)
            response = self.target.complete(transcript, timeout_s=self.timeout_s)
            raw_turns.append(ConversationTurn(index, attacker_message, response))
            previous = response
            if response.tool_calls:
                stopped_reason = "tool_call_requested"
                break
            transcript.append(Message(Role.ASSISTANT, response.content))

        secrets = tuple(sorted({*self.redact_secrets, *self.target.sensitive_values}))
        safe_messages = tuple(
            Message(message.role, redact_text(message.content, secrets), message.name)
            for message in transcript
        )
        safe_turns = tuple(
            ConversationTurn(
                turn.index,
                Message(
                    turn.attacker_message.role,
                    redact_text(turn.attacker_message.content, secrets),
                    turn.attacker_message.name,
                ),
                _redact_response(turn.response, secrets),
            )
            for turn in raw_turns
        )
        return ConversationAttackResult(safe_messages, safe_turns, guard.count, stopped_reason)


def _redact_response(response: TargetResponse, secrets: Sequence[str]) -> TargetResponse:
    return TargetResponse(
        content=redact_text(response.content, secrets),
        model=redact_text(response.model, secrets) if response.model else None,
        finish_reason=(
            redact_text(response.finish_reason, secrets) if response.finish_reason else None
        ),
        latency_ms=response.latency_ms,
        usage=response.usage,
        tool_calls=tuple(
            ToolCall(
                redact_text(call.name, secrets),
                redact_text(call.arguments, secrets),
                redact_text(call.call_id, secrets) if call.call_id else None,
            )
            for call in response.tool_calls
        ),
        metadata=redact_value(response.metadata, secrets),
    )
