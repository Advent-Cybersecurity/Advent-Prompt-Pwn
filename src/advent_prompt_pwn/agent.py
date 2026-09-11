"""Side-effect-free agent and tool-use simulation."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from advent_prompt_pwn.core.models import Message, Role, TargetResponse, ToolCall
from advent_prompt_pwn.core.redaction import redact_text, redact_value
from advent_prompt_pwn.core.scope import RequestGuard, Scope
from advent_prompt_pwn.targets.base import Target
from advent_prompt_pwn.validation import validate_json_value

_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


@dataclass(frozen=True, slots=True)
class SandboxTool:
    """Static synthetic tool definition that cannot perform real side effects."""

    name: str
    response: Mapping[str, Any]
    allowed_argument_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _TOOL_NAME.fullmatch(self.name):
            raise ValueError("sandbox tool name must use safe identifier characters")
        validate_json_value(self.response, label="sandbox tool response")
        if any(
            not isinstance(key, str) or not key or len(key) > 128
            for key in self.allowed_argument_keys
        ):
            raise ValueError("sandbox allowed argument keys must be 1 through 128 characters")
        object.__setattr__(self, "response", dict(self.response))


@dataclass(frozen=True, slots=True)
class ToolObservation:
    """Recorded sandbox decision for one requested tool call."""

    name: str
    call_id: str | None
    allowed: bool
    reason: str
    arguments: Mapping[str, Any]
    response: Mapping[str, Any]


class ToolSandbox:
    """Validate tool requests and return static responses without executing code."""

    def __init__(self, tools: Sequence[SandboxTool], *, max_argument_bytes: int = 65_536) -> None:
        if (
            isinstance(max_argument_bytes, bool)
            or not isinstance(max_argument_bytes, int)
            or not 1 <= max_argument_bytes <= 2_000_000
        ):
            raise ValueError("max_argument_bytes must be between 1 and 2000000")
        indexed = {tool.name: tool for tool in tools}
        if len(indexed) != len(tools):
            raise ValueError("sandbox tool names must be unique")
        self._tools = indexed
        self.max_argument_bytes = max_argument_bytes

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def handle(self, call: ToolCall) -> ToolObservation:
        """Return a synthetic observation for one normalized tool call."""

        if len(call.arguments.encode("utf-8")) > self.max_argument_bytes:
            return ToolObservation(
                call.name,
                call.call_id,
                False,
                "tool arguments exceeded the sandbox byte limit",
                {},
                {},
            )
        try:
            arguments = json.loads(call.arguments or "{}")
        except json.JSONDecodeError:
            return ToolObservation(
                call.name,
                call.call_id,
                False,
                "tool arguments were not valid JSON",
                {},
                {},
            )
        if not isinstance(arguments, dict):
            return ToolObservation(
                call.name,
                call.call_id,
                False,
                "tool arguments were not a JSON object",
                {},
                {},
            )
        tool = self._tools.get(call.name)
        if tool is None:
            return ToolObservation(
                call.name,
                call.call_id,
                False,
                "tool was not present in the sandbox allowlist",
                arguments,
                {},
            )
        unexpected = sorted(set(arguments) - set(tool.allowed_argument_keys))
        if unexpected:
            return ToolObservation(
                call.name,
                call.call_id,
                False,
                "tool arguments included unapproved keys",
                arguments,
                {},
            )
        return ToolObservation(
            call.name,
            call.call_id,
            True,
            "static sandbox response returned",
            arguments,
            tool.response,
        )


@dataclass(frozen=True, slots=True)
class AgentStep:
    """One model response and its simulated tool observations."""

    response: TargetResponse
    observations: tuple[ToolObservation, ...]


@dataclass(frozen=True, slots=True)
class AgentRunResult:
    """Bounded transcript produced by the side-effect-free agent harness."""

    messages: tuple[Message, ...]
    steps: tuple[AgentStep, ...]
    requests: int
    stopped_reason: str


class AgentSandboxHarness:
    """Run a target through bounded live turns using only static sandbox tools."""

    def __init__(
        self,
        target: Target,
        sandbox: ToolSandbox,
        *,
        scope: Scope | None = None,
        max_rounds: int = 4,
        max_tool_calls: int = 16,
        timeout_s: float = 30.0,
        redact_secrets: Sequence[str] = (),
    ) -> None:
        if (
            isinstance(max_rounds, bool)
            or not isinstance(max_rounds, int)
            or not 1 <= max_rounds <= 32
        ):
            raise ValueError("max_rounds must be between 1 and 32")
        if (
            isinstance(max_tool_calls, bool)
            or not isinstance(max_tool_calls, int)
            or not 1 <= max_tool_calls <= 128
        ):
            raise ValueError("max_tool_calls must be between 1 and 128")
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s)
            or not 0 < timeout_s <= 600
        ):
            raise ValueError("timeout_s must be between 0 and 600")
        self.target = target
        self.sandbox = sandbox
        self.scope = scope or Scope.local_only(max_requests=max_rounds)
        self.max_rounds = max_rounds
        self.max_tool_calls = max_tool_calls
        self.timeout_s = timeout_s
        self.redact_secrets = tuple(value for value in redact_secrets if value)

    def run(self, messages: Sequence[Message]) -> AgentRunResult:
        """Run until the target stops requesting tools or a bound is reached."""

        transcript = list(messages)
        if not transcript:
            raise ValueError("agent harness requires at least one message")
        self.scope.assert_endpoint(self.target.endpoint)
        guard = RequestGuard(self.scope)
        raw_steps: list[tuple[TargetResponse, tuple[ToolObservation, ...]]] = []
        tool_call_count = 0
        stopped_reason = "max_rounds"
        for _round in range(self.max_rounds):
            self.scope.assert_endpoint(self.target.endpoint)
            guard.acquire()
            self.scope.assert_endpoint(self.target.endpoint)
            response = self.target.complete(transcript, timeout_s=self.timeout_s)
            tool_call_count += len(response.tool_calls)
            if tool_call_count > self.max_tool_calls:
                raise ValueError("agent harness exceeded its cumulative tool-call limit")
            observations = tuple(self.sandbox.handle(call) for call in response.tool_calls)
            raw_steps.append((response, observations))
            if not observations:
                stopped_reason = "completed"
                break
            assistant_content = response.content or (
                "[sandboxed tool requests: "
                + ", ".join(call.name for call in response.tool_calls)
                + "]"
            )
            transcript.append(Message(Role.ASSISTANT, assistant_content))
            for observation in observations:
                payload = {
                    "allowed": observation.allowed,
                    "reason": observation.reason,
                    "response": observation.response,
                }
                transcript.append(
                    Message(
                        Role.TOOL,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        name=observation.name,
                    )
                )

        secrets = tuple(sorted({*self.redact_secrets, *self.target.sensitive_values}))
        safe_messages = tuple(
            Message(message.role, redact_text(message.content, secrets), message.name)
            for message in transcript
        )
        safe_steps = tuple(
            AgentStep(
                response=_redact_response(response, secrets),
                observations=tuple(_redact_observation(item, secrets) for item in observations),
            )
            for response, observations in raw_steps
        )
        return AgentRunResult(safe_messages, safe_steps, guard.count, stopped_reason)


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


def _redact_observation(observation: ToolObservation, secrets: Sequence[str]) -> ToolObservation:
    return ToolObservation(
        name=redact_text(observation.name, secrets),
        call_id=(redact_text(observation.call_id, secrets) if observation.call_id else None),
        allowed=observation.allowed,
        reason=redact_text(observation.reason, secrets),
        arguments=redact_value(observation.arguments, secrets),
        response=redact_value(observation.response, secrets),
    )
