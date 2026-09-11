"""Deterministic in-memory targets for tests and demonstrations."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from advent_prompt_pwn.core.models import Message, TargetResponse
from advent_prompt_pwn.targets.base import Target

ResponseFactory = Callable[[Sequence[Message]], str | TargetResponse]


def _callable_identity(value: Callable[..., Any]) -> dict[str, str]:
    return {
        "module": getattr(value, "__module__", type(value).__module__),
        "qualname": getattr(value, "__qualname__", type(value).__qualname__),
    }


class FakeTarget(Target):
    """Return a fixed value or invoke a local callback."""

    def __init__(self, response: str | ResponseFactory = "SAFE_RESPONSE", *, name: str = "fake"):
        self._response = response
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def endpoint(self) -> str:
        return "memory://fake"

    @property
    def supports_concurrency(self) -> bool:
        return not callable(self._response)

    @property
    def resume_identity(self) -> dict[str, Any]:
        response: Any = (
            {"callable": _callable_identity(self._response)}
            if callable(self._response)
            else {"fixed_response": self._response}
        )
        return {**super().resume_identity, "response": response}

    def complete(self, messages: Sequence[Message], *, timeout_s: float) -> TargetResponse:
        del timeout_s
        value = self._response(messages) if callable(self._response) else self._response
        if isinstance(value, TargetResponse):
            return value
        return TargetResponse(content=value, model="fake")


class FunctionTarget(Target):
    """Adapt an application callback without requiring a network server."""

    def __init__(self, function: ResponseFactory, *, name: str = "function") -> None:
        self._function = function
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def endpoint(self) -> str:
        return f"function://{self._name}"

    @property
    def resume_identity(self) -> dict[str, Any]:
        return {
            **super().resume_identity,
            "function": _callable_identity(self._function),
        }

    def complete(self, messages: Sequence[Message], *, timeout_s: float) -> TargetResponse:
        del timeout_s
        value = self._function(messages)
        return value if isinstance(value, TargetResponse) else TargetResponse(content=value)
