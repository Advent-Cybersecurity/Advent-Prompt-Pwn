"""Target adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any

from advent_prompt_pwn.core.models import Message, TargetResponse


class Target(ABC):
    """A model or AI application that can complete chat messages."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable target name."""

    @property
    @abstractmethod
    def endpoint(self) -> str:
        """Endpoint used for scope validation."""

    @property
    def supports_concurrency(self) -> bool:
        """Whether one adapter instance may serve concurrent requests."""

        return False

    @property
    def resume_identity(self) -> Mapping[str, Any]:
        """Return the complete secret-free execution identity used for resume binding."""

        return {
            "adapter": f"{type(self).__module__}.{type(self).__qualname__}",
            "name": self.name,
            "endpoint": self.endpoint,
        }

    @abstractmethod
    def complete(self, messages: Sequence[Message], *, timeout_s: float) -> TargetResponse:
        """Complete a normalized chat conversation."""

    def close(self) -> None:
        """Release target resources."""

        return None
