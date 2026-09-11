"""Strategy interfaces and helpers."""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from collections.abc import Iterable

from advent_prompt_pwn.core.models import AttackCase, AttackVariant, Message, Role


def case_messages(case: AttackCase, prompt: str | None = None) -> tuple[Message, ...]:
    """Create the ordinary system and user message sequence for a case."""

    messages: list[Message] = []
    if case.system_prompt:
        messages.append(Message(Role.SYSTEM, case.system_prompt))
    messages.append(Message(Role.USER, prompt or case.prompt))
    return tuple(messages)


class Strategy(ABC):
    """Generate one or more attack variants for a case."""

    name: str

    @abstractmethod
    def generate(self, case: AttackCase, rng: random.Random) -> Iterable[AttackVariant]:
        """Generate deterministic variants using the supplied random generator."""
