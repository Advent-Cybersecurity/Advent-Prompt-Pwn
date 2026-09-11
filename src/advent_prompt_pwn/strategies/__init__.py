"""Attack strategy public API."""

from advent_prompt_pwn.strategies.base import Strategy
from advent_prompt_pwn.strategies.builtin import (
    CompositeStrategy,
    DelimiterStrategy,
    DirectStrategy,
    EncodingStrategy,
    IndirectDocumentStrategy,
    IndirectFixtureStrategy,
    InstructionOverrideStrategy,
    MultiTurnStrategy,
    MutationStrategy,
    RagPoisoningStrategy,
    RoleConfusionStrategy,
)
from advent_prompt_pwn.strategies.registry import get_strategy, strategy_names

__all__ = [
    "CompositeStrategy",
    "DelimiterStrategy",
    "DirectStrategy",
    "EncodingStrategy",
    "IndirectDocumentStrategy",
    "IndirectFixtureStrategy",
    "InstructionOverrideStrategy",
    "MultiTurnStrategy",
    "MutationStrategy",
    "RagPoisoningStrategy",
    "RoleConfusionStrategy",
    "Strategy",
    "get_strategy",
    "strategy_names",
]
