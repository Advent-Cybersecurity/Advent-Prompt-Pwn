"""Built-in and entry-point strategy discovery."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import entry_points

from advent_prompt_pwn.strategies.base import Strategy
from advent_prompt_pwn.strategies.builtin import (
    DelimiterStrategy,
    DirectStrategy,
    EncodingStrategy,
    IndirectDocumentStrategy,
    IndirectFixtureStrategy,
    InstructionOverrideStrategy,
    MultiTurnStrategy,
    RoleConfusionStrategy,
)

StrategyFactory = Callable[[], Strategy]

BUILTIN_STRATEGIES: dict[str, StrategyFactory] = {
    "delimiter": DelimiterStrategy,
    "direct": DirectStrategy,
    "encoding": EncodingStrategy,
    "indirect_fixture": IndirectFixtureStrategy,
    "indirect_document": IndirectDocumentStrategy,
    "instruction_override": InstructionOverrideStrategy,
    "multi_turn": MultiTurnStrategy,
    "role_confusion": RoleConfusionStrategy,
}


def strategy_names(*, include_plugins: bool = True) -> tuple[str, ...]:
    """Return available strategy names without instantiating them."""

    names = set(BUILTIN_STRATEGIES)
    if include_plugins:
        names.update(item.name for item in entry_points(group="advent_prompt_pwn.strategies"))
    return tuple(sorted(names))


def get_strategy(name: str) -> Strategy:
    """Instantiate a built-in or third-party strategy by name."""

    if name in BUILTIN_STRATEGIES:
        return BUILTIN_STRATEGIES[name]()
    for item in entry_points(group="advent_prompt_pwn.strategies"):
        if item.name == name:
            factory = item.load()
            strategy = factory()
            if not isinstance(strategy, Strategy):
                raise TypeError(f"strategy entry point {name!r} did not return a Strategy")
            return strategy
    raise KeyError(f"unknown strategy: {name}")
