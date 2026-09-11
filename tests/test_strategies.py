from __future__ import annotations

import random

import pytest

from advent_prompt_pwn import (
    AttackCase,
    CompositeStrategy,
    ContainsOracle,
    DelimiterStrategy,
    DirectStrategy,
    EncodingStrategy,
    IndirectDocumentStrategy,
    IndirectFixtureStrategy,
    InstructionOverrideStrategy,
    MultiTurnStrategy,
    Role,
    RoleConfusionStrategy,
)
from advent_prompt_pwn.strategies import get_strategy, strategy_names


def _case(*, system: str | None = "system") -> AttackCase:
    return AttackCase("case", "Case", "objective", ContainsOracle("marker"), system)


def test_direct_strategy_preserves_case_messages() -> None:
    variant = next(iter(DirectStrategy().generate(_case(), random.Random(1))))
    assert [message.role for message in variant.messages] == [Role.SYSTEM, Role.USER]
    assert variant.messages[-1].content == "objective"


def test_direct_strategy_without_system_has_one_message() -> None:
    variant = next(iter(DirectStrategy().generate(_case(system=None), random.Random(1))))
    assert len(variant.messages) == 1


def test_instruction_override_generates_each_template() -> None:
    variants = list(InstructionOverrideStrategy().generate(_case(), random.Random(1)))
    assert len(variants) == 3
    assert all("objective" in variant.messages[-1].content for variant in variants)
    with pytest.raises(ValueError, match="at least one"):
        InstructionOverrideStrategy([])


def test_delimiter_strategy_generates_parseable_json_variant() -> None:
    variants = list(DelimiterStrategy().generate(_case(), random.Random(1)))
    assert len(variants) == 3
    assert '"external_instruction"' in variants[-1].messages[-1].content


def test_indirect_document_strategy_supplies_safe_system_instruction() -> None:
    variant = next(
        iter(
            IndirectDocumentStrategy("Document body.").generate(
                _case(system=None), random.Random(1)
            )
        )
    )
    assert variant.messages[0].role is Role.SYSTEM
    assert "untrusted" in variant.messages[0].content
    assert "<document>" in variant.messages[1].content


def test_multi_turn_strategy_contains_assistant_acknowledgement() -> None:
    variant = next(iter(MultiTurnStrategy().generate(_case(), random.Random(1))))
    assert [message.role for message in variant.messages][-3:] == [
        Role.USER,
        Role.ASSISTANT,
        Role.USER,
    ]


def test_encoding_strategy_is_deterministic_and_records_encoding() -> None:
    variants = list(EncodingStrategy().generate(_case(), random.Random(7)))
    assert len(variants) == 3
    assert {variant.metadata["encoding"] for variant in variants} == {
        "base64",
        "url",
        "unicode_escape",
    }
    assert "objective" not in variants[0].messages[-1].content
    assert len({variant.messages[-1].content for variant in variants}) == 3


def test_role_confusion_and_indirect_fixtures() -> None:
    role_variants = list(RoleConfusionStrategy().generate(_case(), random.Random(1)))
    fixture_variants = list(IndirectFixtureStrategy().generate(_case(), random.Random(1)))
    assert len(role_variants) == 3
    assert len(fixture_variants) == 3
    assert {variant.metadata["fixture_type"] for variant in fixture_variants} == {
        "email",
        "html",
        "markdown",
    }


def test_composite_strategy_deduplicates_messages() -> None:
    strategy = CompositeStrategy([DirectStrategy(), DirectStrategy()])
    assert len(list(strategy.generate(_case(), random.Random(1)))) == 1
    with pytest.raises(ValueError, match="at least one"):
        CompositeStrategy([])


def test_strategy_registry_lists_and_builds_builtins() -> None:
    assert "direct" in strategy_names(include_plugins=False)
    assert isinstance(get_strategy("direct"), DirectStrategy)
    with pytest.raises(KeyError, match="unknown"):
        get_strategy("missing")


def test_strategy_registry_loads_and_validates_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import advent_prompt_pwn.strategies.registry as registry

    class EntryPoint:
        name = "plugin"

        def __init__(self, value: object) -> None:
            self.value = value

        def load(self) -> object:
            return self.value

    valid = EntryPoint(lambda: DirectStrategy())
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: [valid])
    assert "plugin" in strategy_names()
    assert isinstance(get_strategy("plugin"), DirectStrategy)

    invalid = EntryPoint(lambda: object())
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: [invalid])
    with pytest.raises(TypeError, match="did not return"):
        get_strategy("plugin")
