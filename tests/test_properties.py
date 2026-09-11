from __future__ import annotations

import random
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from advent_prompt_pwn import AttackCase, CanaryLeakOracle, Scope
from advent_prompt_pwn.core.redaction import redact_text, redact_value
from advent_prompt_pwn.core.scope import RequestGuard
from advent_prompt_pwn.exceptions import BudgetExceeded
from advent_prompt_pwn.integrity import canonical_sha256
from advent_prompt_pwn.strategies import get_strategy, strategy_names

_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    min_size=1,
    max_size=160,
)
_PROMPT = _TEXT.filter(lambda value: bool(value.strip()))
_SECRET = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
    min_size=8,
    max_size=40,
).filter(lambda value: value not in "[REDACTED]")
_JSON_VALUES: st.SearchStrategy[Any] = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), _TEXT),
    lambda children: st.one_of(
        st.lists(children, max_size=6),
        st.dictionaries(_TEXT, children, max_size=6),
    ),
    max_leaves=20,
)


def _strings_in(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(
            text
            for key, item in value.items()
            for text in (*_strings_in(key), *_strings_in(item))
        )
    if isinstance(value, (list, tuple)):
        return tuple(text for item in value for text in _strings_in(item))
    return ()


@given(value=_TEXT, secret=_SECRET)
def test_redaction_is_idempotent_and_removes_supplied_secrets(
    value: str,
    secret: str,
) -> None:
    rendered = redact_text(value + secret, (secret,))
    assert secret not in rendered or secret == "[REDACTED]"
    assert redact_text(rendered, (secret,)) == rendered


@given(value=_JSON_VALUES, secret=_SECRET)
def test_recursive_redaction_never_leaves_supplied_secret(
    value: Any,
    secret: str,
) -> None:
    redacted = redact_value(value, (secret,))
    if secret != "[REDACTED]":
        assert all(secret not in text for text in _strings_in(redacted))
    assert redact_value(redacted, (secret,)) == redacted


@given(items=st.dictionaries(_TEXT, st.integers(), min_size=1, max_size=12))
def test_canonical_hash_is_independent_of_mapping_insertion_order(
    items: dict[str, int],
) -> None:
    reversed_items = dict(reversed(tuple(items.items())))
    assert canonical_sha256(items) == canonical_sha256(reversed_items)


@settings(suppress_health_check=(HealthCheck.too_slow,), deadline=None)
@given(prompt=_PROMPT, seed=st.integers(min_value=0, max_value=2**32 - 1))
def test_every_builtin_strategy_emits_well_formed_unique_variants(
    prompt: str,
    seed: int,
) -> None:
    case = AttackCase(
        "property-case",
        "Property case",
        prompt,
        CanaryLeakOracle("LAB_PROPERTY_CANARY"),
    )
    for name in strategy_names():
        variants = tuple(get_strategy(name).generate(case, random.Random(seed)))
        assert variants
        assert len({variant.variant_id for variant in variants}) == len(variants)
        assert all(variant.case_id == case.case_id for variant in variants)
        assert all(variant.strategy == name for variant in variants)
        assert all(variant.messages for variant in variants)


class RequestGuardStateMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.limit = 25
        self.expected = 0
        self.guard = RequestGuard(
            Scope.local_only(max_requests=self.limit, requests_per_minute=1_000_000)
        )

    @rule(amount=st.integers(min_value=0, max_value=8))
    def reserve(self, amount: int) -> None:
        if self.expected + amount <= self.limit:
            self.guard.reserve(amount)
            self.expected += amount
        else:
            try:
                self.guard.reserve(amount)
            except BudgetExceeded:
                pass
            else:
                raise AssertionError("over-budget reservation was accepted")

    @precondition(lambda self: self.expected > 0)
    @rule(data=st.data())
    def release(self, data: st.DataObject) -> None:
        amount = data.draw(st.integers(min_value=0, max_value=self.expected))
        self.guard.release(amount)
        self.expected -= amount

    @invariant()
    def count_matches_model(self) -> None:
        assert self.guard.count == self.expected
        assert 0 <= self.guard.count <= self.limit


TestRequestGuardStateMachine = RequestGuardStateMachine.TestCase


def test_concurrent_reservations_never_exceed_the_shared_budget() -> None:
    limit = 64
    guard = RequestGuard(Scope.local_only(max_requests=limit, requests_per_minute=1_000_000))

    def reserve_once(_: int) -> bool:
        try:
            guard.reserve(1)
        except BudgetExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=32) as executor:
        accepted = sum(executor.map(reserve_once, range(limit * 4)))

    assert accepted == limit
    assert guard.count == limit
