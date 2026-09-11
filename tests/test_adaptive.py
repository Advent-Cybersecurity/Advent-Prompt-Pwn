from __future__ import annotations

import pytest

from advent_prompt_pwn import (
    AdaptivePromptMinimizer,
    AdaptivePromptMutator,
    AttackCase,
    ContainsOracle,
    FakeTarget,
    MinimizationConfig,
    MutationSearchConfig,
    Scope,
    ScopedPromptEvaluator,
    ScopedPromptScorer,
)
from advent_prompt_pwn.exceptions import BudgetExceeded


def test_adaptive_minimizer_reduces_successful_prompt_without_retaining_candidates() -> None:
    prompt = "remove this line\nKEEP objective words\nremove that line"
    result = AdaptivePromptMinimizer().minimize(prompt, lambda value: "KEEP" in value)

    assert result.minimized_prompt == "KEEP"
    assert result.reduction_ratio > 0.8
    assert result.successful_reductions > 0
    assert result.evaluations == len(result.attempts)
    assert all(len(attempt.candidate_sha256) == 64 for attempt in result.attempts)
    assert all(not hasattr(attempt, "candidate") for attempt in result.attempts)


def test_adaptive_minimizer_rejects_invalid_start_and_honors_budget() -> None:
    minimizer = AdaptivePromptMinimizer(MinimizationConfig(max_evaluations=2))
    with pytest.raises(ValueError, match="does not satisfy"):
        minimizer.minimize("safe prompt", lambda value: False)
    with pytest.raises(ValueError, match="must not be empty"):
        minimizer.minimize(" ", lambda value: True)
    with pytest.raises(TypeError, match="boolean"):
        minimizer.minimize("prompt", lambda value: "yes")  # type: ignore[return-value]

    result = minimizer.minimize("KEEP one two three four", lambda value: "KEEP" in value)
    assert result.budget_exhausted
    assert result.evaluations == 2


@pytest.mark.parametrize(
    "config",
    [
        {"max_evaluations": 1},
        {"max_seconds": 0},
        {"minimum_characters": 0},
        {"max_evaluations": True},
    ],
)
def test_minimization_config_rejects_invalid_limits(config: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        MinimizationConfig(**config)


def test_scoped_prompt_evaluator_uses_scope_budget_and_case_oracle() -> None:
    case = AttackCase("case", "case", "LAB_KEEP", ContainsOracle("LAB_KEEP"))
    evaluator = ScopedPromptEvaluator(
        FakeTarget(lambda messages: messages[-1].content),
        case,
        scope=Scope.local_only(max_requests=2, requests_per_minute=1_000_000),
        timeout_s=1,
    )
    assert evaluator("LAB_KEEP")
    assert not evaluator("safe")
    assert evaluator.request_count == 2
    with pytest.raises(BudgetExceeded, match="budget exhausted"):
        evaluator("LAB_KEEP")
    with pytest.raises(ValueError, match="timeout"):
        ScopedPromptEvaluator(FakeTarget(), case, scope=Scope.local_only(), timeout_s=0)
    with pytest.raises(ValueError, match="timeout"):
        ScopedPromptEvaluator(FakeTarget(), case, scope=Scope.local_only(), timeout_s=True)


def test_scoped_prompt_scorer_exposes_oracle_score_with_request_accounting() -> None:
    case = AttackCase("case", "case", "LAB_KEEP", ContainsOracle("LAB_KEEP"))
    scorer = ScopedPromptScorer(
        FakeTarget(lambda messages: messages[-1].content),
        case,
        scope=Scope.local_only(max_requests=2, requests_per_minute=1_000_000),
    )
    assert scorer("LAB_KEEP") == 1.0
    assert scorer("safe") == 0.0
    assert scorer.request_count == 2


def test_adaptive_mutator_uses_score_feedback_and_keeps_digest_audit() -> None:
    def mutate(value: str) -> tuple[str, ...]:
        return (f"{value} alpha", f"{value} TARGET")

    result = AdaptivePromptMutator(
        (mutate,),
        config=MutationSearchConfig(max_evaluations=8, max_generations=2, beam_width=1),
    ).search("base", lambda value: 1.0 if "TARGET" in value else 0.1)

    assert result.best_prompt == "base TARGET"
    assert result.best_score == 1.0
    assert result.generations == 2
    assert result.evaluations == len(result.attempts)
    assert all(len(attempt.candidate_sha256) == 64 for attempt in result.attempts)


@pytest.mark.parametrize(
    "config",
    [
        {"max_evaluations": True},
        {"max_seconds": float("inf")},
        {"max_generations": 0},
        {"beam_width": 0},
        {"max_candidates_per_mutator": 129},
    ],
)
def test_mutation_search_config_rejects_invalid_limits(config: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        MutationSearchConfig(**config)  # type: ignore[arg-type]


def test_adaptive_mutator_rejects_invalid_contracts() -> None:
    with pytest.raises(ValueError, match="at least one"):
        AdaptivePromptMutator(())
    with pytest.raises(ValueError, match="must not be empty"):
        AdaptivePromptMutator().search(" ", lambda value: 0.0)
    with pytest.raises(ValueError, match="finite score"):
        AdaptivePromptMutator().search("base", lambda value: float("nan"))
    with pytest.raises(TypeError, match="finite sequence"):
        AdaptivePromptMutator((lambda value: "not-a-sequence",)).search("base", lambda value: 0.0)
