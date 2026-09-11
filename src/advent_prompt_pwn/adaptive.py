"""Budget-bound adaptive prompt reduction utilities."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from advent_prompt_pwn.core.models import AttackCase, AttackVariant, Message, OracleResult, Role
from advent_prompt_pwn.core.scope import RequestGuard, Scope
from advent_prompt_pwn.targets.base import Target

PromptEvaluator = Callable[[str], bool]
PromptScorer = Callable[[str], float]
PromptMutator = Callable[[str], Sequence[str]]


class ScopedPromptEvaluator:
    """Evaluate adaptive candidates through the ordinary scope and request guard."""

    def __init__(
        self,
        target: Target,
        case: AttackCase,
        *,
        scope: Scope,
        timeout_s: float = 30.0,
    ) -> None:
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s)
            or not 0 < timeout_s <= 600
        ):
            raise ValueError("timeout_s must be between 0 and 600")
        scope.assert_endpoint(target.endpoint)
        self.target = target
        self.case = case
        self.scope = scope
        self.timeout_s = timeout_s
        self._guard = RequestGuard(scope)

    @property
    def request_count(self) -> int:
        return self._guard.count

    def __call__(self, prompt: str) -> bool:
        return self._assess(prompt).success

    def _assess(self, prompt: str) -> OracleResult:
        self.scope.assert_endpoint(self.target.endpoint)
        self._guard.acquire()
        self.scope.assert_endpoint(self.target.endpoint)
        messages: list[Message] = []
        if self.case.system_prompt:
            messages.append(Message(Role.SYSTEM, self.case.system_prompt))
        messages.append(Message(Role.USER, prompt))
        variant = AttackVariant(
            variant_id=f"{self.case.case_id}:adaptive:{self.request_count}",
            case_id=self.case.case_id,
            strategy="adaptive_minimization",
            messages=tuple(messages),
            metadata={"adaptive_evaluation": self.request_count},
        )
        response = self.target.complete(messages, timeout_s=self.timeout_s)
        return self.case.oracle.evaluate(self.case, variant, response)


class ScopedPromptScorer:
    """Return the case oracle score while applying scope and request accounting."""

    def __init__(
        self,
        target: Target,
        case: AttackCase,
        *,
        scope: Scope,
        timeout_s: float = 30.0,
    ) -> None:
        self._evaluator = ScopedPromptEvaluator(
            target,
            case,
            scope=scope,
            timeout_s=timeout_s,
        )

    @property
    def request_count(self) -> int:
        return self._evaluator.request_count

    def __call__(self, prompt: str) -> float:
        return self._evaluator._assess(prompt).score


@dataclass(frozen=True, slots=True)
class MinimizationConfig:
    """Safety and work limits for adaptive prompt minimization."""

    max_evaluations: int = 64
    max_seconds: float = 60.0
    minimum_characters: int = 1

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_evaluations, bool)
            or not isinstance(self.max_evaluations, int)
            or not 2 <= self.max_evaluations <= 10_000
        ):
            raise ValueError("max_evaluations must be between 2 and 10000")
        if (
            isinstance(self.max_seconds, bool)
            or not isinstance(self.max_seconds, (int, float))
            or not math.isfinite(self.max_seconds)
            or not 0 < self.max_seconds <= 86_400
        ):
            raise ValueError("max_seconds must be between 0 and 86400")
        if (
            isinstance(self.minimum_characters, bool)
            or not isinstance(self.minimum_characters, int)
            or self.minimum_characters < 1
        ):
            raise ValueError("minimum_characters must be positive")


@dataclass(frozen=True, slots=True)
class MinimizationAttempt:
    """Non-sensitive audit metadata for one evaluated candidate."""

    candidate_sha256: str
    characters: int
    units: int
    successful: bool


@dataclass(frozen=True, slots=True)
class MinimizationResult:
    """Result of a deterministic, budget-bound reduction run."""

    original_prompt: str
    minimized_prompt: str
    evaluations: int
    successful_reductions: int
    budget_exhausted: bool
    elapsed_seconds: float
    attempts: tuple[MinimizationAttempt, ...]

    @property
    def reduction_ratio(self) -> float:
        """Return the fraction of original characters removed."""

        return 1.0 - (len(self.minimized_prompt) / len(self.original_prompt))


class AdaptivePromptMinimizer:
    """Reduce a successful prompt while preserving an evaluator outcome.

    The caller controls the evaluator and therefore the authorization boundary,
    target, oracle, and request accounting. Candidate text is not retained in the
    audit trail, only its digest and size.
    """

    def __init__(self, config: MinimizationConfig | None = None) -> None:
        self.config = config or MinimizationConfig()

    def minimize(self, prompt: str, evaluator: PromptEvaluator) -> MinimizationResult:
        """Apply line and token delta debugging to a known-successful prompt."""

        if not prompt.strip():
            raise ValueError("prompt must not be empty")
        started = time.monotonic()
        attempts: list[MinimizationAttempt] = []
        reductions = 0

        def evaluate(candidate: str, units: int) -> bool | None:
            if len(attempts) >= self.config.max_evaluations:
                return None
            if time.monotonic() - started >= self.config.max_seconds:
                return None
            if len(candidate.strip()) < self.config.minimum_characters:
                return False
            successful = evaluator(candidate)
            if not isinstance(successful, bool):
                raise TypeError("prompt evaluator must return a boolean")
            attempts.append(
                MinimizationAttempt(
                    candidate_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
                    characters=len(candidate),
                    units=units,
                    successful=successful,
                )
            )
            return successful

        initial = evaluate(prompt, 1)
        if initial is not True:
            if initial is None:
                raise RuntimeError("minimization budget expired before initial evaluation")
            raise ValueError("initial prompt does not satisfy the evaluator")

        current = prompt
        phases: tuple[Callable[[str], Sequence[str]], ...] = (
            lambda value: value.splitlines(keepends=True),
            lambda value: re.findall(r"\S+\s*", value),
        )
        for split in phases:
            parts = list(split(current))
            if len(parts) < 2:
                continue
            granularity = 2
            while len(parts) >= 2:
                chunk_size = math.ceil(len(parts) / granularity)
                accepted = False
                for start in range(0, len(parts), chunk_size):
                    candidate_parts = parts[:start] + parts[start + chunk_size :]
                    candidate = "".join(candidate_parts).strip()
                    decision = evaluate(candidate, len(candidate_parts))
                    if decision is None:
                        current = "".join(parts).strip()
                        return self._result(prompt, current, attempts, reductions, started, True)
                    if decision:
                        parts = candidate_parts
                        reductions += 1
                        granularity = max(2, granularity - 1)
                        accepted = True
                        break
                if accepted:
                    continue
                if granularity >= len(parts):
                    break
                granularity = min(len(parts), granularity * 2)
            current = "".join(parts).strip()

        exhausted = (
            len(attempts) >= self.config.max_evaluations
            or time.monotonic() - started >= self.config.max_seconds
        )
        return self._result(prompt, current, attempts, reductions, started, exhausted)

    @staticmethod
    def _result(
        original: str,
        minimized: str,
        attempts: list[MinimizationAttempt],
        reductions: int,
        started: float,
        exhausted: bool,
    ) -> MinimizationResult:
        return MinimizationResult(
            original_prompt=original,
            minimized_prompt=minimized,
            evaluations=len(attempts),
            successful_reductions=reductions,
            budget_exhausted=exhausted,
            elapsed_seconds=time.monotonic() - started,
            attempts=tuple(attempts),
        )


@dataclass(frozen=True, slots=True)
class MutationSearchConfig:
    """Safety and search limits for feedback-guided prompt mutation."""

    max_evaluations: int = 64
    max_seconds: float = 60.0
    max_generations: int = 4
    beam_width: int = 4
    max_candidates_per_mutator: int = 8

    def __post_init__(self) -> None:
        bounds = (
            ("max_evaluations", self.max_evaluations, 2, 10_000),
            ("max_generations", self.max_generations, 1, 100),
            ("beam_width", self.beam_width, 1, 128),
            ("max_candidates_per_mutator", self.max_candidates_per_mutator, 1, 128),
        )
        for label, value, minimum, maximum in bounds:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(f"{label} must be between {minimum} and {maximum}")
        if (
            isinstance(self.max_seconds, bool)
            or not isinstance(self.max_seconds, (int, float))
            or not math.isfinite(self.max_seconds)
            or not 0 < self.max_seconds <= 86_400
        ):
            raise ValueError("max_seconds must be between 0 and 86400")


@dataclass(frozen=True, slots=True)
class MutationEvaluation:
    """Non-sensitive audit metadata for one score-guided candidate."""

    candidate_sha256: str
    characters: int
    generation: int
    score: float


@dataclass(frozen=True, slots=True)
class AdaptiveMutationResult:
    """Best candidate and bounded audit trail from an adaptive mutation search."""

    original_prompt: str
    best_prompt: str
    best_score: float
    evaluations: int
    generations: int
    budget_exhausted: bool
    elapsed_seconds: float
    attempts: tuple[MutationEvaluation, ...]


def default_prompt_mutations(prompt: str) -> tuple[str, ...]:
    """Return deterministic, provider-neutral mutations for one prompt."""

    compact = " ".join(prompt.split())
    return (
        f"Authorized security evaluation objective:\n{prompt}",
        f"```untrusted-instruction\n{prompt}\n```",
        f'{{"untrusted_instruction": {json.dumps(prompt)}}}',
        f"<external_instruction>{prompt}</external_instruction>",
        compact,
        prompt.swapcase(),
    )


class AdaptivePromptMutator:
    """Search mutations using bounded feedback from a caller-supplied scorer."""

    def __init__(
        self,
        mutators: Sequence[PromptMutator] | None = None,
        *,
        config: MutationSearchConfig | None = None,
    ) -> None:
        self.mutators = tuple((default_prompt_mutations,) if mutators is None else mutators)
        if not self.mutators:
            raise ValueError("adaptive mutation requires at least one mutator")
        self.config = config or MutationSearchConfig()

    def search(self, prompt: str, scorer: PromptScorer) -> AdaptiveMutationResult:
        """Select and expand the highest-scoring novel mutations."""

        if not prompt.strip():
            raise ValueError("prompt must not be empty")
        started = time.monotonic()
        attempts: list[MutationEvaluation] = []
        seen: set[str] = set()

        def evaluate(candidate: str, generation: int) -> tuple[str, float] | None:
            if len(attempts) >= self.config.max_evaluations:
                return None
            if time.monotonic() - started >= self.config.max_seconds:
                return None
            if not isinstance(candidate, str):
                raise TypeError("prompt mutators must return strings")
            candidate = candidate.strip()
            if not candidate or candidate in seen:
                return (candidate, -1.0)
            seen.add(candidate)
            raw_score = scorer(candidate)
            if (
                isinstance(raw_score, bool)
                or not isinstance(raw_score, (int, float))
                or not math.isfinite(raw_score)
                or not 0.0 <= raw_score <= 1.0
            ):
                raise ValueError("prompt scorer must return a finite score between 0 and 1")
            score = float(raw_score)
            attempts.append(
                MutationEvaluation(
                    candidate_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
                    characters=len(candidate),
                    generation=generation,
                    score=score,
                )
            )
            return candidate, score

        initial = evaluate(prompt, 0)
        if initial is None:  # pragma: no cover - the initial budget is validated above
            raise RuntimeError("mutation budget expired before initial evaluation")
        best_prompt, best_score = initial
        frontier = [initial]
        generations = 0
        exhausted = False

        for generation in range(1, self.config.max_generations + 1):
            candidates: list[tuple[str, float]] = []
            for parent, _score in frontier:
                for mutator in self.mutators:
                    generated = mutator(parent)
                    if isinstance(generated, (str, bytes)) or not isinstance(generated, Sequence):
                        raise TypeError("prompt mutators must return a finite sequence of strings")
                    for candidate in generated[: self.config.max_candidates_per_mutator]:
                        evaluated = evaluate(candidate, generation)
                        if evaluated is None:
                            exhausted = True
                            break
                        if evaluated[1] >= 0:
                            candidates.append(evaluated)
                    if exhausted:
                        break
                if exhausted:
                    break
            if not candidates:
                break
            candidates.sort(key=lambda item: (-item[1], len(item[0]), item[0]))
            frontier = candidates[: self.config.beam_width]
            candidate_prompt, candidate_score = frontier[0]
            if candidate_score > best_score or (
                candidate_score == best_score
                and (
                    len(candidate_prompt) < len(best_prompt)
                    or (
                        len(candidate_prompt) == len(best_prompt) and candidate_prompt < best_prompt
                    )
                )
            ):
                best_prompt, best_score = candidate_prompt, candidate_score
            generations = generation
            if exhausted:
                break

        exhausted = (
            exhausted
            or len(attempts) >= self.config.max_evaluations
            or (time.monotonic() - started >= self.config.max_seconds)
        )
        return AdaptiveMutationResult(
            original_prompt=prompt,
            best_prompt=best_prompt,
            best_score=best_score,
            evaluations=len(attempts),
            generations=generations,
            budget_exhausted=exhausted,
            elapsed_seconds=time.monotonic() - started,
            attempts=tuple(attempts),
        )
