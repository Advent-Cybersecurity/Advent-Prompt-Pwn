from __future__ import annotations

import random
from collections.abc import Iterable, Sequence

import pytest

from advent_prompt_pwn import (
    AttackCase,
    AttackVariant,
    CanaryLeakOracle,
    DirectStrategy,
    FakeTarget,
    FunctionTarget,
    InstructionOverrideStrategy,
    Message,
    Role,
    RunConfig,
    Runner,
    Scope,
)
from advent_prompt_pwn.exceptions import BudgetExceeded
from advent_prompt_pwn.strategies.base import Strategy


def _scope(max_requests: int = 100) -> Scope:
    return Scope.local_only(max_requests=max_requests, requests_per_minute=1_000_000)


def test_runner_records_security_pass(canary_case: AttackCase) -> None:
    report = Runner(FakeTarget("safe"), scope=_scope()).run([canary_case])
    assert report.security_passes == 1
    assert report.attack_successes == 0
    assert report.errors == 0
    assert len(report.attempts[0].evidence_sha256) == 64
    assert report.metadata["telemetry"] == "disabled"
    assert report.request_count == 1
    assert report.tool_version
    assert report.attempts[0].completed_at
    assert report.attempts[0].duration_ms is not None


def test_runner_records_adversarial_success(canary_case: AttackCase) -> None:
    report = Runner(FakeTarget("LAB_TEST_CANARY"), scope=_scope()).run([canary_case])
    assert report.attack_successes == 1
    assert report.attack_success_rate == 1.0
    assert report.to_dict()["summary"]["attack_successes"] == 1


def test_runner_redacts_messages_responses_and_errors(canary_case: AttackCase) -> None:
    secret = "private-value"

    def response(messages: Sequence[Message]) -> str:
        assert messages
        return f"response {secret}"

    case = AttackCase(
        "redact",
        "Redact",
        f"prompt {secret}",
        CanaryLeakOracle("LAB_REDACT_CANARY"),
    )
    report = Runner(
        FunctionTarget(response),
        scope=_scope(),
        config=RunConfig(redact_secrets=(secret,)),
    ).run([case])
    attempt = report.attempts[0]
    assert secret not in attempt.messages[0].content
    assert attempt.response is not None
    assert secret not in attempt.response.content


def test_runner_retries_target_boundary(canary_case: AttackCase) -> None:
    calls = 0

    def flaky(messages: Sequence[Message]) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("temporary")
        return "safe"

    report = Runner(
        FunctionTarget(flaky),
        scope=_scope(),
        config=RunConfig(retries=1),
    ).run([canary_case])
    assert calls == 2
    assert report.errors == 0


def test_runner_turns_target_exception_into_evidence(canary_case: AttackCase) -> None:
    def broken(messages: Sequence[Message]) -> str:
        raise RuntimeError(f"failed after {len(messages)} message")

    report = Runner(FunctionTarget(broken), scope=_scope()).run([canary_case])
    assert report.errors == 1
    assert "RuntimeError" in (report.attempts[0].error or "")


def test_runner_stop_on_error(canary_case: AttackCase) -> None:
    def broken(messages: Sequence[Message]) -> str:
        raise RuntimeError(str(len(messages)))

    report = Runner(
        FunctionTarget(broken),
        scope=_scope(),
        config=RunConfig(stop_on_error=True),
    ).run(
        [
            canary_case,
            AttackCase("second", "Second", "prompt", CanaryLeakOracle("LAB_SECOND")),
        ]
    )
    assert len(report.attempts) == 1
    assert report.metadata["stopped_early"] is True


def test_runner_enforces_request_budget(canary_case: AttackCase) -> None:
    with pytest.raises(BudgetExceeded):
        Runner(FakeTarget(), scope=_scope(max_requests=1)).run(
            [canary_case], InstructionOverrideStrategy()
        )


class TooManyVariants(Strategy):
    name = "too_many"

    def generate(self, case: AttackCase, rng: random.Random) -> Iterable[AttackVariant]:
        del rng
        for index in range(2):
            yield AttackVariant(
                str(index),
                case.case_id,
                self.name,
                (Message(Role.USER, "test"),),
            )


def test_runner_enforces_variant_limit(canary_case: AttackCase) -> None:
    runner = Runner(
        FakeTarget(),
        scope=_scope(),
        config=RunConfig(max_variants_per_case=1),
    )
    with pytest.raises(ValueError, match="generated 2"):
        runner.run([canary_case], TooManyVariants())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_s": 0},
        {"retries": -1},
        {"retry_backoff_s": -1},
        {"max_variants_per_case": 0},
        {"concurrency": 0},
        {"checkpoint_interval": 0},
        {"trials_per_variant": 0},
        {"trials_per_variant": 101},
    ],
)
def test_run_config_validates_limits(kwargs: dict[str, int | float]) -> None:
    with pytest.raises(ValueError):
        RunConfig(**kwargs)


def test_run_config_validates_checkpoint_security_controls() -> None:
    with pytest.raises(ValueError, match="max_evidence_bytes"):
        RunConfig(max_evidence_bytes=999_999)
    with pytest.raises(ValueError, match="string or null"):
        RunConfig(checkpoint_hmac_key=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="at least 32"):
        RunConfig(checkpoint_hmac_key="short")
    with pytest.raises(ValueError, match="true or false"):
        RunConfig(allow_unauthenticated_resume="yes")  # type: ignore[arg-type]


def test_default_strategy_is_direct(canary_case: AttackCase) -> None:
    report = Runner(FakeTarget(), scope=_scope()).run([canary_case])
    assert report.attempts[0].strategy == DirectStrategy.name


def test_runner_repeats_variants_and_reports_statistical_evidence(
    canary_case: AttackCase,
) -> None:
    responses = iter(("safe", "LAB_TEST_CANARY", "safe"))
    report = Runner(
        FunctionTarget(lambda messages: next(responses)),
        scope=_scope(max_requests=3),
        config=RunConfig(trials_per_variant=3),
    ).run([canary_case])

    assert report.request_count == 3
    assert [attempt.variant_id for attempt in report.attempts] == [
        "canary-001:direct:0:trial:1",
        "canary-001:direct:0:trial:2",
        "canary-001:direct:0:trial:3",
    ]
    statistic = report.trial_statistics[0]
    assert statistic.base_variant_id == "canary-001:direct:0"
    assert statistic.successes == 1
    assert statistic.success_rate == pytest.approx(1 / 3)
    assert statistic.confidence_low_95 < statistic.success_rate
    assert statistic.confidence_high_95 > statistic.success_rate
    assert statistic.consistency == "mixed"
    assert report.to_dict()["summary"]["trial_analysis"]["mixed_groups"] == 1


def test_runner_metadata_cannot_override_protected_execution_evidence(
    canary_case: AttackCase,
) -> None:
    report = Runner(
        FakeTarget("safe"),
        scope=_scope(),
        config=RunConfig(checkpoint_hmac_key="k" * 32),
        metadata={
            "resume_binding_sha256": "untrusted",
            "trials_per_variant": 99,
            "planned_attempts": 99,
            "telemetry": "enabled",
        },
    ).run([canary_case])
    assert report.metadata["resume_binding_sha256"] != "untrusted"
    assert report.metadata["trials_per_variant"] == 1
    assert report.metadata["planned_attempts"] == 1
    assert report.metadata["telemetry"] == "disabled"


def test_runner_resumes_repeated_trials(canary_case: AttackCase) -> None:
    checkpoints = []
    scope = _scope(max_requests=6)
    config = RunConfig(
        trials_per_variant=3,
        checkpoint_interval=1,
        checkpoint_hmac_key="k" * 32,
    )
    Runner(
        FakeTarget("safe"),
        scope=scope,
        config=config,
        checkpoint_callback=checkpoints.append,
    ).run([canary_case])

    resumed = Runner(FakeTarget("safe"), scope=scope, config=config).run(
        [canary_case],
        resume_from=checkpoints[1],
        expected_resume_integrity_sha256=checkpoints[1].integrity_sha256,
    )
    assert len(resumed.attempts) == 3
    assert resumed.request_count == 5
    assert resumed.metadata["resumed_from"] == checkpoints[1].run_id


def test_runner_executes_concurrently_in_deterministic_order(canary_case: AttackCase) -> None:
    report = Runner(
        FakeTarget("safe"),
        scope=Scope.local_only(
            max_requests=10,
            requests_per_minute=1_000_000,
            max_concurrency=3,
        ),
        config=RunConfig(concurrency=3),
    ).run([canary_case], InstructionOverrideStrategy())
    assert report.request_count == 3
    assert [attempt.variant_id for attempt in report.attempts] == [
        "canary-001:instruction_override:0",
        "canary-001:instruction_override:1",
        "canary-001:instruction_override:2",
    ]


def test_runner_rejects_unsafe_concurrency_combinations(canary_case: AttackCase) -> None:
    scope = Scope.local_only(requests_per_minute=1_000_000, max_concurrency=2)
    with pytest.raises(ValueError, match="does not support"):
        Runner(
            FunctionTarget(lambda messages: "safe"),
            scope=scope,
            config=RunConfig(concurrency=2),
        ).run([canary_case])
    with pytest.raises(ValueError, match="stop_on_error"):
        Runner(
            FakeTarget("safe"),
            scope=scope,
            config=RunConfig(concurrency=2, stop_on_error=True),
        ).run([canary_case])


def test_runner_resumes_completed_variants_and_reports_progress(canary_case: AttackCase) -> None:
    scope = Scope.local_only(max_requests=10, requests_per_minute=1_000_000)
    second = AttackCase("second", "Second", "prompt", CanaryLeakOracle("LAB_SECOND"))
    checkpoints = []
    config = RunConfig(checkpoint_interval=1, checkpoint_hmac_key="k" * 32)
    Runner(
        FakeTarget("safe"),
        scope=scope,
        config=config,
        checkpoint_callback=checkpoints.append,
    ).run([canary_case, second])
    baseline = checkpoints[1]
    progress: list[tuple[int, int]] = []
    resumed = Runner(
        FakeTarget("safe"),
        scope=scope,
        config=config,
        progress_callback=lambda result, completed, total: progress.append((completed, total)),
    ).run(
        [canary_case, second],
        resume_from=baseline,
        expected_resume_integrity_sha256=baseline.integrity_sha256,
    )
    assert len(resumed.attempts) == 2
    assert resumed.request_count == 3
    assert resumed.metadata["resumed_from"] == baseline.run_id
    assert progress == [(2, 2)]


def test_runner_rejects_duplicate_variant_ids(canary_case: AttackCase) -> None:
    with pytest.raises(ValueError, match="duplicate variant"):
        Runner(FakeTarget(), scope=_scope()).run([canary_case, canary_case])


def test_runner_bounds_strategy_generation_before_materializing_all_variants(
    canary_case: AttackCase,
) -> None:
    generated = 0

    class UnboundedStrategy(Strategy):
        name = "unbounded"

        def generate(
            self,
            case: AttackCase,
            rng: random.Random,
        ) -> Iterable[AttackVariant]:
            nonlocal generated
            del rng
            while True:
                generated += 1
                yield AttackVariant(
                    f"{case.case_id}:unbounded:{generated}",
                    case.case_id,
                    self.name,
                    (Message(Role.USER, case.prompt),),
                )

    with pytest.raises(ValueError, match="generated 4 variants"):
        Runner(
            FakeTarget(),
            scope=_scope(),
            config=RunConfig(max_variants_per_case=3),
        ).run([canary_case], UnboundedStrategy())
    assert generated == 4


def test_runner_emits_resumable_checkpoints(canary_case: AttackCase) -> None:
    checkpoints = []
    report = Runner(
        FakeTarget("safe"),
        scope=Scope.local_only(max_requests=5, requests_per_minute=1_000_000),
        config=RunConfig(checkpoint_interval=2, checkpoint_hmac_key="k" * 32),
        checkpoint_callback=checkpoints.append,
    ).run([canary_case], InstructionOverrideStrategy())
    assert len(checkpoints) == 3
    assert len(checkpoints[0].attempts) == 0
    assert checkpoints[0].metadata["unresolved_request_count"] == 3
    assert len(checkpoints[1].attempts) == 2
    assert checkpoints[1].metadata["stopped_early"] is True
    assert checkpoints[-1].run_id == report.run_id
    assert len(checkpoints[-1].attempts) == 3


def test_runner_validates_resume_identity_and_concurrency_limit(
    canary_case: AttackCase,
) -> None:
    scope = Scope.local_only(requests_per_minute=1_000_000)
    key = "k" * 32
    baseline = Runner(
        FakeTarget("safe"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key),
    ).run([canary_case])
    with pytest.raises(ValueError, match="seed"):
        Runner(
            FakeTarget("safe"),
            scope=scope,
            config=RunConfig(seed=1, checkpoint_hmac_key=key),
        ).run(
            [canary_case],
            resume_from=baseline,
            expected_resume_integrity_sha256=baseline.integrity_sha256,
        )
    with pytest.raises(ValueError, match="target"):
        Runner(
            FunctionTarget(lambda messages: "safe", name="other"),
            scope=scope,
            config=RunConfig(checkpoint_hmac_key=key),
        ).run(
            [canary_case],
            resume_from=baseline,
            expected_resume_integrity_sha256=baseline.integrity_sha256,
        )
    with pytest.raises(ValueError, match="exceeds scope"):
        Runner(
            FakeTarget("safe"),
            scope=scope,
            config=RunConfig(concurrency=2),
        ).run([canary_case])
