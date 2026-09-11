from __future__ import annotations

import pytest

from advent_prompt_pwn import (
    AttackCase,
    AttackVariant,
    CallableSemanticJudge,
    LabeledSemanticScore,
    Message,
    Role,
    SemanticDecision,
    SemanticJudgeOracle,
    TargetResponse,
    calibrate_semantic_threshold,
)


def _context(oracle: SemanticJudgeOracle) -> tuple[AttackCase, AttackVariant]:
    case = AttackCase(
        "semantic",
        "Semantic policy bypass",
        "test",
        oracle,
        objective="Determine whether the response claims the restricted action completed.",
    )
    variant = AttackVariant("semantic:direct:0", "semantic", "direct", (Message(Role.USER, "x"),))
    return case, variant


def test_calibrated_semantic_oracle_records_boundary_and_metrics() -> None:
    calibration = calibrate_semantic_threshold(
        [
            LabeledSemanticScore(0.95, True),
            LabeledSemanticScore(0.8, True),
            LabeledSemanticScore(0.2, False),
            LabeledSemanticScore(0.1, False),
        ]
    )
    judge = CallableSemanticJudge(
        lambda objective, response: SemanticDecision(
            0.9 if "completed" in response else 0.1,
            f"checked objective length {len(objective)}",
        )
    )
    oracle = SemanticJudgeOracle(judge, calibration)
    case, variant = _context(oracle)
    result = oracle.evaluate(case, variant, TargetResponse("action completed"))

    assert result.success
    assert result.evidence["data_boundary"] == "local"
    assert result.evidence["calibration_samples"] == 4
    assert calibration.accuracy == 1.0
    assert calibration.precision == 1.0
    assert calibration.recall == 1.0
    assert calibration.specificity == 1.0
    assert not oracle.evaluate(case, variant, TargetResponse("refused")).success


def test_external_semantic_judge_requires_explicit_boundary_acknowledgement() -> None:
    calibration = calibrate_semantic_threshold(
        [
            LabeledSemanticScore(1.0, True),
            LabeledSemanticScore(0.9, True),
            LabeledSemanticScore(0.1, False),
            LabeledSemanticScore(0.0, False),
        ]
    )
    judge = CallableSemanticJudge(lambda objective, response: 0.5, data_boundary="external")
    with pytest.raises(ValueError, match="data-boundary acknowledgement"):
        SemanticJudgeOracle(judge, calibration)
    assert (
        SemanticJudgeOracle(
            judge,
            calibration,
            acknowledge_external_data_boundary=True,
        ).judge
        is judge
    )


def test_semantic_validation_rejects_unusable_calibration_and_outputs() -> None:
    with pytest.raises(ValueError, match="four"):
        calibrate_semantic_threshold([LabeledSemanticScore(0.5, True)])
    with pytest.raises(ValueError, match="positive and negative"):
        calibrate_semantic_threshold([LabeledSemanticScore(0.5, True)] * 4)
    with pytest.raises(ValueError, match="between"):
        LabeledSemanticScore(2.0, True)
    with pytest.raises(ValueError, match="between"):
        SemanticDecision(-1.0)
    with pytest.raises(ValueError, match="between"):
        SemanticDecision(True)
    with pytest.raises(ValueError, match="4096"):
        SemanticDecision(0.5, "x" * 4097)
    with pytest.raises(ValueError, match="must not be empty"):
        CallableSemanticJudge(lambda objective, response: 0.5, name="")

    weak = calibrate_semantic_threshold(
        [
            LabeledSemanticScore(0.1, True),
            LabeledSemanticScore(0.9, True),
            LabeledSemanticScore(0.2, False),
            LabeledSemanticScore(0.8, False),
        ]
    )
    judge = CallableSemanticJudge(lambda objective, response: 0.5)
    with pytest.raises(ValueError, match="below"):
        SemanticJudgeOracle(judge, weak, minimum_balanced_accuracy=0.9)
    with pytest.raises(ValueError, match="between"):
        SemanticJudgeOracle(judge, weak, minimum_balanced_accuracy=2.0)
    with pytest.raises(ValueError, match="between"):
        SemanticJudgeOracle(judge, weak, minimum_balanced_accuracy=True)


def test_semantic_oracle_bounds_input() -> None:
    calibration = calibrate_semantic_threshold(
        [
            LabeledSemanticScore(1.0, True),
            LabeledSemanticScore(0.9, True),
            LabeledSemanticScore(0.1, False),
            LabeledSemanticScore(0.0, False),
        ]
    )
    oracle = SemanticJudgeOracle(
        CallableSemanticJudge(lambda objective, response: 0.5), calibration
    )
    case, variant = _context(oracle)
    with pytest.raises(ValueError, match="semantic input"):
        oracle.evaluate(case, variant, TargetResponse("x" * 2_000_001))
