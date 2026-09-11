from __future__ import annotations

import pytest

from advent_prompt_pwn import (
    AttackCase,
    CanaryLeakOracle,
    FakeTarget,
    InstructionOverrideStrategy,
    Message,
    OracleResult,
    Role,
    Runner,
    Scope,
    Severity,
)
from advent_prompt_pwn.core.models import AttackVariant, AttemptResult, RunReport, ensure_messages


def test_message_normalizes_role_and_serializes() -> None:
    message = Message(Role.USER, "hello", "tester")
    assert message.role is Role.USER
    assert message.to_dict() == {"role": "user", "content": "hello", "name": "tester"}


def test_message_rejects_empty_content() -> None:
    with pytest.raises(ValueError, match="content"):
        Message(Role.USER, "")


def test_attack_case_requires_identifiers() -> None:
    oracle = CanaryLeakOracle("LAB_CASE_CANARY")
    with pytest.raises(ValueError, match="case_id"):
        AttackCase("", "name", "prompt", oracle)
    with pytest.raises(ValueError, match="case name"):
        AttackCase("id", "", "prompt", oracle)
    with pytest.raises(ValueError, match="prompt"):
        AttackCase("id", "name", " ", oracle)


def test_attack_variant_requires_messages() -> None:
    with pytest.raises(ValueError, match="at least one"):
        AttackVariant("v", "c", "direct", ())


def test_oracle_score_range_is_validated() -> None:
    with pytest.raises(ValueError, match="between"):
        OracleResult(True, "bad", 1.1)


def test_findings_are_deduplicated_and_keep_case_severity() -> None:
    case = AttackCase(
        "critical-case",
        "Critical case",
        "prompt",
        CanaryLeakOracle("LAB_CRITICAL"),
        severity=Severity.CRITICAL,
    )
    report = Runner(
        FakeTarget("LAB_CRITICAL"),
        scope=Scope.local_only(max_requests=3, requests_per_minute=1_000_000),
    ).run([case], InstructionOverrideStrategy())
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.occurrence_count == 3
    assert finding.finding_id.startswith("APPWN-")
    assert report.to_dict()["summary"]["severity_counts"]["critical"] == 1


def test_attempt_and_report_validate_runtime_metadata() -> None:
    message = Message(Role.USER, "test")
    assert ensure_messages([message]) == (message,)
    common = {
        "case_id": "case",
        "case_name": "Case",
        "variant_id": "variant",
        "strategy": "direct",
        "messages": (message,),
        "response": None,
        "oracle": None,
        "started_at": "start",
        "evidence_sha256": "0" * 64,
    }
    with pytest.raises(ValueError, match="request_attempts"):
        AttemptResult(**common, request_attempts=0)
    with pytest.raises(ValueError, match="duration"):
        AttemptResult(**common, duration_ms=-1)
    report_values = {
        "run_id": "run",
        "target_name": "target",
        "target_endpoint": "memory://fake",
        "started_at": "start",
        "completed_at": "end",
        "seed": 0,
        "attempts": (),
    }
    with pytest.raises(ValueError, match="schema"):
        RunReport(**report_values, schema_version=2)
    with pytest.raises(ValueError, match="request_count"):
        RunReport(**report_values, request_count=-1)
