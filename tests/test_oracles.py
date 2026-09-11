from __future__ import annotations

import pytest
import regex

from advent_prompt_pwn import (
    AllOracle,
    AnyOracle,
    AttackCase,
    AttackVariant,
    CanaryLeakOracle,
    ContainsAllOracle,
    ContainsAnyOracle,
    ContainsOracle,
    JsonKeysOracle,
    JsonPathOracle,
    Message,
    RegexOracle,
    Role,
    TargetResponse,
    ToolCallOracle,
)
from advent_prompt_pwn.core.models import ToolCall
from advent_prompt_pwn.oracles import oracle_from_spec


def _context(oracle: ContainsOracle) -> tuple[AttackCase, AttackVariant]:
    case = AttackCase("case", "case", "prompt", oracle)
    variant = AttackVariant("variant", "case", "direct", (Message(Role.USER, "prompt"),))
    return case, variant


def test_contains_oracle_is_case_insensitive_by_default() -> None:
    oracle = ContainsOracle("MARKER")
    case, variant = _context(oracle)
    result = oracle.evaluate(case, variant, TargetResponse("marker found"))
    assert result.success
    assert result.score == 1.0


def test_contains_oracle_can_be_case_sensitive() -> None:
    oracle = ContainsOracle("MARKER", case_sensitive=True)
    case, variant = _context(oracle)
    assert not oracle.evaluate(case, variant, TargetResponse("marker")).success
    with pytest.raises(ValueError, match="must not be empty"):
        ContainsOracle("")
    with pytest.raises(ValueError, match="needle exceeds"):
        ContainsOracle("x" * 4097)
    case, variant = _context(ContainsOracle("x"))
    with pytest.raises(ValueError, match="literal input"):
        ContainsOracle("x").evaluate(case, variant, TargetResponse("x" * 2_000_001))


def test_canary_requires_synthetic_prefix() -> None:
    with pytest.raises(ValueError, match="LAB_"):
        CanaryLeakOracle("real-secret")


def test_regex_oracle_records_match() -> None:
    oracle = RegexOracle(r"LAB_[A-Z]+")
    case, variant = _context(ContainsOracle("x"))
    result = oracle.evaluate(case, variant, TargetResponse("value LAB_TOKEN"))
    assert result.success
    assert result.evidence["match"] == "LAB_TOKEN"


def test_invalid_regex_is_rejected() -> None:
    with pytest.raises(regex.error, match="unterminated character set"):
        RegexOracle("[")


@pytest.mark.parametrize(
    ("content", "success"),
    [
        ('{"unsafe": true, "action": "send"}', True),
        ('{"unsafe": true}', False),
        ("[]", False),
        ("bad", False),
    ],
)
def test_json_keys_oracle(content: str, success: bool) -> None:
    oracle = JsonKeysOracle(["unsafe", "action"])
    case, variant = _context(ContainsOracle("x"))
    assert oracle.evaluate(case, variant, TargetResponse(content)).success is success


def test_json_keys_requires_keys() -> None:
    with pytest.raises(ValueError, match="at least one"):
        JsonKeysOracle([])
    with pytest.raises(ValueError, match="exceeds"):
        JsonKeysOracle([str(index) for index in range(129)])
    with pytest.raises(ValueError, match="characters"):
        JsonKeysOracle(["x" * 65_537])


def test_tool_call_oracle_uses_normalized_calls() -> None:
    oracle = ToolCallOracle("send_email")
    case, variant = _context(ContainsOracle("x"))
    response = TargetResponse("", tool_calls=(ToolCall("send_email", "{}", "call-1"),))
    assert oracle.evaluate(case, variant, response).success


def test_literal_collection_oracles() -> None:
    case, variant = _context(ContainsOracle("x"))
    response = TargetResponse("Alpha and BETA")
    any_result = ContainsAnyOracle(["missing", "beta"]).evaluate(case, variant, response)
    all_result = ContainsAllOracle(["alpha", "beta"]).evaluate(case, variant, response)
    assert any_result.success
    assert any_result.evidence["matches"] == ["beta"]
    assert all_result.success
    assert all_result.score == 1.0
    assert not ContainsAllOracle(["alpha", "missing"]).evaluate(case, variant, response).success
    with pytest.raises(ValueError, match="at least one"):
        ContainsAnyOracle([])
    with pytest.raises(ValueError, match="values"):
        ContainsAnyOracle([str(index) for index in range(129)])
    bounded = ContainsAnyOracle([str(index) for index in range(128)])
    with pytest.raises(ValueError, match="scan budget"):
        bounded.evaluate(case, variant, TargetResponse("x" * 100_000))


def test_json_path_oracle_handles_objects_arrays_and_expected_values() -> None:
    case, variant = _context(ContainsOracle("x"))
    response = TargetResponse('{"result": {"actions": [{"name": "send"}]}}')
    assert JsonPathOracle("result.actions.0.name", "send").evaluate(case, variant, response).success
    assert not JsonPathOracle("result.missing").evaluate(case, variant, response).success
    assert not JsonPathOracle("result.actions", []).evaluate(case, variant, response).success
    assert not JsonPathOracle("result").evaluate(case, variant, TargetResponse("bad")).success
    with pytest.raises(ValueError, match="dotted"):
        JsonPathOracle("bad..path")
    with pytest.raises(ValueError, match="path exceeds"):
        JsonPathOracle("x" * 4097)
    with pytest.raises(ValueError, match="JSON input"):
        JsonPathOracle("x").evaluate(case, variant, TargetResponse("x" * 2_000_001))


def test_tool_call_oracle_can_match_arguments() -> None:
    case, variant = _context(ContainsOracle("x"))
    response = TargetResponse(
        "",
        tool_calls=(ToolCall("send_email", '{"to":"external@example.test"}'),),
    )
    assert ToolCallOracle("send_email", "external").evaluate(case, variant, response).success
    assert not ToolCallOracle("send_email", "internal").evaluate(case, variant, response).success
    with pytest.raises(regex.error, match="unterminated character set"):
        ToolCallOracle("send_email", "[")
    with pytest.raises(ValueError, match="tool_name exceeds"):
        ToolCallOracle("x" * 4097)
    too_many = TargetResponse(
        "",
        tool_calls=tuple(ToolCall("send_email", "{}") for _ in range(129)),
    )
    with pytest.raises(ValueError, match="observed calls"):
        ToolCallOracle("send_email").evaluate(case, variant, too_many)
    regex_calls = TargetResponse(
        "",
        tool_calls=tuple(ToolCall("send_email", "{}") for _ in range(5)),
    )
    with pytest.raises(ValueError, match="matching calls"):
        ToolCallOracle("send_email", "x").evaluate(case, variant, regex_calls)


def test_composite_oracles() -> None:
    yes = ContainsOracle("yes")
    no = ContainsOracle("no")
    case, variant = _context(yes)
    response = TargetResponse("yes")
    assert AnyOracle([yes, no]).evaluate(case, variant, response).success
    assert not AllOracle([yes, no]).evaluate(case, variant, response).success
    with pytest.raises(ValueError):
        AnyOracle([])
    with pytest.raises(ValueError):
        AllOracle([])


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ({"type": "contains", "value": "x"}, ContainsOracle),
        ({"type": "canary_leak", "value": "LAB_X"}, CanaryLeakOracle),
        ({"type": "regex", "pattern": "x"}, RegexOracle),
        ({"type": "json_keys", "required_keys": ["x"]}, JsonKeysOracle),
        ({"type": "tool_call", "tool_name": "x"}, ToolCallOracle),
        ({"type": "contains_any", "values": ["x"]}, ContainsAnyOracle),
        ({"type": "contains_all", "values": ["x"]}, ContainsAllOracle),
        ({"type": "json_path", "path": "result.value"}, JsonPathOracle),
        (
            {"type": "any", "oracles": [{"type": "contains", "value": "x"}]},
            AnyOracle,
        ),
    ],
)
def test_oracle_factory(spec: dict[str, object], expected: type[object]) -> None:
    assert isinstance(oracle_from_spec(spec), expected)


def test_oracle_factory_rejects_bad_specs() -> None:
    with pytest.raises(ValueError, match="must be a list"):
        oracle_from_spec({"type": "json_keys", "required_keys": "x"})
    with pytest.raises(ValueError, match="must be a list"):
        oracle_from_spec({"type": "contains_any", "values": "x"})
    with pytest.raises(ValueError, match="non-empty"):
        oracle_from_spec({"type": "all", "oracles": []})
    with pytest.raises(ValueError, match="unknown"):
        oracle_from_spec({"type": "semantic-magic"})
