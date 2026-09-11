from __future__ import annotations

import json
from pathlib import Path

import pytest

from advent_prompt_pwn import get_schema
from advent_prompt_pwn.cli import main
from advent_prompt_pwn.schema import SCHEMA_NAMES, validate_schema_document


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_bundled_schemas_are_json_objects(name: str) -> None:
    schema = get_schema(name)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["type"] == "object"
    if name == "report-v1":
        assert "integrity_sha256" in schema["required"]


def test_unknown_schema_is_rejected() -> None:
    with pytest.raises(KeyError, match="unknown schema"):
        get_schema("missing")


def test_engagement_schema_validator_enforces_types_and_bounds() -> None:
    base = {
        "version": 1,
        "engagement": {
            "id": "ok",
            "name": "name",
            "owner": "owner",
            "authorization_reference": "SOW-1",
        },
        "corpus": "cases.yaml",
        "target": {"type": "fake"},
        "scope": {
            "mode": "local",
            "max_requests": 1,
            "requests_per_minute": 1,
            "max_concurrency": 1,
        },
    }
    validate_schema_document(base, "engagement-v1")
    invalid = [
        ([], "type object"),
        ({**base, "version": True}, "must equal"),
        (
            {**base, "engagement": {**base["engagement"], "name": ""}},
            "shorter",
        ),
        (
            {**base, "engagement": {**base["engagement"], "id": "?"}},
            "pattern",
        ),
        ({**base, "scope": {**base["scope"], "max_requests": 0}}, "at least"),
        (
            {**base, "scope": {**base["scope"], "allowed_ports": [65_536]}},
            "at most",
        ),
        ({**base, "execution": {"timeout_seconds": 0}}, "greater than"),
        ({**base, "target": {"type": "fake", "headers_env": {"X": 1}}}, "string"),
    ]
    for document, message in invalid:
        with pytest.raises(ValueError, match=message):
            validate_schema_document(document, "engagement-v1")


def test_cli_prints_and_saves_schema(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["schema", "corpus-v1"]) == 0
    assert "advent-prompt-pwn corpus v1" in capsys.readouterr().out
    output = tmp_path / "schema.json"
    assert main(["schema", "report-v1", "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["title"].endswith("report v1")
