from __future__ import annotations

import pytest

from advent_prompt_pwn.cli import _parser, _scope, _target
from advent_prompt_pwn.targets import (
    AnthropicTarget,
    AzureOpenAITarget,
    GeminiTarget,
    OpenAITarget,
)


@pytest.mark.parametrize(
    ("arguments", "expected_type"),
    [
        (["--target", "openai", "--model", "gpt-lab"], OpenAITarget),
        (["--target", "anthropic", "--model", "claude-lab"], AnthropicTarget),
        (["--target", "gemini", "--model", "gemini-lab"], GeminiTarget),
        (
            [
                "--target",
                "azure-openai",
                "--resource",
                "resource-lab",
                "--deployment",
                "deployment-lab",
                "--api-version",
                "2026-01-01",
            ],
            AzureOpenAITarget,
        ),
    ],
)
def test_cli_builds_provider_targets(arguments: list[str], expected_type: type[object]) -> None:
    args = _parser().parse_args(["run", "cases.yaml", *arguments])
    target = _target(args)
    try:
        assert isinstance(target, expected_type)
    finally:
        target.close()


def test_cli_requires_complete_azure_configuration() -> None:
    args = _parser().parse_args(["run", "cases.yaml", "--target", "azure-openai"])
    with pytest.raises(ValueError, match="resource"):
        _target(args)


def test_cli_builds_pinned_time_bounded_scope() -> None:
    args = _parser().parse_args(
        [
            "run",
            "cases.yaml",
            "--authorized",
            "--authorization-ref",
            "SOW-1",
            "--allow-host",
            "ai.example.test",
            "--allow-port",
            "443",
            "--pin-dns",
            "ai.example.test=192.0.2.10,2001:db8::10",
            "--not-before",
            "2030-01-01T00:00:00Z",
            "--not-after",
            "2030-01-02T00:00:00Z",
        ]
    )
    scope = _scope(args)
    assert scope.pinned_dns["ai.example.test"] == ("192.0.2.10", "2001:db8::10")
    assert scope.not_after == "2030-01-02T00:00:00Z"


def test_cli_rejects_malformed_and_duplicate_dns_pins() -> None:
    base = [
        "run",
        "cases.yaml",
        "--authorized",
        "--authorization-ref",
        "SOW-1",
        "--allow-host",
        "ai.example.test",
    ]
    malformed = _parser().parse_args([*base, "--pin-dns", "bad"])
    with pytest.raises(ValueError, match="HOST=IP"):
        _scope(malformed)
    duplicate = _parser().parse_args(
        [
            *base,
            "--pin-dns",
            "ai.example.test=192.0.2.10",
            "--pin-dns",
            "AI.EXAMPLE.TEST=192.0.2.11",
        ]
    )
    with pytest.raises(ValueError, match="duplicate"):
        _scope(duplicate)
