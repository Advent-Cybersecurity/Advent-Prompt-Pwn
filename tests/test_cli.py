from __future__ import annotations

import runpy
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from advent_prompt_pwn import (
    AttackCase,
    CanaryLeakOracle,
    FakeTarget,
    Message,
    RunConfig,
    Runner,
    Scope,
)
from advent_prompt_pwn.cli import _extra_body, _headers_env, main
from advent_prompt_pwn.integrity import seal_report
from advent_prompt_pwn.report_io import load_report
from advent_prompt_pwn.reporters import save_report


def test_cli_init_validate_and_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    corpus = tmp_path / "cases.yaml"
    assert main(["init", str(corpus)]) == 0
    assert main(["validate", str(corpus)]) == 0
    assert main(["strategies"]) == 0
    output = capsys.readouterr().out
    assert "Valid corpus" in output
    assert "instruction_override" in output


def test_cli_doctor(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor"]) == 0
    assert "telemetry disabled" in capsys.readouterr().out


def test_cli_rejects_host_header_override() -> None:
    with pytest.raises(ValueError, match="must not override Host"):
        _headers_env(["Host=APPWN_HOST"])


def test_cli_secure_and_vulnerable_exit_codes(tmp_path: Path) -> None:
    corpus = tmp_path / "cases.yaml"
    main(["init", str(corpus)])
    safe_report = tmp_path / "safe.json"
    assert (
        main(
            [
                "run",
                str(corpus),
                "--output",
                str(safe_report),
                "--requests-per-minute",
                "1000000",
            ]
        )
        == 0
    )
    finding_report = tmp_path / "finding.sarif"
    assert (
        main(
            [
                "run",
                str(corpus),
                "--fake-response",
                "LAB_ADVENT_CANARY_7F3A",
                "--output",
                str(finding_report),
                "--format",
                "sarif",
                "--requests-per-minute",
                "1000000",
            ]
        )
        == 1
    )
    assert finding_report.exists()


def test_cli_can_disable_finding_exit_code(tmp_path: Path) -> None:
    corpus = tmp_path / "cases.yaml"
    main(["init", str(corpus)])
    assert (
        main(
            [
                "run",
                str(corpus),
                "--fake-response",
                "LAB_ADVENT_CANARY_7F3A",
                "--no-fail-on-findings",
                "--output",
                str(tmp_path / "report.json"),
                "--requests-per-minute",
                "1000000",
            ]
        )
        == 0
    )
def test_cli_reports_configuration_errors(tmp_path: Path) -> None:
    corpus = tmp_path / "cases.yaml"
    main(["init", str(corpus)])
    with pytest.raises(SystemExit) as raised:
        main(
            [
                "run",
                str(corpus),
                "--target",
                "ollama",
                "--requests-per-minute",
                "1000000",
            ]
        )
    assert raised.value.code == 2


def test_cli_engagement_run_and_verify(tmp_path: Path) -> None:
    manifest = tmp_path / "engagement.yaml"
    assert main(["engagement", "init", str(manifest)]) == 0
    assert main(["engagement", "validate", str(manifest)]) == 0
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "requests_per_minute: 120",
            "requests_per_minute: 1000000",
        ),
        encoding="utf-8",
    )
    output = tmp_path / "evidence"
    assert (
        main(
            [
                "engagement",
                "run",
                str(manifest),
                "--output-dir",
                str(output),
                "--quiet",
            ]
        )
        == 0
    )
    bundles = list(output.glob("run-*"))
    assert len(bundles) == 1
    assert main(["verify", str(bundles[0])]) == 0
    assert main(["verify", str(bundles[0] / "report.json")]) == 0


def test_cli_compare_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APPWN_COMPARE_KEY", "k" * 32)
    safe = tmp_path / "safe.json"
    finding = tmp_path / "finding.json"
    state = {"response": "safe"}

    def response(messages: Sequence[Message]) -> str:
        del messages
        return state["response"]

    target = FakeTarget(response)
    scope = Scope.local_only(requests_per_minute=1_000_000)
    config = RunConfig(checkpoint_hmac_key="k" * 32)
    case = AttackCase(
        "case",
        "Case",
        "prompt",
        CanaryLeakOracle("LAB_ADVENT_CANARY_7F3A"),
    )
    corpus_sha256 = "c" * 64
    comparison_metadata = {
        "strategies": ["direct"],
        "selected_cases": ["case"],
        "trials_per_variant": 1,
    }
    save_report(
        Runner(
            target,
            scope=scope,
            config=config,
            corpus_sha256=corpus_sha256,
            metadata=comparison_metadata,
        ).run([case]),
        safe,
    )
    state["response"] = "LAB_ADVENT_CANARY_7F3A"
    save_report(
        Runner(
            target,
            scope=scope,
            config=config,
            corpus_sha256=corpus_sha256,
            metadata=comparison_metadata,
        ).run([case]),
        finding,
    )
    assert (
        main(
            [
                "compare",
                str(safe),
                str(finding),
                "--output",
                str(tmp_path / "comparison.md"),
                "--checkpoint-hmac-env",
                "APPWN_COMPARE_KEY",
            ]
        )
        == 1
    )
    assert (
        main(
            [
                "compare",
                str(safe),
                str(finding),
                "--output",
                str(tmp_path / "comparison.json"),
                "--no-fail-on-regression",
                "--checkpoint-hmac-env",
                "APPWN_COMPARE_KEY",
            ]
        )
        == 0
    )
    checkpoints = []
    Runner(
        target,
        scope=scope,
        config=config,
        checkpoint_callback=checkpoints.append,
        corpus_sha256=corpus_sha256,
        metadata=comparison_metadata,
    ).run([case])
    partial = tmp_path / "partial.json"
    save_report(checkpoints[0], partial)
    with pytest.raises(SystemExit):
        main(
            [
                "compare",
                str(safe),
                str(partial),
                "--checkpoint-hmac-env",
                "APPWN_COMPARE_KEY",
            ]
        )

    signed = load_report(finding)
    forged_metadata = dict(signed.metadata)
    forged_metadata.pop("checkpoint_hmac_sha256")
    save_report(
        seal_report(
            replace(
                signed,
                metadata=forged_metadata,
                integrity_sha256="",
            )
        ),
        finding,
    )
    with pytest.raises(SystemExit):
        main(
            [
                "compare",
                str(safe),
                str(finding),
                "--checkpoint-hmac-env",
                "APPWN_COMPARE_KEY",
            ]
        )


def test_cli_one_off_checkpoint_bundle_and_concurrency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("APPWN_CHECKPOINT_KEY", "k" * 32)
    corpus = tmp_path / "cases.yaml"
    main(["init", str(corpus)])
    checkpoint = tmp_path / "checkpoint.json"
    bundle = tmp_path / "bundle"
    assert (
        main(
            [
                "run",
                str(corpus),
                "--strategy",
                "instruction_override",
                "--concurrency",
                "2",
                "--max-requests",
                "3",
                "--requests-per-minute",
                "1000000",
                "--checkpoint-interval",
                "1",
                "--checkpoint",
                str(checkpoint),
                "--checkpoint-hmac-env",
                "APPWN_CHECKPOINT_KEY",
                "--bundle",
                str(bundle),
                "--output",
                str(tmp_path / "report.json"),
            ]
        )
        == 0
    )
    checkpoint_output = capsys.readouterr().out
    assert checkpoint_output.count("Checkpoint candidate:") >= 2
    assert "Integrity:" in checkpoint_output
    assert checkpoint.exists()
    assert main(["verify", str(bundle)]) == 0
    assert (
        main(
            [
                "verify",
                str(bundle),
                "--checkpoint-hmac-env",
                "APPWN_CHECKPOINT_KEY",
            ]
        )
        == 0
    )
    report = bundle / "report.json"
    report.write_text(report.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert main(["verify", str(bundle)]) == 2


def test_cli_helpers_validate_external_body_and_header_mapping(tmp_path: Path) -> None:
    body = tmp_path / "body.json"
    body.write_text('{"temperature": 0}', encoding="utf-8")
    assert _extra_body(str(body)) == {"temperature": 0}
    assert _headers_env(["Authorization=TOKEN_ENV"]) == {"Authorization": "TOKEN_ENV"}
    with pytest.raises(ValueError, match="HEADER=ENV_VAR"):
        _headers_env(["bad"])
    with pytest.raises(ValueError, match="header name"):
        _headers_env(["Bad Header=TOKEN_ENV"])
    with pytest.raises(ValueError, match="environment variable"):
        _headers_env(["Authorization=BAD-NAME"])
    body.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        _extra_body(str(body))


def test_cli_automatically_redacts_selected_adapter_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "synthetic-cli-credential"
    monkeypatch.setenv("CLI_ADAPTER_KEY", secret)
    corpus = tmp_path / "cases.yaml"
    main(["init", str(corpus)])
    report = tmp_path / "report.json"
    assert (
        main(
            [
                "run",
                str(corpus),
                "--api-key-env",
                "CLI_ADAPTER_KEY",
                "--fake-response",
                secret,
                "--output",
                str(report),
                "--requests-per-minute",
                "1000000",
            ]
        )
        == 0
    )
    assert secret not in report.read_text(encoding="utf-8")


def test_cli_authorized_scope_and_new_resource_options(tmp_path: Path) -> None:
    corpus = tmp_path / "cases.yaml"
    main(["init", str(corpus)])
    assert (
        main(
            [
                "run",
                str(corpus),
                "--authorized",
                "--allow-host",
                "192.0.2.10",
                "--authorization-ref",
                "SOW-42",
                "--allow-query-parameter",
                "tenant",
                "--allow-unpinned-dns",
                "--max-evidence-bytes",
                "1000000",
                "--requests-per-minute",
                "1000000",
                "--output",
                str(tmp_path / "authorized.json"),
            ]
        )
        == 0
    )


def test_python_module_entrypoint_runs_doctor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["advent-prompt-pwn", "doctor"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("advent_prompt_pwn.__main__", run_name="__main__")
    assert raised.value.code == 0
