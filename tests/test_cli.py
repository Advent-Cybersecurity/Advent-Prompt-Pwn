from __future__ import annotations

import json
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
from advent_prompt_pwn.bundle import write_evidence_bundle
from advent_prompt_pwn.cli import _extra_body, _headers_env, _terminal_safe, main
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


def test_cli_neutralizes_untrusted_terminal_controls(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hostile = "field\x1b]0;spoofed\x07\r\nforged\x85"
    rendered = _terminal_safe(hostile + ("x" * 5000))
    assert rendered.startswith("field\\x1b]0;spoofed\\x07\\x0d\\x0aforged\\x85")
    assert rendered.endswith("...[truncated]")
    assert len(rendered) <= 4096

    corpus = tmp_path / "hostile.json"
    corpus.write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "id": hostile,
                        "name": "First",
                        "prompt": "prompt",
                        "oracle": {"type": "contains", "value": "marker"},
                    },
                    {
                        "id": hostile,
                        "name": "Second",
                        "prompt": "prompt",
                        "oracle": {"type": "contains", "value": "marker"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as raised:
        main(["validate", str(corpus)])
    assert raised.value.code == 2
    corpus_error = capsys.readouterr().err
    assert "\x1b" not in corpus_error
    assert "\\x1b" in corpus_error
    assert "\\x0a" in corpus_error

    report = Runner(
        FakeTarget("safe"),
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run(
        [AttackCase("case", "Case", "prompt", CanaryLeakOracle("LAB_TERMINAL"))]
    )
    valid_hostile = seal_report(
        replace(report, run_id=hostile, integrity_sha256="")
    )
    valid_report = tmp_path / "valid-hostile.json"
    save_report(valid_hostile, valid_report)
    assert main(["verify", str(valid_report)]) == 0
    valid_output = capsys.readouterr().out
    assert "\x1b" not in valid_output
    assert "\\x1b" in valid_output

    hostile_attempt = replace(
        report.attempts[0],
        variant_id=hostile,
        evidence_sha256="invalid",
    )
    invalid_hostile = seal_report(
        replace(report, attempts=(hostile_attempt,), integrity_sha256="")
    )
    invalid_report = tmp_path / "invalid-hostile.json"
    save_report(invalid_hostile, invalid_report)
    assert main(["verify", str(invalid_report)]) == 2
    invalid_output = capsys.readouterr().out
    assert "\x1b" not in invalid_output
    assert "\\x1b" in invalid_output

    many_invalid_attempts = tuple(
        replace(
            report.attempts[0],
            variant_id=f"variant-{index}-" + ("x" * 4090),
            evidence_sha256="invalid",
        )
        for index in range(100)
    )
    many_invalid = seal_report(
        replace(report, attempts=many_invalid_attempts, integrity_sha256="")
    )
    many_invalid_report = tmp_path / "many-invalid.json"
    save_report(many_invalid, many_invalid_report)
    assert main(["verify", str(many_invalid_report)]) == 2
    bounded_output = capsys.readouterr().out
    assert len(bounded_output) <= 4096
    assert "additional diagnostics omitted" in bounded_output

    bundle = tmp_path / "bundle"
    write_evidence_bundle(report, bundle)
    manifest_path = bundle / "bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["path"] = hostile
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert main(["verify", str(bundle)]) == 2
    bundle_output = capsys.readouterr().out
    assert "\x1b" not in bundle_output
    assert "\\x1b" in bundle_output


def test_python_module_entrypoint_runs_doctor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["advent-prompt-pwn", "doctor"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("advent_prompt_pwn.__main__", run_name="__main__")
    assert raised.value.code == 0
