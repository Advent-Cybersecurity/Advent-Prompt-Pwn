from __future__ import annotations

import json
from pathlib import Path
from xml.etree.ElementTree import fromstring

import pytest

from advent_prompt_pwn import (
    AttackCase,
    CanaryLeakOracle,
    FakeTarget,
    RunConfig,
    Runner,
    RunReport,
    Scope,
)
from advent_prompt_pwn.reporters import (
    report_html,
    report_json,
    report_jsonl,
    report_junit,
    report_markdown,
    report_sarif,
    save_report,
)


def _report() -> RunReport:
    case = AttackCase("case", "Case", "prompt", CanaryLeakOracle("LAB_REPORT"))
    return Runner(
        FakeTarget("LAB_REPORT"),
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run([case])


def test_json_and_jsonl_reports() -> None:
    report = _report()
    document = json.loads(report_json(report))
    assert document["summary"]["attack_successes"] == 1
    lines = report_jsonl(report).splitlines()
    assert json.loads(lines[0])["type"] == "run"
    assert json.loads(lines[1])["type"] == "attempt"


def test_human_and_ci_reports() -> None:
    report = _report()
    assert "ADVERSARIAL SUCCESS" in report_markdown(report)
    assert "<failure" in report_junit(report)
    sarif = json.loads(report_sarif(report))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "AI-case"


def test_html_report_escapes_model_output() -> None:
    case = AttackCase("html", "<Case>", "prompt", CanaryLeakOracle("LAB_HTML"))
    report = Runner(
        FakeTarget("LAB_HTML<script>alert(1)</script>"),
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run([case])
    rendered = report_html(report)
    assert "&lt;script&gt;" in rendered
    assert "<script>" not in rendered


def test_junit_replaces_xml_forbidden_control_characters() -> None:
    case = AttackCase("xml", "XML", "prompt", CanaryLeakOracle("LAB_XML"))
    report = Runner(
        FakeTarget("safe\x00target"),
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run([case])
    rendered = report_junit(report)
    fromstring(rendered)  # noqa: S314 - parses locally generated XML
    assert "\\u0000" in rendered


def test_human_reports_include_repeated_trial_analysis() -> None:
    case = AttackCase("trials", "Trials", "prompt", CanaryLeakOracle("LAB_TRIAL"))
    report = Runner(
        FakeTarget("LAB_TRIAL"),
        scope=Scope.local_only(max_requests=2, requests_per_minute=1_000_000),
        config=RunConfig(trials_per_variant=2),
    ).run([case])
    assert "Repeated-trial analysis" in report_markdown(report)
    assert "Repeated-trial groups" in report_html(report)


@pytest.mark.parametrize("suffix", ["json", "jsonl", "html", "md", "xml", "sarif"])
def test_save_report_infers_format(tmp_path: Path, suffix: str) -> None:
    path = save_report(_report(), tmp_path / f"report.{suffix}")
    assert path.exists()
    assert path.read_text(encoding="utf-8")


def test_save_report_rejects_unknown_format(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported"):
        save_report(_report(), tmp_path / "report.bad")
