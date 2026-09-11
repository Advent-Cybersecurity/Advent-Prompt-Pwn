from __future__ import annotations

from pathlib import Path

from examples.qualification_assessments import build_assessments

from advent_prompt_pwn.report_io import load_report, verify_report_evidence


def test_offline_qualification_assessments_detect_every_fixture(tmp_path: Path) -> None:
    destinations = build_assessments(tmp_path)
    reports = [load_report(path) for path in destinations if path.suffix == ".json"]
    assert len(destinations) == 6
    assert len(reports) == 3
    assert all(report.findings for report in reports)
    assert all(not report.errors for report in reports)
    assert all(verify_report_evidence(report) == () for report in reports)
