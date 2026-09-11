from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from advent_prompt_pwn import (
    AttackCase,
    CanaryLeakOracle,
    FakeTarget,
    Runner,
    Scope,
    compare_reports,
)
from advent_prompt_pwn.bundle import verify_evidence_bundle, write_evidence_bundle
from advent_prompt_pwn.comparison import save_comparison
from advent_prompt_pwn.exceptions import ReportError
from advent_prompt_pwn.report_io import load_report, report_from_dict, verify_report_evidence
from advent_prompt_pwn.reporters import save_report


def _report(response: str, *, name: str = "fake"):
    case = AttackCase("case", "Case", "prompt", CanaryLeakOracle("LAB_REPORT_IO"))
    return Runner(
        FakeTarget(response, name=name),
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run([case])


def test_report_round_trip_and_integrity_verification(tmp_path: Path) -> None:
    original = _report("LAB_REPORT_IO")
    path = save_report(original, tmp_path / "report.json")
    loaded = load_report(path)
    assert loaded.run_id == original.run_id
    assert loaded.findings[0].finding_id == original.findings[0].finding_id
    assert verify_report_evidence(loaded) == ()


def test_report_integrity_detects_tampering(tmp_path: Path) -> None:
    path = save_report(_report("LAB_REPORT_IO"), tmp_path / "report.json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["attempts"][0]["response"]["content"] = "tampered"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert "digest mismatch" in verify_report_evidence(load_report(path))[0]


def test_report_loader_rejects_duplicate_json_object_keys(tmp_path: Path) -> None:
    path = save_report(_report("safe"), tmp_path / "report.json")
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace('"request_count": 1,', '"request_count": 999,\n  "request_count": 1,'),
        encoding="utf-8",
    )
    with pytest.raises(ReportError, match="duplicate JSON object key"):
        load_report(path)


def test_report_loader_rejects_invalid_documents(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ReportError, match="root"):
        load_report(path)
    with pytest.raises(ReportError, match="attempts"):
        report_from_dict({"run_id": "x"})
    with pytest.raises(ReportError, match="could not load"):
        load_report(tmp_path / "missing.json")


def test_report_loader_rejects_malformed_nested_values() -> None:
    raw = json.loads(json.dumps(_report("safe").to_dict()))
    raw["attempts"][0]["messages"] = "bad"
    with pytest.raises(ReportError, match="messages"):
        report_from_dict(raw)
    raw = json.loads(json.dumps(_report("safe").to_dict()))
    raw["attempts"][0]["response"]["tool_calls"] = "bad"
    with pytest.raises(ReportError, match="tool_calls"):
        report_from_dict(raw)
    raw = json.loads(json.dumps(_report("safe").to_dict()))
    raw["attempts"][0]["tags"] = "bad"
    with pytest.raises(ReportError, match="tags"):
        report_from_dict(raw)


def test_report_verifier_checks_structural_invariants() -> None:
    original = _report("safe")
    attempt = replace(original.attempts[0], evidence_sha256="bad")
    report = replace(
        original,
        attempts=(attempt, attempt),
        corpus_sha256="bad",
        request_count=0,
    )
    errors = verify_report_evidence(report)
    assert any("duplicate variant" in error for error in errors)
    assert any("invalid evidence" in error for error in errors)
    assert "invalid corpus digest" in errors
    assert any("request count" in error for error in errors)


def test_evidence_bundle_round_trip_and_checksum_failure(tmp_path: Path) -> None:
    directory = write_evidence_bundle(_report("LAB_REPORT_IO"), tmp_path / "bundle")
    verified = verify_evidence_bundle(directory)
    assert verified.valid
    assert verified.files_checked == 4
    with pytest.raises(FileExistsError, match="non-empty"):
        write_evidence_bundle(_report("safe"), directory)
    report = directory / "report.json"
    report.write_text(report.read_text(encoding="utf-8") + " ", encoding="utf-8")
    failed = verify_evidence_bundle(directory)
    assert not failed.valid
    assert any("checksum mismatch" in error for error in failed.errors)


def test_evidence_bundle_rejects_invalid_manifest(tmp_path: Path) -> None:
    directory = tmp_path / "bundle"
    directory.mkdir()
    (directory / "bundle-manifest.json").write_text("{}", encoding="utf-8")
    assert not verify_evidence_bundle(directory).valid


def test_evidence_bundle_handles_force_unknown_formats_and_unsafe_paths(
    tmp_path: Path,
) -> None:
    directory = write_evidence_bundle(
        _report("safe"),
        tmp_path / "bundle",
        formats=("json",),
    )
    assert (
        write_evidence_bundle(
            _report("safe"),
            directory,
            formats=("json",),
            force=True,
        )
        == directory
    )
    with pytest.raises(ValueError, match="unsupported"):
        write_evidence_bundle(_report("safe"), tmp_path / "bad", formats=("bad",))
    manifest = directory / "bundle-manifest.json"
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["files"] = [{"path": "../outside", "sha256": "0" * 64, "size": 1}]
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    result = verify_evidence_bundle(directory)
    assert any("unexpected bundle path" in error for error in result.errors)


def test_evidence_bundle_reports_missing_listed_file_and_report(tmp_path: Path) -> None:
    directory = write_evidence_bundle(
        _report("safe"),
        tmp_path / "bundle",
        formats=("json",),
    )
    manifest = directory / "bundle-manifest.json"
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["files"][0]["path"] = "missing.json"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    (directory / "report.json").rename(directory / "moved.json")
    result = verify_evidence_bundle(directory)
    assert any("unexpected bundle path" in error for error in result.errors)
    assert "bundle is missing report.json" in result.errors


def test_comparison_tracks_new_resolved_and_persistent_findings(tmp_path: Path) -> None:
    safe = _report("safe")
    vulnerable = _report("LAB_REPORT_IO")
    new = compare_reports(safe, vulnerable)
    assert new.regressed
    assert len(new.new_findings) == 1
    resolved = compare_reports(vulnerable, safe)
    assert len(resolved.resolved_findings) == 1
    persistent = compare_reports(vulnerable, _report("LAB_REPORT_IO"))
    assert len(persistent.persistent_findings) == 1
    assert save_comparison(new, tmp_path / "comparison.md").read_text(encoding="utf-8")
    assert json.loads(save_comparison(new, tmp_path / "comparison.json").read_text())["regressed"]
    with pytest.raises(ValueError, match="same target"):
        compare_reports(vulnerable, _report("LAB_REPORT_IO", name="other"))
    with pytest.raises(ValueError, match="corpus"):
        compare_reports(
            replace(vulnerable, corpus_sha256="a" * 64),
            replace(vulnerable, corpus_sha256="b" * 64),
        )
    assert not compare_reports(
        replace(vulnerable, corpus_sha256="a" * 64),
        replace(vulnerable, corpus_sha256="b" * 64),
        allow_corpus_change=True,
    ).new_findings
