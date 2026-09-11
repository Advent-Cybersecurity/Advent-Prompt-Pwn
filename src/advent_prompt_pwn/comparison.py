"""Baseline comparison for engagement regression testing."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from advent_prompt_pwn.core.models import AttemptResult, Finding, RunReport
from advent_prompt_pwn.integrity import canonical_sha256
from advent_prompt_pwn.io import atomic_write_text_chunks
from advent_prompt_pwn.report_io import MAX_REPORT_BYTES
from advent_prompt_pwn.reporters import markdown_text


@dataclass(frozen=True, slots=True)
class ReportComparison:
    """Finding and execution changes between two compatible reports."""

    baseline_run_id: str
    current_run_id: str
    target_name: str
    new_findings: tuple[Finding, ...]
    resolved_findings: tuple[Finding, ...]
    persistent_findings: tuple[Finding, ...]
    new_error_keys: tuple[str, ...]
    resolved_error_keys: tuple[str, ...]

    @property
    def regressed(self) -> bool:
        return bool(self.new_findings or self.new_error_keys)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for key in ("new_findings", "resolved_findings", "persistent_findings"):
            value[key] = [finding.to_dict() for finding in getattr(self, key)]
        value["regressed"] = self.regressed
        value["summary"] = {
            "new_findings": len(self.new_findings),
            "resolved_findings": len(self.resolved_findings),
            "persistent_findings": len(self.persistent_findings),
            "new_errors": len(self.new_error_keys),
            "resolved_errors": len(self.resolved_error_keys),
        }
        return value


def _error_keys(report: RunReport) -> set[str]:
    return {f"{attempt.case_id}:{attempt.strategy}" for attempt in report.attempts if attempt.error}


def comparison_plan_identity(
    report: RunReport,
    *,
    required: bool = False,
    label: str = "report",
) -> tuple[tuple[str, ...], tuple[str, ...], int, int, int] | None:
    """Return a validated execution-selection identity when one is recorded."""

    strategies = report.metadata.get("strategies")
    selected_cases = report.metadata.get("selected_cases")
    trials_per_variant = report.metadata.get("trials_per_variant")
    planned_attempts = report.metadata.get("planned_attempts")
    selection_present = strategies is not None or selected_cases is not None
    if not selection_present and not required:
        return None
    if not (
        isinstance(strategies, (list, tuple))
        and strategies
        and all(isinstance(item, str) and item for item in strategies)
        and isinstance(selected_cases, (list, tuple))
        and selected_cases
        and all(isinstance(item, str) and item for item in selected_cases)
        and not isinstance(trials_per_variant, bool)
        and isinstance(trials_per_variant, int)
        and trials_per_variant > 0
        and not isinstance(planned_attempts, bool)
        and isinstance(planned_attempts, int)
        and planned_attempts >= 0
        and not isinstance(report.seed, bool)
        and isinstance(report.seed, int)
    ):
        raise ValueError(f"{label} report has invalid execution selection metadata")
    return (
        tuple(strategies),
        tuple(selected_cases),
        trials_per_variant,
        report.seed,
        planned_attempts,
    )


def _coverage_counts(report: RunReport) -> Counter[tuple[str, str]]:
    return Counter((attempt.case_id, attempt.strategy) for attempt in report.attempts)


def _job_identity(attempt: AttemptResult) -> str:
    return canonical_sha256(
        {
            "case_id": attempt.case_id,
            "case_name": attempt.case_name,
            "variant_id": attempt.variant_id,
            "strategy": attempt.strategy,
            "messages": [message.to_dict() for message in attempt.messages],
            "tags": attempt.tags,
            "severity": attempt.severity,
            "metadata": attempt.metadata,
        }
    )


def _job_identities(report: RunReport) -> tuple[str, ...]:
    return tuple(sorted(_job_identity(attempt) for attempt in report.attempts))


def compare_reports(
    baseline: RunReport,
    current: RunReport,
    *,
    allow_corpus_change: bool = False,
) -> ReportComparison:
    """Compare complete findings by stable case-based identifiers.

    Callers must authenticate reports loaded from untrusted storage before comparison.
    """

    for label, report in (("baseline", baseline), ("current", current)):
        stopped_early = report.metadata.get("stopped_early")
        planned_attempts = report.metadata.get("planned_attempts")
        unresolved_requests = report.metadata.get("unresolved_request_count", 0)
        if (
            stopped_early is not False
            or isinstance(planned_attempts, bool)
            or not isinstance(planned_attempts, int)
            or planned_attempts != len(report.attempts)
            or isinstance(unresolved_requests, bool)
            or not isinstance(unresolved_requests, int)
            or unresolved_requests != 0
        ):
            raise ValueError(f"{label} report is incomplete and cannot be compared")

    baseline_identity = baseline.metadata.get("target_endpoint_sha256")
    current_identity = current.metadata.get("target_endpoint_sha256")
    baseline_contract = baseline.metadata.get("target_contract_sha256")
    current_contract = current.metadata.get("target_contract_sha256")
    keyed_identity_present = any(
        value is not None
        for value in (
            baseline_identity,
            current_identity,
            baseline_contract,
            current_contract,
        )
    )
    if keyed_identity_present and not all(
        isinstance(value, str) and value
        for value in (
            baseline_identity,
            current_identity,
            baseline_contract,
            current_contract,
        )
    ):
        raise ValueError("keyed reports require complete target identities")
    redacted_endpoint = "[REDACTED]" in unquote(
        baseline.target_endpoint
    ) or "[REDACTED]" in unquote(current.target_endpoint)
    if redacted_endpoint and (not baseline_identity or not current_identity):
        raise ValueError(
            "reports with redacted endpoints require keyed target identities; "
            "configure the same checkpoint HMAC key for both runs"
        )
    if (
        baseline.target_name != current.target_name
        or baseline.target_endpoint != current.target_endpoint
        or baseline_identity != current_identity
    ):
        raise ValueError("reports must use the same target endpoint")
    if baseline_contract != current_contract:
        raise ValueError("reports must use the same target contract")
    baseline_plan = comparison_plan_identity(baseline, label="baseline")
    current_plan = comparison_plan_identity(current, label="current")
    if (
        baseline_plan is not None
        or current_plan is not None
    ) and baseline_plan != current_plan:
        raise ValueError("reports must use the same execution selection")
    if _coverage_counts(baseline) != _coverage_counts(current):
        raise ValueError("reports must use the same execution coverage")
    if (
        not allow_corpus_change
        and baseline.corpus_sha256
        and current.corpus_sha256
        and baseline.corpus_sha256 != current.corpus_sha256
    ):
        raise ValueError("reports use different corpus digests")
    if not allow_corpus_change and _job_identities(baseline) != _job_identities(current):
        raise ValueError("reports must use the same generated jobs")
    baseline_findings = {finding.case_id: finding for finding in baseline.findings}
    current_findings = {finding.case_id: finding for finding in current.findings}
    baseline_ids = set(baseline_findings)
    current_ids = set(current_findings)
    baseline_errors = _error_keys(baseline)
    current_errors = _error_keys(current)
    return ReportComparison(
        baseline_run_id=baseline.run_id,
        current_run_id=current.run_id,
        target_name=current.target_name,
        new_findings=tuple(current_findings[key] for key in sorted(current_ids - baseline_ids)),
        resolved_findings=tuple(
            baseline_findings[key] for key in sorted(baseline_ids - current_ids)
        ),
        persistent_findings=tuple(
            current_findings[key] for key in sorted(current_ids & baseline_ids)
        ),
        new_error_keys=tuple(sorted(current_errors - baseline_errors)),
        resolved_error_keys=tuple(sorted(baseline_errors - current_errors)),
    )


def comparison_json(comparison: ReportComparison) -> str:
    """Render a comparison as stable JSON."""

    return json.dumps(comparison.to_dict(), indent=2, sort_keys=True)


def comparison_markdown(comparison: ReportComparison) -> str:
    """Render a concise engagement regression report."""

    lines = [
        "# AI Red-Team Baseline Comparison",
        "",
        f"- Target: {markdown_text(comparison.target_name)}",
        f"- Baseline run: {markdown_text(comparison.baseline_run_id)}",
        f"- Current run: {markdown_text(comparison.current_run_id)}",
        f"- Regression detected: `{'yes' if comparison.regressed else 'no'}`",
        "",
        "## Summary",
        "",
        f"- New findings: {len(comparison.new_findings)}",
        f"- Resolved findings: {len(comparison.resolved_findings)}",
        f"- Persistent findings: {len(comparison.persistent_findings)}",
        f"- New execution errors: {len(comparison.new_error_keys)}",
        "",
    ]
    for heading, findings in (
        ("New findings", comparison.new_findings),
        ("Resolved findings", comparison.resolved_findings),
        ("Persistent findings", comparison.persistent_findings),
    ):
        lines.extend((f"## {heading}", ""))
        if findings:
            lines.extend(
                f"- {markdown_text(finding.finding_id)} "
                f"[{finding.severity.value.upper()}] {markdown_text(finding.title)} "
                f"({finding.occurrence_count} occurrence(s))"
                for finding in findings
            )
        else:
            lines.append("None.")
        lines.append("")
    return "\n".join(lines)


def save_comparison(comparison: ReportComparison, path: str | Path) -> Path:
    """Save JSON or Markdown comparison output."""

    destination = Path(path)
    chunks: Iterable[str]
    if destination.suffix.lower() in {".md", ".markdown"}:
        chunks = (comparison_markdown(comparison),)
    else:
        chunks = json.JSONEncoder(indent=2, sort_keys=True).iterencode(comparison.to_dict())
    return atomic_write_text_chunks(destination, chunks, max_bytes=MAX_REPORT_BYTES)
