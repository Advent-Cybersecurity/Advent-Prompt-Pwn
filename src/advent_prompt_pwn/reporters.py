"""Machine-readable and human-readable report writers."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from html import escape
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring

from advent_prompt_pwn.core.models import RunReport
from advent_prompt_pwn.io import atomic_write_text_chunks
from advent_prompt_pwn.report_io import MAX_REPORT_BYTES


def report_json(report: RunReport, *, indent: int = 2) -> str:
    """Serialize a complete report as JSON."""

    return json.dumps(report.to_dict(), indent=indent, sort_keys=True)


def _report_json_chunks(report: RunReport) -> Iterator[str]:
    yield from json.JSONEncoder(indent=2, sort_keys=True).iterencode(report.to_dict())


def report_jsonl(report: RunReport) -> str:
    """Serialize one metadata record followed by one record per attempt."""

    return "".join(_report_jsonl_chunks(report))


def _report_jsonl_chunks(report: RunReport) -> Iterator[str]:

    header: dict[str, Any] = {
        "type": "run",
        "run_id": report.run_id,
        "target_name": report.target_name,
        "target_endpoint": report.target_endpoint,
        "started_at": report.started_at,
        "completed_at": report.completed_at,
        "seed": report.seed,
        "authorization_reference": report.authorization_reference,
        "engagement_id": report.engagement_id,
        "corpus_sha256": report.corpus_sha256,
        "request_count": report.request_count,
        "schema_version": report.schema_version,
        "tool_version": report.tool_version,
        "integrity_sha256": report.integrity_sha256,
        "metadata": report.metadata,
    }
    yield json.dumps(header, sort_keys=True)
    yield "\n"
    for attempt in report.attempts:
        yield json.dumps({"type": "attempt", **attempt.to_dict()}, sort_keys=True)
        yield "\n"


def markdown_text(value: str) -> str:
    """Render untrusted text as inert Markdown content."""

    flattened = value.replace("\r", " ").replace("\n", " ")
    escaped = flattened.replace("\\", "\\\\")
    for character in "`*_{}[]()<>#+-.!|":
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def report_markdown(report: RunReport) -> str:
    """Render a concise assessment report in Markdown."""

    lines = [
        "# AI Red-Team Run Report",
        "",
        f"- Run ID: {markdown_text(report.run_id)}",
        f"- Target: {markdown_text(report.target_name)}",
        f"- Endpoint: {markdown_text(report.target_endpoint)}",
        f"- Started: {markdown_text(report.started_at)}",
        f"- Completed: {markdown_text(report.completed_at)}",
        f"- Seed: `{report.seed}`",
        f"- Authorization: {markdown_text(report.authorization_reference or 'local-only')}",
        f"- Engagement: {markdown_text(report.engagement_id or 'not-specified')}",
        f"- Tool version: {markdown_text(report.tool_version or 'unknown')}",
        f"- Corpus SHA-256: {markdown_text(report.corpus_sha256 or 'not-recorded')}",
        f"- Report SHA-256: {markdown_text(report.integrity_sha256)}",
        "",
        "## Summary",
        "",
        f"- Attempts: {len(report.attempts)}",
        f"- Adversarial successes: {report.attack_successes}",
        f"- Security passes: {report.security_passes}",
        f"- Errors: {report.errors}",
        f"- Deduplicated findings: {len(report.findings)}",
        f"- Requests including retries: {report.request_count}",
        f"- Attack success rate: {report.attack_success_rate:.1%}",
    ]
    trial_statistics = report.trial_statistics
    if trial_statistics:
        lines.extend(
            (
                f"- Repeated-trial groups: {len(trial_statistics)}",
                f"- Mixed-outcome groups: "
                f"{sum(item.consistency == 'mixed' for item in trial_statistics)}",
                "",
                "## Repeated-trial analysis",
                "",
                "| Case | Variant | Trials | Success rate | 95% interval | Consistency |",
                "|---|---|---:|---:|---:|---|",
            )
        )
        for statistic in trial_statistics:
            lines.append(
                f"| {markdown_text(statistic.case_id)} | "
                f"{markdown_text(statistic.base_variant_id)} | "
                f"{statistic.evaluated_trials}/{statistic.planned_trials} | "
                f"{statistic.success_rate:.1%} | "
                f"{statistic.confidence_low_95:.1%} to "
                f"{statistic.confidence_high_95:.1%} | "
                f"{markdown_text(statistic.consistency)} |"
            )
    lines.extend(
        (
            "",
            "## Findings",
            "",
            "| ID | Severity | Title | Occurrences | Strategies |",
            "|---|---|---|---:|---|",
        )
    )
    for finding in report.findings:
        lines.append(
            f"| {markdown_text(finding.finding_id)} | {finding.severity.value.upper()} | "
            f"{markdown_text(finding.title)} | {finding.occurrence_count} | "
            f"{markdown_text(', '.join(finding.strategies))} |"
        )
    if not report.findings:
        lines.append("| None | - | No adversarial objectives were observed | 0 | - |")
    lines.extend(
        (
            "",
            "## Attempts",
            "",
            "| Case | Strategy | Severity | Outcome | Evidence |",
            "|---|---|---|---|---|",
        )
    )
    for attempt in report.attempts:
        if attempt.error:
            outcome = f"ERROR: {attempt.error}"
        elif attempt.attack_succeeded:
            outcome = "ADVERSARIAL SUCCESS"
        else:
            outcome = "SECURITY PASS"
        lines.append(
            f"| {markdown_text(attempt.case_name)} | {markdown_text(attempt.strategy)} | "
            f"{attempt.severity.value.upper()} | {markdown_text(outcome)} | "
            f"{markdown_text(attempt.evidence_sha256[:12])} |"
        )
    lines.extend(
        (
            "",
            "## Interpretation",
            "",
            "An adversarial success means the configured oracle observed its test objective. "
            "It is evidence for review, not an automatic severity rating. Errors are excluded "
            "from the attack success rate.",
            "",
        )
    )
    return "\n".join(lines)


def report_junit(report: RunReport) -> str:
    """Render findings as JUnit failures for CI systems."""

    return "".join(_report_junit_chunks(report))


def _xml_text(value: str) -> str:
    """Replace code points that XML 1.0 cannot represent."""

    rendered: list[str] = []
    for character in value:
        codepoint = ord(character)
        if (
            character in "\t\n\r"
            or 0x20 <= codepoint <= 0xD7FF
            or 0xE000 <= codepoint <= 0xFFFD
            or 0x10000 <= codepoint <= 0x10FFFF
        ):
            rendered.append(character)
        else:
            rendered.append(
                f"\\u{codepoint:04X}"
                if codepoint <= 0xFFFF
                else f"\\U{codepoint:08X}"
            )
    return "".join(rendered)


def _report_junit_chunks(report: RunReport) -> Iterator[str]:
    yield '<?xml version="1.0" encoding="utf-8"?>\n'
    yield (
        f'<testsuite name="advent-prompt-pwn" tests="{len(report.attempts)}" '
        f'failures="{report.attack_successes}" errors="{report.errors}">'
    )
    for attempt in report.attempts:
        case = Element(
            "testcase",
            {"classname": _xml_text(attempt.strategy), "name": _xml_text(attempt.case_id)},
        )
        if attempt.error:
            error = _xml_text(attempt.error)
            SubElement(case, "error", {"message": error}).text = error
        elif attempt.attack_succeeded:
            reason = attempt.oracle.reason if attempt.oracle else "oracle succeeded"
            reason = _xml_text(reason)
            SubElement(case, "failure", {"message": reason}).text = reason
        output = SubElement(case, "system-out")
        output.text = _xml_text(attempt.response.content) if attempt.response else ""
        yield tostring(case, encoding="unicode")
    yield "</testsuite>"


def report_sarif(report: RunReport) -> str:
    """Render adversarial successes as SARIF 2.1.0 results."""

    findings = []
    rules: dict[str, dict[str, Any]] = {}
    for attempt in report.attempts:
        if not attempt.attack_succeeded:
            continue
        rule_id = f"AI-{attempt.case_id}"
        rules[rule_id] = {
            "id": rule_id,
            "shortDescription": {"text": attempt.case_name},
            "properties": {"tags": list(attempt.tags)},
        }
        findings.append(
            {
                "ruleId": rule_id,
                "level": {
                    "critical": "error",
                    "high": "error",
                    "medium": "warning",
                    "low": "note",
                    "info": "none",
                }[attempt.severity.value],
                "message": {
                    "text": attempt.oracle.reason if attempt.oracle else "Adversarial success"
                },
                "properties": {
                    "strategy": attempt.strategy,
                    "finding_id": attempt.finding_id,
                    "severity": attempt.severity.value,
                    "evidence_sha256": attempt.evidence_sha256,
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "advent-prompt-pwn",
                        "informationUri": "https://www.adventcybersecurity.com/",
                        "rules": list(rules.values()),
                    }
                },
                "results": findings,
                "properties": {"run_id": report.run_id, "target": report.target_name},
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True)


def report_html(report: RunReport) -> str:
    """Render a standalone, safely escaped HTML assessment report."""

    return "".join(_report_html_chunks(report))


def _attempt_outcome(attempt: Any) -> tuple[str, str]:
    if attempt.error:
        return "ERROR", attempt.error
    if attempt.attack_succeeded:
        return (
            "ADVERSARIAL SUCCESS",
            attempt.oracle.reason if attempt.oracle else "Oracle succeeded",
        )
    return (
        "SECURITY PASS",
        attempt.oracle.reason if attempt.oracle else "Oracle did not succeed",
    )


def _report_html_chunks(report: RunReport) -> Iterator[str]:
    authorization = report.authorization_reference or "local-only"
    trial_statistics = report.trial_statistics
    trial_summary = ""
    if trial_statistics:
        mixed = sum(item.consistency == "mixed" for item in trial_statistics)
        trial_summary = (
            '<p><span class="metric">Repeated-trial groups: '
            f"<strong>{len(trial_statistics)}</strong></span>"
            '<span class="metric">Mixed outcomes: '
            f"<strong>{mixed}</strong></span></p>"
        )
    yield f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Red-Team Run {escape(report.run_id)}</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;
padding:0 1rem;color:#18202a}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccd3db;padding:.6rem;text-align:left}}
th{{background:#eef2f6}}
code,pre{{font-family:ui-monospace,monospace}}
pre{{white-space:pre-wrap;background:#f5f7f9;padding:1rem}}
.adversarial-success{{color:#a31212;font-weight:700}}
.security-pass{{color:#166534;font-weight:700}}
.error{{color:#92400e;font-weight:700}}
details{{margin:1rem 0}}
.metric{{display:inline-block;margin-right:2rem}}
</style>
</head>
<body>
<h1>AI Red-Team Run Report</h1>
<p>Target: <code>{escape(report.target_name)}</code><br>
Endpoint: <code>{escape(report.target_endpoint)}</code><br>
Authorization: <code>{escape(authorization)}</code><br>
Engagement: <code>{escape(report.engagement_id or "not-specified")}</code><br>
Run ID: <code>{escape(report.run_id)}</code><br>
Report SHA-256: <code>{escape(report.integrity_sha256)}</code></p>
<h2>Summary</h2>
<p><span class="metric">Attempts: <strong>{len(report.attempts)}</strong></span>
<span class="metric">Adversarial successes: <strong>{report.attack_successes}</strong></span>
<span class="metric">Findings: <strong>{len(report.findings)}</strong></span>
<span class="metric">Security passes: <strong>{report.security_passes}</strong></span>
<span class="metric">Errors: <strong>{report.errors}</strong></span></p>
{trial_summary}
<h2>Attempts</h2>
<table><thead><tr><th>Finding</th><th>Case</th><th>Strategy</th><th>Severity</th>
<th>Outcome</th><th>Evidence</th></tr></thead>
<tbody>"""
    for attempt in report.attempts:
        outcome, _ = _attempt_outcome(attempt)
        yield (
            "<tr>"
            f"<td><code>{attempt.finding_id if attempt.attack_succeeded else '-'}</code></td>"
            f"<td>{escape(attempt.case_name)}</td>"
            f"<td><code>{escape(attempt.strategy)}</code></td>"
            f"<td>{attempt.severity.value.upper()}</td>"
            f'<td class="{outcome.lower().replace(" ", "-")}">{outcome}</td>'
            f"<td><code>{attempt.evidence_sha256[:12]}</code></td>"
            "</tr>"
        )
    yield """</tbody></table>
<h2>Evidence details</h2>
"""
    for attempt in report.attempts:
        outcome, reason = _attempt_outcome(attempt)
        response = attempt.response.content if attempt.response else ""
        yield (
            "<details>"
            f"<summary>{escape(attempt.case_name)}: {escape(outcome)}</summary>"
            f"<p>{escape(reason)}</p>"
            f"<pre>{escape(response)}</pre>"
            "</details>"
        )
    yield """
<p>An adversarial success means the configured oracle observed its test objective.
Review the evidence before assigning severity.</p>
</body>
</html>
"""


_REPORTERS = {
    "json": report_json,
    "jsonl": report_jsonl,
    "html": report_html,
    "md": report_markdown,
    "markdown": report_markdown,
    "junit": report_junit,
    "xml": report_junit,
    "sarif": report_sarif,
}


def save_report(report: RunReport, path: str | Path, *, format_name: str | None = None) -> Path:
    """Save a report, inferring its format from the suffix when omitted."""

    destination = Path(path)
    selected = (format_name or destination.suffix.lstrip(".") or "json").lower()
    try:
        render = _REPORTERS[selected]
    except KeyError as exc:
        raise ValueError(f"unsupported report format: {selected}") from exc
    chunked: dict[str, Iterable[str]] = {
        "json": _report_json_chunks(report),
        "jsonl": _report_jsonl_chunks(report),
        "html": _report_html_chunks(report),
        "junit": _report_junit_chunks(report),
        "xml": _report_junit_chunks(report),
    }
    chunks = chunked.get(selected)
    if chunks is None:
        chunks = (render(report),)
    return atomic_write_text_chunks(destination, chunks, max_bytes=MAX_REPORT_BYTES)
