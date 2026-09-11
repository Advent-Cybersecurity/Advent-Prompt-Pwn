"""Strict report loading and evidence-integrity verification."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from advent_prompt_pwn.core.models import (
    AttemptResult,
    Message,
    OracleResult,
    Role,
    RunReport,
    Severity,
    TargetResponse,
    ToolCall,
)
from advent_prompt_pwn.exceptions import ReportError
from advent_prompt_pwn.integrity import attempt_sha256, digest_matches, report_sha256
from advent_prompt_pwn.io import read_bounded_bytes
from advent_prompt_pwn.parsing import reject_duplicate_json_keys
from advent_prompt_pwn.validation import validate_json_value

MAX_REPORT_BYTES = 100_000_000
_SHA256_LENGTH = 64


def _is_sha256(value: str) -> bool:
    return len(value) == _SHA256_LENGTH and all(
        character in "0123456789abcdef" for character in value
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReportError(f"{label} must be a mapping")
    return value


def _messages(raw: Any) -> tuple[Message, ...]:
    if not isinstance(raw, list):
        raise ReportError("attempt messages must be a list")
    values: list[Message] = []
    for item in raw:
        data = _mapping(item, "message")
        values.append(
            Message(
                role=Role(str(data["role"])),
                content=str(data["content"]),
                name=str(data["name"]) if data.get("name") is not None else None,
            )
        )
    return tuple(values)


def _tool_calls(raw: Any) -> tuple[ToolCall, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ReportError("response tool_calls must be a list")
    return tuple(
        ToolCall(
            name=str(_mapping(item, "tool call")["name"]),
            arguments=str(_mapping(item, "tool call").get("arguments", "")),
            call_id=(
                str(_mapping(item, "tool call")["call_id"])
                if _mapping(item, "tool call").get("call_id") is not None
                else None
            ),
        )
        for item in raw
    )


def _response(raw: Any) -> TargetResponse | None:
    if raw is None:
        return None
    data = _mapping(raw, "response")
    usage = _mapping(data.get("usage", {}), "response usage")
    metadata = _mapping(data.get("metadata", {}), "response metadata")
    return TargetResponse(
        content=str(data.get("content", "")),
        model=str(data["model"]) if data.get("model") is not None else None,
        finish_reason=(
            str(data["finish_reason"]) if data.get("finish_reason") is not None else None
        ),
        latency_ms=float(data["latency_ms"]) if data.get("latency_ms") is not None else None,
        usage={str(key): int(value) for key, value in usage.items()},
        tool_calls=_tool_calls(data.get("tool_calls", [])),
        metadata=dict(metadata),
    )


def _oracle(raw: Any) -> OracleResult | None:
    if raw is None:
        return None
    data = _mapping(raw, "oracle result")
    success = data["success"]
    if not isinstance(success, bool):
        raise ReportError("oracle success must be true or false")
    return OracleResult(
        success=success,
        reason=str(data["reason"]),
        score=float(data.get("score", 1.0)),
        evidence=dict(_mapping(data.get("evidence", {}), "oracle evidence")),
    )


def _attempt(raw: Any) -> AttemptResult:
    data = _mapping(raw, "attempt")
    metadata = _mapping(data.get("metadata", {}), "attempt metadata")
    tags = data.get("tags", [])
    if not isinstance(tags, list):
        raise ReportError("attempt tags must be a list")
    return AttemptResult(
        case_id=str(data["case_id"]),
        case_name=str(data["case_name"]),
        variant_id=str(data["variant_id"]),
        strategy=str(data["strategy"]),
        messages=_messages(data["messages"]),
        response=_response(data.get("response")),
        oracle=_oracle(data.get("oracle")),
        started_at=str(data["started_at"]),
        evidence_sha256=str(data["evidence_sha256"]),
        error=str(data["error"]) if data.get("error") is not None else None,
        tags=tuple(str(tag) for tag in tags),
        completed_at=str(data.get("completed_at", "")),
        duration_ms=(float(data["duration_ms"]) if data.get("duration_ms") is not None else None),
        request_attempts=int(data.get("request_attempts", 1)),
        severity=Severity(str(data.get("severity", "medium"))),
        metadata=dict(metadata),
    )


def report_from_dict(raw: Mapping[str, Any]) -> RunReport:
    """Build a typed run report from an untrusted JSON mapping."""

    try:
        validate_json_value(
            raw,
            label="report",
            max_nodes=1_000_000,
            max_collection_items=100_000,
        )
    except ValueError as exc:
        raise ReportError(str(exc)) from exc
    attempts = raw.get("attempts")
    if not isinstance(attempts, list):
        raise ReportError("report attempts must be a list")
    metadata = _mapping(raw.get("metadata", {}), "report metadata")
    report = RunReport(
        run_id=str(raw["run_id"]),
        target_name=str(raw["target_name"]),
        target_endpoint=str(raw["target_endpoint"]),
        started_at=str(raw["started_at"]),
        completed_at=str(raw["completed_at"]),
        seed=int(raw["seed"]),
        attempts=tuple(_attempt(item) for item in attempts),
        authorization_reference=(
            str(raw["authorization_reference"])
            if raw.get("authorization_reference") is not None
            else None
        ),
        metadata=dict(metadata),
        schema_version=int(raw.get("schema_version", 1)),
        tool_version=str(raw.get("tool_version", "")),
        engagement_id=(str(raw["engagement_id"]) if raw.get("engagement_id") is not None else None),
        corpus_sha256=(str(raw["corpus_sha256"]) if raw.get("corpus_sha256") is not None else None),
        request_count=int(raw.get("request_count", 0)),
        integrity_sha256=str(raw.get("integrity_sha256", "")),
    )
    expected = report.to_dict()
    if _canonical_json(raw) != _canonical_json(expected):
        raise ReportError(
            "report derived fields or canonical schema do not match; unknown, omitted, or "
            "mistyped fields are not integrity-covered"
        )
    return report


def load_report(path: str | Path) -> RunReport:
    """Load a bounded JSON report and reconstruct its typed model."""

    source = Path(path)
    try:
        report_bytes = read_bounded_bytes(source, MAX_REPORT_BYTES, label="report")
        raw: Any = json.loads(
            report_bytes.decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
        validate_json_value(
            raw,
            label="report",
            max_nodes=1_000_000,
            max_collection_items=100_000,
        )
    except ReportError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ReportError(f"could not load report {source}: {exc}") from exc
    try:
        return report_from_dict(_mapping(raw, "report root"))
    except (KeyError, TypeError, ValueError) as exc:
        raise ReportError(f"invalid report {source}: {exc}") from exc


def verify_report_evidence(report: RunReport) -> tuple[str, ...]:
    """Return integrity errors for attempt hashes and report invariants."""

    errors: list[str] = []
    seen: set[str] = set()
    finding_cases: dict[str, str] = {}
    for attempt in report.attempts:
        if attempt.variant_id in seen:
            errors.append(f"duplicate variant id: {attempt.variant_id}")
        seen.add(attempt.variant_id)
        if not _is_sha256(attempt.evidence_sha256):
            errors.append(f"invalid evidence digest for {attempt.variant_id}")
            continue
        observed = attempt_sha256(attempt)
        if not digest_matches(observed, attempt.evidence_sha256):
            errors.append(f"evidence digest mismatch for {attempt.variant_id}")
    for finding in report.findings:
        previous_case = finding_cases.setdefault(finding.finding_id, finding.case_id)
        if previous_case != finding.case_id:
            errors.append(
                f"finding id collision between cases {previous_case!r} and {finding.case_id!r}"
            )
    if report.corpus_sha256 and not _is_sha256(report.corpus_sha256):
        errors.append("invalid corpus digest")
    unresolved = report.metadata.get("unresolved_request_count", 0)
    if (
        not isinstance(unresolved, int)
        or isinstance(unresolved, bool)
        or unresolved < 0
    ):
        errors.append("unresolved request count is invalid")
        unresolved = 0
    if report.request_count != (
        sum(attempt.request_attempts for attempt in report.attempts) + unresolved
    ):
        errors.append("request count does not equal completed and unresolved request accounting")
    if not _is_sha256(report.integrity_sha256):
        errors.append("invalid report integrity digest")
    elif not digest_matches(report_sha256(report), report.integrity_sha256):
        errors.append("report integrity digest mismatch")
    return tuple(errors)
