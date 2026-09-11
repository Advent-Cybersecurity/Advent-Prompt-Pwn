"""Canonical modification-detection hashes for assessment evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, replace
from enum import Enum
from typing import Any

from advent_prompt_pwn.core.models import AttemptResult, RunReport


def _normalize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value


def canonical_sha256(value: Any) -> str:
    """Hash a JSON-compatible value using a stable canonical encoding."""

    encoded = json.dumps(
        _normalize(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def attempt_sha256(attempt: AttemptResult) -> str:
    """Hash every persisted attempt field except the digest itself."""

    payload = asdict(attempt)
    payload.pop("evidence_sha256", None)
    return canonical_sha256(payload)


def report_sha256(report: RunReport) -> str:
    """Hash the complete report envelope, including its attempt digests."""

    payload = asdict(report)
    payload.pop("integrity_sha256", None)
    return canonical_sha256(payload)


def seal_attempt(attempt: AttemptResult) -> AttemptResult:
    """Return an attempt with its canonical modification-detection digest."""

    return replace(attempt, evidence_sha256=attempt_sha256(attempt))


def seal_report(report: RunReport) -> RunReport:
    """Return a report with its canonical envelope digest."""

    return replace(report, integrity_sha256=report_sha256(report))


def digest_matches(observed: str, expected: str) -> bool:
    """Compare hexadecimal digests without data-dependent early exit."""

    return hmac.compare_digest(observed, expected)
