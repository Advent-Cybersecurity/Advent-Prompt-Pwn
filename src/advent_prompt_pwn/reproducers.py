"""Deterministic extraction of compact reproducers from observed successes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import Any

from advent_prompt_pwn.core.models import AttemptResult, Message, RunReport
from advent_prompt_pwn.exceptions import ReportError
from advent_prompt_pwn.io import atomic_write_text_chunks
from advent_prompt_pwn.report_io import MAX_REPORT_BYTES, verify_report_evidence


@dataclass(frozen=True, slots=True)
class MinimalReproducer:
    """Shortest already-observed successful variant for one finding."""

    finding_id: str
    case_id: str
    variant_id: str
    strategy: str
    messages: tuple[Message, ...]
    message_count: int
    character_count: int
    evidence_sha256: str
    oracle_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "variant_id": self.variant_id,
            "strategy": self.strategy,
            "messages": [message.to_dict() for message in self.messages],
            "message_count": self.message_count,
            "character_count": self.character_count,
            "evidence_sha256": self.evidence_sha256,
            "oracle_reason": self.oracle_reason,
        }


def select_minimal_reproducers(report: RunReport) -> tuple[MinimalReproducer, ...]:
    """Select the smallest successful evidence item for each finding.

    This does not claim delta-debugging minimality. It chooses the shortest variant that
    already succeeded in the supplied integrity-verified report.
    """

    integrity_errors = verify_report_evidence(report)
    if integrity_errors:
        raise ReportError("report failed integrity verification: " + "; ".join(integrity_errors))
    successful = [attempt for attempt in report.attempts if attempt.attack_succeeded]
    grouped: dict[str, list[AttemptResult]] = {}
    for attempt in successful:
        grouped.setdefault(attempt.case_id, []).append(attempt)

    selected: list[MinimalReproducer] = []
    for attempts in grouped.values():
        best = min(
            attempts,
            key=lambda attempt: (
                sum(len(message.content) for message in attempt.messages),
                len(attempt.messages),
                attempt.variant_id,
            ),
        )
        selected.append(
            MinimalReproducer(
                finding_id=best.finding_id,
                case_id=best.case_id,
                variant_id=best.variant_id,
                strategy=best.strategy,
                messages=best.messages,
                message_count=len(best.messages),
                character_count=sum(len(message.content) for message in best.messages),
                evidence_sha256=best.evidence_sha256,
                oracle_reason=(
                    best.oracle.reason if best.oracle else "adversarial objective observed"
                ),
            )
        )
    return tuple(sorted(selected, key=lambda item: (item.case_id, item.variant_id)))


def save_minimal_reproducers(report: RunReport, path: str | Path) -> Path:
    """Write a versioned compact-reproducer document for practitioner review."""

    document = {
        "schema_version": 1,
        "source_run_id": report.run_id,
        "source_report_sha256": report.integrity_sha256,
        "reproducers": [item.to_dict() for item in select_minimal_reproducers(report)],
    }
    return atomic_write_text_chunks(
        Path(path),
        chain(json.JSONEncoder(indent=2, sort_keys=True).iterencode(document), ("\n",)),
        max_bytes=MAX_REPORT_BYTES,
    )
