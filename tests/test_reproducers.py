from __future__ import annotations

import json
import random
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

import pytest

from advent_prompt_pwn import (
    AttackCase,
    AttackVariant,
    CanaryLeakOracle,
    FakeTarget,
    Message,
    Role,
    Runner,
    Scope,
    select_minimal_reproducers,
)
from advent_prompt_pwn.cli import main
from advent_prompt_pwn.exceptions import ReportError
from advent_prompt_pwn.reporters import save_report
from advent_prompt_pwn.reproducers import save_minimal_reproducers
from advent_prompt_pwn.strategies.base import Strategy


class ReproducerCandidates(Strategy):
    name = "reproducer_candidates"

    def generate(self, case: AttackCase, rng: random.Random) -> Iterable[AttackVariant]:
        del rng
        yield AttackVariant(
            "long",
            case.case_id,
            self.name,
            (Message(Role.USER, "a deliberately longer successful prompt"),),
        )
        yield AttackVariant(
            "short",
            case.case_id,
            self.name,
            (Message(Role.USER, "short"),),
        )


def _finding_report():
    case = AttackCase("reproducer", "Reproducer", "prompt", CanaryLeakOracle("LAB_REPRO"))
    return Runner(
        FakeTarget("LAB_REPRO"),
        scope=Scope.local_only(max_requests=2, requests_per_minute=1_000_000),
    ).run([case], ReproducerCandidates())


def test_selects_shortest_observed_success_and_writes_document(tmp_path: Path) -> None:
    report = _finding_report()
    selected = select_minimal_reproducers(report)
    assert len(selected) == 1
    assert selected[0].variant_id == "short"
    assert selected[0].character_count == 5

    destination = save_minimal_reproducers(report, tmp_path / "reproducers.json")
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["source_report_sha256"] == report.integrity_sha256
    assert document["reproducers"][0]["messages"][0]["content"] == "short"


def test_reproducer_extraction_rejects_tampered_evidence() -> None:
    report = _finding_report()
    tampered = replace(report, target_name="changed")
    with pytest.raises(ReportError, match="integrity"):
        select_minimal_reproducers(tampered)


def test_cli_extracts_reproducers(tmp_path: Path) -> None:
    source = save_report(_finding_report(), tmp_path / "report.json")
    output = tmp_path / "reproducers.json"
    assert main(["reproducers", str(source), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["reproducers"]
