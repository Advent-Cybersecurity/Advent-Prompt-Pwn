from __future__ import annotations

import json
from pathlib import Path

import pytest

from advent_prompt_pwn.core.models import Severity
from advent_prompt_pwn.corpus import STARTER_CORPUS, load_corpus, write_starter_corpus
from advent_prompt_pwn.exceptions import CorpusError


def test_write_and_load_starter_corpus(tmp_path: Path) -> None:
    path = write_starter_corpus(tmp_path / "cases.yaml")
    cases = load_corpus(path)
    assert len(cases) == 1
    assert cases[0].case_id == "direct-canary"


def test_starter_writer_does_not_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "cases.yaml"
    path.write_text("existing", encoding="utf-8")
    with pytest.raises(FileExistsError, match="overwrite"):
        write_starter_corpus(path)
    write_starter_corpus(path, force=True)
    assert path.read_text(encoding="utf-8") == STARTER_CORPUS


def test_load_json_corpus(tmp_path: Path) -> None:
    document = {
        "version": 1,
        "cases": [
            {
                "id": "json-case",
                "name": "JSON",
                "prompt": "prompt",
                "tags": ["json"],
                "metadata": {"owner": "lab"},
                "severity": "high",
                "oracle": {"type": "contains", "value": "marker"},
            }
        ],
    }
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    case = load_corpus(path)[0]
    assert case.metadata["owner"] == "lab"
    assert case.severity is Severity.HIGH


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("version: 2\ncases: []", "version"),
        ("version: 1\ncases: []", "non-empty"),
        ("- invalid", "root"),
        ("version: 1\ncases: [text]", "mapping"),
        ("version: 1\ncases: [{}]", "missing field"),
    ],
)
def test_invalid_corpora_are_rejected(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(CorpusError, match=message):
        load_corpus(path)


def test_duplicate_case_ids_are_rejected(tmp_path: Path) -> None:
    case = """
  - id: duplicate
    name: Duplicate
    prompt: Prompt
    oracle: {type: contains, value: x}
"""
    path = tmp_path / "duplicate.yaml"
    path.write_text(f"version: 1\ncases:{case}{case}", encoding="utf-8")
    with pytest.raises(CorpusError, match="duplicate"):
        load_corpus(path)


def test_missing_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(CorpusError, match="could not read"):
        load_corpus(tmp_path / "missing.yaml")


def test_yaml_parse_error_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("version: [", encoding="utf-8")
    with pytest.raises(CorpusError, match="could not parse"):
        load_corpus(path)
