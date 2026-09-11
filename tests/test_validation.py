from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from advent_prompt_pwn.io import atomic_write_text
from advent_prompt_pwn.validation import validate_json_value


@pytest.mark.parametrize(
    ("value", "kwargs", "message"),
    [
        ([1, 2], {"max_nodes": 2}, "values"),
        ([[[1]]], {"max_depth": 1}, "nesting depth"),
        ({"a": 1, "b": 2}, {"max_collection_items": 1}, "mapping"),
        ([1, 2], {"max_collection_items": 1}, "collection"),
        ("long", {"max_string_chars": 2}, "overlong string"),
        ({"long": 1}, {"max_string_chars": 2}, "overlong key"),
        ({1: "value"}, {}, "keys must be strings"),
        ({"x": object()}, {}, "unsupported value type"),
        (math.inf, {}, "non-finite"),
    ],
)
def test_json_value_resource_bounds(
    value: object,
    kwargs: dict[str, int],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_json_value(value, label="test", **kwargs)


def test_json_value_rejects_cycles_and_accepts_primitives() -> None:
    cycle: list[object] = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="cyclic"):
        validate_json_value(cycle, label="test")
    validate_json_value(
        {"none": None, "bool": True, "int": 1, "float": 1.5, "tuple": ("ok",)},
        label="test",
    )


def test_atomic_writer_cleans_up_after_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "output.txt"

    def fail_replace(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
        del source, target
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated"):
        atomic_write_text(destination, "value")
    assert list(tmp_path.iterdir()) == []
