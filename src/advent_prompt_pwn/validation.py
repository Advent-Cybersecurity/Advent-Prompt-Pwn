"""Shared resource bounds for untrusted JSON-like documents."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


def validate_json_value(
    value: Any,
    *,
    label: str,
    max_depth: int = 32,
    max_nodes: int = 100_000,
    max_collection_items: int = 10_000,
    max_string_chars: int = 1_000_000,
) -> None:
    """Reject cyclic, excessively large, or non-JSON-compatible structures."""

    stack: list[tuple[Any, int]] = [(value, 0)]
    containers: set[int] = set()
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ValueError(f"{label} exceeds {max_nodes} values")
        if depth > max_depth:
            raise ValueError(f"{label} exceeds nesting depth {max_depth}")
        if isinstance(current, str):
            if len(current) > max_string_chars:
                raise ValueError(f"{label} contains an overlong string")
            continue
        if current is None or isinstance(current, (bool, int)):
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError(f"{label} contains a non-finite number")
            continue
        if isinstance(current, Mapping):
            marker = id(current)
            if marker in containers:
                raise ValueError(f"{label} contains a cyclic or aliased container")
            containers.add(marker)
            if len(current) > max_collection_items:
                raise ValueError(f"{label} mapping exceeds {max_collection_items} entries")
            for key, item in current.items():
                if not isinstance(key, str):
                    raise ValueError(f"{label} mapping keys must be strings")
                if len(key) > max_string_chars:
                    raise ValueError(f"{label} contains an overlong key")
                stack.append((item, depth + 1))
            continue
        if isinstance(current, (list, tuple)):
            marker = id(current)
            if marker in containers:
                raise ValueError(f"{label} contains a cyclic or aliased container")
            containers.add(marker)
            if len(current) > max_collection_items:
                raise ValueError(f"{label} collection exceeds {max_collection_items} entries")
            stack.extend((item, depth + 1) for item in current)
            continue
        raise ValueError(f"{label} contains unsupported value type {type(current).__name__}")
