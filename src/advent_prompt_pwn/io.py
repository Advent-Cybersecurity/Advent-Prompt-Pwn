"""Durable, collision-resistant local file writes."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable
from pathlib import Path


def read_bounded_bytes(path: str | Path, max_bytes: int, *, label: str) -> bytes:
    """Read at most ``max_bytes`` and reject growth during the read."""

    source = Path(path)
    with source.open("rb") as handle:
        value = handle.read(max_bytes + 1)
    if len(value) > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")
    return value


def atomic_write_text(path: str | Path, value: str) -> Path:
    """Atomically replace a text file through a randomized sibling temporary file."""

    return atomic_write_text_chunks(path, (value,))


def atomic_write_text_chunks(
    path: str | Path,
    chunks: Iterable[str],
    *,
    max_bytes: int | None = None,
) -> Path:
    """Atomically write text chunks while optionally enforcing an encoded-byte limit."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            observed = 0
            for chunk in chunks:
                observed += len(chunk.encode("utf-8"))
                if max_bytes is not None and observed > max_bytes:
                    raise ValueError(f"rendered report exceeds {max_bytes} bytes")
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination
