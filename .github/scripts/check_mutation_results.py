"""Fail CI when mutmut metadata contains unresolved outcomes."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

STATUS_BY_EXIT_CODE = {
    None: "not checked",
    -11: "segfault",
    -9: "segfault",
    0: "survived",
    1: "killed",
    2: "interrupted",
    3: "killed",
    5: "no tests",
    24: "timeout",
    33: "no tests",
    34: "skipped",
    35: "suspicious",
    36: "timeout",
    37: "caught by type check",
    152: "timeout",
    255: "timeout",
}
ACCEPTED = {"caught by type check", "killed", "skipped"}


def _load_results(root: Path) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*.meta")):
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
        exit_codes = raw.get("exit_code_by_key")
        if not isinstance(exit_codes, dict):
            raise ValueError(f"invalid mutmut metadata: {path}")
        for mutant, exit_code in sorted(exit_codes.items()):
            status = STATUS_BY_EXIT_CODE.get(exit_code, f"unknown exit code {exit_code}")
            results.append((str(mutant), status))
    return results


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path("mutants")
    destination = Path(argv[2]) if len(argv) > 2 else Path("mutation-results.txt")
    results = _load_results(root)
    if not results:
        destination.write_text("No mutation results found.\n", encoding="utf-8")
        print("No mutation results found.")
        return 2
    counts = Counter(status for _, status in results)
    unresolved = [(mutant, status) for mutant, status in results if status not in ACCEPTED]
    lines = [
        f"Total mutants: {len(results)}",
        *(f"{status}: {counts[status]}" for status in sorted(counts)),
        "",
        *(f"{mutant}: {status}" for mutant, status in unresolved),
    ]
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 1 if unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
