"""JSONL I/O for benchmark suites and results."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from bench.schema import BenchmarkCase, BenchmarkResult


def read_suite(path: str | Path) -> List[BenchmarkCase]:
    """Read a benchmark suite from a JSONL file.

    Each line is a JSON object representing one BenchmarkCase.
    Blank lines and lines starting with ``//`` are skipped.

    Raises:
        ValueError: On malformed JSON or missing required fields (includes
            file path and line number).
    """
    cases: List[BenchmarkCase] = []
    with open(path) as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                data = json.loads(line)
                cases.append(BenchmarkCase.from_dict(data))
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                raise ValueError(f"{path}:{line_no}: invalid case: {e}") from e
    return cases


def write_results(results: List[BenchmarkResult], path: str | Path) -> None:
    """Write benchmark results to a JSONL file (one object per line)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for result in results:
            f.write(json.dumps(result.to_dict(), default=str) + "\n")


def read_results(path: str | Path) -> List[BenchmarkResult]:
    """Read benchmark results from a JSONL file."""
    results: List[BenchmarkResult] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            results.append(BenchmarkResult.from_dict(json.loads(line)))
    return results
