"""Empirical P(letter-difference delta mod 26 | lag) from a declared English corpus.

Mono- and source-generic statistics: a monoalphabetic substitution preserves
letter differences only at lag-fixed structure; this module measures the English
baseline against which mono-invariant forced differences are scored.
"""
from __future__ import annotations
import hashlib
import json
import os
from typing import Dict, List

_A = ord("A")


def _to_idx(text: str) -> List[int]:
    return [ord(c) - _A for c in text.upper() if "A" <= c.upper() <= "Z"]


def build_lag_stats(text: str, l_max: int = 12) -> Dict[int, List[float]]:
    idx = _to_idx(text)
    n = len(idx)
    out: Dict[int, List[float]] = {}
    for lag in range(1, l_max + 1):
        counts = [0] * 26
        for i in range(n - lag):
            counts[(idx[i] - idx[i + lag]) % 26] += 1
        total = sum(counts) or 1
        out[lag] = [c / total for c in counts]
    return out


def corpus_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_or_build(corpus_path: str, l_max: int = 12, cache_path: str | None = None) -> Dict[int, List[float]]:
    if cache_path and os.path.exists(cache_path):
        with open(cache_path) as fh:
            raw = json.load(fh)
        return {int(k): v for k, v in raw.items()}
    text = open(corpus_path, encoding="utf-8", errors="ignore").read()
    stats = build_lag_stats(text, l_max=l_max)
    if cache_path:
        json.dump({str(k): v for k, v in stats.items()}, open(cache_path, "w"))
    return stats
