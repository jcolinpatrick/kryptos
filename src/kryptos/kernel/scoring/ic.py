"""Index of Coincidence scoring.

IC is transposition-invariant — it measures substitution characteristics
regardless of letter order.
"""
from __future__ import annotations

from collections import Counter
from typing import List

from kryptos.kernel.constants import IC_ENGLISH, IC_RANDOM


def ic(text: str) -> float:
    """Compute Index of Coincidence for text.

    Returns a value typically between 0.038 (random) and 0.067 (English).
    Note: IC is invariant under transposition.
    """
    freq = Counter(text.upper())
    n = sum(freq.values())
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def ic_by_position(text: str, period: int) -> List[float]:
    """Compute IC for each residue class modulo period.

    If text is polyalphabetic with this period, each class should
    have IC near English (0.067).
    """
    groups: list[str] = [""] * period
    for i, ch in enumerate(text):
        groups[i % period] += ch
    return [ic(g) for g in groups]


def ic_score(text: str) -> float:
    """Score text by how close its IC is to English.

    Returns value in [0, 1] where 1.0 = perfect English IC.
    """
    text_ic = ic(text)
    if text_ic >= IC_ENGLISH:
        return 1.0
    if text_ic <= IC_RANDOM:
        return 0.0
    return (text_ic - IC_RANDOM) / (IC_ENGLISH - IC_RANDOM)
